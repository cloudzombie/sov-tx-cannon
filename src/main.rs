#![forbid(unsafe_code)]
// egui's API is uniformly `f32`, so float literals passed to it take the f32
// fallback intentionally (same posture as SOV-Station).
#![allow(unknown_lints)]
#![allow(float_literal_f32_fallback)]

//! SOV TX Cannon — an automated transaction traffic generator.
//!
//! Watches a SOV node's chain tip over JSON-RPC and, on each NEW block, fires a
//! configurable number of transparent transfers from a wallet the user unlocks
//! (SOV-Station's own encrypted keystore) to destination addresses the user sets.
//!
//! This is PURELY functional traffic generation: it only READS chain state and
//! SUBMITS already-signed transactions through the same key-free RPC surface any
//! wallet uses. It touches no consensus, mining, block-encoding, or genesis code.
//!
//! Security posture (see the worker docs, below): the master passphrase and every
//! wallet signing seed live in `zeroize`-wiped buffers for the session only;
//! nothing secret is ever written to disk or logged.

mod logic;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use zeroize::{Zeroize, Zeroizing};

use sov_primitives::AccountId;
use sov_rpc::{Keystore, RpcClient};

use logic::{
    build_signed_transfer, grains_to_xus, parse_xus, AmountMode, DestMode, DestSelector, KeyScheme,
    NonceSequencer, Rng,
};

/// Default node RPC endpoint (SOV-Station's node default).
const DEFAULT_RPC: &str = "127.0.0.1:8645";
/// Hard cap on transactions fired per new block, to keep the tool sane.
const MAX_RATE: u32 = 100;
/// Estimated fee reserved per transfer for the local affordability pre-check:
/// `INTRINSIC_GAS (21_000) × gas_price (1 grain on mainnet)`. The node's mempool
/// is the real authority — this only lets us surface "insufficient balance"
/// before firing rather than eating a rejection per tx.
const FEE_ESTIMATE_GRAINS: u128 = 21_000;
/// How often the worker polls the tip while idle between blocks.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

fn main() -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([760.0, 820.0])
            .with_min_inner_size([620.0, 560.0])
            .with_title("SOV TX Cannon"),
        ..Default::default()
    };
    eframe::run_native(
        "SOV TX Cannon",
        options,
        Box::new(|_cc| Ok(Box::new(CannonApp::default()))),
    )
    .map_err(|e| format!("GUI failed: {e}"))
}

/// One unlocked, spendable wallet held in memory for the session.
///
/// The durable secret is `seed`, kept in a `Zeroizing` buffer so it is wiped from
/// memory when this struct drops (on lock, unlock-again, or app exit). The
/// `Keypair` is never stored — it is derived transiently only for the instant of
/// signing.
struct UnlockedWallet {
    label: String,
    account: AccountId,
    scheme: KeyScheme,
    seed: Zeroizing<[u8; 32]>,
    /// Last known liquid balance in grains (read via RPC), for display.
    balance_grains: Option<u128>,
}

/// The keystore path: `~/.sov-station/wallets.keystore` (same file SOV-Station
/// writes). Kept overridable in the UI for non-default installs.
fn default_keystore_path() -> String {
    let home = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
        .unwrap_or_default();
    PathBuf::from(home)
        .join(".sov-station")
        .join("wallets.keystore")
        .to_string_lossy()
        .into_owned()
}

/// A single line in the live per-tx log.
#[derive(Clone)]
struct LogLine {
    height: u64,
    to: String,
    amount_grains: u128,
    nonce: u64,
    ok: bool,
    detail: String,
}

/// Live status shared between the UI thread and the firing worker.
#[derive(Default)]
struct Status {
    running: bool,
    tip_height: u64,
    sent_ok: u64,
    sent_fail: u64,
    last_error: String,
    /// Spend-from balance the worker refreshes each block.
    from_balance_grains: Option<u128>,
    /// Newest-last per-tx log (bounded).
    log: Vec<LogLine>,
}

impl Status {
    fn push_log(&mut self, line: LogLine) {
        self.log.push(line);
        // Bound memory: keep the most recent 500 lines.
        let len = self.log.len();
        if len > 500 {
            self.log.drain(0..len - 500);
        }
    }
}

/// Immutable-per-run configuration handed to the worker thread when firing starts.
struct RunConfig {
    rpc_addr: String,
    from: AccountId,
    scheme: KeyScheme,
    seed: Zeroizing<[u8; 32]>,
    dests: Vec<AccountId>,
    dest_mode: DestMode,
    amount_mode: AmountMode,
    rate: u32,
    dry_run: bool,
}

/// A running firing session (its stop flag + thread handle).
struct Session {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Session {
    /// Signal the worker to stop and join it (so its seed copy is zeroized before
    /// we return).
    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// The application state.
struct CannonApp {
    // Connection + unlock inputs.
    rpc_addr: String,
    keystore_path: String,
    /// Secret input: wiped on drop and immediately after a successful unlock.
    passphrase: Zeroizing<String>,
    unlock_msg: String,

    // Unlocked wallets + which one to spend from.
    wallets: Vec<UnlockedWallet>,
    selected: usize,

    // Traffic configuration (UI form fields).
    dests_text: String,
    dest_random: bool,
    amount_random: bool,
    amount_fixed: String,
    amount_min: String,
    amount_max: String,
    rate: String,
    dry_run: bool,
    config_msg: String,

    // Live run.
    status: Arc<Mutex<Status>>,
    session: Option<Session>,
}

impl Default for CannonApp {
    fn default() -> Self {
        Self {
            rpc_addr: DEFAULT_RPC.to_string(),
            keystore_path: default_keystore_path(),
            passphrase: Zeroizing::new(String::new()),
            unlock_msg: String::new(),
            wallets: Vec::new(),
            selected: 0,
            dests_text: String::new(),
            dest_random: false,
            amount_random: false,
            amount_fixed: "0.001".to_string(),
            amount_min: "0.001".to_string(),
            amount_max: "0.01".to_string(),
            rate: "1".to_string(),
            dry_run: true,
            config_msg: String::new(),
            status: Arc::new(Mutex::new(Status::default())),
            session: None,
        }
    }
}

impl CannonApp {
    fn is_running(&self) -> bool {
        self.session.is_some()
    }

    /// Read + decrypt SOV-Station's keystore with the typed passphrase, load the
    /// spendable wallets, then WIPE the passphrase. Watch-only entries (no seed)
    /// are skipped — they cannot sign.
    fn unlock(&mut self) {
        if self.is_running() {
            return;
        }
        if self.passphrase.is_empty() {
            self.unlock_msg = "enter your master passphrase".into();
            return;
        }
        let text = match std::fs::read_to_string(&self.keystore_path) {
            Ok(t) => t,
            Err(e) => {
                self.unlock_msg = format!("cannot read keystore: {e}");
                return;
            }
        };
        // Reuse SOV-Station's exact hardened decryption (Argon2id + ChaCha20-Poly1305).
        let ks = match Keystore::from_encrypted_or_plain(&text, Some(self.passphrase.as_str())) {
            Ok(ks) => ks,
            Err(e) => {
                self.unlock_msg = format!("unlock failed: {e}");
                self.passphrase.zeroize();
                return;
            }
        };

        // Drop any previously unlocked wallets first (zeroizes their seeds).
        self.wipe_wallets();
        for (i, entry) in ks.miners.iter().enumerate() {
            // Skip watch-only entries: empty seed, public key present.
            if entry.seed_hex.trim().is_empty() {
                continue;
            }
            let scheme = match KeyScheme::from_keystore(entry.scheme.as_deref()) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut seed_bytes = match hex::decode(entry.seed_hex.trim()) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let seed_arr: [u8; 32] = match seed_bytes.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => {
                    wipe_vec(&mut seed_bytes);
                    continue;
                }
            };
            // Move the seed into a zeroizing buffer, then wipe the transient copy.
            let mut seed = Zeroizing::new(seed_arr);
            wipe_vec(&mut seed_bytes);
            let account = match AccountId::new(entry.account.trim()) {
                Ok(a) => a,
                Err(_) => {
                    // Wipe the seed we just built before discarding it.
                    *seed = [0u8; 32];
                    continue;
                }
            };
            let label = if entry.account.trim().is_empty() {
                format!("wallet #{i}")
            } else {
                entry.account.trim().to_string()
            };
            self.wallets.push(UnlockedWallet {
                label,
                account,
                scheme,
                seed,
                balance_grains: None,
            });
        }
        // The passphrase has done its job; wipe it from memory now.
        self.passphrase.zeroize();

        if self.wallets.is_empty() {
            self.unlock_msg =
                "unlocked, but no spendable wallets found (watch-only or empty keystore)".into();
        } else {
            self.selected = 0;
            self.unlock_msg = format!("unlocked {} wallet(s)", self.wallets.len());
            self.refresh_balances();
        }
    }

    /// Wipe all in-memory key material (called on lock, re-unlock, and exit).
    fn wipe_wallets(&mut self) {
        // UnlockedWallet::seed is Zeroizing → wiped on drop.
        self.wallets.clear();
        self.selected = 0;
    }

    /// Refresh each unlocked wallet's balance from the node (best-effort).
    fn refresh_balances(&mut self) {
        let client = RpcClient::new(self.rpc_addr.clone()).with_timeout(Duration::from_secs(5));
        for w in &mut self.wallets {
            w.balance_grains = client.balance(&w.account).ok().map(|b| b.grains());
        }
    }

    /// Parse the destination textarea into validated account ids.
    fn parse_dests(&self) -> Result<Vec<AccountId>, String> {
        let mut out = Vec::new();
        for (n, raw) in self.dests_text.lines().enumerate() {
            let s = raw.trim();
            if s.is_empty() {
                continue;
            }
            let acct = AccountId::new(s)
                .map_err(|e| format!("line {}: '{s}' is not a valid account: {e}", n + 1))?;
            out.push(acct);
        }
        if out.is_empty() {
            return Err("add at least one destination address (one per line)".into());
        }
        Ok(out)
    }

    /// Parse + validate the amount mode from the UI fields.
    fn parse_amount_mode(&self) -> Result<AmountMode, String> {
        let mode = if self.amount_random {
            let min = parse_xus(&self.amount_min).ok_or("amount min is not a valid XUS value")?;
            let max = parse_xus(&self.amount_max).ok_or("amount max is not a valid XUS value")?;
            AmountMode::Range { min, max }
        } else {
            let v = parse_xus(&self.amount_fixed).ok_or("amount is not a valid XUS value")?;
            AmountMode::Fixed(v)
        };
        mode.validate()?;
        Ok(mode)
    }

    /// Build the full run configuration from the current form; on any error, set
    /// `config_msg` and return `None`.
    fn build_run_config(&mut self) -> Option<RunConfig> {
        if self.wallets.is_empty() {
            self.config_msg = "unlock a wallet first".into();
            return None;
        }
        let dests = match self.parse_dests() {
            Ok(d) => d,
            Err(e) => {
                self.config_msg = e;
                return None;
            }
        };
        let amount_mode = match self.parse_amount_mode() {
            Ok(m) => m,
            Err(e) => {
                self.config_msg = e;
                return None;
            }
        };
        let rate: u32 = match self.rate.trim().parse() {
            Ok(r) if (1..=MAX_RATE).contains(&r) => r,
            _ => {
                self.config_msg = format!("rate must be between 1 and {MAX_RATE}");
                return None;
            }
        };
        let w = &self.wallets[self.selected];
        Some(RunConfig {
            rpc_addr: self.rpc_addr.clone(),
            from: w.account.clone(),
            scheme: w.scheme,
            // Clone the seed into a fresh zeroizing buffer moved to the worker.
            seed: Zeroizing::new(*w.seed),
            dests,
            dest_mode: if self.dest_random {
                DestMode::Random
            } else {
                DestMode::RoundRobin
            },
            amount_mode,
            rate,
            dry_run: self.dry_run,
        })
    }

    /// Start firing: spawn the worker thread with a copy of the signing seed.
    fn start(&mut self, ctx: &eframe::egui::Context) {
        if self.is_running() {
            return;
        }
        let Some(cfg) = self.build_run_config() else {
            return;
        };
        // Reset counters for the new run.
        {
            let mut st = self.status.lock().unwrap();
            *st = Status {
                running: true,
                ..Status::default()
            };
        }
        self.config_msg = if cfg.dry_run {
            "running (DRY-RUN: building + logging txs, NOT submitting)".into()
        } else {
            "running: firing live transactions each new block".into()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let status = self.status.clone();
        let ctx = ctx.clone();
        let worker_stop = stop.clone();
        let handle = thread::spawn(move || run_worker(cfg, status, worker_stop, ctx));
        self.session = Some(Session {
            stop,
            handle: Some(handle),
        });
    }

    /// Stop firing and join the worker (which zeroizes its seed copy on exit).
    fn stop(&mut self) {
        if let Some(mut s) = self.session.take() {
            s.stop_and_join();
        }
        if let Ok(mut st) = self.status.lock() {
            st.running = false;
        }
        self.config_msg = "stopped".into();
    }
}

impl Drop for CannonApp {
    fn drop(&mut self) {
        // Ensure the worker's seed copy is wiped, then wipe ours.
        if let Some(mut s) = self.session.take() {
            s.stop_and_join();
        }
        self.wipe_wallets();
        self.passphrase.zeroize();
    }
}

/// Best-effort overwrite of a byte vector's contents before it is freed.
fn wipe_vec(v: &mut Vec<u8>) {
    for b in v.iter_mut() {
        *b = 0;
    }
    v.clear();
}

/// The firing worker: owns a `Zeroizing` copy of the signing seed for its lifetime
/// and wipes it on return (normal stop or panic-unwind of this frame).
///
/// Each new tip height: refresh the spend-from balance + reconcile the nonce
/// sequencer against the node, then build `rate` signed transfers and (unless
/// dry-run) submit them, updating shared status/counters/log. The seed is used
/// only to derive a transient keypair inside `build_signed_transfer`; the keypair
/// never outlives a single signature and is never stored or logged.
fn run_worker(
    cfg: RunConfig,
    status: Arc<Mutex<Status>>,
    stop: Arc<AtomicBool>,
    ctx: eframe::egui::Context,
) {
    let client = RpcClient::new(cfg.rpc_addr.clone()).with_timeout(Duration::from_secs(15));
    let mut selector = match DestSelector::new(cfg.dests.clone(), cfg.dest_mode) {
        Ok(s) => s,
        Err(e) => {
            set_error(&status, &e);
            return;
        }
    };
    let mut rng = Rng::from_entropy();
    let mut seq = NonceSequencer::new();
    let mut last_height: Option<u64> = None;

    while !stop.load(Ordering::SeqCst) {
        let height = match client.height() {
            Ok(h) => h,
            Err(e) => {
                set_error(&status, &format!("RPC height failed: {e}"));
                sleep_interruptible(&stop, POLL_INTERVAL);
                continue;
            }
        };
        {
            let mut st = status.lock().unwrap();
            st.tip_height = height;
        }
        ctx.request_repaint();

        let is_new = last_height.map(|h| height > h).unwrap_or(true);
        if !is_new {
            sleep_interruptible(&stop, POLL_INTERVAL);
            continue;
        }
        last_height = Some(height);

        // Reconcile the nonce sequencer against the node's reported next nonce.
        match client.nonce(&cfg.from) {
            Ok(n) => seq.reconcile(n),
            Err(e) => {
                set_error(&status, &format!("RPC nonce failed: {e}"));
                sleep_interruptible(&stop, POLL_INTERVAL);
                continue;
            }
        }

        // Refresh spend-from balance for display + the affordability pre-check.
        let mut known_balance = client.balance(&cfg.from).ok().map(|b| b.grains());
        if let Ok(mut st) = status.lock() {
            st.from_balance_grains = known_balance;
        }

        for _ in 0..cfg.rate {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            let to = selector.next(&mut rng);
            let amount = cfg.amount_mode.pick(&mut rng);
            let nonce = seq.peek();

            // Local affordability pre-check (the node's mempool is the real gate).
            if let Some(bal) = known_balance {
                if bal < amount.saturating_add(FEE_ESTIMATE_GRAINS) {
                    let detail = format!(
                        "insufficient balance ({} XUS) for {} XUS + fee — stopping",
                        grains_to_xus(bal),
                        grains_to_xus(amount)
                    );
                    log_tx(&status, height, &to, amount, nonce, false, &detail);
                    set_error(&status, &detail);
                    // Stop this run: continuing would just spew rejects.
                    stop.store(true, Ordering::SeqCst);
                    break;
                }
            }

            let stx =
                match build_signed_transfer(&cfg.seed, cfg.scheme, &cfg.from, &to, amount, nonce) {
                    Ok(s) => s,
                    Err(e) => {
                        log_tx(&status, height, &to, amount, nonce, false, &e);
                        bump_fail(&status);
                        continue;
                    }
                };
            // Only advance the nonce once we've committed to sending this one.
            let _ = seq.next();

            if cfg.dry_run {
                log_tx(
                    &status,
                    height,
                    &to,
                    amount,
                    nonce,
                    true,
                    "dry-run (not submitted)",
                );
                bump_ok(&status);
                // Optimistically debit our local balance view so the affordability
                // pre-check reflects the spend even without a live submit.
                if let Some(b) = known_balance.as_mut() {
                    *b = b.saturating_sub(amount.saturating_add(FEE_ESTIMATE_GRAINS));
                }
                continue;
            }

            match client.submit_transaction(&stx) {
                Ok(txid) => {
                    log_tx(
                        &status,
                        height,
                        &to,
                        amount,
                        nonce,
                        true,
                        &format!("submitted {}", short_hash(&txid.to_hex())),
                    );
                    bump_ok(&status);
                    if let Some(b) = known_balance.as_mut() {
                        *b = b.saturating_sub(amount.saturating_add(FEE_ESTIMATE_GRAINS));
                    }
                }
                Err(e) => {
                    log_tx(&status, height, &to, amount, nonce, false, &format!("{e}"));
                    bump_fail(&status);
                }
            }
        }

        if let Ok(mut st) = status.lock() {
            st.from_balance_grains = known_balance;
        }
        ctx.request_repaint();
        sleep_interruptible(&stop, POLL_INTERVAL);
    }

    // Mark stopped for the UI. `cfg` (and its Zeroizing seed) drops here → wiped.
    if let Ok(mut st) = status.lock() {
        st.running = false;
    }
    ctx.request_repaint();
}

fn short_hash(h: &str) -> String {
    if h.len() > 12 {
        format!("{}…{}", &h[..6], &h[h.len() - 4..])
    } else {
        h.to_string()
    }
}

fn sleep_interruptible(stop: &Arc<AtomicBool>, dur: Duration) {
    // Wake early if asked to stop, so Stop feels instant.
    let step = Duration::from_millis(50);
    let mut slept = Duration::ZERO;
    while slept < dur {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        thread::sleep(step);
        slept += step;
    }
}

fn set_error(status: &Arc<Mutex<Status>>, msg: &str) {
    if let Ok(mut st) = status.lock() {
        st.last_error = msg.to_string();
    }
}

fn bump_ok(status: &Arc<Mutex<Status>>) {
    if let Ok(mut st) = status.lock() {
        st.sent_ok += 1;
    }
}

fn bump_fail(status: &Arc<Mutex<Status>>) {
    if let Ok(mut st) = status.lock() {
        st.sent_fail += 1;
    }
}

#[allow(clippy::too_many_arguments)]
fn log_tx(
    status: &Arc<Mutex<Status>>,
    height: u64,
    to: &AccountId,
    amount_grains: u128,
    nonce: u64,
    ok: bool,
    detail: &str,
) {
    if let Ok(mut st) = status.lock() {
        st.push_log(LogLine {
            height,
            to: to.as_str().to_string(),
            amount_grains,
            nonce,
            ok,
            detail: detail.to_string(),
        });
    }
}

impl eframe::App for CannonApp {
    fn update(&mut self, ctx: &eframe::egui::Context, _frame: &mut eframe::Frame) {
        use eframe::egui;

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.heading("SOV TX Cannon");
                ui.label(
                    egui::RichText::new(
                        "Automated transaction traffic generator — fires signed transfers each new block.",
                    )
                    .small()
                    .weak(),
                );
                ui.add_space(8.0);

                let running = self.is_running();

                // ---- 1. Connect + Unlock ------------------------------------
                egui::CollapsingHeader::new("1 · Connect & Unlock")
                    .default_open(true)
                    .show(ui, |ui| {
                        egui::Grid::new("conn").num_columns(2).show(ui, |ui| {
                            ui.label("Node RPC");
                            ui.add_enabled(
                                !running,
                                egui::TextEdit::singleline(&mut self.rpc_addr)
                                    .hint_text(DEFAULT_RPC)
                                    .desired_width(320.0),
                            );
                            ui.end_row();

                            ui.label("Keystore");
                            ui.add_enabled(
                                !running,
                                egui::TextEdit::singleline(&mut self.keystore_path)
                                    .desired_width(320.0),
                            );
                            ui.end_row();

                            ui.label("Passphrase");
                            let pw = egui::TextEdit::singleline(&mut *self.passphrase)
                                .password(true)
                                .hint_text("master passphrase")
                                .desired_width(320.0);
                            ui.add_enabled(!running && self.wallets.is_empty(), pw);
                            ui.end_row();
                        });

                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(!running, egui::Button::new("Unlock wallets"))
                                .clicked()
                            {
                                self.unlock();
                            }
                            if !self.wallets.is_empty()
                                && ui
                                    .add_enabled(!running, egui::Button::new("Lock / wipe keys"))
                                    .clicked()
                            {
                                self.wipe_wallets();
                                self.unlock_msg = "keys wiped from memory".into();
                            }
                            if !self.wallets.is_empty() && ui.button("Refresh balances").clicked() {
                                self.refresh_balances();
                            }
                        });
                        if !self.unlock_msg.is_empty() {
                            ui.label(egui::RichText::new(&self.unlock_msg).small().weak());
                        }
                    });

                // ---- 2. Spend-from wallet -----------------------------------
                if !self.wallets.is_empty() {
                    egui::CollapsingHeader::new("2 · Spend from")
                        .default_open(true)
                        .show(ui, |ui| {
                            egui::ComboBox::from_label("Wallet")
                                .selected_text(
                                    self.wallets
                                        .get(self.selected)
                                        .map(|w| w.label.clone())
                                        .unwrap_or_default(),
                                )
                                .show_ui(ui, |ui| {
                                    for (i, w) in self.wallets.iter().enumerate() {
                                        let bal = w
                                            .balance_grains
                                            .map(|g| format!("  ({} XUS)", grains_to_xus(g)))
                                            .unwrap_or_default();
                                        ui.add_enabled_ui(!running, |ui| {
                                            ui.selectable_value(
                                                &mut self.selected,
                                                i,
                                                format!("{}{bal}", w.label),
                                            );
                                        });
                                    }
                                });
                            if let Some(w) = self.wallets.get(self.selected) {
                                let bal = w
                                    .balance_grains
                                    .map(|g| format!("{} XUS", grains_to_xus(g)))
                                    .unwrap_or_else(|| "unknown (node offline?)".into());
                                ui.label(
                                    egui::RichText::new(format!(
                                        "account {}  ·  balance {bal}",
                                        w.account.as_str()
                                    ))
                                    .small()
                                    .weak(),
                                );
                            }
                        });

                    // ---- 3. Configure ---------------------------------------
                    egui::CollapsingHeader::new("3 · Configure traffic")
                        .default_open(true)
                        .show(ui, |ui| {
                            ui.label("Destinations (one account id per line):");
                            ui.add_enabled(
                                !running,
                                egui::TextEdit::multiline(&mut self.dests_text)
                                    .hint_text("alice.sov\nbob.sov\ncarol.sov")
                                    .desired_rows(4)
                                    .desired_width(f32::INFINITY),
                            );
                            ui.add_enabled_ui(!running, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label("Pick destination:");
                                    ui.radio_value(&mut self.dest_random, false, "round-robin");
                                    ui.radio_value(&mut self.dest_random, true, "random");
                                });
                            });

                            ui.separator();
                            ui.add_enabled_ui(!running, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label("Amount (XUS):");
                                    ui.radio_value(&mut self.amount_random, false, "fixed");
                                    ui.radio_value(&mut self.amount_random, true, "random range");
                                });
                                if self.amount_random {
                                    ui.horizontal(|ui| {
                                        ui.label("min");
                                        ui.add(
                                            egui::TextEdit::singleline(&mut self.amount_min)
                                                .desired_width(90.0),
                                        );
                                        ui.label("max");
                                        ui.add(
                                            egui::TextEdit::singleline(&mut self.amount_max)
                                                .desired_width(90.0),
                                        );
                                    });
                                } else {
                                    ui.horizontal(|ui| {
                                        ui.label("value");
                                        ui.add(
                                            egui::TextEdit::singleline(&mut self.amount_fixed)
                                                .desired_width(90.0),
                                        );
                                    });
                                }

                                ui.separator();
                                ui.horizontal(|ui| {
                                    ui.label(format!("Rate (tx per new block, 1–{MAX_RATE}):"));
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.rate)
                                            .desired_width(60.0),
                                    );
                                });
                                ui.checkbox(
                                    &mut self.dry_run,
                                    "Dry-run (build + log txs, do NOT submit)",
                                );
                            });
                        });

                    // ---- 4. Start / Stop ------------------------------------
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if !running {
                            let label = if self.dry_run {
                                "▶ Start (dry-run)"
                            } else {
                                "▶ Start firing"
                            };
                            if ui
                                .add(egui::Button::new(egui::RichText::new(label).strong()))
                                .clicked()
                            {
                                self.start(ctx);
                            }
                        } else if ui
                            .add(egui::Button::new(egui::RichText::new("■ Stop").strong()))
                            .clicked()
                        {
                            self.stop();
                        }
                    });
                    if !self.config_msg.is_empty() {
                        ui.label(egui::RichText::new(&self.config_msg).small().weak());
                    }
                }

                // ---- 5. Live status ------------------------------------------
                ui.add_space(10.0);
                ui.separator();
                ui.heading("Live status");
                let st = self.status.lock().unwrap();
                egui::Grid::new("status").num_columns(2).show(ui, |ui| {
                    ui.label("Running");
                    ui.label(if st.running { "yes" } else { "no" });
                    ui.end_row();
                    ui.label("Tip height");
                    ui.label(st.tip_height.to_string());
                    ui.end_row();
                    ui.label("Sent OK");
                    ui.label(st.sent_ok.to_string());
                    ui.end_row();
                    ui.label("Sent FAIL");
                    ui.label(st.sent_fail.to_string());
                    ui.end_row();
                    ui.label("Spend-from balance");
                    ui.label(
                        st.from_balance_grains
                            .map(|g| format!("{} XUS", grains_to_xus(g)))
                            .unwrap_or_else(|| "—".into()),
                    );
                    ui.end_row();
                });
                if !st.last_error.is_empty() {
                    ui.colored_label(egui::Color32::from_rgb(200, 80, 80), &st.last_error);
                }

                ui.add_space(6.0);
                ui.label("Per-tx log (newest last):");
                egui::ScrollArea::vertical()
                    .max_height(220.0)
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for line in &st.log {
                            let mark = if line.ok { "OK " } else { "ERR" };
                            let color = if line.ok {
                                egui::Color32::from_rgb(90, 170, 90)
                            } else {
                                egui::Color32::from_rgb(200, 80, 80)
                            };
                            ui.horizontal(|ui| {
                                ui.colored_label(color, mark);
                                ui.label(
                                    egui::RichText::new(format!(
                                        "h{} n{} → {} · {} XUS · {}",
                                        line.height,
                                        line.nonce,
                                        line.to,
                                        grains_to_xus(line.amount_grains),
                                        line.detail
                                    ))
                                    .small()
                                    .monospace(),
                                );
                            });
                        }
                    });
            });
        });
    }
}
