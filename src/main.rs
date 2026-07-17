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
//! Wallet identity: the keystore's `account` field is a DISPLAY LABEL. The real
//! on-chain id is derived from the seed ([`logic::derive_account_id`]) exactly as
//! the node does — that derived id is what balances, nonces, and the tx signer use.
//!
//! Security posture (see the worker docs, below): the master passphrase and every
//! wallet signing seed live in `zeroize`-wiped buffers for the session only;
//! nothing secret is ever written to disk or logged.

mod logic;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use sov_primitives::AccountId;
use sov_rpc::{Keystore, RpcClient};

use logic::{
    build_signed_transfer, decode_keystore, grains_to_xus, merge_wallets, parse_xus, short_account,
    AmountMode, DecodedWallet, DestMode, DestSelector, KeyScheme, NonceSequencer, Rng,
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
/// How often the connection monitor probes the node while the app is open.
const CONN_POLL: Duration = Duration::from_millis(2_500);
/// Timeout for a single connection probe.
const CONN_TIMEOUT: Duration = Duration::from_secs(3);

fn main() -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([820.0, 900.0])
            .with_min_inner_size([640.0, 600.0])
            .with_title("SOV TX Cannon"),
        ..Default::default()
    };
    eframe::run_native(
        "SOV TX Cannon",
        options,
        Box::new(|cc| Ok(Box::new(CannonApp::new(&cc.egui_ctx)))),
    )
    .map_err(|e| format!("GUI failed: {e}"))
}

/// One unlocked, spendable wallet held in memory for the session.
///
/// `wallet.account` is the seed-DERIVED on-chain id; `wallet.label` is the
/// keystore's display string. The durable secret is `wallet.seed`, kept in a
/// `Zeroizing` buffer wiped when this struct drops (on lock, unlock-again, or
/// app exit). A `Keypair` is never stored — it is derived transiently only for
/// the instant of signing.
struct UnlockedWallet {
    wallet: DecodedWallet,
    /// Last known liquid balance in grains (read via RPC), for display.
    balance_grains: Option<u128>,
}

/// `~/.sov-station/` — where SOV-Station keeps its wallet files.
fn station_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
        .unwrap_or_default();
    PathBuf::from(home).join(".sov-station")
}

/// The PRIMARY keystore: `~/.sov-station/wallets.auto` — the store SOV-Station
/// itself auto-loads on launch, encrypted under the MASTER passphrase. (The
/// sibling `wallets.keystore` is a manual export/backup; we also try it and
/// merge, see [`CannonApp::unlock`].) Kept overridable in the UI.
fn default_keystore_path() -> String {
    station_dir()
        .join("wallets.auto")
        .to_string_lossy()
        .into_owned()
}

/// The secondary (backup/export) keystore path: `~/.sov-station/wallets.keystore`.
fn backup_keystore_path() -> String {
    station_dir()
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
    next_nonce: u64,
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

/// Live node-connection state, fed by the background [`conn_monitor`] thread.
/// Independent of firing: it probes `height()` every [`CONN_POLL`] while the app
/// is open, so the header indicator is always current.
#[derive(Default, Clone)]
struct ConnState {
    /// At least one probe has completed (before that: "checking…").
    probed: bool,
    ok: bool,
    tip: u64,
    /// The REAL error from the last failed probe (never swallowed).
    error: String,
}

/// Immutable-per-run configuration handed to the worker thread when firing starts.
struct RunConfig {
    rpc_addr: String,
    /// The seed-DERIVED on-chain id — used for balance/nonce queries and as the
    /// signed tx's `signer`.
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
    started: Instant,
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
    /// Non-secret status from the last balance refresh (errors surfaced, not
    /// swallowed).
    balance_msg: String,

    // Live connection indicator (fed by the monitor thread).
    conn: Arc<Mutex<ConnState>>,
    conn_addr: Arc<Mutex<String>>,
    conn_poke: Arc<AtomicBool>,
    conn_stop: Arc<AtomicBool>,

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

impl CannonApp {
    fn new(ctx: &eframe::egui::Context) -> Self {
        apply_theme(ctx);
        let conn = Arc::new(Mutex::new(ConnState::default()));
        let conn_addr = Arc::new(Mutex::new(DEFAULT_RPC.to_string()));
        let conn_poke = Arc::new(AtomicBool::new(true)); // probe immediately
        let conn_stop = Arc::new(AtomicBool::new(false));
        {
            // The monitor holds NO secret material — only the RPC address and the
            // probe result — so it is detached (not joined) on exit; its at-most-3s
            // in-flight probe cannot delay shutdown or leak anything.
            let conn = conn.clone();
            let addr = conn_addr.clone();
            let poke = conn_poke.clone();
            let stop = conn_stop.clone();
            let ctx = ctx.clone();
            thread::spawn(move || conn_monitor(conn, addr, poke, stop, ctx));
        }
        Self {
            rpc_addr: DEFAULT_RPC.to_string(),
            keystore_path: default_keystore_path(),
            passphrase: Zeroizing::new(String::new()),
            unlock_msg: String::new(),
            balance_msg: String::new(),
            conn,
            conn_addr,
            conn_poke,
            conn_stop,
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

    fn is_running(&self) -> bool {
        self.session.is_some()
    }

    /// Ask the connection monitor to probe NOW (unlock, "Test connection", or an
    /// address edit).
    fn poke_connection(&self) {
        if let Ok(mut a) = self.conn_addr.lock() {
            if *a != self.rpc_addr {
                *a = self.rpc_addr.clone();
            }
        }
        self.conn_poke.store(true, Ordering::SeqCst);
    }

    /// Read + decrypt the wallet stores with the typed passphrase, then WIPE the
    /// passphrase.
    ///
    /// Sources, all with the SAME passphrase, results MERGED (dedup by DERIVED
    /// account id):
    ///   1. the UI's keystore path (default `~/.sov-station/wallets.auto`, the
    ///      store SOV-Station auto-loads — the REAL working wallets), and
    ///   2. the sibling backup/export `~/.sov-station/wallets.keystore`, so a
    ///      same-passphrase backup's wallets show too.
    ///
    /// A missing or non-decrypting file is skipped; it is an error only if NO
    /// source yields a spendable wallet.
    fn unlock(&mut self) {
        if self.is_running() {
            return;
        }
        if self.passphrase.is_empty() {
            self.unlock_msg = "enter your master passphrase".into();
            return;
        }

        let mut candidates = vec![self.keystore_path.trim().to_string()];
        for extra in [default_keystore_path(), backup_keystore_path()] {
            if !candidates.contains(&extra) {
                candidates.push(extra);
            }
        }

        let mut merged: Vec<DecodedWallet> = Vec::new();
        let mut notes: Vec<String> = Vec::new();
        let mut sources = 0usize;
        for path in &candidates {
            let name = PathBuf::from(path)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.clone());
            let text = match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) => {
                    notes.push(format!("{name}: not read ({e})"));
                    continue;
                }
            };
            // Reuse SOV-Station's exact hardened decryption (Argon2id + ChaCha20-Poly1305).
            match Keystore::from_encrypted_or_plain(&text, Some(self.passphrase.as_str())) {
                Ok(ks) => {
                    let wallets = decode_keystore(&ks);
                    notes.push(format!("{name}: {} wallet(s)", wallets.len()));
                    merge_wallets(&mut merged, wallets);
                    sources += 1;
                }
                Err(e) => notes.push(format!("{name}: {e}")),
            }
        }
        // The passphrase has done its job; wipe it from memory now.
        self.passphrase.zeroize();

        if merged.is_empty() {
            // Neither store yielded a spendable wallet — surface why, per file.
            self.unlock_msg = if sources == 0 {
                format!("unlock failed — {}", notes.join("; "))
            } else {
                format!(
                    "unlocked, but no spendable wallets found (watch-only or empty) — {}",
                    notes.join("; ")
                )
            };
            return;
        }

        // Drop any previously unlocked wallets first (zeroizes their seeds).
        self.wipe_wallets();
        self.wallets = merged
            .into_iter()
            .map(|wallet| UnlockedWallet {
                wallet,
                balance_grains: None,
            })
            .collect();
        self.selected = 0;
        self.unlock_msg = format!(
            "unlocked {} wallet(s) — {}",
            self.wallets.len(),
            notes.join("; ")
        );
        self.poke_connection();
        self.refresh_balances();
    }

    /// Wipe all in-memory key material (called on lock, re-unlock, and exit).
    fn wipe_wallets(&mut self) {
        // UnlockedWallet's seed is Zeroizing → wiped on drop.
        self.wallets.clear();
        self.selected = 0;
    }

    /// Refresh each unlocked wallet's balance from the node, SURFACING any RPC
    /// error to `balance_msg` (never silently blanking).
    fn refresh_balances(&mut self) {
        let client = RpcClient::new(self.rpc_addr.clone()).with_timeout(Duration::from_secs(5));
        let mut first_err: Option<String> = None;
        for w in &mut self.wallets {
            match client.balance(&w.wallet.account) {
                Ok(b) => w.balance_grains = Some(b.grains()),
                Err(e) => {
                    w.balance_grains = None;
                    if first_err.is_none() {
                        first_err = Some(format!(
                            "balance query failed for {}: {e}",
                            short_account(&w.wallet.account)
                        ));
                    }
                }
            }
        }
        self.balance_msg = first_err.unwrap_or_default();
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
            from: w.wallet.account.clone(),
            scheme: w.wallet.scheme,
            // Clone the seed into a fresh zeroizing buffer moved to the worker.
            seed: Zeroizing::new(*w.wallet.seed),
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
            "DRY-RUN: building + logging txs, NOT submitting".into()
        } else {
            "LIVE: firing signed transactions each new block".into()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let status = self.status.clone();
        let ctx = ctx.clone();
        let worker_stop = stop.clone();
        let handle = thread::spawn(move || run_worker(cfg, status, worker_stop, ctx));
        self.session = Some(Session {
            stop,
            handle: Some(handle),
            started: Instant::now(),
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
        // The (secret-free) connection monitor exits on its next tick.
        self.conn_stop.store(true, Ordering::SeqCst);
    }
}

/// The background connection monitor: probes `height()` on the shared RPC
/// address every [`CONN_POLL`] (or immediately when poked), publishing the
/// result — including the REAL error text on failure — to the shared
/// [`ConnState`]. Holds no secret material, ever.
fn conn_monitor(
    conn: Arc<Mutex<ConnState>>,
    addr: Arc<Mutex<String>>,
    poke: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    ctx: eframe::egui::Context,
) {
    let mut last_probe: Option<Instant> = None;
    while !stop.load(Ordering::SeqCst) {
        let due = last_probe.map(|t| t.elapsed() >= CONN_POLL).unwrap_or(true)
            || poke.swap(false, Ordering::SeqCst);
        if !due {
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        last_probe = Some(Instant::now());
        let target = addr.lock().map(|a| a.clone()).unwrap_or_default();
        let result = RpcClient::new(target.clone())
            .with_timeout(CONN_TIMEOUT)
            .height();
        if let Ok(mut c) = conn.lock() {
            c.probed = true;
            match result {
                Ok(h) => {
                    c.ok = true;
                    c.tip = h;
                    c.error.clear();
                }
                Err(e) => {
                    c.ok = false;
                    c.error = format!("Can't reach node at {target}: {e}");
                }
            }
        }
        ctx.request_repaint();
    }
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
        if let Ok(mut st) = status.lock() {
            st.next_nonce = seq.peek();
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
            if let Ok(mut st) = status.lock() {
                st.next_nonce = seq.peek();
            }

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

// ---- Theme + shared colors ------------------------------------------------

const COL_OK: eframe::egui::Color32 = eframe::egui::Color32::from_rgb(96, 200, 120);
const COL_ERR: eframe::egui::Color32 = eframe::egui::Color32::from_rgb(235, 100, 100);
const COL_WARN: eframe::egui::Color32 = eframe::egui::Color32::from_rgb(235, 180, 80);
const COL_DIM: eframe::egui::Color32 = eframe::egui::Color32::from_rgb(150, 155, 165);

/// A clean dark theme (slightly softer than egui's default dark).
fn apply_theme(ctx: &eframe::egui::Context) {
    use eframe::egui;
    let mut v = egui::Visuals::dark();
    v.panel_fill = egui::Color32::from_rgb(22, 24, 28);
    v.window_fill = egui::Color32::from_rgb(22, 24, 28);
    v.extreme_bg_color = egui::Color32::from_rgb(14, 15, 18);
    v.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(30, 33, 39);
    v.selection.bg_fill = egui::Color32::from_rgb(45, 90, 140);
    ctx.set_visuals(v);
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(10.0, 5.0);
    ctx.set_style(style);
}

/// A titled section card.
fn section<R>(
    ui: &mut eframe::egui::Ui,
    title: &str,
    add: impl FnOnce(&mut eframe::egui::Ui) -> R,
) -> R {
    use eframe::egui;
    egui::Frame::group(ui.style())
        .fill(egui::Color32::from_rgb(27, 30, 36))
        .inner_margin(egui::Margin::same(10.0))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(title)
                    .strong()
                    .size(15.0)
                    .color(egui::Color32::from_rgb(210, 215, 225)),
            );
            ui.add_space(6.0);
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

fn fmt_elapsed(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

impl eframe::App for CannonApp {
    fn update(&mut self, ctx: &eframe::egui::Context, _frame: &mut eframe::Frame) {
        use eframe::egui;

        // Keep the connection indicator + elapsed clock ticking even when idle.
        ctx.request_repaint_after(Duration::from_millis(500));

        let running = self.is_running();
        let conn = self.conn.lock().map(|c| c.clone()).unwrap_or_default();

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("SOV TX Cannon");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Live node indicator — always visible, top right too.
                        if !conn.probed {
                            ui.colored_label(COL_DIM, "● checking…");
                        } else if conn.ok {
                            ui.colored_label(COL_OK, format!("● Connected — tip {}", conn.tip));
                        } else {
                            ui.colored_label(COL_ERR, "● Disconnected");
                        }
                    });
                });
                ui.label(
                    egui::RichText::new(
                        "Fires signed transparent transfers each new block. Unlock → pick wallet → paste targets → set rate → (dry-run) → fire.",
                    )
                    .small()
                    .color(COL_DIM),
                );
                ui.add_space(8.0);

                // ---- Connection --------------------------------------------
                section(ui, "Connection", |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Node RPC");
                        let resp = ui.add_enabled(
                            !running,
                            egui::TextEdit::singleline(&mut self.rpc_addr)
                                .hint_text(DEFAULT_RPC)
                                .desired_width(240.0),
                        )
                        .on_hover_text("host:port of the node's JSON-RPC (SOV-Station default 127.0.0.1:8645)");
                        if resp.changed() {
                            self.poke_connection();
                        }
                        if ui
                            .button("Test connection")
                            .on_hover_text("Probe the node's height RPC now")
                            .clicked()
                        {
                            self.poke_connection();
                        }
                    });
                    // The prominent live status line (real error, never swallowed).
                    if !conn.probed {
                        ui.colored_label(COL_DIM, "● checking node…");
                    } else if conn.ok {
                        ui.colored_label(
                            COL_OK,
                            format!("● Connected — tip {}", conn.tip),
                        );
                    } else {
                        ui.colored_label(COL_ERR, format!("● {}", conn.error));
                    }
                });
                ui.add_space(6.0);

                // ---- Wallet -------------------------------------------------
                section(ui, "Wallet", |ui| {
                    egui::Grid::new("wallet_grid").num_columns(2).show(ui, |ui| {
                        ui.label("Keystore");
                        ui.add_enabled(
                            !running,
                            egui::TextEdit::singleline(&mut self.keystore_path)
                                .desired_width(360.0),
                        )
                        .on_hover_text(
                            "SOV-Station's auto-loaded store (wallets.auto). A same-passphrase \
                             wallets.keystore backup is also tried and merged automatically.",
                        );
                        ui.end_row();

                        ui.label("Passphrase");
                        let pw = egui::TextEdit::singleline(&mut *self.passphrase)
                            .password(true)
                            .hint_text("master passphrase")
                            .desired_width(360.0);
                        ui.add_enabled(!running && self.wallets.is_empty(), pw)
                            .on_hover_text("SOV-Station's MASTER passphrase — wiped from memory right after unlock");
                        ui.end_row();
                    });

                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(!running, egui::Button::new("Unlock wallets"))
                            .on_hover_text("Decrypt the keystore(s) and load spendable wallets")
                            .clicked()
                        {
                            self.unlock();
                        }
                        if !self.wallets.is_empty()
                            && ui
                                .add_enabled(!running, egui::Button::new("Lock / wipe keys"))
                                .on_hover_text("Zeroize every seed held in memory")
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
                        ui.label(egui::RichText::new(&self.unlock_msg).small().color(COL_DIM));
                    }
                    if !self.balance_msg.is_empty() {
                        ui.colored_label(COL_WARN, &self.balance_msg);
                    }

                    if !self.wallets.is_empty() {
                        ui.add_space(4.0);
                        ui.separator();
                        ui.label("Spend from:");
                        let display = |w: &UnlockedWallet| {
                            format!("{} — {}", w.wallet.label, short_account(&w.wallet.account))
                        };
                        egui::ComboBox::from_id_salt("spend_from")
                            .width(360.0)
                            .selected_text(
                                self.wallets.get(self.selected).map(display).unwrap_or_default(),
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
                                            format!("{}{bal}", display(w)),
                                        );
                                    });
                                }
                            });
                        if let Some(w) = self.wallets.get(self.selected) {
                            let bal = w
                                .balance_grains
                                .map(|g| format!("{} XUS", grains_to_xus(g)))
                                .unwrap_or_else(|| "unknown (node unreachable?)".into());
                            ui.label(
                                egui::RichText::new(format!(
                                    "on-chain id {}  ·  balance {bal}",
                                    w.wallet.account.as_str()
                                ))
                                .small()
                                .monospace()
                                .color(COL_DIM),
                            )
                            .on_hover_text(
                                "The REAL on-chain account id, derived from this wallet's key \
                                 (the keystore name above is only a display label).",
                            );
                        }
                    }
                });
                ui.add_space(6.0);

                // ---- Targets ------------------------------------------------
                if !self.wallets.is_empty() {
                    section(ui, "Targets", |ui| {
                        ui.add_enabled_ui(!running, |ui| {
                            ui.label("Destinations (one account id per line):");
                            ui.add(
                                egui::TextEdit::multiline(&mut self.dests_text)
                                    .hint_text("alice.sov\nbob.sov\ncarol.sov")
                                    .desired_rows(4)
                                    .desired_width(f32::INFINITY),
                            );
                            ui.horizontal(|ui| {
                                ui.label("Pick destination:");
                                ui.radio_value(&mut self.dest_random, false, "round-robin");
                                ui.radio_value(&mut self.dest_random, true, "random");
                            });

                            ui.separator();
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
                                    egui::TextEdit::singleline(&mut self.rate).desired_width(60.0),
                                )
                                .on_hover_text("How many transfers to fire each time a NEW block arrives");
                            });
                        });
                    });
                    ui.add_space(6.0);

                    // ---- Fire -----------------------------------------------
                    section(ui, "Fire", |ui| {
                        ui.add_enabled_ui(!running, |ui| {
                            ui.checkbox(
                                &mut self.dry_run,
                                egui::RichText::new(
                                    "Dry-run — build + log transactions, do NOT submit",
                                )
                                .strong(),
                            )
                            .on_hover_text("Uncheck only when you want REAL transactions on the wire");
                        });
                        if self.dry_run {
                            ui.colored_label(COL_WARN, "DRY-RUN mode: nothing will be submitted");
                        }
                        ui.add_space(4.0);

                        // The one big, unmistakable Start/Stop control.
                        let (label, fill) = if running {
                            ("■  STOP", COL_ERR)
                        } else if self.dry_run {
                            ("▶  Start firing (dry-run)", egui::Color32::from_rgb(60, 95, 145))
                        } else {
                            ("▶  Start firing", egui::Color32::from_rgb(40, 120, 70))
                        };
                        let big = egui::Button::new(
                            egui::RichText::new(label)
                                .size(18.0)
                                .strong()
                                .color(egui::Color32::WHITE),
                        )
                        .fill(fill)
                        .min_size(egui::vec2(ui.available_width(), 40.0));
                        if ui
                            .add(big)
                            .on_hover_text(if running {
                                "Stop immediately — joins the worker and wipes its seed copy"
                            } else {
                                "Begin firing on each new block"
                            })
                            .clicked()
                        {
                            if running {
                                self.stop();
                            } else {
                                self.start(ctx);
                            }
                        }
                        if !self.config_msg.is_empty() {
                            ui.label(egui::RichText::new(&self.config_msg).small().color(COL_DIM));
                        }

                        // Run state + live counters.
                        ui.add_space(4.0);
                        let st = self.status.lock().unwrap();
                        ui.horizontal(|ui| {
                            if running {
                                ui.colored_label(COL_OK, "● RUNNING");
                                if let Some(s) = &self.session {
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "elapsed {}",
                                            fmt_elapsed(s.started.elapsed())
                                        ))
                                        .monospace(),
                                    );
                                }
                            } else {
                                ui.colored_label(COL_DIM, "● STOPPED");
                            }
                            ui.separator();
                            ui.colored_label(COL_OK, format!("OK {}", st.sent_ok));
                            ui.colored_label(COL_ERR, format!("failed {}", st.sent_fail));
                            ui.separator();
                            ui.label(
                                egui::RichText::new(format!(
                                    "tip {} · next nonce {}",
                                    st.tip_height, st.next_nonce
                                ))
                                .monospace(),
                            );
                        });
                        ui.label(
                            egui::RichText::new(format!(
                                "spend-from balance: {}",
                                st.from_balance_grains
                                    .map(|g| format!("{} XUS", grains_to_xus(g)))
                                    .unwrap_or_else(|| "—".into())
                            ))
                            .small()
                            .color(COL_DIM),
                        );
                        if !st.last_error.is_empty() {
                            ui.colored_label(COL_ERR, &st.last_error);
                        }

                        // Colorized scrolling per-tx log.
                        ui.add_space(6.0);
                        ui.label("Per-tx log (newest last):");
                        egui::Frame::default()
                            .fill(egui::Color32::from_rgb(14, 15, 18))
                            .inner_margin(egui::Margin::same(6.0))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                egui::ScrollArea::vertical()
                                    .max_height(220.0)
                                    .stick_to_bottom(true)
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        if st.log.is_empty() {
                                            ui.label(
                                                egui::RichText::new("no transactions yet")
                                                    .small()
                                                    .color(COL_DIM),
                                            );
                                        }
                                        for line in &st.log {
                                            let (mark, color) = if line.ok {
                                                ("OK ", COL_OK)
                                            } else {
                                                ("ERR", COL_ERR)
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
            });
        });
    }
}
