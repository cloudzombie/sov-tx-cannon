#![forbid(unsafe_code)]
// egui's API is uniformly `f32`, so float literals passed to it take the f32
// fallback intentionally (same posture as SOV-Station).
#![allow(unknown_lints)]
#![allow(float_literal_f32_fallback)]

//! SOV TX Cannon — an automated transaction traffic generator.
//!
//! Fires transparent transfers from wallets the user unlocks (SOV-Station's own
//! encrypted keystore) to destination addresses the user sets, in one of three
//! rate modes:
//!   * **Per block** — on each NEW chain tip, fire N transactions (the original
//!     behavior).
//!   * **Target TX/s** — a steady paced rate decoupled from blocks.
//!   * **Firehose** — submit as fast as sign+POST allows; the mempool's capacity
//!     rejections are the only brake (the cannon holds and retries the same
//!     nonce on those, self-pacing to the drain rate).
//!
//! Multiple wallets can fire in parallel (one worker per wallet, each with its
//! own nonce sequencer and its own zeroizing seed copy), and a live meter panel
//! shows attempted/accepted/rejected per second, a rejection breakdown, and the
//! node's mempool depth with a saturation flag.
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
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use sov_primitives::AccountId;
use sov_rpc::{Keystore, RpcClient};

use logic::{
    build_signed_transfer, classify_reject, disposition, grains_to_xus, parse_xus, AmountMode,
    DestMode, DestSelector, Disposition, KeyScheme, MeterKind, NonceSequencer, Pacer, RateMeter,
    RateMode, RejectClass, Rng,
};

/// Default node RPC endpoint (SOV-Station's node default).
const DEFAULT_RPC: &str = "127.0.0.1:8645";
/// Hard cap on transactions fired per new block, to keep the tool sane.
const MAX_RATE: u32 = 100;
/// Hard cap on the Target-TX/s rate. Well above the chain's ~1–5 TPS inclusion
/// ceiling (150 s blocks, ~5 KiB PQ txs, 1→4 MiB elastic cap) — the point of the
/// tool is to demonstrate that ceiling, not to DoS the client machine.
const MAX_TPS: f64 = 500.0;
/// Estimated fee reserved per transfer for the local affordability pre-check:
/// `INTRINSIC_GAS (21_000) × gas_price (1 grain on mainnet)`. The node's mempool
/// is the real authority — this only lets us surface "insufficient balance"
/// before firing rather than eating a rejection per tx.
const FEE_ESTIMATE_GRAINS: u128 = 21_000;
/// How often the per-block worker polls the tip while idle between blocks.
const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// How often a continuous-mode worker reconciles its nonce + balance with the
/// node (well under the 150 s block time; also catches external spends fast).
const RECONCILE_INTERVAL: Duration = Duration::from_secs(1);
/// Back-off after a capacity (mempool/sender-limit) rejection before retrying
/// the SAME nonce — this is what self-paces the firehose to the drain rate.
const CAPACITY_BACKOFF: Duration = Duration::from_millis(200);
/// Back-off after an unclassified submit failure (transport, unknown reject).
const OTHER_BACKOFF: Duration = Duration::from_millis(500);
/// The node's default mempool capacity (display hint for the saturation flag;
/// the node remains the authority — its "mempool is full" rejections are what
/// actually gate submission).
const MEMPOOL_CAP_HINT: u64 = 16_384;
/// Depth at which the meter panel flags the mempool SATURATED (~95% of cap).
const SATURATION_DEPTH: u64 = MEMPOOL_CAP_HINT / 20 * 19;
/// Rolling window (seconds) for the live per-second meters.
const METER_WINDOW_SECS: u64 = 5;

fn main() -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([760.0, 900.0])
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
    /// Whether this wallet is selected to fire (the multi-wallet checklist).
    fire: bool,
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
    wallet: String,
    height: u64,
    to: String,
    amount_grains: u128,
    nonce: u64,
    ok: bool,
    detail: String,
}

/// Live per-wallet state the worker publishes for the meter panel.
#[derive(Clone, Default)]
struct WalletStat {
    label: String,
    next_nonce: u64,
    balance_grains: Option<u128>,
    /// Set when this wallet's worker stopped early (why), e.g. affordability.
    stopped: Option<String>,
}

/// Live status shared between the UI thread and the firing workers.
struct Status {
    running: bool,
    tip_height: u64,
    /// Node mempool depth, polled ~1/s by the monitor thread.
    mempool_depth: Option<u64>,
    /// Rolling throughput meters (attempted/accepted/rejected-by-reason).
    meter: RateMeter,
    /// The meter's clock origin — all events are stamped relative to this.
    t0: Instant,
    /// Per-wallet live state, indexed by worker/wallet order.
    wallets: Vec<WalletStat>,
    /// Number of workers still running (0 ⇒ the run has drained/ended).
    live_workers: usize,
    last_error: String,
    /// Newest-last per-tx log (bounded).
    log: Vec<LogLine>,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            running: false,
            tip_height: 0,
            mempool_depth: None,
            meter: RateMeter::new(METER_WINDOW_SECS),
            t0: Instant::now(),
            wallets: Vec::new(),
            live_workers: 0,
            last_error: String::new(),
            log: Vec::new(),
        }
    }
}

/// Persistent node-connection state, refreshed ~every 2s by a keyless monitor
/// thread that runs for the app's WHOLE life (independent of any firing session) —
/// so the connection indicator is live the moment the app opens, not only while
/// firing. Holds no key material.
#[derive(Default)]
struct Conn {
    /// Whether ANY probe has completed yet (so the UI can show "connecting…").
    ever: bool,
    /// Whether the last probe reached the node.
    ok: bool,
    /// Last observed chain tip height.
    tip: u64,
    /// Last observed mempool depth.
    mempool: Option<u64>,
    /// The error text from the last failed probe (empty when ok).
    error: String,
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

    /// Milliseconds since the meter clock origin (the run start).
    fn now_ms(&self) -> u64 {
        self.t0.elapsed().as_millis() as u64
    }

    /// Record a meter event stamped "now".
    fn record(&mut self, kind: MeterKind) {
        let now = self.now_ms();
        self.meter.record(now, kind);
    }
}

/// Immutable-per-run configuration handed to ONE worker thread (one wallet).
struct WorkerConfig {
    rpc_addr: String,
    /// Index into `Status::wallets` this worker reports under.
    wallet_index: usize,
    label: String,
    from: AccountId,
    scheme: KeyScheme,
    /// This worker's OWN zeroizing seed copy — wiped when the worker returns.
    seed: Zeroizing<[u8; 32]>,
    dests: Vec<AccountId>,
    dest_mode: DestMode,
    amount_mode: AmountMode,
    /// The rate mode with any per-worker share already applied (Target TX/s is
    /// split across the selected wallets).
    mode: RateMode,
    dry_run: bool,
}

/// A running firing session: one shared stop flag, one monitor thread, and one
/// worker thread per selected wallet.
struct Session {
    stop: Arc<AtomicBool>,
    handles: Vec<thread::JoinHandle<()>>,
}

impl Session {
    /// Signal every thread to stop and join them ALL, so each worker's seed copy
    /// is zeroized before we return.
    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

/// Which rate-mode radio is selected in the UI.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ModeChoice {
    PerBlock,
    TargetTps,
    Firehose,
}

/// The application state.
struct CannonApp {
    // Connection + unlock inputs.
    rpc_addr: String,
    keystore_path: String,
    /// Secret input: wiped on drop and immediately after a successful unlock.
    passphrase: Zeroizing<String>,
    unlock_msg: String,

    // Unlocked wallets (each carries its own `fire` checkbox).
    wallets: Vec<UnlockedWallet>,

    // Traffic configuration (UI form fields).
    dests_text: String,
    dest_random: bool,
    amount_random: bool,
    amount_fixed: String,
    amount_min: String,
    amount_max: String,
    mode: ModeChoice,
    rate: String,
    tps: String,
    dry_run: bool,
    config_msg: String,

    // Live run.
    status: Arc<Mutex<Status>>,
    session: Option<Session>,

    // Always-on connection monitor (independent of firing). `conn_addr` is shared
    // so UI edits to `rpc_addr` reach the monitor; the monitor is spawned lazily on
    // the first `update` (it needs the egui Context to request repaints).
    conn: Arc<Mutex<Conn>>,
    conn_addr: Arc<Mutex<String>>,
    conn_stop: Arc<AtomicBool>,
    conn_started: bool,
}

impl Default for CannonApp {
    fn default() -> Self {
        Self {
            rpc_addr: DEFAULT_RPC.to_string(),
            keystore_path: default_keystore_path(),
            passphrase: Zeroizing::new(String::new()),
            unlock_msg: String::new(),
            wallets: Vec::new(),
            dests_text: String::new(),
            dest_random: false,
            amount_random: false,
            amount_fixed: "0.001".to_string(),
            amount_min: "0.001".to_string(),
            amount_max: "0.01".to_string(),
            mode: ModeChoice::PerBlock,
            rate: "1".to_string(),
            tps: "2".to_string(),
            dry_run: true,
            config_msg: String::new(),
            status: Arc::new(Mutex::new(Status::default())),
            session: None,
            conn: Arc::new(Mutex::new(Conn::default())),
            conn_addr: Arc::new(Mutex::new(DEFAULT_RPC.to_string())),
            conn_stop: Arc::new(AtomicBool::new(false)),
            conn_started: false,
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
                // Default: only the first wallet fires (the simple single-wallet
                // case); the user opts additional wallets in via the checklist.
                fire: self.wallets.is_empty(),
            });
        }
        // The passphrase has done its job; wipe it from memory now.
        self.passphrase.zeroize();

        if self.wallets.is_empty() {
            self.unlock_msg =
                "unlocked, but no spendable wallets found (watch-only or empty keystore)".into();
        } else {
            self.unlock_msg = format!("unlocked {} wallet(s)", self.wallets.len());
            self.refresh_balances();
        }
    }

    /// Wipe all in-memory key material (called on lock, re-unlock, and exit).
    fn wipe_wallets(&mut self) {
        // UnlockedWallet::seed is Zeroizing → wiped on drop.
        self.wallets.clear();
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

    /// Parse + validate the rate mode from the UI fields. `n_workers` is how
    /// many wallets will fire: Target TX/s is split evenly across them so the
    /// AGGREGATE rate matches what the user typed.
    fn parse_rate_mode(&self, n_workers: usize) -> Result<RateMode, String> {
        match self.mode {
            ModeChoice::PerBlock => match self.rate.trim().parse::<u32>() {
                Ok(r) if (1..=MAX_RATE).contains(&r) => Ok(RateMode::PerBlock(r)),
                _ => Err(format!("per-block rate must be between 1 and {MAX_RATE}")),
            },
            ModeChoice::TargetTps => match self.tps.trim().parse::<f64>() {
                Ok(x) if x.is_finite() && (0.1..=MAX_TPS).contains(&x) => {
                    Ok(RateMode::TargetTps(x / n_workers.max(1) as f64))
                }
                _ => Err(format!("target TX/s must be between 0.1 and {MAX_TPS}")),
            },
            ModeChoice::Firehose => Ok(RateMode::Firehose),
        }
    }

    /// Build one worker config per selected wallet from the current form; on any
    /// error, set `config_msg` and return `None`.
    fn build_worker_configs(&mut self) -> Option<Vec<WorkerConfig>> {
        if self.wallets.is_empty() {
            self.config_msg = "unlock a wallet first".into();
            return None;
        }
        let selected: Vec<usize> = self
            .wallets
            .iter()
            .enumerate()
            .filter(|(_, w)| w.fire)
            .map(|(i, _)| i)
            .collect();
        if selected.is_empty() {
            self.config_msg = "select at least one wallet to fire from".into();
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
        let mode = match self.parse_rate_mode(selected.len()) {
            Ok(m) => m,
            Err(e) => {
                self.config_msg = e;
                return None;
            }
        };
        let dest_mode = if self.dest_random {
            DestMode::Random
        } else {
            DestMode::RoundRobin
        };
        let configs = selected
            .into_iter()
            .enumerate()
            .map(|(worker_i, wallet_i)| {
                let w = &self.wallets[wallet_i];
                WorkerConfig {
                    rpc_addr: self.rpc_addr.clone(),
                    wallet_index: worker_i,
                    label: w.label.clone(),
                    from: w.account.clone(),
                    scheme: w.scheme,
                    // Clone the seed into a fresh zeroizing buffer moved to the
                    // worker (wiped when the worker's config drops on return).
                    seed: Zeroizing::new(*w.seed),
                    dests: dests.clone(),
                    dest_mode,
                    amount_mode,
                    mode,
                    dry_run: self.dry_run,
                }
            })
            .collect();
        Some(configs)
    }

    /// Start firing: spawn one worker per selected wallet (each with its own
    /// seed copy) plus the shared tip/mempool monitor.
    fn start(&mut self, ctx: &eframe::egui::Context) {
        if self.is_running() {
            return;
        }
        let Some(configs) = self.build_worker_configs() else {
            return;
        };
        // Reset counters + per-wallet stats for the new run.
        {
            let mut st = self.status.lock().unwrap();
            *st = Status {
                running: true,
                live_workers: configs.len(),
                wallets: configs
                    .iter()
                    .map(|c| WalletStat {
                        label: c.label.clone(),
                        ..WalletStat::default()
                    })
                    .collect(),
                ..Status::default()
            };
        }
        self.config_msg = match (&configs[0].mode, self.dry_run) {
            (_, true) => "running (DRY-RUN: building + logging txs, NOT submitting)".into(),
            (RateMode::PerBlock(n), false) => {
                format!(
                    "running: firing {n} tx per new block × {} wallet(s)",
                    configs.len()
                )
            }
            (RateMode::TargetTps(_), false) => {
                format!(
                    "running: pacing ~{} TX/s across {} wallet(s)",
                    self.tps.trim(),
                    configs.len()
                )
            }
            (RateMode::Firehose, false) => {
                format!(
                    "running: FIREHOSE from {} wallet(s) — mempool is the brake",
                    configs.len()
                )
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::with_capacity(configs.len() + 1);
        // The monitor: tip height + mempool depth, ~1/s.
        {
            let status = self.status.clone();
            let ctx = ctx.clone();
            let stop = stop.clone();
            let rpc_addr = self.rpc_addr.clone();
            handles.push(thread::spawn(move || {
                run_monitor(rpc_addr, status, stop, ctx)
            }));
        }
        for cfg in configs {
            let status = self.status.clone();
            let ctx = ctx.clone();
            let stop = stop.clone();
            handles.push(thread::spawn(move || run_worker(cfg, status, stop, ctx)));
        }
        self.session = Some(Session { stop, handles });
    }

    /// Stop firing: halt ALL workers and join them (each worker's seed copy is
    /// zeroized as its config drops) before returning.
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
        // Ensure every worker's seed copy is wiped, then wipe ours.
        if let Some(mut s) = self.session.take() {
            s.stop_and_join();
        }
        // Signal the always-on connection monitor to exit (keyless; detached).
        self.conn_stop.store(true, Ordering::SeqCst);
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

/// The tip/mempool monitor thread: polls `sov_getHeight` + `sov_getMempoolSize`
/// about once a second and publishes them for the meter panel. Holds no keys.
fn run_monitor(
    rpc_addr: String,
    status: Arc<Mutex<Status>>,
    stop: Arc<AtomicBool>,
    ctx: eframe::egui::Context,
) {
    let client = RpcClient::new(rpc_addr).with_timeout(Duration::from_secs(5));
    while !stop.load(Ordering::SeqCst) {
        let height = client.height().ok();
        let depth = client.mempool_size().ok();
        if let Ok(mut st) = status.lock() {
            if let Some(h) = height {
                st.tip_height = h;
            }
            st.mempool_depth = depth.map(|d| d as u64);
        }
        ctx.request_repaint();
        sleep_interruptible(&stop, Duration::from_secs(1));
    }
}

/// Persistent connection monitor: probes the node's tip height + mempool depth
/// every ~2s for the app's whole life, so the connection indicator is live from the
/// moment the app opens (not only while firing). Re-reads the RPC address each loop
/// so editing it takes effect. Holds NO key material.
fn run_conn_monitor(
    conn: Arc<Mutex<Conn>>,
    addr: Arc<Mutex<String>>,
    stop: Arc<AtomicBool>,
    ctx: eframe::egui::Context,
) {
    while !stop.load(Ordering::SeqCst) {
        let a = addr.lock().map(|s| s.clone()).unwrap_or_default();
        let client = RpcClient::new(a).with_timeout(Duration::from_secs(3));
        let height = client.height();
        let depth = client.mempool_size().ok();
        if let Ok(mut c) = conn.lock() {
            c.ever = true;
            match height {
                Ok(h) => {
                    c.ok = true;
                    c.tip = h;
                    c.mempool = depth.map(|d| d as u64);
                    c.error.clear();
                }
                Err(e) => {
                    c.ok = false;
                    c.error = format!("{e}");
                }
            }
        }
        ctx.request_repaint();
        sleep_interruptible(&stop, Duration::from_secs(2));
    }
}

/// What one fire attempt tells the worker loop to do next.
enum FireResult {
    /// Sent (or dry-run-built) fine — keep going at full pace.
    Continue,
    /// Capacity or unknown failure — back off for `Duration`, nonce held.
    Backoff(Duration),
    /// This wallet's run is over (affordability) — exit the worker.
    Stop,
}

/// Everything one worker needs across fire attempts (kept in one struct so the
/// per-mode loops share a single `fire_once` implementation).
struct WorkerState {
    client: RpcClient,
    selector: DestSelector,
    rng: Rng,
    seq: NonceSequencer,
    /// Local balance view for the affordability pre-check (debited per send,
    /// refreshed from the node each reconcile).
    known_balance: Option<u128>,
    /// Last chain height observed (for log lines).
    height: u64,
}

/// The firing worker for ONE wallet: owns a `Zeroizing` copy of that wallet's
/// signing seed for its lifetime and wipes it on return (normal stop or
/// panic-unwind of this frame). The seed is used only to derive a transient
/// keypair inside `build_signed_transfer`; the keypair never outlives a single
/// signature and is never stored or logged.
///
/// Per-block mode fires `n` txs on each new tip (the original behavior, with
/// `NonceSequencer::next`). The continuous modes (Target TX/s, Firehose) use the
/// commit-on-accept flow instead: PEEK the nonce, build+sign+submit, and only
/// ADVANCE when the node consumed the slot — a capacity rejection holds the same
/// nonce and retries after a short back-off, so the account never gaps or wedges.
fn run_worker(
    cfg: WorkerConfig,
    status: Arc<Mutex<Status>>,
    stop: Arc<AtomicBool>,
    ctx: eframe::egui::Context,
) {
    let selector = match DestSelector::new(cfg.dests.clone(), cfg.dest_mode) {
        Ok(s) => s,
        Err(e) => {
            set_error(&status, &e);
            worker_finished(&status, &ctx);
            return;
        }
    };
    let mut ws = WorkerState {
        client: RpcClient::new(cfg.rpc_addr.clone()).with_timeout(Duration::from_secs(15)),
        selector,
        rng: Rng::from_entropy(),
        seq: NonceSequencer::new(),
        known_balance: None,
        height: 0,
    };

    match cfg.mode {
        RateMode::PerBlock(n) => run_per_block(&cfg, n, &mut ws, &status, &stop, &ctx),
        RateMode::TargetTps(tps) => {
            run_continuous(&cfg, Some(Pacer::new(tps)), &mut ws, &status, &stop)
        }
        RateMode::Firehose => run_continuous(&cfg, None, &mut ws, &status, &stop),
    }

    worker_finished(&status, &ctx);
    // `cfg` (and its Zeroizing seed) drops here → wiped.
}

/// Decrement the live-worker count; the LAST worker out marks the run stopped.
fn worker_finished(status: &Arc<Mutex<Status>>, ctx: &eframe::egui::Context) {
    if let Ok(mut st) = status.lock() {
        st.live_workers = st.live_workers.saturating_sub(1);
        if st.live_workers == 0 {
            st.running = false;
        }
    }
    ctx.request_repaint();
}

/// Per-block mode: on each NEW tip, reconcile + fire `rate` transfers (the
/// original cannon behavior, unchanged except that an affordability stop ends
/// only THIS wallet's worker, and results feed the shared meters).
fn run_per_block(
    cfg: &WorkerConfig,
    rate: u32,
    ws: &mut WorkerState,
    status: &Arc<Mutex<Status>>,
    stop: &Arc<AtomicBool>,
    ctx: &eframe::egui::Context,
) {
    let mut last_height: Option<u64> = None;
    while !stop.load(Ordering::SeqCst) {
        let height = match ws.client.height() {
            Ok(h) => h,
            Err(e) => {
                set_error(status, &format!("RPC height failed: {e}"));
                sleep_interruptible(stop, POLL_INTERVAL);
                continue;
            }
        };
        ws.height = height;
        ctx.request_repaint();

        let is_new = last_height.map(|h| height > h).unwrap_or(true);
        if !is_new {
            sleep_interruptible(stop, POLL_INTERVAL);
            continue;
        }
        last_height = Some(height);

        if !sync_with_node(cfg, ws, status) {
            sleep_interruptible(stop, POLL_INTERVAL);
            continue;
        }

        for _ in 0..rate {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            match fire_once(cfg, ws, status, /* commit_on_accept = */ false) {
                FireResult::Continue => {}
                FireResult::Backoff(_) => {} // per-block: no pacing, just count it
                FireResult::Stop => return,
            }
        }
        ctx.request_repaint();
        sleep_interruptible(stop, POLL_INTERVAL);
    }
}

/// Continuous modes: Target TX/s (`pacer = Some`) or Firehose (`pacer = None`).
/// Reconciles nonce + balance with the node every [`RECONCILE_INTERVAL`], and
/// uses the commit-on-accept nonce flow (see [`fire_once`]).
fn run_continuous(
    cfg: &WorkerConfig,
    mut pacer: Option<Pacer>,
    ws: &mut WorkerState,
    status: &Arc<Mutex<Status>>,
    stop: &Arc<AtomicBool>,
) {
    let started = Instant::now();
    let mut last_sync: Option<Instant> = None;

    'run: while !stop.load(Ordering::SeqCst) {
        // Periodic reconciliation against the node (nonce floor, balance, tip).
        let due_sync = last_sync
            .map(|t| t.elapsed() >= RECONCILE_INTERVAL)
            .unwrap_or(true);
        if due_sync {
            if !sync_with_node(cfg, ws, status) {
                // Node unreachable: idle briefly, keep trying (nonce is held).
                sleep_interruptible(stop, POLL_INTERVAL);
                continue;
            }
            last_sync = Some(Instant::now());
        }

        let due = match pacer.as_mut() {
            Some(p) => p.take_due(started.elapsed()),
            None => 1, // firehose: one per iteration, as fast as the loop spins
        };
        if due == 0 {
            // Paced mode with nothing due yet: sleep a short beat (no busy-spin).
            sleep_interruptible(stop, Duration::from_millis(25));
            continue;
        }
        for _ in 0..due {
            if stop.load(Ordering::SeqCst) {
                break 'run;
            }
            match fire_once(cfg, ws, status, /* commit_on_accept = */ true) {
                FireResult::Continue => {}
                FireResult::Backoff(d) => {
                    sleep_interruptible(stop, d);
                    break; // re-check pacing/reconcile after a back-off
                }
                FireResult::Stop => break 'run,
            }
        }
        if pacer.is_none() {
            // Firehose: a tiny yield so the UI thread and monitor stay live.
            thread::yield_now();
        }
    }
}

/// Refresh this wallet's nonce floor + balance from the node and publish them.
/// Returns false if the node was unreachable (the caller idles and retries).
fn sync_with_node(cfg: &WorkerConfig, ws: &mut WorkerState, status: &Arc<Mutex<Status>>) -> bool {
    match ws.client.nonce(&cfg.from) {
        Ok(n) => ws.seq.reconcile(n),
        Err(e) => {
            set_error(status, &format!("RPC nonce failed: {e}"));
            return false;
        }
    }
    ws.known_balance = ws.client.balance(&cfg.from).ok().map(|b| b.grains());
    if let Ok(h) = ws.client.height() {
        ws.height = h;
    }
    publish_wallet_stat(cfg, ws, status, None);
    true
}

/// Publish this wallet's live stat row (next nonce, balance, optional stop
/// reason) into the shared status.
fn publish_wallet_stat(
    cfg: &WorkerConfig,
    ws: &WorkerState,
    status: &Arc<Mutex<Status>>,
    stopped: Option<String>,
) {
    if let Ok(mut st) = status.lock() {
        if let Some(wstat) = st.wallets.get_mut(cfg.wallet_index) {
            wstat.next_nonce = ws.seq.peek();
            wstat.balance_grains = ws.known_balance;
            if stopped.is_some() {
                wstat.stopped = stopped;
            }
        }
    }
}

/// Build, sign, and (unless dry-run) submit ONE transfer at the sequencer's
/// peeked nonce, then apply the nonce rule that keeps the account gap-free:
///
/// * ACCEPT (or dry-run build) → commit (`advance`).
/// * Capacity rejection (`mempool is full` / `reached its mempool limit`) → the
///   slot was NOT consumed: hold the SAME nonce, back off, retry. This is what
///   self-paces the firehose to the mempool's drain rate.
/// * `stale transaction` → our txs mined and the node moved ahead: re-query the
///   node's next nonce and reconcile FORWARD (never backward).
/// * `already in the pool` / `already pooled` → the slot IS consumed by our own
///   earlier submit (e.g. after a transport timeout that actually landed):
///   commit and move on.
/// * `insufficient balance` → stop THIS wallet's run and surface why.
/// * Anything else → count it, hold the nonce (not provably consumed), back off.
///
/// Per-block mode passes `commit_on_accept = false` and keeps its original
/// unconditional `next()` semantics (allocate on send).
fn fire_once(
    cfg: &WorkerConfig,
    ws: &mut WorkerState,
    status: &Arc<Mutex<Status>>,
    commit_on_accept: bool,
) -> FireResult {
    let to = ws.selector.next(&mut ws.rng);
    let amount = cfg.amount_mode.pick(&mut ws.rng);
    let nonce = ws.seq.peek();

    // Local affordability pre-check (the node's mempool is the real gate).
    if let Some(bal) = ws.known_balance {
        if bal < amount.saturating_add(FEE_ESTIMATE_GRAINS) {
            let detail = format!(
                "insufficient balance ({} XUS) for {} XUS + fee — stopping this wallet",
                grains_to_xus(bal),
                grains_to_xus(amount)
            );
            record(status, MeterKind::RejAfford);
            log_tx(status, cfg, ws.height, &to, amount, nonce, false, &detail);
            set_error(status, &format!("{}: {detail}", cfg.label));
            publish_wallet_stat(cfg, ws, status, Some(detail));
            return FireResult::Stop;
        }
    }

    let stx = match build_signed_transfer(&cfg.seed, cfg.scheme, &cfg.from, &to, amount, nonce) {
        Ok(s) => s,
        Err(e) => {
            record(status, MeterKind::Attempted);
            record(status, MeterKind::RejOther);
            log_tx(status, cfg, ws.height, &to, amount, nonce, false, &e);
            return FireResult::Continue;
        }
    };
    record(status, MeterKind::Attempted);

    if !commit_on_accept {
        // Per-block mode: allocate the nonce now (original behavior).
        let _ = ws.seq.next();
    }

    if cfg.dry_run {
        record(status, MeterKind::Accepted);
        if commit_on_accept {
            ws.seq.advance();
        }
        log_tx(
            status,
            cfg,
            ws.height,
            &to,
            amount,
            nonce,
            true,
            "dry-run (not submitted)",
        );
        // Optimistically debit our local balance view so the affordability
        // pre-check reflects the spend even without a live submit.
        debit(ws, amount);
        publish_wallet_stat(cfg, ws, status, None);
        return FireResult::Continue;
    }

    match ws.client.submit_transaction(&stx) {
        Ok(txid) => {
            record(status, MeterKind::Accepted);
            if commit_on_accept {
                ws.seq.advance();
            }
            log_tx(
                status,
                cfg,
                ws.height,
                &to,
                amount,
                nonce,
                true,
                &format!("submitted {}", short_hash(&txid.to_hex())),
            );
            debit(ws, amount);
            publish_wallet_stat(cfg, ws, status, None);
            FireResult::Continue
        }
        Err(e) => {
            let msg = format!("{e}");
            let class = classify_reject(&msg);
            record(
                status,
                match class {
                    RejectClass::Capacity => MeterKind::RejCapacity,
                    RejectClass::NonceStale | RejectClass::NonceOccupied => MeterKind::RejNonce,
                    RejectClass::Insufficient => MeterKind::RejAfford,
                    RejectClass::Other => MeterKind::RejOther,
                },
            );
            log_tx(status, cfg, ws.height, &to, amount, nonce, false, &msg);
            match disposition(class) {
                Disposition::HoldAndRetry => FireResult::Backoff(CAPACITY_BACKOFF),
                Disposition::Advance => {
                    if commit_on_accept {
                        ws.seq.advance();
                    }
                    publish_wallet_stat(cfg, ws, status, None);
                    FireResult::Continue
                }
                Disposition::ReconcileForward => {
                    if let Ok(n) = ws.client.nonce(&cfg.from) {
                        ws.seq.reconcile(n);
                    }
                    publish_wallet_stat(cfg, ws, status, None);
                    FireResult::Continue
                }
                Disposition::StopWallet => {
                    set_error(status, &format!("{}: {msg}", cfg.label));
                    publish_wallet_stat(cfg, ws, status, Some(msg));
                    FireResult::Stop
                }
                Disposition::HoldAndRetryOther => {
                    set_error(status, &format!("{}: {msg}", cfg.label));
                    FireResult::Backoff(OTHER_BACKOFF)
                }
            }
        }
    }
}

/// Debit the local balance view by amount + estimated fee (pre-check only).
fn debit(ws: &mut WorkerState, amount: u128) {
    if let Some(b) = ws.known_balance.as_mut() {
        *b = b.saturating_sub(amount.saturating_add(FEE_ESTIMATE_GRAINS));
    }
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
        thread::sleep(step.min(dur - slept));
        slept += step;
    }
}

fn set_error(status: &Arc<Mutex<Status>>, msg: &str) {
    if let Ok(mut st) = status.lock() {
        st.last_error = msg.to_string();
    }
}

fn record(status: &Arc<Mutex<Status>>, kind: MeterKind) {
    if let Ok(mut st) = status.lock() {
        st.record(kind);
    }
}

#[allow(clippy::too_many_arguments)]
fn log_tx(
    status: &Arc<Mutex<Status>>,
    cfg: &WorkerConfig,
    height: u64,
    to: &AccountId,
    amount_grains: u128,
    nonce: u64,
    ok: bool,
    detail: &str,
) {
    if let Ok(mut st) = status.lock() {
        st.push_log(LogLine {
            wallet: cfg.label.clone(),
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

        // Spawn the always-on connection monitor once (it needs the egui Context).
        if !self.conn_started {
            self.conn_started = true;
            let (conn, addr, stop, ctx2) = (
                self.conn.clone(),
                self.conn_addr.clone(),
                self.conn_stop.clone(),
                ctx.clone(),
            );
            thread::spawn(move || run_conn_monitor(conn, addr, stop, ctx2));
        }
        // Propagate the current RPC address to the monitor (so edits take effect).
        if let Ok(mut a) = self.conn_addr.lock() {
            if *a != self.rpc_addr {
                *a = self.rpc_addr.clone();
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.heading("SOV TX Cannon");
                ui.label(
                    egui::RichText::new(
                        "Automated transaction traffic generator — per-block, paced TX/s, or firehose.",
                    )
                    .small()
                    .weak(),
                );
                ui.add_space(6.0);

                // ---- Always-on connection indicator -------------------------
                {
                    let green = egui::Color32::from_rgb(90, 190, 110);
                    let red = egui::Color32::from_rgb(220, 80, 80);
                    let (color, text) = match self.conn.lock() {
                        Ok(c) if !c.ever => (
                            egui::Color32::GRAY,
                            format!("○ connecting to {}…", self.rpc_addr),
                        ),
                        Ok(c) if c.ok => {
                            let mp = c
                                .mempool
                                .map(|d| format!(" · mempool {d}/{MEMPOOL_CAP_HINT}"))
                                .unwrap_or_default();
                            (green, format!("● Connected — tip {}{mp}", c.tip))
                        }
                        Ok(c) => (
                            red,
                            format!("● Can't reach node at {}: {}", self.rpc_addr, c.error),
                        ),
                        Err(_) => (red, "● connection state unavailable".to_string()),
                    };
                    ui.colored_label(color, egui::RichText::new(text).strong());
                }
                ui.add_space(8.0);

                let running = self.is_running();
                if running {
                    // Keep the meters live without worker-driven repaints.
                    ctx.request_repaint_after(Duration::from_millis(250));
                }

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

                // ---- 2. Fire-from wallets (multi-select) --------------------
                if !self.wallets.is_empty() {
                    egui::CollapsingHeader::new("2 · Fire from (select wallets)")
                        .default_open(true)
                        .show(ui, |ui| {
                            ui.label(
                                egui::RichText::new(
                                    "Each checked wallet fires in parallel with its own nonce stream. \
                                     One wallet is capped by the node's per-sender mempool share (~256 \
                                     pending); check several to push the pool toward its 16,384 cap.",
                                )
                                .small()
                                .weak(),
                            );
                            ui.add_enabled_ui(!running, |ui| {
                                for w in &mut self.wallets {
                                    let bal = w
                                        .balance_grains
                                        .map(|g| format!("  ·  {} XUS", grains_to_xus(g)))
                                        .unwrap_or_default();
                                    ui.checkbox(&mut w.fire, format!("{}{bal}", w.label));
                                    ui.label(
                                        egui::RichText::new(format!("      {}", w.account.as_str()))
                                            .small()
                                            .weak()
                                            .monospace(),
                                    );
                                }
                            });
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
                                    ui.label("Rate mode:");
                                    ui.radio_value(&mut self.mode, ModeChoice::PerBlock, "Per block");
                                    ui.radio_value(
                                        &mut self.mode,
                                        ModeChoice::TargetTps,
                                        "Target TX/s",
                                    );
                                    ui.radio_value(&mut self.mode, ModeChoice::Firehose, "Firehose (MAX)");
                                });
                                match self.mode {
                                    ModeChoice::PerBlock => {
                                        ui.horizontal(|ui| {
                                            ui.label(format!(
                                                "Tx per new block (1–{MAX_RATE}):"
                                            ));
                                            ui.add(
                                                egui::TextEdit::singleline(&mut self.rate)
                                                    .desired_width(60.0),
                                            );
                                        });
                                    }
                                    ModeChoice::TargetTps => {
                                        ui.horizontal(|ui| {
                                            ui.label(format!(
                                                "Target TX/s, aggregate (0.1–{MAX_TPS}):"
                                            ));
                                            ui.add(
                                                egui::TextEdit::singleline(&mut self.tps)
                                                    .desired_width(60.0),
                                            );
                                        });
                                        ui.label(
                                            egui::RichText::new(
                                                "Steady pace decoupled from blocks; split evenly across the selected wallets. \
                                                 On-chain inclusion tops out around 1–5 TPS — expect the surplus to pool up.",
                                            )
                                            .small()
                                            .weak(),
                                        );
                                    }
                                    ModeChoice::Firehose => {
                                        ui.label(
                                            egui::RichText::new(
                                                "No pacing: signs + submits flat-out until the mempool pushes back, \
                                                 then holds the nonce, backs off, and retries — self-pacing to the drain rate.",
                                            )
                                            .small()
                                            .weak(),
                                        );
                                    }
                                }
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

                // ---- 5. Live meters ------------------------------------------
                ui.add_space(10.0);
                ui.separator();
                ui.heading("Live meters");
                let st = self.status.lock().unwrap();
                let now = st.now_ms();
                let rate = |k: MeterKind| st.meter.rate(now, k);
                let attempted_s = rate(MeterKind::Attempted);
                let accepted_s = rate(MeterKind::Accepted);
                let rej_cap_s = rate(MeterKind::RejCapacity);
                let rej_nonce_s = rate(MeterKind::RejNonce);
                let rej_aff_s = rate(MeterKind::RejAfford);
                let rej_other_s = rate(MeterKind::RejOther);
                let rejected_s = rej_cap_s + rej_nonce_s + rej_aff_s + rej_other_s;
                let sent_ok = st.meter.total(MeterKind::Accepted);
                let sent_fail = st.meter.total(MeterKind::RejCapacity)
                    + st.meter.total(MeterKind::RejNonce)
                    + st.meter.total(MeterKind::RejAfford)
                    + st.meter.total(MeterKind::RejOther);

                egui::Grid::new("meters").num_columns(2).show(ui, |ui| {
                    ui.label("Running");
                    ui.label(if st.running {
                        format!("yes ({} worker(s))", st.live_workers)
                    } else {
                        "no".into()
                    });
                    ui.end_row();
                    ui.label("Tip height");
                    ui.label(st.tip_height.to_string());
                    ui.end_row();
                    ui.label("Attempted / s");
                    ui.label(format!("{attempted_s:.1}"));
                    ui.end_row();
                    ui.label("Accepted / s");
                    ui.label(
                        egui::RichText::new(format!("{accepted_s:.1}"))
                            .color(egui::Color32::from_rgb(90, 170, 90)),
                    );
                    ui.end_row();
                    ui.label("Rejected / s");
                    ui.label(format!(
                        "{rejected_s:.1}   (mempool-full {rej_cap_s:.1} · nonce {rej_nonce_s:.1} · afford {rej_aff_s:.1} · other {rej_other_s:.1})"
                    ));
                    ui.end_row();
                    ui.label("Mempool depth");
                    match st.mempool_depth {
                        Some(d) => {
                            ui.horizontal(|ui| {
                                ui.label(format!("{d} / {MEMPOOL_CAP_HINT}"));
                                if d >= SATURATION_DEPTH {
                                    ui.colored_label(
                                        egui::Color32::from_rgb(220, 60, 60),
                                        egui::RichText::new("SATURATED").strong(),
                                    );
                                }
                            });
                        }
                        None => {
                            ui.label("—");
                        }
                    }
                    ui.end_row();
                    ui.label("Totals");
                    ui.label(format!("sent OK {sent_ok} · failed {sent_fail}"));
                    ui.end_row();
                });
                ui.label(
                    egui::RichText::new(
                        "Chain inclusion tops out near 1–5 TPS (150 s blocks, ~5 KiB PQ txs, 1→4 MiB cap): \
                         accepted/s tracks the mempool's drain, attempts and rejections show the pressure.",
                    )
                    .small()
                    .weak(),
                );

                if !st.wallets.is_empty() {
                    ui.add_space(4.0);
                    egui::Grid::new("wallet-stats").num_columns(4).show(ui, |ui| {
                        ui.label(egui::RichText::new("wallet").small().strong());
                        ui.label(egui::RichText::new("next nonce").small().strong());
                        ui.label(egui::RichText::new("balance").small().strong());
                        ui.label(egui::RichText::new("state").small().strong());
                        ui.end_row();
                        for w in &st.wallets {
                            ui.label(egui::RichText::new(&w.label).small().monospace());
                            ui.label(egui::RichText::new(w.next_nonce.to_string()).small());
                            ui.label(
                                egui::RichText::new(
                                    w.balance_grains
                                        .map(|g| format!("{} XUS", grains_to_xus(g)))
                                        .unwrap_or_else(|| "—".into()),
                                )
                                .small(),
                            );
                            match &w.stopped {
                                Some(why) => {
                                    ui.colored_label(
                                        egui::Color32::from_rgb(200, 80, 80),
                                        egui::RichText::new(format!("stopped: {why}")).small(),
                                    );
                                }
                                None => {
                                    ui.label(egui::RichText::new("firing").small().weak());
                                }
                            }
                            ui.end_row();
                        }
                    });
                }

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
                                        "[{}] h{} n{} → {} · {} XUS · {}",
                                        line.wallet,
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
