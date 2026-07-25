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
    build_signed_transfer, classify_reject, derive_account_id, disposition, first_blocker,
    fmt_count, fmt_elapsed, fmt_pct, fmt_rate, grains_to_xus, nice_ceiling, parse_xus, scope_x,
    scope_x_age, scope_y, share, AmountMode, DestMode, DestSelector, Disposition, KeyScheme,
    MeterKind, NonceSequencer, Pacer, Pressure, RateMeter, RateMode, RejectClass, Rng,
    SCOPE_GAP_MS, SCOPE_WINDOW_SECS,
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
/// Back-off while the balance is fully committed by still-pending txs (the refire
/// -after-Stop state): long enough not to spam the node, short enough to resume
/// within a few seconds of the backlog mining out.
const AFFORD_BACKOFF: Duration = Duration::from_secs(4);
/// The node's default mempool capacity (display hint for the saturation flag;
/// the node remains the authority — its "mempool is full" rejections are what
/// actually gate submission).
const MEMPOOL_CAP_HINT: u64 = 16_384;
/// Depth at which the meter panel flags the mempool SATURATED (~95% of cap).
const SATURATION_DEPTH: u64 = MEMPOOL_CAP_HINT / 20 * 19;
/// Rolling window (seconds) for the live per-second meters.
const METER_WINDOW_SECS: u64 = 5;
/// One sample per second, retaining [`SCOPE_WINDOW_SECS`] of mempool history —
/// exactly the span the scope draws, plus a couple of seconds of slack so the
/// left-most segment can be clipped rather than popping.
const MEMPOOL_HISTORY_SAMPLES: usize = SCOPE_WINDOW_SECS as usize + 8;
/// Below this window width the two-column layout folds into one column.
const WIDE_LAYOUT_MIN: f32 = 1_020.0;

/// One observation of the node's mempool at a point in time.
///
/// Only recorded when the node actually answered BOTH `sov_getHeight` and
/// `sov_getMempoolSize`: a sample always represents real data, and a missing
/// answer leaves a visible gap in the trace rather than a fabricated zero.
#[derive(Clone, Copy)]
struct MempoolSample {
    at_ms: u64,
    depth: u64,
    height: u64,
    /// True on the first sample observed at a newly mined height.
    new_block: bool,
}

/// The mempool time-series behind the scope.
///
/// It lives OUTSIDE [`Status`] on purpose: it describes the NODE, not a firing
/// run, so it keeps filling while the app is idle and survives start/stop. Its
/// clock origin is app launch, so `at_ms` is comparable across runs.
struct MempoolHistory {
    t0: Instant,
    samples: Vec<MempoolSample>,
}

impl Default for MempoolHistory {
    fn default() -> Self {
        Self {
            t0: Instant::now(),
            samples: Vec::new(),
        }
    }
}

impl MempoolHistory {
    /// Milliseconds since app launch.
    fn now_ms(&self) -> u64 {
        self.t0.elapsed().as_millis() as u64
    }

    /// Record one real observation, marking it as the first sample at a newly
    /// mined height, and keep the retained series bounded.
    fn sample(&mut self, height: u64, depth: u64) {
        let new_block = self.samples.last().is_some_and(|last| height > last.height);
        let at_ms = self.now_ms();
        self.samples.push(MempoolSample {
            at_ms,
            depth,
            height,
            new_block,
        });
        let excess = self.samples.len().saturating_sub(MEMPOOL_HISTORY_SAMPLES);
        if excess > 0 {
            self.samples.drain(0..excess);
        }
    }
}

fn main() -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            // Roomy enough for the two-column operator layout on a laptop screen…
            .with_inner_size([1_180.0, 820.0])
            // …and still coherent when folded to one column.
            .with_min_inner_size([720.0, 560.0])
            .with_title("SOV TX Cannon"),
        ..Default::default()
    };
    eframe::run_native(
        "SOV TX Cannon",
        options,
        Box::new(|cc| {
            apply_theme(&cc.egui_ctx);
            Ok(Box::new(CannonApp::default()))
        }),
    )
    .map_err(|e| format!("GUI failed: {e}"))
}

/// The instrument-panel palette. Every signal below is paired with a word or a
/// glyph elsewhere in the UI — color is never the only carrier of state.
mod palette {
    use eframe::egui::Color32;

    /// Window background — near-black with a blue cast.
    pub const BG: Color32 = Color32::from_rgb(11, 15, 20);
    /// Raised surfaces (cards, panels).
    pub const SURFACE: Color32 = Color32::from_rgb(18, 24, 32);
    /// A surface one step brighter (inputs, table stripes).
    pub const SURFACE_HI: Color32 = Color32::from_rgb(25, 33, 43);
    /// Hairlines and card borders.
    pub const LINE: Color32 = Color32::from_rgb(34, 45, 58);
    /// Primary text.
    pub const TEXT: Color32 = Color32::from_rgb(215, 224, 234);
    /// Secondary text.
    pub const DIM: Color32 = Color32::from_rgb(129, 148, 166);
    /// Tertiary text / axis furniture.
    pub const FAINT: Color32 = Color32::from_rgb(85, 104, 120);
    /// Flow: submissions, mempool depth.
    pub const CYAN: Color32 = Color32::from_rgb(63, 201, 218);
    /// Attempts.
    pub const VIOLET: Color32 = Color32::from_rgb(155, 140, 255);
    /// Healthy / accepted.
    pub const GREEN: Color32 = Color32::from_rgb(79, 201, 139);
    /// Blocks, caution, self-pacing.
    pub const AMBER: Color32 = Color32::from_rgb(242, 183, 64);
    /// Failure, live-fire arming, saturation.
    pub const RED: Color32 = Color32::from_rgb(232, 97, 92);
}

/// Set the type scale and chrome once at startup.
///
/// Nothing is smaller than 10 pt, spacing is generous enough for a pointer, and
/// the monospace face is what every changing number is rendered in so digits
/// never jitter as values change width.
fn apply_theme(ctx: &eframe::egui::Context) {
    use eframe::egui::{self, FontFamily::Monospace, FontFamily::Proportional, FontId, TextStyle};

    let mut style = (*ctx.style()).clone();
    style.text_styles = [
        (TextStyle::Heading, FontId::new(17.0, Proportional)),
        (TextStyle::Body, FontId::new(13.0, Proportional)),
        (TextStyle::Button, FontId::new(13.0, Proportional)),
        (TextStyle::Small, FontId::new(11.0, Proportional)),
        (TextStyle::Monospace, FontId::new(12.5, Monospace)),
    ]
    .into();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    style.spacing.interact_size.y = 26.0;

    let v = &mut style.visuals;
    v.dark_mode = true;
    v.panel_fill = palette::BG;
    v.window_fill = palette::SURFACE;
    v.extreme_bg_color = palette::SURFACE_HI;
    v.faint_bg_color = palette::SURFACE_HI;
    v.override_text_color = Some(palette::TEXT);
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, palette::LINE);
    v.widgets.inactive.bg_fill = palette::SURFACE_HI;
    v.widgets.inactive.weak_bg_fill = palette::SURFACE_HI;
    v.widgets.hovered.bg_fill = palette::LINE;
    v.widgets.hovered.weak_bg_fill = palette::LINE;
    v.selection.bg_fill = palette::CYAN.gamma_multiply(0.35);
    v.selection.stroke = egui::Stroke::new(1.0, palette::CYAN);
    ctx.set_style(style);
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

/// Just the filename of a store path, for compact unlock messages.
fn short_path(p: &str) -> String {
    std::path::Path::new(p)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.to_string())
}

/// A file under `~/.sov-station/`.
fn sov_station_file(name: &str) -> String {
    let home = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
        .unwrap_or_default();
    PathBuf::from(home)
        .join(".sov-station")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

/// The PRIMARY wallet store: `~/.sov-station/wallets.auto` — the store SOV-Station
/// auto-loads on launch under the MASTER passphrase (NOT `wallets.keystore`, which
/// is a manual export/backup and often has its own passphrase). Overridable in the UI.
fn default_keystore_path() -> String {
    sov_station_file("wallets.auto")
}

/// The manual export/backup store — merged in on unlock if it decrypts with the same
/// master passphrase (so a user who kept a same-passphrase backup sees those too).
fn backup_keystore_path() -> String {
    sov_station_file("wallets.keystore")
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
    /// The nonce this wallet started the run at — the baseline for "nonces
    /// committed this run". `None` until the first successful node reconcile,
    /// so progress is never shown as a guess.
    first_nonce: Option<u64>,
    balance_grains: Option<u128>,
    /// Set once this wallet's worker has exited (normally, at the end of a run).
    ended: bool,
    /// Set if the worker exited because of a fault, with the reason.
    fault: Option<String>,
    /// Set while this wallet is waiting rather than firing (back-off reason).
    waiting: Option<String>,
}

impl WalletStat {
    /// Nonces this wallet has committed since the run began, or `None` while the
    /// baseline is still unknown.
    fn committed(&self) -> Option<u64> {
        self.first_nonce.map(|f| self.next_nonce.saturating_sub(f))
    }
}

/// Live status shared between the UI thread and the firing workers.
struct Status {
    running: bool,
    /// Rolling throughput meters (attempted/accepted/rejected-by-reason).
    meter: RateMeter,
    /// The meter's clock origin — all events are stamped relative to this, and
    /// it doubles as the run's start time for the elapsed readout.
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
    /// When the last SUCCESSFUL probe completed — the heartbeat. The indicator
    /// only shows green while this is fresh, so a wedged monitor or dead node can
    /// never leave a stale "Connected" on screen.
    beat_at: Option<Instant>,
    /// Round-trip time of the last successful probe.
    latency_ms: u64,
}

/// How old the last successful heartbeat may be and still count as "Connected".
/// One probe cycle is ~2s + a worst case bounded 3s connect/read, so anything
/// older than this means beats are genuinely being missed.
const HEARTBEAT_FRESH: Duration = Duration::from_secs(7);

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

    /// Cumulative accepted / rejected for this run.
    fn totals(&self) -> (u64, u64) {
        let ok = self.meter.total(MeterKind::Accepted);
        let bad = self.meter.total(MeterKind::RejCapacity)
            + self.meter.total(MeterKind::RejNonce)
            + self.meter.total(MeterKind::RejAfford)
            + self.meter.total(MeterKind::RejOther);
        (ok, bad)
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
    /// Background threads joining a stopped session's workers (so Stop never blocks
    /// the UI thread on an in-flight RPC). Reaped when finished; joined on exit.
    draining: Vec<thread::JoinHandle<()>>,
    /// Closed-loop mode: fire ONLY to the unlocked wallets' own addresses, so every
    /// XUS stays among the user's accounts (nothing can be sent to a foreign key).
    recycle: bool,

    // Always-on node monitor (independent of firing). `conn_addr` is shared so UI
    // edits to `rpc_addr` reach the monitor; the monitor is spawned lazily on the
    // first `update` (it needs the egui Context to request repaints).
    conn: Arc<Mutex<Conn>>,
    conn_addr: Arc<Mutex<String>>,
    conn_stop: Arc<AtomicBool>,
    conn_started: bool,
    /// Mempool time-series behind the scope — node state, so it outlives runs.
    history: Arc<Mutex<MempoolHistory>>,

    // ---- View state (no bearing on what is fired) ----
    /// Summary of the last completed run, shown after Stop.
    last_run: Option<RunSummary>,
    /// Show only failures in the event log.
    log_errors_only: bool,
    /// Setup column collapsed to give the telemetry the full width.
    setup_open: bool,
}

/// What a finished run did — kept so "stopped" is a result, not a blank screen.
#[derive(Clone)]
struct RunSummary {
    accepted: u64,
    rejected: u64,
    duration_secs: u64,
    wallets: usize,
    mode: String,
    dry_run: bool,
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
            draining: Vec::new(),
            recycle: true, // default: closed-loop — principal recycles among the user's wallets
            conn: Arc::new(Mutex::new(Conn::default())),
            conn_addr: Arc::new(Mutex::new(DEFAULT_RPC.to_string())),
            conn_stop: Arc::new(AtomicBool::new(false)),
            conn_started: false,
            history: Arc::new(Mutex::new(MempoolHistory::default())),
            last_run: None,
            log_errors_only: false,
            setup_open: true,
        }
    }
}

impl CannonApp {
    fn is_running(&self) -> bool {
        self.session.is_some()
    }

    /// Decrypt SOV-Station's wallet store(s) with the master passphrase and load the
    /// spendable wallets, then WIPE the passphrase. Reads a CANDIDATE list — the UI
    /// path (default `wallets.auto`, SOV-Station's primary store) plus `wallets.auto`
    /// and the `wallets.keystore` backup — and MERGES them, deduping by the DERIVED
    /// on-chain id. Each wallet's on-chain account is derived from its SEED
    /// ([`derive_account_id`]); the keystore's `account` field is only a display
    /// label. Watch-only entries (no seed) are skipped — they cannot sign.
    fn unlock(&mut self) {
        if self.is_running() {
            return;
        }
        if self.passphrase.is_empty() {
            self.unlock_msg = "enter your master passphrase".into();
            return;
        }

        // Candidate stores, deduped: the UI path first, then the two default stores.
        let mut candidates = vec![self.keystore_path.trim().to_string()];
        for extra in [default_keystore_path(), backup_keystore_path()] {
            if !candidates.contains(&extra) {
                candidates.push(extra);
            }
        }

        // Drop any previously unlocked wallets first (zeroizes their seeds).
        self.wipe_wallets();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut notes: Vec<String> = Vec::new();
        for path in &candidates {
            let text = match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(_) => continue, // missing store — skip silently
            };
            // Reuse SOV-Station's exact hardened decryption (Argon2id + ChaCha20-Poly1305).
            let ks = match Keystore::from_encrypted_or_plain(&text, Some(self.passphrase.as_str()))
            {
                Ok(ks) => ks,
                Err(_) => {
                    notes.push(format!(
                        "{}: wrong passphrase / not readable",
                        short_path(path)
                    ));
                    continue;
                }
            };
            for (i, entry) in ks.miners.iter().enumerate() {
                if entry.seed_hex.trim().is_empty() {
                    continue; // watch-only: no seed to sign with
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
                let mut seed = Zeroizing::new(seed_arr);
                wipe_vec(&mut seed_bytes);
                // The REAL on-chain id — derived from the seed, NOT the label field.
                let account = derive_account_id(&seed, scheme);
                if !seen.insert(account.to_string()) {
                    *seed = [0u8; 32]; // duplicate across stores — wipe + skip
                    continue;
                }
                let label = if entry.account.trim().is_empty() {
                    format!("wallet #{i}")
                } else {
                    entry.account.trim().to_string()
                };
                let fire = self.wallets.is_empty(); // default: first wallet only
                self.wallets.push(UnlockedWallet {
                    label,
                    account,
                    scheme,
                    seed,
                    balance_grains: None,
                    fire,
                });
            }
        }
        // The passphrase has done its job; wipe it from memory now.
        self.passphrase.zeroize();

        if self.wallets.is_empty() {
            self.unlock_msg = if notes.is_empty() {
                "no spendable wallets found (watch-only or empty store)".into()
            } else {
                format!("unlock failed — {}", notes.join("; "))
            };
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
        // Closed-loop: destinations are the unlocked wallets' OWN addresses, so the
        // principal stays among the user's accounts — nothing can be sent to a key the
        // user doesn't hold. Each tx still pays its miner fee (~21,000 grains), which
        // consensus routes to whoever mines the block — a third party on mainnet.
        if self.recycle {
            let mine: Vec<AccountId> = self.wallets.iter().map(|w| w.account.clone()).collect();
            if mine.is_empty() {
                return Err(
                    "unlock your wallets first — recycle sends XUS among your own accounts".into(),
                );
            }
            return Ok(mine);
        }
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
        self.config_msg.clear();
        self.last_run = None;
        let stop = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::with_capacity(configs.len());
        for cfg in configs {
            let status = self.status.clone();
            let ctx = ctx.clone();
            let stop = stop.clone();
            handles.push(thread::spawn(move || run_worker(cfg, status, stop, ctx)));
        }
        self.session = Some(Session { stop, handles });
    }

    /// Stop firing. Signals every worker immediately, then joins them on a
    /// BACKGROUND thread so an in-flight submit/read can never freeze the UI. Each
    /// worker's seed copy is still zeroized as its config drops when the worker exits;
    /// the join thread is tracked in `draining` (reaped in `update`, joined on exit)
    /// so the wipe is always completed.
    fn stop(&mut self) {
        if let Some(s) = self.session.take() {
            s.stop.store(true, Ordering::SeqCst); // halt workers now
            self.draining.push(thread::spawn(move || {
                let mut s = s;
                s.stop_and_join();
            }));
        }
        if let Ok(mut st) = self.status.lock() {
            st.running = false;
            // Freeze what this run actually did, so "stopped" is a RESULT rather
            // than an empty panel. Every figure here is a real counter.
            let (accepted, rejected) = st.totals();
            self.last_run = Some(RunSummary {
                accepted,
                rejected,
                duration_secs: st.t0.elapsed().as_secs(),
                wallets: st.wallets.len(),
                mode: self.mode_summary(),
                dry_run: self.dry_run,
            });
        }
        self.config_msg.clear();
    }

    /// One-line description of the configured rate mode and its parameter,
    /// exactly as it will be (or was) applied.
    fn mode_summary(&self) -> String {
        match self.mode {
            ModeChoice::PerBlock => format!("per block × {}", self.rate.trim()),
            ModeChoice::TargetTps => format!("paced {} TX/s", self.tps.trim()),
            ModeChoice::Firehose => "firehose".into(),
        }
    }

    /// How many wallets are checked to fire.
    fn selected_count(&self) -> usize {
        self.wallets.iter().filter(|w| w.fire).count()
    }

    /// How many destinations the current configuration resolves to — used only
    /// for the readiness check, so it never reports an error the operator has
    /// not yet caused.
    fn destination_count(&self) -> usize {
        self.parse_dests().map(|d| d.len()).unwrap_or(0)
    }
}

impl Drop for CannonApp {
    fn drop(&mut self) {
        // Ensure every worker's seed copy is wiped, then wipe ours.
        if let Some(mut s) = self.session.take() {
            s.stop_and_join();
        }
        // Wait out any background stop-joins so their workers' seeds finish wiping.
        for h in self.draining.drain(..) {
            let _ = h.join();
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

/// Persistent node monitor: probes tip height + mempool depth once a second for
/// the app's WHOLE life, so both the connection indicator and the mempool scope
/// are live from the moment the app opens — not only while firing. Re-reads the
/// RPC address each loop so editing it takes effect. Holds NO key material.
///
/// This is the single source of tip/mempool truth. A sample is appended to the
/// history only when the node answered BOTH calls; a failed probe leaves a real
/// gap in the trace instead of a fabricated point.
fn run_conn_monitor(
    conn: Arc<Mutex<Conn>>,
    history: Arc<Mutex<MempoolHistory>>,
    addr: Arc<Mutex<String>>,
    stop: Arc<AtomicBool>,
    ctx: eframe::egui::Context,
) {
    while !stop.load(Ordering::SeqCst) {
        let a = addr.lock().map(|s| s.clone()).unwrap_or_default();
        let client = RpcClient::new(a).with_timeout(Duration::from_secs(3));
        let probe_started = Instant::now();
        let height = client.height();
        let latency = probe_started.elapsed();
        let depth = height.is_ok().then(|| client.mempool_size().ok()).flatten();
        // Keep the (Copy) height for the history sample; the error text is moved
        // into the connection view below.
        let height_ok = height.as_ref().ok().copied();
        if let Ok(mut c) = conn.lock() {
            c.ever = true;
            match height {
                Ok(h) => {
                    c.ok = true;
                    c.tip = h;
                    c.mempool = depth.map(|d| d as u64);
                    c.error.clear();
                    c.beat_at = Some(Instant::now());
                    c.latency_ms = latency.as_millis() as u64;
                }
                Err(e) => {
                    c.ok = false;
                    c.error = format!("{e}");
                }
            }
        }
        if let (Some(h), Some(d)) = (height_ok, depth) {
            if let Ok(mut hist) = history.lock() {
                hist.sample(h, d as u64);
            }
        }
        ctx.request_repaint();
        sleep_interruptible(&stop, Duration::from_secs(1));
    }
}

/// What one fire attempt tells the worker loop to do next.
enum FireResult {
    /// Sent (or dry-run-built) fine — keep going at full pace.
    Continue,
    /// Capacity or unknown failure — back off for `Duration`, nonce held.
    ///
    /// There is deliberately no "give up" outcome: every rejection the node can
    /// return is recoverable (hold the nonce, resync, or wait for balance), so a
    /// worker only ever exits because the operator stopped the run.
    Backoff(Duration),
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
    /// The network signing domain from `sov_getSigningDomain` — `None` while the
    /// `tx-domain` fork is dormant (legacy signing), `Some` once active
    /// (network-bound signing). Refreshed on each node reconcile so a cannon
    /// running across the activation switches over automatically.
    domain: Option<sov_primitives::SigningDomain>,
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
            set_error(&status, &format!("{}: {e}", cfg.label));
            worker_finished(&status, &ctx, cfg.wallet_index, Some(e));
            return;
        }
    };
    let mut ws = WorkerState {
        // Short timeout: a worker blocked in a submit/read is what a background Stop
        // join has to wait out, so keep it small (a slow/saturated node must never
        // make Stop feel hung).
        client: RpcClient::new(cfg.rpc_addr.clone()).with_timeout(Duration::from_secs(4)),
        selector,
        rng: Rng::from_entropy(),
        seq: NonceSequencer::new(),
        known_balance: None,
        height: 0,
        domain: None,
    };

    match cfg.mode {
        RateMode::PerBlock(n) => run_per_block(&cfg, n, &mut ws, &status, &stop, &ctx),
        RateMode::TargetTps(tps) => {
            run_continuous(&cfg, Some(Pacer::new(tps)), &mut ws, &status, &stop)
        }
        RateMode::Firehose => run_continuous(&cfg, None, &mut ws, &status, &stop),
    }

    worker_finished(&status, &ctx, cfg.wallet_index, None);
    // `cfg` (and its Zeroizing seed) drops here → wiped.
}

/// Mark this wallet's worker as ended (with `fault` if it ended because of one)
/// and decrement the live-worker count; the LAST worker out marks the run
/// stopped. The wallet table shows workers winding down one by one during a
/// stop, so "STOPPING" is visibly making progress rather than just spinning.
fn worker_finished(
    status: &Arc<Mutex<Status>>,
    ctx: &eframe::egui::Context,
    wallet_index: usize,
    fault: Option<String>,
) {
    if let Ok(mut st) = status.lock() {
        if let Some(w) = st.wallets.get_mut(wallet_index) {
            w.ended = true;
            w.waiting = None;
            if fault.is_some() {
                w.fault = fault;
            }
        }
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
    // Refresh the signing domain only on a definitive answer: a transient RPC
    // failure must not silently downgrade an active-fork worker to legacy
    // signatures (an old node without the method already answers `None`).
    if let Ok(domain) = ws.client.signing_domain() {
        ws.domain = domain;
    }
    publish_wallet_stat(cfg, ws, status, None);
    true
}

/// A per-wallet condition worth surfacing in the wallet table.
enum WalletNote {
    /// Not firing right now, and why — self-clearing when firing resumes.
    Waiting(String),
}

/// Publish this wallet's live stat row (next nonce, balance, condition) into the
/// shared status. The first publish also records the nonce baseline the run's
/// per-wallet progress is measured from.
fn publish_wallet_stat(
    cfg: &WorkerConfig,
    ws: &WorkerState,
    status: &Arc<Mutex<Status>>,
    note: Option<WalletNote>,
) {
    if let Ok(mut st) = status.lock() {
        if let Some(wstat) = st.wallets.get_mut(cfg.wallet_index) {
            let peek = ws.seq.peek();
            wstat.first_nonce.get_or_insert(peek);
            wstat.next_nonce = peek;
            wstat.balance_grains = ws.known_balance;
            match note {
                Some(WalletNote::Waiting(why)) => wstat.waiting = Some(why),
                // Firing normally again: clear any stale wait reason.
                None => wstat.waiting = None,
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

    // Local affordability pre-check (the node's mempool is the real gate). A shortfall
    // is NOT fatal: pending txs from a previous run release the balance as they mine
    // (closed-loop recycle returns it outright) — refresh from the node and wait.
    if let Some(bal) = ws.known_balance {
        if bal < amount.saturating_add(FEE_ESTIMATE_GRAINS) {
            if let Ok(fresh) = ws.client.balance(&cfg.from) {
                ws.known_balance = Some(fresh.grains());
            }
            if ws
                .known_balance
                .is_some_and(|b| b < amount.saturating_add(FEE_ESTIMATE_GRAINS))
            {
                let detail = format!(
                    "balance {} XUS can't cover {} XUS + fee — waiting for pending txs to mine",
                    grains_to_xus(ws.known_balance.unwrap_or(0)),
                    grains_to_xus(amount)
                );
                record(status, MeterKind::RejAfford);
                publish_wallet_stat(cfg, ws, status, Some(WalletNote::Waiting(detail)));
                return FireResult::Backoff(AFFORD_BACKOFF);
            }
        }
    }

    let stx = match build_signed_transfer(
        &cfg.seed,
        cfg.scheme,
        &cfg.from,
        &to,
        amount,
        nonce,
        ws.domain.as_ref(),
    ) {
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
                Disposition::WaitAffordable => {
                    // The pool holds earlier txs committing this balance (typically a
                    // previous run's backlog). Refresh our view, hold the nonce, wait —
                    // firing resumes by itself as blocks mine the backlog out.
                    if let Ok(fresh) = ws.client.balance(&cfg.from) {
                        ws.known_balance = Some(fresh.grains());
                    }
                    if let Ok(n) = ws.client.nonce(&cfg.from) {
                        ws.seq.reconcile(n);
                    }
                    publish_wallet_stat(
                        cfg,
                        ws,
                        status,
                        Some(WalletNote::Waiting(
                            "balance committed by pending txs — resumes as they mine".into(),
                        )),
                    );
                    FireResult::Backoff(AFFORD_BACKOFF)
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

// ===========================================================================
// Presentation
// ===========================================================================
//
// The layout is fixed furniture around a scrolling telemetry column, so the two
// things an operator always needs — the state strip and the firing controls —
// are never scrolled out of reach:
//
//   ┌──────────────────────────────────────────────────────────────────┐
//   │ SOV TX CANNON                       [● LIVE  tip 11,842  38 ms]  │ top
//   │ ▶ FIRING · LIVE — firehose · 3 wallets · 12.4 accepted/s   4m 07s │ strip
//   ├──────────────┬───────────────────────────────────────────────────┤
//   │ SETUP        │  ATTEMPTED   ACCEPTED   REJECTED   MEMPOOL        │
//   │  node+keys   │    14.2        12.4        1.8      ◕ HEAVY       │
//   │  wallets     │  ┌─ MEMPOOL PRESSURE ───────────────────────────┐ │
//   │  traffic     │  │  the scope (5 min, block markers, sat line)  │ │
//   │              │  └──────────────────────────────────────────────┘ │
//   │              │  outcome breakdown / wallets / event log          │
//   ├──────────────┴───────────────────────────────────────────────────┤
//   │ [▶ START] (Per block)(Target TX/s)(Firehose)  5 tx  [DRY][LIVE]  │ bar
//   └──────────────────────────────────────────────────────────────────┘
//
// Every number that changes is drawn in the monospace face so digits are
// tabular and do not jitter, and every colored signal is paired with a word or
// a glyph so nothing depends on color perception alone.

use eframe::egui::{self, Color32, Pos2, Rect, RichText, Sense, Shape, Stroke, Ui, Vec2};

/// A bordered surface used for every grouped block.
fn card_frame() -> egui::Frame {
    egui::Frame::none()
        .fill(palette::SURFACE)
        .stroke(Stroke::new(1.0, palette::LINE))
        .rounding(egui::Rounding::same(8.0))
        .inner_margin(egui::Margin::symmetric(12.0, 10.0))
}

/// A small-caps section marker.
fn eyebrow(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(text.to_uppercase())
            .small()
            .monospace()
            .color(palette::FAINT),
    );
}

/// The four headline readings. `value` is already formatted; `sub` is the
/// supporting cumulative figure. A datum the node did not supply arrives here as
/// the dash, never as a zero.
struct Tile<'a> {
    label: &'a str,
    glyph: &'a str,
    value: String,
    unit: &'a str,
    sub: String,
    accent: Color32,
}

fn stat_tile(ui: &mut Ui, t: &Tile) {
    card_frame().show(ui, |ui| {
        // Fill the column exactly and hold a common height, so the four tiles
        // form one clean band whatever their content.
        ui.set_min_width(ui.available_width());
        ui.set_min_height(62.0);
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(t.glyph).small().monospace().color(t.accent));
                eyebrow(ui, t.label);
            });
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(&t.value)
                        .monospace()
                        .size(24.0)
                        .color(t.accent),
                );
                if !t.unit.is_empty() {
                    ui.label(RichText::new(t.unit).small().color(palette::FAINT));
                }
            });
            // Truncate rather than wrap: a tile must never change height.
            ui.add(egui::Label::new(RichText::new(&t.sub).small().color(palette::DIM)).truncate());
        });
    });
}

/// The mempool scope: depth over a fixed five-minute, right-anchored window,
/// with a vertical stroke at every block we observed arriving and a dashed line
/// at the saturation threshold.
///
/// What it looks like in each regime:
///   * **no data** — the axis and the saturation line are still drawn, with an
///     explicit "waiting for the first sample" note. Never an implied zero.
///   * **zero depth** — the trace runs flat along the baseline; block strokes
///     still mark the tip advancing, so a live-but-idle chain is obvious.
///   * **steady state** — a sawtooth: depth climbs between blocks and steps down
///     at each amber stroke as a block drains the pool.
///   * **saturation** — the trace rides at or above the dashed SAT line and the
///     occupancy bar below turns solid; capacity rejections become the pacer.
///   * **gap** — a probe that failed leaves a real hole: the trace breaks and a
///     hatched baseline marks the seconds the node told us nothing.
fn draw_scope(
    ui: &mut Ui,
    samples: &[MempoolSample],
    now_ms: u64,
    depth: Option<u64>,
    node_ok: bool,
) {
    let width = ui.available_width().max(240.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 214.0), Sense::hover());
    let p = ui.painter_at(rect);
    p.rect_filled(rect, egui::Rounding::same(8.0), palette::SURFACE);
    p.rect_stroke(
        rect,
        egui::Rounding::same(8.0),
        Stroke::new(1.0, palette::LINE),
    );

    // --- furniture -------------------------------------------------------
    let head = Rect::from_min_size(
        rect.min + Vec2::new(12.0, 9.0),
        Vec2::new(width - 24.0, 14.0),
    );
    p.text(
        head.left_top(),
        egui::Align2::LEFT_TOP,
        "MEMPOOL PRESSURE",
        egui::FontId::monospace(10.5),
        palette::DIM,
    );
    p.text(
        head.right_top(),
        egui::Align2::RIGHT_TOP,
        format!("{} MIN WINDOW · 1 S SAMPLES", SCOPE_WINDOW_SECS / 60),
        egui::FontId::monospace(10.5),
        palette::FAINT,
    );

    // Plot box: left gutter for depth labels, bottom gutter for the time axis
    // and the occupancy bar.
    let plot = Rect::from_min_max(
        Pos2::new(rect.left() + 54.0, rect.top() + 30.0),
        Pos2::new(rect.right() - 12.0, rect.bottom() - 62.0),
    );
    let window_ms = SCOPE_WINDOW_SECS * 1_000;

    // Vertical scale: the taller of the visible peak and the saturation line, so
    // the SAT line is always on screen and the axis only steps at 1-2-5 values
    // (the trace never rescales for a one-sample wobble).
    let peak = samples.iter().map(|s| s.depth).max().unwrap_or(0);
    let ceiling = nice_ceiling(peak.max(SATURATION_DEPTH));

    for i in 0..=4 {
        let value = ceiling * i / 4;
        let y = scope_y(value, ceiling, plot.bottom(), plot.top());
        p.line_segment(
            [Pos2::new(plot.left(), y), Pos2::new(plot.right(), y)],
            Stroke::new(1.0, palette::LINE),
        );
        p.text(
            Pos2::new(plot.left() - 8.0, y),
            egui::Align2::RIGHT_CENTER,
            fmt_count(value),
            egui::FontId::monospace(10.0),
            palette::FAINT,
        );
    }

    // Saturation threshold — dashed, and labelled in words.
    let sat_y = scope_y(SATURATION_DEPTH, ceiling, plot.bottom(), plot.top());
    let mut x = plot.left();
    while x < plot.right() {
        let x2 = (x + 5.0).min(plot.right());
        p.line_segment(
            [Pos2::new(x, sat_y), Pos2::new(x2, sat_y)],
            Stroke::new(1.0, palette::RED.gamma_multiply(0.75)),
        );
        x += 10.0;
    }
    p.text(
        Pos2::new(plot.left() + 4.0, sat_y - 2.0),
        egui::Align2::LEFT_BOTTOM,
        "SATURATION",
        egui::FontId::monospace(10.0),
        palette::RED,
    );

    // Time axis: a tick each minute, "now" pinned to the right edge.
    for m in 0..=(SCOPE_WINDOW_SECS / 60) {
        let x = scope_x_age(m * 60_000, window_ms, plot.left(), plot.right());
        p.line_segment(
            [
                Pos2::new(x, plot.bottom()),
                Pos2::new(x, plot.bottom() + 4.0),
            ],
            Stroke::new(1.0, palette::LINE),
        );
        let (label, align) = if m == 0 {
            ("now".to_string(), egui::Align2::RIGHT_TOP)
        } else {
            (format!("-{m}m"), egui::Align2::CENTER_TOP)
        };
        p.text(
            Pos2::new(x, plot.bottom() + 5.0),
            align,
            label,
            egui::FontId::monospace(10.0),
            palette::FAINT,
        );
    }

    // --- the trace -------------------------------------------------------
    let visible: Vec<&MempoolSample> = samples
        .iter()
        .filter(|s| now_ms.saturating_sub(s.at_ms) <= window_ms)
        .collect();

    if visible.len() < 2 {
        let note = if node_ok {
            "waiting for the first mempool sample from the node"
        } else {
            "no samples — the node is not answering"
        };
        p.text(
            plot.center(),
            egui::Align2::CENTER_CENTER,
            note,
            egui::FontId::proportional(12.0),
            palette::FAINT,
        );
    } else {
        let pos = |s: &MempoolSample| {
            Pos2::new(
                scope_x(s.at_ms, now_ms, window_ms, plot.left(), plot.right()),
                scope_y(s.depth, ceiling, plot.bottom(), plot.top()),
            )
        };
        // Split into contiguous runs; a probe gap breaks the line instead of
        // inventing a straight interpolation across seconds we never saw.
        let mut run: Vec<Pos2> = vec![pos(visible[0])];
        let mut runs: Vec<Vec<Pos2>> = Vec::new();
        let mut gaps: Vec<(f32, f32)> = Vec::new();
        for pair in visible.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            if b.at_ms.saturating_sub(a.at_ms) > SCOPE_GAP_MS {
                gaps.push((pos(a).x, pos(b).x));
                runs.push(std::mem::take(&mut run));
            }
            run.push(pos(b));
        }
        runs.push(run);

        for (x0, x1) in gaps {
            let mut x = x0;
            while x < x1 {
                let x2 = (x + 3.0).min(x1);
                p.line_segment(
                    [Pos2::new(x, plot.bottom()), Pos2::new(x2, plot.bottom())],
                    Stroke::new(2.0, palette::FAINT),
                );
                x += 6.0;
            }
            p.text(
                Pos2::new((x0 + x1) * 0.5, plot.bottom() - 4.0),
                egui::Align2::CENTER_BOTTOM,
                "no data",
                egui::FontId::monospace(10.0),
                palette::FAINT,
            );
        }

        for run in &runs {
            // Fill: one convex trapezoid per segment (vertical sides), so the
            // area is correct for any shape of trace.
            for seg in run.windows(2) {
                p.add(Shape::convex_polygon(
                    vec![
                        seg[0],
                        seg[1],
                        Pos2::new(seg[1].x, plot.bottom()),
                        Pos2::new(seg[0].x, plot.bottom()),
                    ],
                    palette::CYAN.gamma_multiply(0.16),
                    Stroke::NONE,
                ));
            }
            if run.len() >= 2 {
                p.add(Shape::line(run.clone(), Stroke::new(1.8, palette::CYAN)));
            } else if let Some(only) = run.first() {
                p.circle_filled(*only, 1.8, palette::CYAN);
            }
        }

        // Block markers, newest first so the freshest labels win the space.
        let mut labelled_at: Vec<f32> = Vec::new();
        for s in visible.iter().rev().filter(|s| s.new_block) {
            let x = pos(s).x;
            p.line_segment(
                [Pos2::new(x, plot.top()), Pos2::new(x, plot.bottom())],
                Stroke::new(1.0, palette::AMBER.gamma_multiply(0.55)),
            );
            p.line_segment(
                [
                    Pos2::new(x, plot.bottom() - 6.0),
                    Pos2::new(x, plot.bottom()),
                ],
                Stroke::new(2.0, palette::AMBER),
            );
            if labelled_at.iter().all(|&l| (l - x).abs() > 46.0) {
                labelled_at.push(x);
                p.text(
                    Pos2::new(x - 3.0, plot.top() + 1.0),
                    egui::Align2::RIGHT_TOP,
                    format!("#{}", s.height),
                    egui::FontId::monospace(10.0),
                    palette::AMBER,
                );
            }
        }
    }

    // --- occupancy bar (the WIP's "discrete transactions" read) -----------
    // A single continuous bar of cells, each worth a known number of pooled
    // transactions, so "how full is the pool right now" is legible without
    // reading the trace.
    let cells = 64usize;
    let per_cell = (MEMPOOL_CAP_HINT / cells as u64).max(1);
    let bar_top = rect.bottom() - 40.0;
    let gap = 2.0;
    let cell_w = ((plot.width() - gap * (cells as f32 - 1.0)) / cells as f32).max(1.0);
    let pressure = depth.map(|d| Pressure::of(d, MEMPOOL_CAP_HINT));
    let filled = depth.map(|d| {
        // Ceil, so a single pooled transaction lights exactly one cell.
        let f = d.min(MEMPOOL_CAP_HINT).div_ceil(per_cell);
        f.min(cells as u64) as usize
    });
    for i in 0..cells {
        let x = plot.left() + i as f32 * (cell_w + gap);
        let cell = Rect::from_min_size(Pos2::new(x, bar_top), Vec2::new(cell_w, 14.0));
        let on = filled.is_some_and(|f| i < f);
        let color = match (on, pressure) {
            (true, Some(Pressure::Saturated)) => palette::RED,
            (true, Some(Pressure::Heavy)) => palette::AMBER,
            (true, _) => palette::CYAN,
            // Unknown depth is drawn as an empty, hatched-looking track — it is
            // visibly NOT "zero pooled transactions".
            (false, None) => palette::LINE.gamma_multiply(0.6),
            (false, _) => palette::SURFACE_HI,
        };
        p.rect_filled(cell, egui::Rounding::same(1.0), color);
    }

    let caption = match (depth, pressure) {
        (Some(d), Some(pr)) => format!(
            "{} {}  ·  {} pooled  ·  {} of {} cap  ·  1 cell = {} tx",
            pr.glyph(),
            pr.label(),
            fmt_count(d),
            fmt_pct(d, MEMPOOL_CAP_HINT),
            fmt_count(MEMPOOL_CAP_HINT),
            per_cell
        ),
        _ => "— depth unavailable (the node did not answer sov_getMempoolSize)".to_string(),
    };
    p.text(
        Pos2::new(plot.left(), rect.bottom() - 10.0),
        egui::Align2::LEFT_BOTTOM,
        caption,
        egui::FontId::monospace(10.5),
        if depth.is_some() {
            palette::DIM
        } else {
            palette::FAINT
        },
    );
}

/// One row of the outcome breakdown: a labelled proportional bar.
#[allow(clippy::too_many_arguments)]
fn outcome_row(
    ui: &mut Ui,
    glyph: &str,
    label: &str,
    note: &str,
    per_sec: f64,
    total: u64,
    frac: f32,
    color: Color32,
) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(glyph).monospace().color(color));
        ui.allocate_ui(Vec2::new(112.0, 0.0), |ui| {
            ui.label(RichText::new(label).small().color(palette::TEXT));
        });
        let bar_w = (ui.available_width() - 160.0).clamp(40.0, 300.0);
        let (rect, _) = ui.allocate_exact_size(Vec2::new(bar_w, 10.0), Sense::hover());
        let p = ui.painter_at(rect);
        p.rect_filled(rect, egui::Rounding::same(2.0), palette::SURFACE_HI);
        if frac > 0.0 {
            let filled =
                Rect::from_min_size(rect.min, Vec2::new(rect.width() * frac, rect.height()));
            p.rect_filled(filled, egui::Rounding::same(2.0), color);
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                RichText::new(fmt_count(total))
                    .monospace()
                    .small()
                    .color(palette::DIM),
            );
            ui.label(RichText::new(fmt_rate(per_sec)).monospace().color(color));
        });
    });
    if !note.is_empty() {
        ui.label(
            RichText::new(format!("      {note}"))
                .small()
                .color(palette::FAINT),
        );
    }
}

/// The operator-facing state of the whole app — the one thing the status strip
/// answers before anything else.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OpState {
    /// Something still has to be configured before firing is possible.
    Setup,
    /// Configured and able to fire.
    Ready,
    /// Workers are firing.
    Firing,
    /// Stop pressed; workers are finishing their in-flight submits.
    Draining,
    /// A run finished and its results are on screen.
    Stopped,
}

impl OpState {
    fn glyph(self) -> &'static str {
        match self {
            OpState::Setup => "◇",
            OpState::Ready => "◆",
            OpState::Firing => "▶",
            OpState::Draining => "◐",
            OpState::Stopped => "■",
        }
    }
    fn word(self) -> &'static str {
        match self {
            OpState::Setup => "SETUP",
            OpState::Ready => "READY",
            OpState::Firing => "FIRING",
            OpState::Draining => "STOPPING",
            OpState::Stopped => "STOPPED",
        }
    }
    fn color(self) -> Color32 {
        match self {
            OpState::Setup => palette::DIM,
            OpState::Ready => palette::CYAN,
            OpState::Firing => palette::GREEN,
            OpState::Draining => palette::AMBER,
            OpState::Stopped => palette::DIM,
        }
    }
}

/// A frame-local copy of the node monitor's state, so no lock is held while
/// drawing.
#[derive(Clone)]
struct ConnView {
    probed: bool,
    ok: bool,
    fresh: bool,
    tip: u64,
    mempool: Option<u64>,
    latency_ms: u64,
    beat_age: Option<u64>,
    error: String,
}

impl ConnView {
    /// (glyph, word, color) — the word carries the state without the color.
    fn badge(&self) -> (&'static str, &'static str, Color32) {
        if !self.probed {
            ("○", "PROBING", palette::FAINT)
        } else if self.ok && self.fresh {
            ("●", "LIVE", palette::GREEN)
        } else if self.ok {
            ("◐", "STALLED", palette::AMBER)
        } else {
            ("✖", "OFFLINE", palette::RED)
        }
    }
}

impl eframe::App for CannonApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Spawn the always-on node monitor once (it needs the egui Context).
        if !self.conn_started {
            self.conn_started = true;
            let (conn, hist, addr, stop, ctx2) = (
                self.conn.clone(),
                self.history.clone(),
                self.conn_addr.clone(),
                self.conn_stop.clone(),
                ctx.clone(),
            );
            thread::spawn(move || run_conn_monitor(conn, hist, addr, stop, ctx2));
        }
        // Propagate the current RPC address to the monitor (so edits take effect).
        if let Ok(mut a) = self.conn_addr.lock() {
            if *a != self.rpc_addr {
                *a = self.rpc_addr.clone();
            }
        }
        // Reap finished background stop-join threads.
        self.draining.retain(|h| !h.is_finished());

        // --- frame-local snapshots (locks released before any drawing) -----
        let conn = match self.conn.lock() {
            Ok(c) => ConnView {
                probed: c.ever,
                ok: c.ok,
                fresh: c.beat_at.is_some_and(|t| t.elapsed() < HEARTBEAT_FRESH),
                tip: c.tip,
                mempool: c.mempool,
                latency_ms: c.latency_ms,
                beat_age: c.beat_at.map(|t| t.elapsed().as_secs()),
                error: c.error.clone(),
            },
            Err(_) => ConnView {
                probed: true,
                ok: false,
                fresh: false,
                tip: 0,
                mempool: None,
                latency_ms: 0,
                beat_age: None,
                error: "connection state unavailable".into(),
            },
        };

        let running = self.is_running();
        let draining = !self.draining.is_empty();
        let blocker = if running {
            None
        } else {
            first_blocker(
                self.wallets.len(),
                self.selected_count(),
                self.destination_count(),
            )
        };
        let state = if running {
            OpState::Firing
        } else if draining {
            OpState::Draining
        } else if self.last_run.is_some() {
            OpState::Stopped
        } else if blocker.is_some() {
            OpState::Setup
        } else {
            OpState::Ready
        };

        // Keep the beat age and the scope's "now" edge ticking even when idle;
        // a live run repaints fast enough for the meters to feel continuous.
        ctx.request_repaint_after(if running {
            Duration::from_millis(200)
        } else {
            Duration::from_millis(500)
        });

        self.top_bar(ctx, &conn, state, running);
        self.control_bar(ctx, &conn, running, draining, blocker);

        let wide = ctx.screen_rect().width() >= WIDE_LAYOUT_MIN;
        if wide {
            egui::SidePanel::left("setup")
                .resizable(true)
                .default_width(348.0)
                .width_range(300.0..=460.0)
                .frame(
                    egui::Frame::none()
                        .fill(palette::BG)
                        .inner_margin(egui::Margin::symmetric(12.0, 10.0)),
                )
                .show_animated(ctx, self.setup_open, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("setup-scroll")
                        .auto_shrink([false, false])
                        .show(ui, |ui| self.setup_column(ui, running));
                });
        }

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(palette::BG)
                    .inner_margin(egui::Margin::symmetric(12.0, 10.0)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("main-scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        // Folded layout: the setup column becomes the first block
                        // of the single scrolling column instead of disappearing.
                        if !wide {
                            egui::CollapsingHeader::new(
                                RichText::new("SETUP — node, keys, traffic")
                                    .small()
                                    .strong(),
                            )
                            .default_open(self.wallets.is_empty())
                            .show(ui, |ui| self.setup_column(ui, running));
                            ui.add_space(8.0);
                        }
                        self.telemetry(ui, &conn, state);
                    });
            });
    }
}

impl CannonApp {
    // ---- top: identity, node health, and the one-line state strip --------
    fn top_bar(&mut self, ctx: &egui::Context, conn: &ConnView, state: OpState, running: bool) {
        egui::TopBottomPanel::top("topbar")
            .frame(
                egui::Frame::none()
                    .fill(palette::SURFACE)
                    .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                    .stroke(Stroke::new(1.0, palette::LINE)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("SOV TX CANNON")
                            .monospace()
                            .strong()
                            .color(palette::TEXT),
                    );
                    ui.label(
                        RichText::new("traffic generator")
                            .small()
                            .color(palette::FAINT),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (glyph, word, color) = conn.badge();
                        // Node identity + health: glyph AND word AND color.
                        let detail = if conn.ok && conn.fresh {
                            format!(
                                "tip {}  ·  {} ms",
                                fmt_count(conn.tip),
                                fmt_count(conn.latency_ms)
                            )
                        } else if conn.ok {
                            format!(
                                "last beat {} ago  ·  tip {}",
                                fmt_elapsed(conn.beat_age.unwrap_or(0)),
                                fmt_count(conn.tip)
                            )
                        } else if conn.probed {
                            conn.error.clone()
                        } else {
                            self.rpc_addr.clone()
                        };
                        ui.label(
                            RichText::new(detail)
                                .monospace()
                                .small()
                                .color(palette::DIM),
                        );
                        ui.label(
                            RichText::new(format!("{glyph} {word}"))
                                .monospace()
                                .strong()
                                .color(color),
                        );
                        ui.label(
                            RichText::new(&self.rpc_addr)
                                .monospace()
                                .small()
                                .color(palette::FAINT),
                        );
                        if !running {
                            let arrow = if self.setup_open { "◀" } else { "▶" };
                            if ui
                                .selectable_label(false, RichText::new(arrow).small())
                                .on_hover_text("show / hide the setup column")
                                .clicked()
                            {
                                self.setup_open = !self.setup_open;
                            }
                        }
                    });
                });

                ui.add_space(6.0);
                // --- the state strip: what is happening, in words -----------
                let detail = self.state_detail(state);
                egui::Frame::none()
                    .fill(state.color().gamma_multiply(0.14))
                    .rounding(egui::Rounding::same(6.0))
                    .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("{} {}", state.glyph(), state.word()))
                                    .monospace()
                                    .strong()
                                    .color(state.color()),
                            );
                            if !self.dry_run && matches!(state, OpState::Firing | OpState::Ready) {
                                ui.label(
                                    RichText::new("⚠ LIVE FIRE")
                                        .monospace()
                                        .small()
                                        .strong()
                                        .color(palette::RED),
                                );
                            }
                            ui.label(RichText::new(detail).color(palette::TEXT));
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if let Ok(st) = self.status.lock() {
                                        if st.running {
                                            ui.label(
                                                RichText::new(fmt_elapsed(
                                                    st.t0.elapsed().as_secs(),
                                                ))
                                                .monospace()
                                                .color(palette::DIM),
                                            );
                                        }
                                    }
                                    // A node problem is a warning here, never a
                                    // lockout: the workers retry and recover.
                                    if conn.probed && !(conn.ok && conn.fresh) {
                                        ui.label(
                                            RichText::new("node unreachable — workers will retry")
                                                .small()
                                                .color(palette::AMBER),
                                        );
                                    }
                                },
                            );
                        });
                    });
            });
    }

    /// The human sentence that follows the state word.
    fn state_detail(&self, state: OpState) -> String {
        match state {
            OpState::Setup => first_blocker(
                self.wallets.len(),
                self.selected_count(),
                self.destination_count(),
            )
            .map(|b| b.message().to_string())
            .unwrap_or_else(|| "finish configuring the run".into()),
            OpState::Ready => format!(
                "{} — {} wallet(s) armed{}",
                self.mode_summary(),
                self.selected_count(),
                if self.dry_run {
                    ", dry-run (nothing is submitted)"
                } else {
                    ""
                }
            ),
            OpState::Firing => {
                let (accepted, wallets) = self
                    .status
                    .lock()
                    .map(|st| {
                        let now = st.now_ms();
                        (st.meter.rate(now, MeterKind::Accepted), st.live_workers)
                    })
                    .unwrap_or((f64::NAN, 0));
                format!(
                    "{} · {} wallet(s) · {} accepted/s{}",
                    self.mode_summary(),
                    wallets,
                    fmt_rate(accepted),
                    if self.dry_run { " (dry-run)" } else { "" }
                )
            }
            OpState::Draining => "workers are finishing their in-flight submits".into(),
            OpState::Stopped => match &self.last_run {
                Some(r) => format!(
                    "{}{} · {} · {} accepted, {} rejected in {}",
                    r.mode,
                    if r.dry_run { " (dry-run)" } else { "" },
                    format_args!("{} wallet(s)", r.wallets),
                    fmt_count(r.accepted),
                    fmt_count(r.rejected),
                    fmt_elapsed(r.duration_secs)
                ),
                None => "run finished".into(),
            },
        }
    }

    // ---- bottom: the firing controls, always on screen -------------------
    fn control_bar(
        &mut self,
        ctx: &egui::Context,
        conn: &ConnView,
        running: bool,
        draining: bool,
        blocker: Option<logic::Blocker>,
    ) {
        egui::TopBottomPanel::bottom("controls")
            .frame(
                egui::Frame::none()
                    .fill(palette::SURFACE)
                    .inner_margin(egui::Margin::symmetric(12.0, 10.0))
                    .stroke(Stroke::new(1.0, palette::LINE)),
            )
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    // --- start / stop ---------------------------------------
                    if running {
                        let btn = egui::Button::new(
                            RichText::new("■  STOP")
                                .monospace()
                                .strong()
                                .color(Color32::WHITE),
                        )
                        .fill(palette::RED.gamma_multiply(0.85))
                        .min_size(Vec2::new(132.0, 34.0));
                        if ui.add(btn).clicked() {
                            self.stop();
                        }
                    } else {
                        let armed = blocker.is_none();
                        let (label, fill) = if self.dry_run {
                            ("▶  START DRY-RUN", palette::CYAN)
                        } else {
                            ("▶  START LIVE FIRE", palette::RED)
                        };
                        let btn = egui::Button::new(
                            RichText::new(label)
                                .monospace()
                                .strong()
                                .color(if armed { Color32::BLACK } else { palette::FAINT }),
                        )
                        .fill(if armed {
                            fill
                        } else {
                            palette::SURFACE_HI
                        })
                        .min_size(Vec2::new(172.0, 34.0));
                        let resp = ui.add_enabled(armed && !draining, btn);
                        if resp.clicked() {
                            self.start(ctx);
                        }
                        if let Some(b) = blocker {
                            resp.on_hover_text(b.message());
                        }
                    }

                    ui.add_space(6.0);
                    ui.separator();

                    // --- rate mode: a segmented control ----------------------
                    ui.add_enabled_ui(!running, |ui| {
                        ui.horizontal(|ui| {
                            for (choice, label) in [
                                (ModeChoice::PerBlock, "Per block"),
                                (ModeChoice::TargetTps, "Target TX/s"),
                                (ModeChoice::Firehose, "Firehose"),
                            ] {
                                let on = self.mode == choice;
                                let text = RichText::new(label)
                                    .monospace()
                                    .small()
                                    .color(if on { Color32::BLACK } else { palette::DIM });
                                let btn = egui::Button::new(text)
                                    .fill(if on { palette::CYAN } else { palette::SURFACE_HI })
                                    .min_size(Vec2::new(0.0, 28.0));
                                if ui.add(btn).clicked() {
                                    self.mode = choice;
                                }
                            }
                        });

                        // The active mode's ONE parameter, inline.
                        match self.mode {
                            ModeChoice::PerBlock => {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.rate)
                                        .desired_width(52.0)
                                        .font(egui::TextStyle::Monospace),
                                );
                                ui.label(
                                    RichText::new(format!("tx / block (1–{MAX_RATE})"))
                                        .small()
                                        .color(palette::DIM),
                                );
                            }
                            ModeChoice::TargetTps => {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.tps)
                                        .desired_width(60.0)
                                        .font(egui::TextStyle::Monospace),
                                );
                                ui.label(
                                    RichText::new(format!("TX/s total (0.1–{MAX_TPS:.0})"))
                                        .small()
                                        .color(palette::DIM),
                                );
                            }
                            ModeChoice::Firehose => {
                                ui.label(
                                    RichText::new("no parameter — the mempool sets the rate")
                                        .small()
                                        .color(palette::DIM),
                                );
                            }
                        }
                    });

                    ui.add_space(6.0);
                    ui.separator();

                    // --- arming: dry-run vs live ----------------------------
                    // Kept INLINE in the wrapping flow (not right-aligned): a
                    // right-to-left sub-layout eats the whole remaining row and
                    // overlaps the mode controls once the window is narrow.
                    ui.add_enabled_ui(!running, |ui| {
                        for (dry, label, color) in [
                            (true, "DRY RUN", palette::CYAN),
                            (false, "LIVE FIRE", palette::RED),
                        ] {
                            let on = self.dry_run == dry;
                            let btn = egui::Button::new(
                                RichText::new(label)
                                    .monospace()
                                    .small()
                                    .strong()
                                    .color(if on { Color32::BLACK } else { palette::DIM }),
                            )
                            .fill(if on { color } else { palette::SURFACE_HI })
                            .min_size(Vec2::new(0.0, 28.0));
                            if ui.add(btn).clicked() {
                                self.dry_run = dry;
                            }
                        }
                    });
                });

                // --- what the selected mode will actually do ----------------
                ui.add_space(2.0);
                let consequence = match self.mode {
                    ModeChoice::PerBlock =>
                        "Waits for each new tip, fires that many transactions, then idles until the next block. \
                         Bursty by design; the pool drains between blocks.",
                    ModeChoice::TargetTps =>
                        "Holds a steady aggregate rate regardless of blocks, split evenly across the selected wallets. \
                         Above the chain's ~1–5 TPS inclusion ceiling the surplus accumulates in the mempool.",
                    ModeChoice::Firehose =>
                        "No pacing: signs and submits flat-out until the mempool refuses, then holds the same nonce, \
                         backs off and retries. Mempool-full rejections ARE the throttle — expect them.",
                };
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(consequence).small().color(palette::FAINT));
                });
                if !self.dry_run && !running {
                    ui.label(
                        RichText::new(
                            "⚠ LIVE FIRE submits real signed transactions and spends real fees on whatever node you are pointed at.",
                        )
                        .small()
                        .color(palette::RED),
                    );
                }
                if !self.config_msg.is_empty() {
                    ui.label(
                        RichText::new(format!("✖ {}", self.config_msg))
                            .small()
                            .color(palette::RED),
                    );
                }
                if !conn.probed {
                    ui.label(
                        RichText::new("○ probing the node…")
                            .small()
                            .color(palette::FAINT),
                    );
                }
            });
    }

    // ---- left: setup ----------------------------------------------------
    fn setup_column(&mut self, ui: &mut Ui, running: bool) {
        // 1. Node + keys
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width() - 4.0);
            eyebrow(ui, "1 · node & keys");
            ui.add_space(4.0);
            ui.label(RichText::new("Node RPC").small().color(palette::DIM));
            ui.add_enabled(
                !running,
                egui::TextEdit::singleline(&mut self.rpc_addr)
                    .hint_text(DEFAULT_RPC)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY),
            );
            ui.label(RichText::new("Keystore").small().color(palette::DIM));
            ui.add_enabled(
                !running,
                egui::TextEdit::singleline(&mut self.keystore_path)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY),
            );
            ui.label(
                RichText::new("Master passphrase")
                    .small()
                    .color(palette::DIM),
            );
            ui.add_enabled(
                !running && self.wallets.is_empty(),
                egui::TextEdit::singleline(&mut *self.passphrase)
                    .password(true)
                    .hint_text("never stored, wiped after unlock")
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                if self.wallets.is_empty() {
                    if ui
                        .add_enabled(!running, egui::Button::new("🔓  Unlock wallets"))
                        .clicked()
                    {
                        self.unlock();
                    }
                } else {
                    if ui
                        .add_enabled(!running, egui::Button::new("🔒  Lock / wipe keys"))
                        .clicked()
                    {
                        self.wipe_wallets();
                        self.unlock_msg = "keys wiped from memory".into();
                    }
                    if ui
                        .add_enabled(!running, egui::Button::new("↻  Refresh balances"))
                        .clicked()
                    {
                        self.refresh_balances();
                    }
                }
            });
            if !self.unlock_msg.is_empty() {
                let bad = self.unlock_msg.contains("failed") || self.unlock_msg.contains("no ");
                ui.label(RichText::new(&self.unlock_msg).small().color(if bad {
                    palette::RED
                } else {
                    palette::DIM
                }));
            }
        });
        ui.add_space(8.0);

        // 2. Wallets
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width() - 4.0);
            ui.horizontal(|ui| {
                eyebrow(ui, "2 · fire from");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if !self.wallets.is_empty() {
                        ui.label(
                            RichText::new(format!(
                                "{} / {} selected",
                                self.selected_count(),
                                self.wallets.len()
                            ))
                            .small()
                            .monospace()
                            .color(palette::DIM),
                        );
                    }
                });
            });
            ui.add_space(4.0);
            if self.wallets.is_empty() {
                // Locked state — say what to do, not just what is missing.
                ui.label(
                    RichText::new("🔒  No wallets unlocked.")
                        .small()
                        .color(palette::AMBER),
                );
                ui.label(
                    RichText::new(
                        "Enter the SOV-Station master passphrase above and unlock. \
                         Seeds are held in wiped-on-drop memory for this session only.",
                    )
                    .small()
                    .color(palette::FAINT),
                );
            } else {
                ui.add_enabled_ui(!running, |ui| {
                    ui.horizontal(|ui| {
                        if ui.small_button("all").clicked() {
                            for w in &mut self.wallets {
                                w.fire = true;
                            }
                        }
                        if ui.small_button("none").clicked() {
                            for w in &mut self.wallets {
                                w.fire = false;
                            }
                        }
                    });
                    for w in &mut self.wallets {
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut w.fire, RichText::new(&w.label).small());
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    // A balance we could not read is a dash, never 0.
                                    let (text, color) = match w.balance_grains {
                                        Some(g) => {
                                            (format!("{} XUS", grains_to_xus(g)), palette::TEXT)
                                        }
                                        None => ("— XUS".to_string(), palette::FAINT),
                                    };
                                    ui.label(RichText::new(text).monospace().small().color(color));
                                },
                            );
                        });
                        ui.label(
                            RichText::new(format!("    {}", short_hash(w.account.as_str())))
                                .monospace()
                                .small()
                                .color(palette::FAINT),
                        )
                        .on_hover_text(w.account.as_str());
                    }
                });
                ui.add_space(2.0);
                ui.label(
                    RichText::new(
                        "Each checked wallet fires in parallel on its own nonce stream. \
                         One wallet is capped by the node's per-sender share (~256 pending); \
                         check several to push the whole pool.",
                    )
                    .small()
                    .color(palette::FAINT),
                );
            }
        });
        ui.add_space(8.0);

        // 3. Traffic shape
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width() - 4.0);
            eyebrow(ui, "3 · traffic");
            ui.add_space(4.0);
            ui.add_enabled_ui(!running, |ui| {
                ui.checkbox(
                    &mut self.recycle,
                    RichText::new("♻ Recycle to my own wallets").small(),
                )
                .on_hover_text(
                    "Destinations become your unlocked wallets' own addresses, so the \
                     principal circulates among YOUR accounts. Each tx still pays its \
                     miner fee (~0.00021 XUS) to whoever mines the block.",
                );
            });
            if self.recycle {
                ui.label(
                    RichText::new(
                        "Closed loop — principal stays with you; each tx still pays its miner fee.",
                    )
                    .small()
                    .color(palette::FAINT),
                );
            } else {
                ui.label(
                    RichText::new("Destinations (one account id per line)")
                        .small()
                        .color(palette::DIM),
                );
                ui.add_enabled(
                    !running,
                    egui::TextEdit::multiline(&mut self.dests_text)
                        .hint_text("alice.sov\nbob.sov")
                        .font(egui::TextStyle::Monospace)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY),
                );
                if let Err(e) = self.parse_dests() {
                    ui.label(RichText::new(format!("✖ {e}")).small().color(palette::RED));
                }
            }
            ui.add_enabled_ui(!running, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("pick").small().color(palette::DIM));
                    ui.radio_value(
                        &mut self.dest_random,
                        false,
                        RichText::new("round-robin").small(),
                    );
                    ui.radio_value(&mut self.dest_random, true, RichText::new("random").small());
                });
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label(RichText::new("amount").small().color(palette::DIM));
                    ui.radio_value(
                        &mut self.amount_random,
                        false,
                        RichText::new("fixed").small(),
                    );
                    ui.radio_value(
                        &mut self.amount_random,
                        true,
                        RichText::new("range").small(),
                    );
                });
                ui.horizontal(|ui| {
                    if self.amount_random {
                        ui.label(RichText::new("min").small().color(palette::DIM));
                        ui.add(
                            egui::TextEdit::singleline(&mut self.amount_min)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(74.0),
                        );
                        ui.label(RichText::new("max").small().color(palette::DIM));
                        ui.add(
                            egui::TextEdit::singleline(&mut self.amount_max)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(74.0),
                        );
                    } else {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.amount_fixed)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(90.0),
                        );
                    }
                    ui.label(RichText::new("XUS").small().color(palette::FAINT));
                });
                if let Err(e) = self.parse_amount_mode() {
                    ui.label(RichText::new(format!("✖ {e}")).small().color(palette::RED));
                }
            });
        });
        ui.add_space(8.0);
    }

    // ---- centre: telemetry ----------------------------------------------
    fn telemetry(&mut self, ui: &mut Ui, conn: &ConnView, state: OpState) {
        let status = Arc::clone(&self.status);
        let st = match status.lock() {
            Ok(st) => st,
            Err(_) => {
                ui.label(
                    RichText::new("live status unavailable (worker state is poisoned)")
                        .color(palette::RED),
                );
                return;
            }
        };
        let now = st.now_ms();
        let ever_ran = self.last_run.is_some() || st.running;
        let r = |k: MeterKind| {
            if ever_ran {
                st.meter.rate(now, k)
            } else {
                f64::NAN // no run yet: unavailable, NOT zero
            }
        };
        let attempted = r(MeterKind::Attempted);
        let accepted = r(MeterKind::Accepted);
        let cap = r(MeterKind::RejCapacity);
        let nonce = r(MeterKind::RejNonce);
        let afford = r(MeterKind::RejAfford);
        let other = r(MeterKind::RejOther);
        let rejected = if ever_ran {
            cap + nonce + afford + other
        } else {
            f64::NAN
        };
        let (t_accepted, t_rejected) = st.totals();
        let t_cap = st.meter.total(MeterKind::RejCapacity);
        let t_nonce = st.meter.total(MeterKind::RejNonce);
        let t_afford = st.meter.total(MeterKind::RejAfford);
        let t_other = st.meter.total(MeterKind::RejOther);

        // --- 1. headline tiles ------------------------------------------
        let pressure = conn.mempool.map(|d| Pressure::of(d, MEMPOOL_CAP_HINT));
        let tiles = [
            Tile {
                label: "attempted",
                glyph: "↗",
                value: fmt_rate(attempted),
                unit: "/s",
                sub: format!(
                    "{} built this run",
                    fmt_count(st.meter.total(MeterKind::Attempted))
                ),
                accent: palette::VIOLET,
            },
            Tile {
                label: "accepted",
                glyph: "✔",
                value: fmt_rate(accepted),
                unit: "/s",
                sub: format!("{} pooled this run", fmt_count(t_accepted)),
                accent: palette::GREEN,
            },
            Tile {
                label: "rejected",
                glyph: "✖",
                value: fmt_rate(rejected),
                unit: "/s",
                sub: format!("{} refused this run", fmt_count(t_rejected)),
                accent: if t_other > 0 {
                    palette::RED
                } else {
                    palette::AMBER
                },
            },
            Tile {
                label: "mempool",
                glyph: pressure.map(|p| p.glyph()).unwrap_or("—"),
                value: conn
                    .mempool
                    .map(fmt_count)
                    .unwrap_or_else(|| "—".to_string()),
                unit: "tx",
                sub: match pressure {
                    Some(p) => format!(
                        "{} · {}",
                        p.label(),
                        fmt_pct(conn.mempool.unwrap_or(0), MEMPOOL_CAP_HINT)
                    ),
                    None => "depth unavailable".into(),
                },
                accent: match pressure {
                    Some(Pressure::Saturated) => palette::RED,
                    Some(Pressure::Heavy) => palette::AMBER,
                    Some(_) => palette::CYAN,
                    None => palette::FAINT,
                },
            },
        ];
        // One band of four when there is room; two rows of two when folded.
        if ui.available_width() >= 760.0 {
            ui.columns(4, |c| {
                for (i, t) in tiles.iter().enumerate() {
                    stat_tile(&mut c[i], t);
                }
            });
        } else {
            for pair in tiles.chunks(2) {
                ui.columns(2, |c| {
                    for (i, t) in pair.iter().enumerate() {
                        stat_tile(&mut c[i], t);
                    }
                });
            }
        }
        ui.add_space(8.0);

        // --- 2. the scope -----------------------------------------------
        {
            let hist = self.history.lock();
            match hist {
                Ok(h) => {
                    let now_ms = h.now_ms();
                    draw_scope(ui, &h.samples, now_ms, conn.mempool, conn.ok);
                }
                Err(_) => {
                    ui.label(
                        RichText::new("mempool history unavailable")
                            .small()
                            .color(palette::RED),
                    );
                }
            }
        }
        ui.add_space(8.0);

        // --- 3. outcome breakdown ---------------------------------------
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width() - 4.0);
            ui.horizontal(|ui| {
                eyebrow(ui, "outcomes");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new("per second   ·   run total")
                            .small()
                            .color(palette::FAINT),
                    );
                });
            });
            ui.add_space(4.0);
            let scale = [attempted, accepted, cap, nonce, afford, other]
                .into_iter()
                .filter(|v| v.is_finite())
                .fold(0.0f64, f64::max)
                .max(1.0);
            outcome_row(
                ui,
                "✔",
                "accepted",
                "the node took it into the mempool",
                accepted,
                t_accepted,
                share(accepted, scale),
                palette::GREEN,
            );
            let cap_note = if self.mode == ModeChoice::Firehose {
                "EXPECTED — this is the firehose pacing itself; the nonce is held and retried"
            } else {
                "back-pressure: the pool is full, the nonce is held and retried (no tx is lost)"
            };
            outcome_row(
                ui,
                "≈",
                if self.mode == ModeChoice::Firehose {
                    "pool full (pacing)"
                } else {
                    "pool full"
                },
                cap_note,
                cap,
                t_cap,
                share(cap, scale),
                palette::AMBER,
            );
            outcome_row(
                ui,
                "↻",
                "nonce resync",
                "our txs mined or the slot was already pooled — the sequencer self-corrects",
                nonce,
                t_nonce,
                share(nonce, scale),
                palette::CYAN,
            );
            outcome_row(
                ui,
                "⏳",
                "awaiting funds",
                "balance is committed by still-pending txs; firing resumes as they mine",
                afford,
                t_afford,
                share(afford, scale),
                palette::VIOLET,
            );
            outcome_row(
                ui,
                "✖",
                "other / fault",
                "unclassified rejections and transport errors — the only bucket that means something is wrong",
                other,
                t_other,
                share(other, scale),
                palette::RED,
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "Only the ✖ row indicates a fault. The three above it are the cannon steering \
                     itself — holding nonces, resyncing and waiting — and are how it stays gap-free.",
                )
                .small()
                .color(palette::FAINT),
            );
        });
        ui.add_space(8.0);

        // --- 4. per-wallet ------------------------------------------------
        if !st.wallets.is_empty() {
            card_frame().show(ui, |ui| {
                ui.set_width(ui.available_width() - 4.0);
                eyebrow(ui, "wallets in this run");
                ui.add_space(4.0);
                egui::Grid::new("wallet-stats")
                    .num_columns(5)
                    .striped(true)
                    .spacing(Vec2::new(14.0, 4.0))
                    .show(ui, |ui| {
                        for h in ["wallet", "next nonce", "committed", "balance", "state"] {
                            ui.label(RichText::new(h).small().color(palette::FAINT));
                        }
                        ui.end_row();
                        for w in &st.wallets {
                            ui.label(RichText::new(&w.label).monospace().small());
                            ui.label(
                                RichText::new(fmt_count(w.next_nonce))
                                    .monospace()
                                    .small()
                                    .color(palette::DIM),
                            );
                            ui.label(
                                RichText::new(
                                    w.committed()
                                        .map(fmt_count)
                                        .unwrap_or_else(|| "—".to_string()),
                                )
                                .monospace()
                                .small()
                                .color(palette::GREEN),
                            );
                            ui.label(
                                RichText::new(
                                    w.balance_grains
                                        .map(|g| format!("{} XUS", grains_to_xus(g)))
                                        .unwrap_or_else(|| "—".into()),
                                )
                                .monospace()
                                .small(),
                            );
                            let (glyph, text, color) = match (&w.fault, w.ended, &w.waiting) {
                                (Some(why), _, _) => ("✖", format!("failed — {why}"), palette::RED),
                                (None, true, _) => ("■", "finished".to_string(), palette::DIM),
                                (None, false, Some(why)) => {
                                    ("⏳", format!("waiting — {why}"), palette::AMBER)
                                }
                                (None, false, None) if st.running => {
                                    ("▶", "firing".to_string(), palette::GREEN)
                                }
                                _ => ("·", "idle".to_string(), palette::FAINT),
                            };
                            ui.label(
                                RichText::new(format!("{glyph} {text}"))
                                    .small()
                                    .color(color),
                            );
                            ui.end_row();
                        }
                    });
            });
            ui.add_space(8.0);
        } else if state == OpState::Setup {
            // Nothing configured yet: an explicit three-step orientation rather
            // than a screen of zeroed meters.
            card_frame().show(ui, |ui| {
                ui.set_width(ui.available_width() - 4.0);
                eyebrow(ui, "getting started");
                ui.add_space(4.0);
                for (n, step) in [
                    "Point at a node and unlock SOV-Station's keystore with your master passphrase.",
                    "Check the wallets to fire from and choose where the XUS goes (recycle keeps it yours).",
                    "Pick a rate mode, leave DRY RUN armed for a rehearsal, then start.",
                ]
                .iter()
                .enumerate()
                {
                    ui.label(
                        RichText::new(format!("{}.  {step}", n + 1))
                            .small()
                            .color(palette::DIM),
                    );
                }
            });
            ui.add_space(8.0);
        }

        // --- 5. faults + event log ---------------------------------------
        if !st.last_error.is_empty() {
            card_frame()
                .stroke(Stroke::new(1.0, palette::RED.gamma_multiply(0.6)))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width() - 4.0);
                    ui.label(
                        RichText::new(format!("✖  {}", st.last_error))
                            .small()
                            .color(palette::RED),
                    );
                });
            ui.add_space(8.0);
        }

        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width() - 4.0);
            ui.horizontal(|ui| {
                eyebrow(ui, "event log");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.checkbox(
                        &mut self.log_errors_only,
                        RichText::new("failures only").small(),
                    );
                    ui.label(
                        RichText::new(format!("{} lines", fmt_count(st.log.len() as u64)))
                            .small()
                            .monospace()
                            .color(palette::FAINT),
                    );
                });
            });
            ui.add_space(4.0);
            if st.log.is_empty() {
                ui.label(
                    RichText::new("no transactions built yet")
                        .small()
                        .color(palette::FAINT),
                );
            }
            egui::ScrollArea::vertical()
                .id_salt("tx-log")
                .max_height(200.0)
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for line in st.log.iter().filter(|l| !self.log_errors_only || !l.ok) {
                        let (glyph, color) = if line.ok {
                            ("✔", palette::GREEN)
                        } else {
                            ("✖", palette::RED)
                        };
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(glyph).monospace().small().color(color));
                            ui.label(
                                RichText::new(format!(
                                    "#{:<8} n{:<7} {:<10} → {:<10} {:>12} XUS  {}",
                                    line.height,
                                    line.nonce,
                                    truncate(&line.wallet, 10),
                                    truncate(&line.to, 10),
                                    grains_to_xus(line.amount_grains),
                                    line.detail
                                ))
                                .monospace()
                                .small()
                                .color(if line.ok {
                                    palette::DIM
                                } else {
                                    palette::TEXT
                                }),
                            );
                        });
                    }
                });
        });
    }
}

/// Clip a label to `n` characters with an ellipsis, so table columns keep their
/// width regardless of what the keystore called a wallet.
fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let head: String = s.chars().take(n.saturating_sub(1)).collect();
        format!("{head}…")
    }
}
