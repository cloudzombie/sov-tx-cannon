//! Pure, deterministic traffic-generation logic — no GUI, no network.
//!
//! Everything the "TX cannon" decides before it touches the wire lives here so it
//! can be unit-tested in isolation:
//!   * [`NonceSequencer`] — strictly monotonic, gap-free, never-reused nonces,
//!     reconciled against the node and committed only when a nonce is consumed.
//!   * [`Pacer`] — the Target-TX/s scheduler (cumulative-due, bounded catch-up).
//!   * [`classify_reject`] + [`disposition`] — map the node's real rejection
//!     strings to what the worker must do with the in-flight nonce.
//!   * [`RateMeter`] — rolling per-second throughput window for the live meters.
//!   * [`DestSelector`] — round-robin or random choice over the destination list.
//!   * [`AmountMode`] — a fixed value or a uniform draw in `[min, max]` inclusive.
//!   * [`build_signed_transfer`] — reuses the chain's real `SignedTransaction::sign`
//!     (no reimplemented crypto) to produce a verifiable transfer.
//!
//!   * [`DuelLedger`] + [`block_outcomes`] + [`duel_verdict`] — the auction
//!     duel's measurement and its honest verdict (including "inconclusive").
//!
//! It also owns every piece of *presentation* arithmetic the GUI needs — axis
//! scaling ([`nice_ceiling`], [`scope_x`], [`scope_y`]), pressure bucketing
//! ([`Pressure`]), readiness ([`first_blocker`]) and number formatting
//! ([`fmt_rate`], [`fmt_count`], …) — so the drawing code contains no arithmetic
//! that could divide by zero, produce NaN, or reach egui's geometry unbounded.
//! All of it is unit-tested below.
//!
//! None of this holds or logs secret material: the signing seed is passed in by
//! the caller only for the duration of a single [`build_signed_transfer`] call.

use std::collections::VecDeque;
use std::time::Duration;

use sov_crypto::Keypair;
use sov_primitives::{AccountId, Balance, SigningDomain};
use sov_types::{Action, SignedTransaction, Transaction};

/// A tiny, self-contained xorshift64\* PRNG.
///
/// It is used ONLY for non-security-sensitive choices — which destination to pay
/// and how large a (test-traffic) amount to send. It is deliberately NOT used for
/// any key, nonce-secret, or signature material. Being seedable makes the random
/// destination/amount modes deterministically testable.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    /// Seed from the OS CSPRNG (production use).
    pub fn from_entropy() -> Self {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).expect("OS entropy is available");
        // A zero state is the one xorshift fixed point; force it non-zero.
        Self(u64::from_le_bytes(b) | 1)
    }

    /// Seed deterministically (used by the unit tests to make the random
    /// destination/amount modes reproducible).
    #[cfg(test)]
    pub fn seeded(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A uniform value in `[0, n)`; `0` if `n == 0`.
    fn below(&mut self, n: u128) -> u128 {
        if n == 0 {
            return 0;
        }
        // Assemble 128 bits so the modulo is well-distributed even for large spans.
        let hi = u128::from(self.next_u64());
        let lo = u128::from(self.next_u64());
        ((hi << 64) | lo) % n
    }
}

/// Hands out per-account nonces for the traffic we generate.
///
/// `pending` is the next nonce we will assign. Each block we [`reconcile`] against
/// the node's reported next nonce (`sov_getNonce`): if the node has moved ahead —
/// because our earlier txs were mined, or someone else spent from the account — we
/// jump forward so we never reuse a nonce; we never move backward, so txs we have
/// already submitted (but that are still in the mempool) keep their reserved,
/// gap-free nonces.
///
/// [`reconcile`]: NonceSequencer::reconcile
#[derive(Clone, Debug, Default)]
pub struct NonceSequencer {
    pending: u64,
}

impl NonceSequencer {
    /// A fresh sequencer; the first [`reconcile`](Self::reconcile) sets the floor.
    pub fn new() -> Self {
        Self { pending: 0 }
    }

    /// Raise the next-nonce floor to the node's reported next nonce, never lowering
    /// it. Call once at the start of each block before allocating.
    pub fn reconcile(&mut self, rpc_next_nonce: u64) {
        if rpc_next_nonce > self.pending {
            self.pending = rpc_next_nonce;
        }
    }

    /// Allocate the next nonce and advance.
    pub fn next(&mut self) -> u64 {
        let n = self.pending;
        self.pending += 1;
        n
    }

    /// The nonce that would be handed out next (for display/tests) — and the
    /// nonce a continuous-mode worker BUILDS AT without yet consuming it.
    pub fn peek(&self) -> u64 {
        self.pending
    }

    /// Commit the peeked nonce: advance past it because the node has consumed
    /// that slot (the tx was ACCEPTED, or was already pooled/mined). This is the
    /// commit half of the continuous modes' peek → submit → commit flow; a
    /// capacity rejection must NOT call this, so the same nonce is retried and
    /// the account never develops a gap.
    pub fn advance(&mut self) {
        self.pending += 1;
    }
}

/// How fast to fire.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RateMode {
    /// Fire `n` transactions on each NEW block (the original behavior).
    PerBlock(u32),
    /// Pace submissions to approximate this many per second, decoupled from
    /// blocks (see [`Pacer`]).
    TargetTps(f64),
    /// Submit as fast as sign+POST allows; the mempool's capacity rejections
    /// are the only brake.
    Firehose,
    /// Keep a gentle, indefinite trickle of real transactions flowing — chain
    /// liveness rather than load. See [`Heartbeat`] for the pacing model.
    Heartbeat {
        /// Target interval between submissions, in milliseconds.
        interval_ms: u64,
        /// Symmetric jitter as a percentage of the interval (0 = metronome).
        jitter_pct: u32,
    },
    /// One side of the two-wallet AUCTION DUEL: the heartbeat pacer, but with the
    /// interval NOT divided across the wallets and jitter forced off, so both
    /// sides beat at the same instants and their transactions compete for the
    /// same blockspace. Only the tip differs between the sides.
    Duel {
        /// Interval between this side's submissions, in milliseconds. Identical
        /// for both sides — that is what makes the run a controlled comparison.
        interval_ms: u64,
        /// Which side this worker is.
        side: DuelSide,
    },
}

/// The Target-TX/s scheduler: given elapsed time since the run started, says how
/// many submissions are due NOW.
///
/// It tracks the cumulative ideal count `floor(elapsed × tps)` and hands out the
/// shortfall, capped at one second's worth per call so a stall (e.g. the app was
/// blocked in a slow RPC) never produces a runaway catch-up burst — the skipped
/// backlog is dropped, not replayed. With regular ticks the cumulative count
/// tracks the ideal exactly (no starvation, even for fractional rates < 1).
#[derive(Clone, Debug)]
pub struct Pacer {
    tps: f64,
    issued: u64,
}

impl Pacer {
    /// A pacer targeting `tps` submissions per second (must be > 0, enforced by
    /// the UI's validation).
    pub fn new(tps: f64) -> Self {
        Self {
            tps: tps.max(f64::MIN_POSITIVE),
            issued: 0,
        }
    }

    /// The most sends one call may return: one second's worth (min 1).
    fn burst_cap(&self) -> u64 {
        (self.tps.ceil() as u64).max(1)
    }

    /// How many submissions are due at `elapsed` since the run started. Advances
    /// the internal cumulative counter; a backlog beyond [`burst_cap`] is
    /// dropped (counted as issued) so there is never a runaway burst.
    ///
    /// [`burst_cap`]: Self::burst_cap
    pub fn take_due(&mut self, elapsed: Duration) -> u64 {
        let target = (elapsed.as_secs_f64() * self.tps) as u64;
        let shortfall = target.saturating_sub(self.issued);
        let due = shortfall.min(self.burst_cap());
        // Mark the whole shortfall issued: what we don't send now is dropped,
        // not deferred, so a stall can't snowball.
        self.issued = self.issued.max(target);
        due
    }
}

// ---------------------------------------------------------------------------
// Heartbeat — the constant, indefinite trickle mode
// ---------------------------------------------------------------------------
//
// The other modes answer "how hard can this chain be pushed". The heartbeat
// answers a different question: "can this chain be kept ALIVE, gently, forever".
// It submits a handful of real transactions per block, indefinitely, self-pacing
// against an ideal schedule so the cadence neither drifts nor bunches, and it
// stops itself before it can drain the funding wallet.

/// Mainnet target block interval, in seconds (2.5 minutes). The cadence is
/// expressed in these human terms — "N transactions per block" — and converted
/// to a submission interval here, in ONE tested place.
pub const BLOCK_SECS: f64 = 150.0;

/// Narrowest heartbeat interval: one transaction every 5 seconds. The heartbeat
/// is deliberately not a load test — [`RateMode::TargetTps`] and
/// [`RateMode::Firehose`] are what push the pool.
pub const HEARTBEAT_MIN_INTERVAL_MS: u64 = 5_000;

/// Widest heartbeat interval: one transaction an hour.
pub const HEARTBEAT_MAX_INTERVAL_MS: u64 = 3_600_000;

/// Default jitter, as a percentage of the interval, applied symmetrically
/// (±20%) so the stream reads as organic rather than as a metronome while the
/// MEAN cadence is preserved exactly.
pub const HEARTBEAT_JITTER_PCT: u32 = 20;

/// The suggested ("auto") heartbeat tip, in grains: 0.0005 XUS.
///
/// The blockspace auction refuses a bid only when the pool is at CAPACITY, where
/// the emergent floor is the lowest tip protecting a slot. A live chain running a
/// heartbeat is nowhere near capacity, so the floor is effectively zero and any
/// nonzero bid both (a) clears it and (b) orders the heartbeat tx ahead of all
/// untipped traffic in the miner's schedule. 0.0005 XUS is ~2.4× the intrinsic
/// fee, so even a week of heartbeat at a few tx per block costs single-digit XUS.
pub const SUGGESTED_TIP_GRAINS: u128 = 50_000;

/// How the operator expressed the heartbeat cadence.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Cadence {
    /// `n` transactions per block, at the [`BLOCK_SECS`] target block time.
    PerBlock(f64),
    /// One transaction every `secs` seconds, independent of blocks.
    EverySecs(f64),
}

impl Cadence {
    /// The submission interval this cadence implies, in milliseconds, or the
    /// reason it is not a usable cadence. Bounded by
    /// [`HEARTBEAT_MIN_INTERVAL_MS`] / [`HEARTBEAT_MAX_INTERVAL_MS`] so no UI
    /// input can ask for a firehose or for a heartbeat that never beats.
    pub fn interval_ms(self) -> Result<u64, String> {
        let secs = match self {
            Cadence::PerBlock(n) => {
                if !n.is_finite() || n <= 0.0 {
                    return Err("transactions per block must be greater than zero".into());
                }
                BLOCK_SECS / n
            }
            Cadence::EverySecs(s) => {
                if !s.is_finite() || s <= 0.0 {
                    return Err("the interval must be greater than zero".into());
                }
                s
            }
        };
        let ms = (secs * 1_000.0).round();
        if !ms.is_finite() {
            return Err("that cadence is not a number".into());
        }
        let ms = ms as u64;
        if ms < HEARTBEAT_MIN_INTERVAL_MS {
            return Err(format!(
                "too fast for a heartbeat — keep it at or below one tx every {:.0} s ({:.1} tx/block); use Target TX/s to push harder",
                HEARTBEAT_MIN_INTERVAL_MS as f64 / 1_000.0,
                BLOCK_SECS / (HEARTBEAT_MIN_INTERVAL_MS as f64 / 1_000.0),
            ));
        }
        if ms > HEARTBEAT_MAX_INTERVAL_MS {
            return Err(format!(
                "too slow — keep it at or under one tx every {:.0} min",
                HEARTBEAT_MAX_INTERVAL_MS as f64 / 60_000.0,
            ));
        }
        Ok(ms)
    }

    /// The cadence in both human framings, for the status line.
    pub fn describe(self) -> String {
        match self.interval_ms() {
            Ok(ms) => {
                let secs = ms as f64 / 1_000.0;
                format!(
                    "{:.2} tx/block · one every {}",
                    BLOCK_SECS / secs,
                    fmt_secs(secs)
                )
            }
            Err(e) => e,
        }
    }
}

/// A duration in seconds rendered compactly for a cadence readout.
pub fn fmt_secs(secs: f64) -> String {
    if secs < 90.0 {
        format!("{secs:.0} s")
    } else {
        format!("{:.1} min", secs / 60.0)
    }
}

/// The heartbeat's self-pacing scheduler.
///
/// It holds an IDEAL schedule — `anchor + issued × interval` — rather than
/// sleeping `interval` after each send, so the cadence cannot drift as signing,
/// RPC latency and back-offs eat time: a submission that lands late is followed
/// by one that is due immediately, and the long-run rate is exactly the target.
///
/// Two properties matter as much as the average, and both are tested:
///   * **it never bunches** — the deficit it will make up is bounded by one
///     interval, so at most ONE catch-up submission is ever due at once; and
///   * **a stall is dropped, not replayed** — if it falls more than one interval
///     behind (the node was unreachable for a minute, the app was blocked), it
///     re-anchors on "now" instead of firing the whole backlog at once.
///
/// Time is caller-supplied milliseconds (monotonic in production, scripted in
/// the tests). Jitter is symmetric around the ideal instant, so it changes the
/// TEXTURE of the stream without changing its rate.
#[derive(Clone, Debug)]
pub struct Heartbeat {
    interval_ms: u64,
    jitter_pct: u32,
    /// Origin of the current ideal schedule.
    anchor_ms: u64,
    /// Submissions issued since the anchor.
    issued: u64,
    /// When the next submission is due (may be in the past ⇒ due now).
    next_at_ms: u64,
}

impl Heartbeat {
    /// A heartbeat at `interval_ms` (clamped into the supported band) with
    /// `jitter_pct` of symmetric jitter. The first submission is due immediately,
    /// so the operator sees the stream start rather than waiting out an interval.
    pub fn new(interval_ms: u64, jitter_pct: u32) -> Self {
        Self {
            interval_ms: interval_ms.clamp(HEARTBEAT_MIN_INTERVAL_MS, HEARTBEAT_MAX_INTERVAL_MS),
            jitter_pct: jitter_pct.min(90),
            anchor_ms: 0,
            issued: 0,
            next_at_ms: 0,
        }
    }

    /// The configured interval, in milliseconds.
    pub fn interval_ms(&self) -> u64 {
        self.interval_ms
    }

    /// Whether a submission is due at `now_ms`.
    pub fn due(&self, now_ms: u64) -> bool {
        now_ms >= self.next_at_ms
    }

    /// How long to wait before the next submission is due (zero ⇒ due now).
    pub fn wait_ms(&self, now_ms: u64) -> u64 {
        self.next_at_ms.saturating_sub(now_ms)
    }

    /// Record that a submission actually went out at `now_ms` and schedule the
    /// next one. `rng` is consulted only when jitter is enabled.
    pub fn on_submitted(&mut self, now_ms: u64, rng: &mut Rng) {
        self.issued = self.issued.saturating_add(1);
        let ideal = self
            .anchor_ms
            .saturating_add(self.issued.saturating_mul(self.interval_ms));
        // More than one whole interval behind: the time is GONE (a stall, a long
        // back-off). Re-anchor on now and drop the backlog — never replay it.
        let base = if ideal.saturating_add(self.interval_ms) < now_ms {
            self.anchor_ms = now_ms;
            self.issued = 0;
            now_ms.saturating_add(self.interval_ms)
        } else {
            ideal
        };
        self.next_at_ms = self.jittered(base, rng);
    }

    /// Apply symmetric jitter of ±`jitter_pct`% of the interval around `base`.
    fn jittered(&self, base: u64, rng: &mut Rng) -> u64 {
        let span = self.interval_ms as u128 * self.jitter_pct as u128 / 100;
        if span == 0 {
            return base;
        }
        // Uniform in [base - span, base + span]: mean = base, so the cadence is
        // unchanged. Saturating, so an early instant can never wrap.
        let offset = rng.below(span * 2 + 1);
        (base as u128)
            .saturating_add(span)
            .saturating_sub(offset)
            .min(u64::MAX as u128) as u64
    }
}

/// Which tip the heartbeat bids — the operator's choice of whether to exercise
/// the blockspace auction at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TipChoice {
    /// The suggested tip ([`SUGGESTED_TIP_GRAINS`]): exercises the auction and
    /// lands promptly. The default.
    Auto,
    /// The operator's own fixed/range tip, so a bid can be placed deliberately at,
    /// above or below the floor and the outcome watched.
    Manual,
    /// No tip at all: the bare action, no `Tipped` envelope. This deliberately
    /// does NOT exercise the auction — and under contention such a transaction can
    /// WAIT below the dynamic floor for a long time. That is legitimate behaviour
    /// to demonstrate, and the UI says so rather than looking stalled.
    NoTip,
}

impl TipChoice {
    /// The words the UI shows for this choice.
    pub fn label(self) -> &'static str {
        match self {
            TipChoice::Auto => "Auto tip",
            TipChoice::Manual => "Manual tip",
            TipChoice::NoTip => "No tip",
        }
    }

    /// An honest one-line consequence of the choice.
    pub fn consequence(self) -> &'static str {
        match self {
            TipChoice::Auto => {
                "Bids the suggested tip (0.0005 XUS) — exercises the blockspace auction and lands \
                 in the next block or two."
            }
            TipChoice::Manual => {
                "Bids exactly what you configure in section 3 — set it above, at or below the \
                 floor and watch what the auction does with it."
            }
            TipChoice::NoTip => {
                "Bare action, no Tipped envelope: the auction is NOT exercised. Under contention \
                 an untipped transaction can wait below the floor for a long time — submitted and \
                 landed are reported separately so waiting never looks like a fault."
            }
        }
    }
}

/// Resolve the heartbeat's [`TipMode`] from the operator's three-way choice and
/// the manually configured tip.
///
/// This is only the BID. Whether it becomes an `Action::Tipped` envelope is
/// decided later by [`transfer_action`] against the node's live `fee-auction`
/// state, so no choice here can emit a tipped transaction on a chain where the
/// fork is dormant.
pub fn heartbeat_tip_mode(choice: TipChoice, manual: TipMode) -> TipMode {
    match choice {
        TipChoice::Auto => TipMode::Fixed(SUGGESTED_TIP_GRAINS),
        TipChoice::Manual => manual,
        TipChoice::NoTip => TipMode::Off,
    }
}

/// The heartbeat's safety rails: what it may never spend past.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeartbeatLimits {
    /// Balance the funding wallet must keep. The heartbeat PAUSES rather than
    /// taking the balance below this — it never drains a wallet.
    pub reserve_grains: u128,
    /// Optional cap on transactions submitted this session (off by default).
    pub max_tx: Option<u64>,
    /// Optional cap on total spend (transfer + fee + tip) this session.
    pub max_spend_grains: Option<u128>,
}

impl HeartbeatLimits {
    /// Rails with only the balance reserve armed.
    pub fn reserve_only(reserve_grains: u128) -> Self {
        Self {
            reserve_grains,
            max_tx: None,
            max_spend_grains: None,
        }
    }
}

/// Why the heartbeat is not sending right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeartbeatHalt {
    /// The next send would take the balance below the operator's reserve.
    /// Recoverable: PAUSE, keep watching (in closed-loop recycle the principal
    /// comes back as the pending txs mine, and the heartbeat resumes by itself).
    BalanceFloor {
        /// The wallet's balance, in grains.
        balance: u128,
        /// The reserve it must not dip below, in grains.
        reserve: u128,
    },
    /// The session transaction cap was reached — terminal.
    TxCap(u64),
    /// The session spend cap would be exceeded — terminal.
    SpendCap(u128),
}

impl HeartbeatHalt {
    /// Whether this halt ends the session (a cap) rather than pausing it (the
    /// balance floor, which can free up again).
    pub fn is_terminal(&self) -> bool {
        matches!(self, HeartbeatHalt::TxCap(_) | HeartbeatHalt::SpendCap(_))
    }

    /// The operator-facing reason, in words.
    pub fn message(&self) -> String {
        match self {
            HeartbeatHalt::BalanceFloor { balance, reserve } => format!(
                "paused at the balance floor — {} XUS left, reserve is {} XUS",
                fmt_xus(*balance),
                fmt_xus(*reserve)
            ),
            HeartbeatHalt::TxCap(n) => {
                format!(
                    "session cap reached — {} transactions submitted",
                    fmt_count(*n)
                )
            }
            HeartbeatHalt::SpendCap(g) => {
                format!("session spend cap reached — {} XUS spent", fmt_xus(*g))
            }
        }
    }
}

/// Decide whether the heartbeat may submit its next transaction.
///
/// `balance` is the worker's latest view of the funding wallet (`None` = not yet
/// known, which is NOT treated as empty — the node is the authority and the
/// mempool would refuse an unaffordable tx anyway). `next_cost` is what the next
/// send commits: transfer + fee + tip.
///
/// Checked in the order an operator would want them reported: the caps that end
/// the session first, then the floor that pauses it.
pub fn heartbeat_halt(
    limits: &HeartbeatLimits,
    balance: Option<u128>,
    sent: u64,
    spent: u128,
    next_cost: u128,
) -> Option<HeartbeatHalt> {
    if let Some(max) = limits.max_tx {
        if sent >= max {
            return Some(HeartbeatHalt::TxCap(sent));
        }
    }
    if let Some(max) = limits.max_spend_grains {
        if spent.saturating_add(next_cost) > max {
            return Some(HeartbeatHalt::SpendCap(spent));
        }
    }
    if let Some(bal) = balance {
        // The floor is a floor AFTER the send: never take the wallet below it.
        if bal.saturating_sub(next_cost) < limits.reserve_grains {
            return Some(HeartbeatHalt::BalanceFloor {
                balance: bal,
                reserve: limits.reserve_grains,
            });
        }
    }
    None
}

/// A count observed over `elapsed_secs`, expressed in transactions per block —
/// the same unit the heartbeat's target is set in, so target and actual are
/// directly comparable. `None` until enough time has passed for the figure to
/// mean anything (a fraction of a block would read as wild noise).
pub fn per_block_rate(count: u64, elapsed_secs: f64) -> Option<f64> {
    if !elapsed_secs.is_finite() || elapsed_secs < BLOCK_SECS / 5.0 {
        return None;
    }
    Some(count as f64 * BLOCK_SECS / elapsed_secs)
}

// ---------------------------------------------------------------------------
// Auction duel — the two-sided, controlled experiment on the fee auction
// ---------------------------------------------------------------------------
//
// The duel answers ONE question with evidence: on this chain, right now, does
// bidding more in the blockspace auction get a transaction mined sooner?
//
// It is a CONTROLLED experiment, which is why it is its own mode rather than a
// setting. Everything about the two sides is held identical — the same cadence
// (both sides beat off the same interval, with jitter forced OFF so the pair is
// submitted as close to simultaneously as two threads can manage and therefore
// competes for the SAME blockspace), the same amount policy, the same
// destination policy, the same safety rails, the same node. The ONLY variable
// is the tip. That isolation is the entire point: without it, nothing observed
// could honestly be attributed to the bid.
//
// Every figure below is an observation, never an inference:
//   * a landing is read from the CHAIN — our signer's transaction found in a
//     mined block (which gives the exact height AND its index in that block's
//     execution order), or, as a fallback, the node's own account nonce
//     advancing past a nonce we submitted. Never from mempool acceptance.
//   * time-to-land is the (blocks, seconds) gap between submitting and that
//     observation.
//   * the verdict is computed from those numbers by [`duel_verdict`], and says
//     so plainly when there are not yet enough of them.

/// The duel is two-sided by construction: exactly this many wallets.
pub const DUEL_WALLETS: usize = 2;

/// Side A's default bid: ten times the suggested tip. Deliberately well clear of
/// any floor a gently-loaded chain can produce, so the experiment starts with a
/// real spread between the sides rather than two indistinguishable bids.
pub const DUEL_HIGH_BID_GRAINS: u128 = SUGGESTED_TIP_GRAINS * 10;

/// Default duel cadence: one PAIR every 60 s — about 2.5 pairs per 150 s block,
/// enough contention to observe ordering without becoming a load test.
pub const DUEL_DEFAULT_INTERVAL_SECS: f64 = 60.0;

/// Landings (both sides together) required before the verdict is anything other
/// than "inconclusive". Small samples of a two-way race say nothing.
pub const DUEL_MIN_LANDED: u64 = 4;

/// A difference in mean wait smaller than this many blocks is not a difference:
/// the landing observation is polled, so sub-block differences are noise.
pub const DUEL_BLOCK_EPSILON: f64 = 0.5;

/// Per-side landing samples retained. Bounds memory for an indefinite run while
/// keeping enough history for the per-block strip and the means.
pub const DUEL_MAX_SAMPLES: usize = 512;

/// Which side of the duel a worker is. Side A is the high bid by convention, so
/// the panel and the verdict always read the same way round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DuelSide {
    /// The high bid.
    A,
    /// The low (or absent) bid.
    B,
}

impl DuelSide {
    /// The side's full name, as the UI and the verdict say it.
    pub fn label(self) -> &'static str {
        match self {
            DuelSide::A => "Side A (high bid)",
            DuelSide::B => "Side B (low bid)",
        }
    }

    /// The one-letter form, for the per-block strip.
    pub fn short(self) -> &'static str {
        match self {
            DuelSide::A => "A",
            DuelSide::B => "B",
        }
    }
}

/// Why a duel cannot arm: it is not a two-sided contest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DuelBlock {
    /// Fewer than two wallets are selected.
    TooFew(usize),
    /// More than two wallets are selected.
    TooMany(usize),
}

impl DuelBlock {
    /// The operator-facing reason, in words — this is what a disabled Start says.
    pub fn message(self) -> String {
        match self {
            DuelBlock::TooFew(n) => format!(
                "The duel needs EXACTLY two wallets — one per side — and {n} is selected. Check a \
                 second unlocked wallet to fire as side B."
            ),
            DuelBlock::TooMany(n) => format!(
                "The duel needs EXACTLY two wallets — one per side — and {n} are selected. A third \
                 sender would add traffic that is neither side, so the comparison would no longer \
                 be controlled."
            ),
        }
    }
}

/// Whether this selection can arm a duel. `None` means it can — exactly two.
///
/// This is the enforcement the mode is built around: with one wallet there is no
/// contest, and with three the bid is no longer the only variable.
pub fn duel_wallet_check(selected: usize) -> Option<DuelBlock> {
    if selected < DUEL_WALLETS {
        Some(DuelBlock::TooFew(selected))
    } else if selected > DUEL_WALLETS {
        Some(DuelBlock::TooMany(selected))
    } else {
        None
    }
}

/// Resolve both sides' bids through the SAME resolver the heartbeat uses
/// ([`heartbeat_tip_mode`]), so a duel bid is constructed no differently from any
/// other bid — only its value differs between the sides.
///
/// Each side is `(choice, manual)`: the manual mode is consulted only for
/// [`TipChoice::Manual`], so a side set to auto or to no-tip is unaffected by
/// whatever the other side's fields say.
pub fn duel_bids(a: (TipChoice, TipMode), b: (TipChoice, TipMode)) -> (TipMode, TipMode) {
    (heartbeat_tip_mode(a.0, a.1), heartbeat_tip_mode(b.0, b.1))
}

/// A resolved bid in words, for the side panels and the frozen run record.
pub fn duel_bid_label(m: TipMode) -> String {
    match m {
        TipMode::Off => "no tip — bare action".to_string(),
        TipMode::Fixed(v) => format!("{} XUS", fmt_xus(v)),
        TipMode::Range { min, max } => format!("{}–{} XUS", fmt_xus(min), fmt_xus(max)),
    }
}

/// The honest caveat when the two sides are not actually bidding differently: the
/// run is then a null/control experiment and cannot show what a higher bid buys.
pub fn duel_bid_note(a: TipMode, b: TipMode) -> Option<&'static str> {
    if a == b {
        Some(
            "both sides are bidding the SAME — this is a null (control) run: it can show that two \
             identical sides behave alike, not what a higher bid buys.",
        )
    } else {
        None
    }
}

/// One transaction of ours observed in a mined block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Landing {
    /// The nonce that landed.
    pub nonce: u64,
    /// The height it was observed at.
    pub height: u64,
    /// Blocks between the tip when it was submitted and the observation.
    pub blocks: u64,
    /// Milliseconds between the submit and the observation.
    pub ms: u64,
    /// Its index in the block's execution order, when the block body was read.
    /// `None` when the landing was inferred from the account nonce instead — the
    /// count is still exact, the ordering is simply not known.
    pub index: Option<usize>,
    /// How many transactions that block held, when the body was read.
    pub txs: Option<usize>,
}

/// A transaction submitted and not yet observed in a block.
#[derive(Clone, Copy, Debug)]
struct InFlight {
    nonce: u64,
    at_ms: u64,
    height: u64,
}

/// One side's measured record: what it submitted, what landed, and how long each
/// landing waited. Fed only by real observations; it never guesses.
#[derive(Clone, Debug, Default)]
pub struct DuelLedger {
    /// Submitted, not yet seen mined. Nonces are monotonic, so this stays sorted.
    inflight: VecDeque<InFlight>,
    /// Recent landings (bounded to [`DUEL_MAX_SAMPLES`]).
    landings: VecDeque<Landing>,
    submitted: u64,
    landed: u64,
    /// Sums over EVERY landing (not just the retained window), so the means stay
    /// honest for a run longer than the sample buffer.
    sum_blocks: u128,
    sum_ms: u128,
}

impl DuelLedger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `nonce` went out at `at_ms` with the tip at `height`.
    ///
    /// Re-submitting a nonce still in flight (a retry after a transport failure)
    /// updates that record rather than counting a second transaction: the account
    /// only ever consumes the nonce once.
    pub fn on_submit(&mut self, nonce: u64, at_ms: u64, height: u64) {
        if let Some(f) = self.inflight.iter_mut().find(|f| f.nonce == nonce) {
            f.at_ms = at_ms;
            f.height = height;
            return;
        }
        self.inflight.push_back(InFlight {
            nonce,
            at_ms,
            height,
        });
        self.submitted = self.submitted.saturating_add(1);
    }

    /// Record our transaction found in a mined block: `nonce` at `index` of a
    /// block of `txs` transactions at `height`, observed at `now_ms`.
    ///
    /// This is the precise path — the height and the intra-block ordering both
    /// come from the block itself. Returns whether it matched something in flight
    /// (a block from before the run, or a re-scan, matches nothing).
    pub fn on_block_hit(
        &mut self,
        height: u64,
        nonce: u64,
        index: usize,
        txs: usize,
        now_ms: u64,
    ) -> bool {
        let Some(pos) = self.inflight.iter().position(|f| f.nonce == nonce) else {
            return false;
        };
        let f = self.inflight.remove(pos).expect("position just found");
        self.push_landing(Landing {
            nonce,
            height,
            blocks: height.saturating_sub(f.height),
            ms: now_ms.saturating_sub(f.at_ms),
            index: Some(index),
            txs: Some(txs),
        });
        true
    }

    /// Sweep up anything the block scan missed: the node reports the account at
    /// `node_nonce`, so every nonce below it HAS been mined. Returns how many
    /// landings this added.
    ///
    /// Landings found this way carry no index — the count and the wait are real,
    /// the position in the block is simply unknown.
    pub fn on_node_nonce(&mut self, node_nonce: u64, now_ms: u64, height: u64) -> u64 {
        let mut added = 0;
        while let Some(f) = self.inflight.front().copied() {
            if f.nonce >= node_nonce {
                break;
            }
            self.inflight.pop_front();
            self.push_landing(Landing {
                nonce: f.nonce,
                height,
                blocks: height.saturating_sub(f.height),
                ms: now_ms.saturating_sub(f.at_ms),
                index: None,
                txs: None,
            });
            added += 1;
        }
        added
    }

    fn push_landing(&mut self, l: Landing) {
        self.landed = self.landed.saturating_add(1);
        self.sum_blocks = self.sum_blocks.saturating_add(u128::from(l.blocks));
        self.sum_ms = self.sum_ms.saturating_add(u128::from(l.ms));
        self.landings.push_back(l);
        while self.landings.len() > DUEL_MAX_SAMPLES {
            self.landings.pop_front();
        }
    }

    /// This side's figures as the panel and the verdict consume them.
    pub fn stats(&self) -> DuelStats {
        let n = self.landed as f64;
        DuelStats {
            submitted: self.submitted,
            landed: self.landed,
            pooled: self.inflight.len() as u64,
            mean_blocks: (self.landed > 0).then(|| self.sum_blocks as f64 / n),
            mean_secs: (self.landed > 0).then(|| self.sum_ms as f64 / n / 1_000.0),
        }
    }

    /// Retained landings, newest last.
    pub fn landings(&self) -> &VecDeque<Landing> {
        &self.landings
    }

    /// `(height, index)` per retained landing — the input to [`block_outcomes`].
    pub fn positions(&self) -> Vec<(u64, Option<usize>)> {
        self.landings.iter().map(|l| (l.height, l.index)).collect()
    }
}

/// One side's measured outcome. `mean_*` are `None` until that side has landed
/// something — an unlanded side reports a dash, never a zero wait.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DuelStats {
    /// Transactions this side submitted.
    pub submitted: u64,
    /// Transactions of this side's the chain has mined.
    pub landed: u64,
    /// Submitted, still sitting in the pool.
    pub pooled: u64,
    /// Mean blocks waited from submit to observed mined.
    pub mean_blocks: Option<f64>,
    /// Mean seconds waited from submit to observed mined.
    pub mean_secs: Option<f64>,
}

/// What happened in one block that at least one side landed in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockOutcome {
    /// The block height.
    pub height: u64,
    /// How many of side A's transactions it included.
    pub a: u64,
    /// How many of side B's.
    pub b: u64,
    /// Which side came FIRST in the block's execution order, when both sides
    /// landed in it and both indexes are known. `None` when only one side landed,
    /// or when the ordering was not observed.
    pub first: Option<DuelSide>,
}

/// Fold both sides' `(height, index)` landings into a per-block record.
///
/// Only blocks at least one side landed in appear: a block neither side made is
/// not an outcome of the duel, and inventing a row for it would misrepresent the
/// sample size.
pub fn block_outcomes(a: &[(u64, Option<usize>)], b: &[(u64, Option<usize>)]) -> Vec<BlockOutcome> {
    let mut heights: Vec<u64> = a.iter().chain(b.iter()).map(|(h, _)| *h).collect();
    heights.sort_unstable();
    heights.dedup();
    heights
        .into_iter()
        .map(|h| {
            let at = |side: &[(u64, Option<usize>)]| -> (u64, Option<usize>) {
                let hits = side.iter().filter(|(hh, _)| *hh == h);
                let mut count = 0;
                let mut first: Option<usize> = None;
                for (_, idx) in hits {
                    count += 1;
                    if let Some(i) = idx {
                        first = Some(first.map_or(*i, |f: usize| f.min(*i)));
                    }
                }
                (count, first)
            };
            let (ac, ai) = at(a);
            let (bc, bi) = at(b);
            let first = match (ac > 0, bc > 0, ai, bi) {
                (true, true, Some(i), Some(j)) if i < j => Some(DuelSide::A),
                (true, true, Some(i), Some(j)) if j < i => Some(DuelSide::B),
                _ => None,
            };
            BlockOutcome {
                height: h,
                a: ac,
                b: bc,
                first,
            }
        })
        .collect()
}

/// Who won the blocks: a side "wins" a block it landed in and the other did not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DuelTally {
    /// Blocks in the sample (blocks at least one side landed in).
    pub blocks: usize,
    /// Blocks only side A landed in.
    pub a_wins: u64,
    /// Blocks only side B landed in.
    pub b_wins: u64,
    /// Blocks BOTH sides landed in.
    pub shared: u64,
    /// Of the shared blocks, how many side A was ordered first in.
    pub a_first: u64,
    /// Of the shared blocks, how many side B was ordered first in.
    pub b_first: u64,
}

/// Count the per-block wins, and — where the block bodies gave us an ordering —
/// which side the miner scheduled first inside the blocks they shared.
pub fn tally_blocks(outcomes: &[BlockOutcome]) -> DuelTally {
    let mut t = DuelTally {
        blocks: outcomes.len(),
        ..DuelTally::default()
    };
    for o in outcomes {
        match (o.a > 0, o.b > 0) {
            (true, false) => t.a_wins += 1,
            (false, true) => t.b_wins += 1,
            (true, true) => {
                t.shared += 1;
                match o.first {
                    Some(DuelSide::A) => t.a_first += 1,
                    Some(DuelSide::B) => t.b_first += 1,
                    None => {}
                }
            }
            (false, false) => {}
        }
    }
    t
}

/// What the measurement says so far. The wording is the payload: each variant
/// carries a sentence built from the real numbers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Not enough landed yet to claim anything.
    Inconclusive(String),
    /// The higher bid measurably landed sooner and/or more often.
    HigherBid(String),
    /// Both sides measured the same, within the noise floor.
    NoDifference(String),
    /// The measurement went the OTHER way — reported as found, not explained away.
    Contrary(String),
}

impl Verdict {
    /// The sentence.
    pub fn text(&self) -> &str {
        match self {
            Verdict::Inconclusive(s)
            | Verdict::HigherBid(s)
            | Verdict::NoDifference(s)
            | Verdict::Contrary(s) => s,
        }
    }

    /// A one-word headline for the panel.
    pub fn word(&self) -> &'static str {
        match self {
            Verdict::Inconclusive(_) => "INCONCLUSIVE",
            Verdict::HigherBid(_) => "HIGHER BID WINS",
            Verdict::NoDifference(_) => "NO DIFFERENCE",
            Verdict::Contrary(_) => "CONTRARY",
        }
    }
}

/// The running verdict, computed from the two sides' measured numbers.
///
/// The rules are deliberately conservative, because the honest answer on a
/// lightly-loaded chain is often "no difference":
///   * fewer than [`DUEL_MIN_LANDED`] landings in total ⇒ INCONCLUSIVE;
///   * one side landing and the other not ⇒ that side won outright;
///   * otherwise compare the mean blocks waited, and call it a difference only
///     when it exceeds [`DUEL_BLOCK_EPSILON`] blocks.
///
/// Nothing here asserts a mechanism — only what was measured.
pub fn duel_verdict(a: &DuelStats, b: &DuelStats, t: &DuelTally) -> Verdict {
    let total = a.landed.saturating_add(b.landed);
    let blocks = format!(
        "blocks won A {} · B {} · shared {}",
        t.a_wins, t.b_wins, t.shared
    );
    if total < DUEL_MIN_LANDED {
        return Verdict::Inconclusive(format!(
            "inconclusive so far — {total} of the {DUEL_MIN_LANDED} landings needed before the \
             numbers mean anything (A landed {}, B landed {}; A has {} pooled, B {})",
            a.landed, b.landed, a.pooled, b.pooled
        ));
    }
    match (a.mean_blocks, b.mean_blocks) {
        (Some(am), Some(bm)) => {
            let d = bm - am; // > 0 ⇒ A waited less
            let order = if t.shared > 0 && (t.a_first + t.b_first) > 0 {
                format!(
                    "; of {} shared blocks the miner ordered A first in {} and B first in {}",
                    t.shared, t.a_first, t.b_first
                )
            } else {
                String::new()
            };
            let core = format!(
                "over {total} landings A waited {am:.1} blocks ({:.0} s) on average and B waited \
                 {bm:.1} blocks ({:.0} s) — {blocks}{order}",
                a.mean_secs.unwrap_or(f64::NAN),
                b.mean_secs.unwrap_or(f64::NAN),
            );
            if d >= DUEL_BLOCK_EPSILON {
                Verdict::HigherBid(format!(
                    "the higher bid landed sooner by {d:.1} blocks: {core}"
                ))
            } else if d <= -DUEL_BLOCK_EPSILON {
                Verdict::Contrary(format!(
                    "the LOWER bid landed sooner by {:.1} blocks — the higher bid did not win this \
                     sample: {core}",
                    -d
                ))
            } else {
                Verdict::NoDifference(format!(
                    "no measurable difference in wait ({:.1} blocks apart, under the {DUEL_BLOCK_EPSILON} \
                     block noise floor): {core}",
                    d.abs()
                ))
            }
        }
        (Some(am), None) => Verdict::HigherBid(format!(
            "only the higher bid is landing: A landed {} in {am:.1} blocks ({:.0} s) on average \
             while B landed none and has {} still pooled — {blocks}",
            a.landed,
            a.mean_secs.unwrap_or(f64::NAN),
            b.pooled
        )),
        (None, Some(bm)) => Verdict::Contrary(format!(
            "only the LOWER bid is landing: B landed {} in {bm:.1} blocks ({:.0} s) on average \
             while A landed none and has {} still pooled — {blocks}",
            b.landed,
            b.mean_secs.unwrap_or(f64::NAN),
            a.pooled
        )),
        (None, None) => Verdict::Inconclusive(
            "inconclusive — nothing has landed on either side yet".to_string(),
        ),
    }
}

/// What kind of rejection the node returned for a submit. Buckets mirror the
/// live-meter breakdown: capacity / nonce / affordability / other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectClass {
    /// The pool (or this sender's fair-share slice of it) is at capacity:
    /// `"mempool is full (N transactions)"` or
    /// `"sender S has reached its mempool limit of L pending transactions"`.
    Capacity,
    /// Our nonce is below the account's current nonce — our earlier txs mined
    /// and the node moved ahead: `"stale transaction: account is at nonce C,
    /// transaction used G"`.
    NonceStale,
    /// The nonce slot is already consumed in the pool (our earlier submit for
    /// it landed): `"transaction already in the pool"` or `"a transaction with
    /// signer S and nonce N is already pooled"`.
    NonceOccupied,
    /// The signer cannot afford it: `"insufficient balance: pooled transfers
    /// would move C grains but only A are held"`.
    Insufficient,
    /// Anything else (unauthorized, invalid params, transport, …).
    Other,
}

/// Classify a submit error by the node's REAL rejection strings (see
/// `MempoolError` in `chain/crates/mempool` — the RPC wraps them as
/// `"rejected: mempool rejected transaction: …"`, and the client as
/// `"rpc error CODE: …"`; substring matching sees through both wrappers).
/// Unrecognized messages land in [`RejectClass::Other`].
pub fn classify_reject(msg: &str) -> RejectClass {
    let m = msg.to_ascii_lowercase();
    if m.contains("mempool is full") || m.contains("reached its mempool limit") {
        RejectClass::Capacity
    } else if m.contains("stale transaction") {
        RejectClass::NonceStale
    } else if m.contains("already in the pool") || m.contains("already pooled") {
        RejectClass::NonceOccupied
    } else if m.contains("insufficient balance") {
        RejectClass::Insufficient
    } else {
        RejectClass::Other
    }
}

/// What the worker must do with its in-flight (peeked, not committed) nonce
/// after a rejection. The rule that keeps the account gap-free: a nonce is
/// committed ONLY when the node has consumed its slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Hold the SAME nonce, back off briefly, retry (capacity: the slot was NOT
    /// consumed — burning the nonce here would wedge the account).
    HoldAndRetry,
    /// The slot IS consumed (a duplicate of our own pooled tx) — commit and move
    /// to the next nonce.
    Advance,
    /// The node is ahead of us (our txs mined) — re-query its next nonce and
    /// reconcile the sequencer forward, without committing blindly.
    ReconcileForward,
    /// The signer's balance is fully committed (typically the PREVIOUS run's txs
    /// still pending in the pool). It frees as they mine — and in closed-loop
    /// recycle it comes straight back — so hold the nonce, wait, re-check. This is
    /// what makes a refire after Stop self-heal instead of instantly killing every
    /// worker while the old run's mempool backlog drains.
    WaitAffordable,
    /// Unknown failure: the slot was not provably consumed, so hold the nonce
    /// (a later duplicate/stale answer resolves it), back off, keep going.
    HoldAndRetryOther,
}

/// The disposition for each rejection class (pure, exhaustively tested).
pub fn disposition(class: RejectClass) -> Disposition {
    match class {
        RejectClass::Capacity => Disposition::HoldAndRetry,
        RejectClass::NonceStale => Disposition::ReconcileForward,
        RejectClass::NonceOccupied => Disposition::Advance,
        RejectClass::Insufficient => Disposition::WaitAffordable,
        RejectClass::Other => Disposition::HoldAndRetryOther,
    }
}

/// The event kinds the live meters track.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeterKind {
    /// A submission attempt (dry-run builds count too).
    Attempted = 0,
    /// The node accepted it (or dry-run built it).
    Accepted = 1,
    /// Rejected: pool/sender capacity.
    RejCapacity = 2,
    /// Rejected: nonce (stale or slot already pooled).
    RejNonce = 3,
    /// Rejected: affordability.
    RejAfford = 4,
    /// Rejected: anything else (incl. transport errors).
    RejOther = 5,
}

/// Number of [`MeterKind`] variants.
pub const METER_KINDS: usize = 6;

/// A rolling per-second throughput meter over a short window of one-second
/// buckets, plus cumulative totals. Time is caller-supplied milliseconds so it
/// is deterministic under test; the GUI feeds it a monotonic clock.
#[derive(Clone, Debug)]
pub struct RateMeter {
    window_secs: u64,
    /// `(second, counts-per-kind)` buckets, oldest first, bounded to the window.
    buckets: VecDeque<(u64, [u64; METER_KINDS])>,
    totals: [u64; METER_KINDS],
}

impl RateMeter {
    /// A meter averaging over the trailing `window_secs` (min 1) seconds.
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs: window_secs.max(1),
            buckets: VecDeque::new(),
            totals: [0; METER_KINDS],
        }
    }

    fn prune(&mut self, now_sec: u64) {
        while let Some(&(sec, _)) = self.buckets.front() {
            if sec + self.window_secs <= now_sec {
                self.buckets.pop_front();
            } else {
                break;
            }
        }
    }

    /// Record one event of `kind` at `now_ms`.
    pub fn record(&mut self, now_ms: u64, kind: MeterKind) {
        let sec = now_ms / 1000;
        self.totals[kind as usize] += 1;
        match self.buckets.back_mut() {
            Some((s, counts)) if *s == sec => counts[kind as usize] += 1,
            _ => {
                let mut counts = [0u64; METER_KINDS];
                counts[kind as usize] = 1;
                self.buckets.push_back((sec, counts));
            }
        }
        self.prune(sec);
    }

    /// Events-per-second of `kind` over the trailing window ending at `now_ms`.
    pub fn rate(&self, now_ms: u64, kind: MeterKind) -> f64 {
        let now_sec = now_ms / 1000;
        let from = now_sec.saturating_sub(self.window_secs - 1);
        let sum: u64 = self
            .buckets
            .iter()
            .filter(|(s, _)| *s >= from && *s <= now_sec)
            .map(|(_, c)| c[kind as usize])
            .sum();
        sum as f64 / self.window_secs as f64
    }

    /// Cumulative count of `kind` since the meter was created.
    pub fn total(&self, kind: MeterKind) -> u64 {
        self.totals[kind as usize]
    }
}

/// How to pick the destination for each transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestMode {
    /// Cycle through the list in order.
    RoundRobin,
    /// Pick a uniformly random entry each time.
    Random,
}

/// Chooses a destination from a fixed, non-empty list per [`DestMode`].
#[derive(Clone, Debug)]
pub struct DestSelector {
    dests: Vec<AccountId>,
    mode: DestMode,
    cursor: usize,
}

impl DestSelector {
    /// Build a selector; errors if the destination list is empty.
    pub fn new(dests: Vec<AccountId>, mode: DestMode) -> Result<Self, String> {
        if dests.is_empty() {
            return Err("add at least one destination address".into());
        }
        Ok(Self {
            dests,
            mode,
            cursor: 0,
        })
    }

    /// The next destination. `rng` is consulted only in [`DestMode::Random`].
    pub fn next(&mut self, rng: &mut Rng) -> AccountId {
        let idx = match self.mode {
            DestMode::RoundRobin => {
                let i = self.cursor;
                self.cursor = (self.cursor + 1) % self.dests.len();
                i
            }
            DestMode::Random => rng.below(self.dests.len() as u128) as usize,
        };
        self.dests[idx].clone()
    }
}

/// How to size each transaction, in grains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmountMode {
    /// Always send exactly this many grains.
    Fixed(u128),
    /// Draw uniformly from `[min, max]` (inclusive) grains.
    Range { min: u128, max: u128 },
}

impl AmountMode {
    /// Validate the mode's shape (non-zero fixed; well-ordered, non-zero range).
    pub fn validate(&self) -> Result<(), String> {
        match self {
            AmountMode::Fixed(v) => {
                if *v == 0 {
                    return Err("amount must be greater than zero".into());
                }
            }
            AmountMode::Range { min, max } => {
                if *max < *min {
                    return Err("amount max must be ≥ min".into());
                }
                if *max == 0 {
                    return Err("amount max must be greater than zero".into());
                }
            }
        }
        Ok(())
    }

    /// Pick a concrete amount. `rng` is consulted only for [`AmountMode::Range`].
    pub fn pick(&self, rng: &mut Rng) -> u128 {
        match self {
            AmountMode::Fixed(v) => *v,
            AmountMode::Range { min, max } => {
                let span = max - min; // max >= min guaranteed by validate
                min + rng.below(span + 1)
            }
        }
    }
}

/// How much priority tip (in grains) to attach to each transaction, bidding for
/// earlier inclusion in the blockspace auction (SOV v0.1.98, `Action::Tipped`).
///
/// A tip is only ever *applied* when the node reports the `fee-auction` deployment
/// as `Active` (see [`parse_fee_auction_active`]); while the fork is dormant the
/// cannon emits the bare inner action, byte-identical to a pre-auction transaction
/// (see [`transfer_action`]). This type only decides the *bid*.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TipMode {
    /// No tip — a zero-bid (legacy) transaction. It is never rejected for bidding
    /// zero; under contention it simply waits behind funded bids.
    Off,
    /// Always attach exactly this many grains as the tip.
    Fixed(u128),
    /// Draw the tip uniformly from `[min, max]` (inclusive) grains, so a fleet of
    /// wallets spreads a realistic spectrum of bids across the fee floor.
    Range { min: u128, max: u128 },
}

impl TipMode {
    /// Validate the mode's shape (a well-ordered range; any fixed value, including
    /// zero, is allowed — a zero tip is simply a legacy bid).
    pub fn validate(&self) -> Result<(), String> {
        if let TipMode::Range { min, max } = self {
            if *max < *min {
                return Err("tip max must be ≥ min".into());
            }
        }
        Ok(())
    }

    /// Pick a concrete tip in grains. `rng` is consulted only for [`TipMode::Range`].
    pub fn pick(&self, rng: &mut Rng) -> u128 {
        match self {
            TipMode::Off => 0,
            TipMode::Fixed(v) => *v,
            TipMode::Range { min, max } => {
                let span = max - min; // max >= min guaranteed by validate
                min + rng.below(span + 1)
            }
        }
    }
}

/// Build the [`Action`] a transfer should carry, wrapping it in an
/// [`Action::Tipped`] envelope ONLY when the blockspace auction is live AND a
/// nonzero tip is bid. Otherwise the bare `Transfer` is returned — byte-identical
/// to a pre-auction transaction, so a cannon pointed at a node where the
/// `fee-auction` fork is still dormant emits exactly what it always did.
///
/// This is the whole gate, in one pure, tested place: the worker decides
/// `auction_active` from the node's `sov_getDeployments`, exactly as SOV-Station
/// gates the envelope, and never emits a `Tipped` a dormant node would reject.
pub fn transfer_action(
    to: AccountId,
    amount_grains: u128,
    tip_grains: u128,
    auction_active: bool,
) -> Action {
    let transfer = Action::Transfer {
        to,
        amount: Balance::from_grains(amount_grains),
    };
    if auction_active && tip_grains > 0 {
        Action::Tipped {
            tip: Balance::from_grains(tip_grains),
            inner: Box::new(transfer),
        }
    } else {
        transfer
    }
}

/// Whether the node reports the blockspace-auction (`fee-auction`) deployment as
/// `Active`, parsed from a `sov_getDeployments` result.
///
/// Mirrors how [`RpcClient::signing_domain`] treats an old node: anything other
/// than an explicit `state == "Active"` for the `fee-auction` deployment reads as
/// dormant (`false`) — a node too old to report deployments, a malformed answer,
/// or a fork still `Defined`/`Started`/`LockedIn` all mean "emit the bare action".
/// Fail-closed: the cannon only ever *adds* a tip when the node has affirmatively
/// activated the envelope.
pub fn parse_fee_auction_active(deployments: &serde_json::Value) -> bool {
    deployments
        .get("deployments")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter().any(|dep| {
                dep.get("name").and_then(|n| n.as_str()) == Some("fee-auction")
                    && dep.get("state").and_then(|s| s.as_str()) == Some("Active")
            })
        })
        .unwrap_or(false)
}

/// The key scheme a wallet seed derives, mirroring the SOV-Station keystore's
/// `scheme` field (`"hybrid65"` is the generated default; ed25519 is the legacy /
/// dev-test scheme).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyScheme {
    Ed25519,
    Hybrid65,
}

impl KeyScheme {
    /// Parse a keystore `scheme` string (absent = ed25519, matching the node).
    pub fn from_keystore(scheme: Option<&str>) -> Result<Self, String> {
        match scheme {
            None | Some("ed25519") => Ok(KeyScheme::Ed25519),
            Some("hybrid65") => Ok(KeyScheme::Hybrid65),
            Some(other) => Err(format!("unknown key scheme `{other}`")),
        }
    }

    /// Reconstruct the signing keypair from a 32-byte seed under this scheme. The
    /// returned keypair is transient — the caller signs and drops it immediately;
    /// the durable secret is the seed the caller holds in a zeroizing buffer.
    pub fn keypair_from_seed(self, seed: &[u8; 32]) -> Keypair {
        match self {
            KeyScheme::Ed25519 => Keypair::from_seed(*seed),
            KeyScheme::Hybrid65 => Keypair::hybrid_from_seed(*seed),
        }
    }
}

/// Build and sign a transparent transfer using the chain's real signing path.
///
/// The seed is used only to derive a transient [`Keypair`] for this one signature.
/// Returns the signed transaction, whose signature is guaranteed to verify (the
/// public key committed in the tx is the one that signed it).
/// The on-chain (implicit) account id for a wallet `seed` under `scheme`, derived
/// EXACTLY as the node/SOV-Station does: the implicit id of the derived public key.
/// The keystore's `account` field is only a DISPLAY LABEL — never the on-chain id —
/// so balance/nonce queries and the tx `signer` MUST use this, not the label.
pub fn derive_account_id(seed: &[u8; 32], scheme: KeyScheme) -> AccountId {
    scheme
        .keypair_from_seed(seed)
        .public_key()
        .implicit_account_id()
    // The transient keypair drops here; the caller keeps only the seed.
}

/// `domain` is the network [`SigningDomain`] from the node's
/// `sov_getSigningDomain` (`RpcClient::signing_domain`): `None` while the
/// `tx-domain` fork is dormant (legacy signature, byte-identical to before),
/// `Some(domain)` once active (network-bound signature).
///
/// `tip_grains` + `auction_active` select the action shape via [`transfer_action`]:
/// a live auction with a nonzero tip produces an `Action::Tipped` envelope; a
/// dormant fork (or a zero tip) produces the bare `Transfer`.
#[allow(clippy::too_many_arguments)]
pub fn build_signed_transfer(
    seed: &[u8; 32],
    scheme: KeyScheme,
    from: &AccountId,
    to: &AccountId,
    amount_grains: u128,
    tip_grains: u128,
    auction_active: bool,
    nonce: u64,
    domain: Option<&SigningDomain>,
) -> Result<SignedTransaction, String> {
    let keypair = scheme.keypair_from_seed(seed);
    let tx = Transaction {
        signer: from.clone(),
        public_key: keypair.public_key(),
        nonce,
        action: transfer_action(to.clone(), amount_grains, tip_grains, auction_active),
    };
    SignedTransaction::sign_in(tx, &keypair, domain).map_err(|e| format!("signing failed: {e}"))
    // `keypair` drops here.
}

/// Parse a decimal XUS amount ("1.5") into grains (1 XUS = 100,000,000 grains).
/// Mirrors SOV-Station's `parse_xus` so the two tools read amounts identically.
pub fn parse_xus(s: &str) -> Option<u128> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if frac.len() > 8 || !frac.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || whole.is_empty() {
        return None;
    }
    let whole: u128 = whole.parse().ok()?;
    let mut frac_padded = frac.to_string();
    while frac_padded.len() < 8 {
        frac_padded.push('0');
    }
    let frac: u128 = frac_padded.parse().ok()?;
    whole.checked_mul(100_000_000)?.checked_add(frac)
}

/// Format grains as a plain decimal XUS string (no thousands separators).
pub fn grains_to_xus(grains: u128) -> String {
    let whole = grains / 100_000_000;
    let frac = grains % 100_000_000;
    if frac == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{}", format!("{frac:08}").trim_end_matches('0'))
    }
}

/// Format grains as XUS for DISPLAY: thousands-separated whole part, trailing
/// zeros trimmed, and never an empty string. This is the one formatter every
/// on-screen XUS figure goes through, so a balance in the wallet table, a tile
/// and a log line all read identically. [`grains_to_xus`] stays the plain
/// machine-readable form (no separators) for anything copied or parsed back.
pub fn fmt_xus(grains: u128) -> String {
    // Built ON the plain form, so the two can never disagree about a value: the
    // display version only groups the whole part.
    let plain = grains_to_xus(grains);
    let (whole, frac) = plain.split_once('.').unwrap_or((plain.as_str(), ""));
    // u64 covers the whole 21M-XUS supply many times over; saturate rather than
    // truncate silently if a caller ever hands us a nonsense value.
    let whole = fmt_count(whole.parse::<u64>().unwrap_or(u64::MAX));
    if frac.is_empty() {
        whole
    } else {
        format!("{whole}.{frac}")
    }
}

// ---------------------------------------------------------------------------
// Presentation logic — pure, bounded, panic-free. The GUI does no arithmetic
// of its own; everything that could divide by zero or produce a NaN lives here
// and is tested.
// ---------------------------------------------------------------------------

/// Width of the mempool scope's time axis, in seconds. The axis is FIXED at this
/// width and right-anchored on "now", so the trace scrolls left at a constant
/// speed instead of rescaling as history accumulates.
pub const SCOPE_WINDOW_SECS: u64 = 300;

/// Consecutive samples further apart than this are a data GAP, not a trend: the
/// scope breaks its trace there rather than drawing a straight line across
/// seconds in which the node told us nothing.
pub const SCOPE_GAP_MS: u64 = 4_000;

/// Round a peak depth up to a readable axis ceiling on the 1-2-5 ladder.
///
/// The floor of 100 matters for honesty: with a ceiling that hugs the data, a
/// pool holding three transactions would draw a full-height trace and read as
/// "saturated". Bounded — never zero (so [`scope_y`] can always divide by it)
/// and never overflows.
pub fn nice_ceiling(peak: u64) -> u64 {
    const FLOOR: u64 = 100;
    let p = peak.max(FLOOR);
    let mut mag: u64 = 1;
    // Largest power of ten <= p, saturating rather than wrapping.
    while mag <= p / 10 {
        match mag.checked_mul(10) {
            Some(next) => mag = next,
            None => return u64::MAX,
        }
    }
    for m in [1u64, 2, 5] {
        if let Some(c) = m.checked_mul(mag) {
            if p <= c {
                return c;
            }
        }
    }
    mag.saturating_mul(10)
}

/// Horizontal position of something `age_ms` old on a right-anchored time axis.
///
/// This is the primitive the axis furniture uses: an age is exact even when the
/// app has been open for less than one window, where subtracting from a
/// wall-clock stamp would saturate at zero and bunch every tick at the edge.
/// A zero `window_ms` yields `right` (no division by zero).
pub fn scope_x_age(age_ms: u64, window_ms: u64, left: f32, right: f32) -> f32 {
    if window_ms == 0 {
        return right;
    }
    let frac = (age_ms.min(window_ms) as f64 / window_ms as f64) as f32;
    right - (right - left) * frac
}

/// Horizontal position of a sample taken at `at_ms` on the same axis.
///
/// `now_ms` is the right edge and `now_ms - window_ms` the left edge; anything
/// older clamps to `left`, anything in the future clamps to `right`.
pub fn scope_x(at_ms: u64, now_ms: u64, window_ms: u64, left: f32, right: f32) -> f32 {
    scope_x_age(now_ms.saturating_sub(at_ms), window_ms, left, right)
}

/// Vertical position of a depth between `bottom` (zero) and `top` (`ceiling`).
/// A zero ceiling yields `bottom`; depths above the ceiling clamp to `top`.
pub fn scope_y(depth: u64, ceiling: u64, bottom: f32, top: f32) -> f32 {
    if ceiling == 0 {
        return bottom;
    }
    let frac = (depth as f64 / ceiling as f64).clamp(0.0, 1.0);
    bottom + (top - bottom) * frac as f32
}

/// How loaded the mempool is. Rendered as a WORD and a distinct glyph shape as
/// well as a color, so the state never depends on color perception.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pressure {
    /// Nothing pooled.
    Empty,
    /// Under a quarter full.
    Light,
    /// Filling — under 60%.
    Building,
    /// Under the saturation line — the pool is not draining as fast as we fill it.
    Heavy,
    /// At or above the saturation line: further submissions are being refused.
    Saturated,
}

impl Pressure {
    /// Bucket a depth against the pool capacity. A zero `cap` (unknown) reads as
    /// [`Pressure::Empty`] at depth 0 and [`Pressure::Building`] otherwise —
    /// never a fabricated percentage.
    pub fn of(depth: u64, cap: u64) -> Self {
        if depth == 0 {
            return Pressure::Empty;
        }
        if cap == 0 {
            return Pressure::Building;
        }
        let pct = depth as f64 / cap as f64;
        if pct >= 0.95 {
            Pressure::Saturated
        } else if pct >= 0.60 {
            Pressure::Heavy
        } else if pct >= 0.25 {
            Pressure::Building
        } else {
            Pressure::Light
        }
    }

    /// The word an operator reads.
    pub fn label(self) -> &'static str {
        match self {
            Pressure::Empty => "EMPTY",
            Pressure::Light => "LIGHT",
            Pressure::Building => "BUILDING",
            Pressure::Heavy => "HEAVY",
            Pressure::Saturated => "SATURATED",
        }
    }

    /// A shape that differs between levels independently of color.
    pub fn glyph(self) -> &'static str {
        match self {
            Pressure::Empty => "○",
            Pressure::Light => "◔",
            Pressure::Building => "◑",
            Pressure::Heavy => "◕",
            Pressure::Saturated => "●",
        }
    }
}

/// What is stopping a run from starting. Only ONE is reported — the first thing
/// the operator has to fix — so the control bar never nags with a list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blocker {
    /// No wallets unlocked yet.
    UnlockWallet,
    /// Wallets are unlocked but none is checked.
    SelectWallet,
    /// Not one usable destination address.
    AddDestination,
}

impl Blocker {
    /// The imperative the operator should act on.
    pub fn message(self) -> &'static str {
        match self {
            Blocker::UnlockWallet => "Unlock a wallet to arm the cannon",
            Blocker::SelectWallet => "Check at least one wallet to fire from",
            Blocker::AddDestination => "Add at least one destination address",
        }
    }
}

/// The first unmet precondition for firing, if any.
///
/// Node reachability is deliberately NOT a blocker: the workers retry a dead
/// node and recover by themselves, so an unreachable node is surfaced as a
/// warning in the status strip instead of locking the operator out.
pub fn first_blocker(wallets: usize, selected: usize, destinations: usize) -> Option<Blocker> {
    if wallets == 0 {
        Some(Blocker::UnlockWallet)
    } else if selected == 0 {
        Some(Blocker::SelectWallet)
    } else if destinations == 0 {
        Some(Blocker::AddDestination)
    } else {
        None
    }
}

/// Format a per-second rate with a stable width and consistent rounding.
/// Non-finite or negative input renders as the explicit unavailable dash — the
/// GUI never shows a made-up zero for a number it does not have.
pub fn fmt_rate(v: f64) -> String {
    if !v.is_finite() || v < 0.0 {
        return "—".into();
    }
    if v < 100.0 {
        format!("{v:.1}")
    } else {
        format!("{}", v.round() as u64)
    }
}

/// Group a count with thin thousands separators, so 16384 reads as 16,384.
pub fn fmt_count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    let first = digits.len() % 3;
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && i % 3 == first {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A percentage of `whole`, clamped to 0–100 and rendered with no decimals.
/// A zero `whole` is unknown, not zero percent — it renders as a dash.
pub fn fmt_pct(part: u64, whole: u64) -> String {
    if whole == 0 {
        return "—".into();
    }
    let pct = (part as f64 / whole as f64 * 100.0).clamp(0.0, 100.0);
    format!("{}%", pct.round() as u64)
}

/// A share in `0.0..=1.0` for bar widths; a zero or non-finite total gives 0.0.
/// Guaranteed finite and in range, so it can be handed straight to layout math.
pub fn share(part: f64, total: f64) -> f32 {
    if !part.is_finite() || !total.is_finite() || total <= 0.0 || part <= 0.0 {
        return 0.0;
    }
    (part / total).clamp(0.0, 1.0) as f32
}

/// Compact elapsed time: `12s`, `4m 07s`, `2h 13m`.
pub fn fmt_elapsed(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3_600 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h {:02}m", secs / 3_600, (secs % 3_600) / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(name: &str) -> AccountId {
        AccountId::new(name).unwrap()
    }

    // ---- Nonce sequencer ------------------------------------------------

    #[test]
    fn nonces_are_monotonic_and_gap_free_across_blocks() {
        // Start from account nonce 5; fire rate=3 for four blocks while nothing is
        // mined (the node keeps reporting 5). Expect 5,6,7,8,...,16 with no reuse.
        let mut seq = NonceSequencer::new();
        let mut handed = Vec::new();
        for _block in 0..4 {
            seq.reconcile(5); // node's next nonce, unchanged
            for _ in 0..3 {
                handed.push(seq.next());
            }
        }
        assert_eq!(handed, (5..17).collect::<Vec<u64>>());
        // Strictly increasing, no duplicates.
        for w in handed.windows(2) {
            assert!(w[1] == w[0] + 1);
        }
    }

    #[test]
    fn reconcile_jumps_forward_when_someone_else_spent() {
        let mut seq = NonceSequencer::new();
        seq.reconcile(5);
        assert_eq!(seq.next(), 5);
        assert_eq!(seq.next(), 6); // pending now 7
                                   // Node reports 9 (an external spend landed): jump forward, never reuse 7/8.
        seq.reconcile(9);
        assert_eq!(seq.next(), 9);
        assert_eq!(seq.peek(), 10);
    }

    #[test]
    fn reconcile_is_a_noop_when_node_is_behind_or_equal() {
        let mut seq = NonceSequencer::new();
        seq.reconcile(10);
        assert_eq!(seq.next(), 10);
        assert_eq!(seq.next(), 11); // pending 12 (our txs still in mempool)
                                    // Node still reports 10 (nothing mined yet) — must NOT rewind to 10.
        seq.reconcile(10);
        assert_eq!(seq.peek(), 12);
        seq.reconcile(5); // even further behind — still no rewind
        assert_eq!(seq.peek(), 12);
        assert_eq!(seq.next(), 12);
    }

    #[test]
    fn reconcile_after_our_txs_mine_continues_without_gap() {
        let mut seq = NonceSequencer::new();
        seq.reconcile(0);
        let first: Vec<u64> = (0..3).map(|_| seq.next()).collect();
        assert_eq!(first, vec![0, 1, 2]);
        // Our 3 txs mined ⇒ node now reports next nonce 3. Continue 3,4,5.
        seq.reconcile(3);
        let second: Vec<u64> = (0..3).map(|_| seq.next()).collect();
        assert_eq!(second, vec![3, 4, 5]);
    }

    // ---- Commit-on-accept nonce flow (continuous modes) -----------------

    /// The scripted outcome of one simulated submit at the peeked nonce.
    enum Sim {
        Accept,
        Reject(RejectClass),
        /// Reject with the node's next nonce to reconcile against.
        StaleWithNodeNonce(u64),
    }

    /// Drive the peek → submit → commit flow the continuous worker uses and
    /// return every nonce actually SUBMITTED, in order.
    fn drive(seq: &mut NonceSequencer, script: &[Sim]) -> Vec<u64> {
        let mut submitted = Vec::new();
        for step in script {
            let nonce = seq.peek();
            submitted.push(nonce); // build+sign+submit happens at the peeked nonce
            match step {
                Sim::Accept => seq.advance(),
                Sim::StaleWithNodeNonce(node_next) => {
                    assert_eq!(
                        disposition(RejectClass::NonceStale),
                        Disposition::ReconcileForward
                    );
                    seq.reconcile(*node_next);
                }
                Sim::Reject(class) => match disposition(*class) {
                    Disposition::HoldAndRetry
                    | Disposition::HoldAndRetryOther
                    | Disposition::WaitAffordable => {}
                    Disposition::Advance => seq.advance(),
                    Disposition::ReconcileForward => unreachable!("use StaleWithNodeNonce"),
                },
            }
        }
        submitted
    }

    #[test]
    fn advance_only_on_accept_keeps_the_stream_gap_free() {
        let mut seq = NonceSequencer::new();
        seq.reconcile(10);
        let submitted = drive(
            &mut seq,
            &[
                Sim::Accept,                             // 10 accepted
                Sim::Reject(RejectClass::Capacity),      // 11 mempool-full → hold
                Sim::Reject(RejectClass::Capacity),      // 11 again → hold
                Sim::Accept,                             // 11 finally accepted
                Sim::Reject(RejectClass::Other),         // 12 unknown → hold
                Sim::Accept,                             // 12 accepted
                Sim::Reject(RejectClass::NonceOccupied), // 13 already pooled → advance
                Sim::Accept,                             // 14 accepted
            ],
        );
        assert_eq!(submitted, vec![10, 11, 11, 11, 12, 12, 13, 14]);
        // The COMMITTED sequence (unique nonces, in order) has no gap and no burn.
        let mut committed = submitted.clone();
        committed.dedup();
        assert_eq!(committed, vec![10, 11, 12, 13, 14]);
        assert_eq!(seq.peek(), 15);
    }

    #[test]
    fn capacity_reject_never_burns_a_nonce() {
        let mut seq = NonceSequencer::new();
        seq.reconcile(0);
        // 100 consecutive mempool-full rejections: the nonce must not move.
        let submitted = drive(
            &mut seq,
            &(0..100)
                .map(|_| Sim::Reject(RejectClass::Capacity))
                .collect::<Vec<_>>(),
        );
        assert!(submitted.iter().all(|&n| n == 0));
        assert_eq!(seq.peek(), 0);
        // The moment capacity frees up, the SAME nonce goes through.
        let after = drive(&mut seq, &[Sim::Accept]);
        assert_eq!(after, vec![0]);
        assert_eq!(seq.peek(), 1);
    }

    #[test]
    fn stale_reject_reconciles_forward_to_the_node() {
        let mut seq = NonceSequencer::new();
        seq.reconcile(5);
        // Our txs 5..8 mined while we were building 5 (stale view): the node now
        // reports next nonce 8 — jump forward, continue gap-free from 8.
        let submitted = drive(
            &mut seq,
            &[Sim::StaleWithNodeNonce(8), Sim::Accept, Sim::Accept],
        );
        assert_eq!(submitted, vec![5, 8, 9]);
        assert_eq!(seq.peek(), 10);
    }

    #[test]
    fn insufficient_waits_and_recovers_holding_the_nonce() {
        // The refire-after-Stop scenario: the previous run's pending txs still
        // commit the balance, the node rejects with "insufficient", and the
        // worker must HOLD the nonce and continue once balance frees — never die.
        let mut seq = NonceSequencer::new();
        seq.reconcile(3);
        let submitted = drive(
            &mut seq,
            &[
                Sim::Accept,
                Sim::Reject(RejectClass::Insufficient),
                Sim::Accept,
            ],
        );
        // The affordability rejection holds nonce 4; the next accept fires it.
        assert_eq!(submitted, vec![3, 4, 4]);
        assert_eq!(seq.peek(), 5);
    }

    // ---- Rejection classification (real node strings) --------------------

    #[test]
    fn classifies_the_nodes_real_rejection_strings() {
        // Full client-visible wrapping: RpcClientError::Rpc → "rpc error CODE: "
        // + RPC server → "rejected: " + NodeError::Mempool → "mempool rejected
        // transaction: " + the MempoolError display strings.
        let wrap = |inner: &str| {
            format!("rpc error -32000: rejected: mempool rejected transaction: {inner}")
        };

        assert_eq!(
            classify_reject(&wrap("mempool is full (16384 transactions)")),
            RejectClass::Capacity
        );
        assert_eq!(
            classify_reject(&wrap(
                "sender 81f4ccaa has reached its mempool limit of 256 pending transactions"
            )),
            RejectClass::Capacity
        );
        assert_eq!(
            classify_reject(&wrap(
                "stale transaction: account is at nonce 12, transaction used 7"
            )),
            RejectClass::NonceStale
        );
        assert_eq!(
            classify_reject(&wrap("transaction already in the pool")),
            RejectClass::NonceOccupied
        );
        assert_eq!(
            classify_reject(&wrap(
                "a transaction with signer cannon.sov and nonce 9 is already pooled"
            )),
            RejectClass::NonceOccupied
        );
        assert_eq!(
            classify_reject(&wrap(
                "insufficient balance: pooled transfers would move 500 grains but only 100 are held"
            )),
            RejectClass::Insufficient
        );
        assert_eq!(
            classify_reject(&wrap("invalid transaction signature")),
            RejectClass::Other
        );
        // Non-mempool rejections and transport failures → the default bucket.
        assert_eq!(
            classify_reject(
                "rpc error -32000: rejected: unauthorized: x.sov cannot be acted on by this key"
            ),
            RejectClass::Other
        );
        assert_eq!(
            classify_reject("transport: Connection refused (os error 61)"),
            RejectClass::Other
        );
    }

    #[test]
    fn dispositions_cover_every_class_correctly() {
        assert_eq!(
            disposition(RejectClass::Capacity),
            Disposition::HoldAndRetry
        );
        assert_eq!(
            disposition(RejectClass::NonceStale),
            Disposition::ReconcileForward
        );
        assert_eq!(
            disposition(RejectClass::NonceOccupied),
            Disposition::Advance
        );
        assert_eq!(
            disposition(RejectClass::Insufficient),
            Disposition::WaitAffordable
        );
        assert_eq!(
            disposition(RejectClass::Other),
            Disposition::HoldAndRetryOther
        );
    }

    // ---- Pacer (Target TX/s) ---------------------------------------------

    #[test]
    fn pacer_tracks_the_cumulative_target_over_regular_ticks() {
        // 7 TX/s sampled every 100 ms for 3 s: cumulative issued must equal
        // floor(elapsed × 7) at every tick — no runaway, no starvation.
        let mut pacer = Pacer::new(7.0);
        let mut issued = 0u64;
        for tick in 1..=30u64 {
            let elapsed = Duration::from_millis(tick * 100);
            issued += pacer.take_due(elapsed);
            let ideal = (elapsed.as_secs_f64() * 7.0) as u64;
            assert_eq!(issued, ideal, "tick {tick}");
        }
        assert_eq!(issued, 21); // exactly 3 s × 7 TX/s
    }

    #[test]
    fn pacer_sub_one_tps_is_not_starved() {
        // 0.5 TX/s: exactly one send every 2 s, none before.
        let mut pacer = Pacer::new(0.5);
        assert_eq!(pacer.take_due(Duration::from_millis(500)), 0);
        assert_eq!(pacer.take_due(Duration::from_millis(1999)), 0);
        assert_eq!(pacer.take_due(Duration::from_millis(2000)), 1);
        assert_eq!(pacer.take_due(Duration::from_millis(3900)), 0);
        assert_eq!(pacer.take_due(Duration::from_millis(4000)), 1);
    }

    #[test]
    fn pacer_caps_catchup_after_a_stall_and_drops_the_backlog() {
        // 10 TX/s but the first tick comes after a 5 s stall: at most one
        // second's worth (10) is due, and the missed 40 are dropped — the next
        // regular tick issues only its incremental share.
        let mut pacer = Pacer::new(10.0);
        assert_eq!(pacer.take_due(Duration::from_secs(5)), 10);
        assert_eq!(pacer.take_due(Duration::from_millis(5100)), 1);
        assert_eq!(pacer.take_due(Duration::from_millis(5200)), 1);
    }

    #[test]
    fn pacer_never_goes_backwards_or_double_issues() {
        let mut pacer = Pacer::new(3.0);
        assert_eq!(pacer.take_due(Duration::from_secs(1)), 3);
        // The same instant again: nothing further is due.
        assert_eq!(pacer.take_due(Duration::from_secs(1)), 0);
        // A (nonsensical) earlier instant must not underflow or issue.
        assert_eq!(pacer.take_due(Duration::from_millis(500)), 0);
        assert_eq!(pacer.take_due(Duration::from_secs(2)), 3);
    }

    // ---- Rate meter -------------------------------------------------------

    #[test]
    fn meter_counts_rates_over_the_window_and_totals_forever() {
        let mut m = RateMeter::new(5);
        // 10 accepted events spread over seconds 0..=4 (2 per second).
        for sec in 0..5u64 {
            for i in 0..2u64 {
                m.record(sec * 1000 + i * 100, MeterKind::Accepted);
            }
        }
        let now = 4_900; // still inside second 4
        assert_eq!(m.rate(now, MeterKind::Accepted), 2.0); // 10 events / 5 s
        assert_eq!(m.total(MeterKind::Accepted), 10);
        assert_eq!(m.rate(now, MeterKind::RejCapacity), 0.0);

        // 10 seconds later the window is empty — rate decays to 0, totals stay.
        let later = 15_000;
        m.record(later, MeterKind::RejCapacity);
        assert_eq!(m.rate(later, MeterKind::Accepted), 0.0);
        assert_eq!(m.rate(later, MeterKind::RejCapacity), 1.0 / 5.0);
        assert_eq!(m.total(MeterKind::Accepted), 10);
        assert_eq!(m.total(MeterKind::RejCapacity), 1);
    }

    #[test]
    fn meter_burst_in_one_second_averages_across_the_window() {
        let mut m = RateMeter::new(5);
        for _ in 0..50 {
            m.record(10_000, MeterKind::Attempted); // 50 events in second 10
        }
        assert_eq!(m.rate(10_500, MeterKind::Attempted), 10.0); // 50 / 5 s
        assert_eq!(m.total(MeterKind::Attempted), 50);
    }

    // ---- Destination selection -----------------------------------------

    #[test]
    fn round_robin_cycles_in_order() {
        let dests = vec![acct("alice.sov"), acct("bob.sov"), acct("carol.sov")];
        let mut sel = DestSelector::new(dests.clone(), DestMode::RoundRobin).unwrap();
        let mut rng = Rng::seeded(1);
        let picked: Vec<AccountId> = (0..7).map(|_| sel.next(&mut rng)).collect();
        assert_eq!(
            picked,
            vec![
                dests[0].clone(),
                dests[1].clone(),
                dests[2].clone(),
                dests[0].clone(),
                dests[1].clone(),
                dests[2].clone(),
                dests[0].clone(),
            ]
        );
    }

    #[test]
    fn random_stays_within_the_list() {
        let dests = vec![acct("alice.sov"), acct("bob.sov"), acct("carol.sov")];
        let mut sel = DestSelector::new(dests.clone(), DestMode::Random).unwrap();
        let mut rng = Rng::seeded(42);
        for _ in 0..1000 {
            let d = sel.next(&mut rng);
            assert!(dests.contains(&d), "random picked an out-of-list address");
        }
    }

    #[test]
    fn empty_destination_list_is_rejected() {
        assert!(DestSelector::new(vec![], DestMode::RoundRobin).is_err());
    }

    // ---- Amount selection ----------------------------------------------

    #[test]
    fn fixed_amount_returns_the_fixed_value() {
        let mode = AmountMode::Fixed(12_345);
        let mut rng = Rng::seeded(7);
        for _ in 0..100 {
            assert_eq!(mode.pick(&mut rng), 12_345);
        }
    }

    #[test]
    fn range_amount_stays_within_bounds_inclusive() {
        let mode = AmountMode::Range { min: 100, max: 200 };
        mode.validate().unwrap();
        let mut rng = Rng::seeded(99);
        let mut saw_min = false;
        let mut saw_max = false;
        for _ in 0..20_000 {
            let v = mode.pick(&mut rng);
            assert!((100..=200).contains(&v), "amount {v} out of [100,200]");
            saw_min |= v == 100;
            saw_max |= v == 200;
        }
        // Both inclusive endpoints must be reachable.
        assert!(saw_min, "min endpoint never produced");
        assert!(saw_max, "max endpoint never produced");
    }

    #[test]
    fn degenerate_range_min_equals_max_is_constant() {
        let mode = AmountMode::Range { min: 50, max: 50 };
        mode.validate().unwrap();
        let mut rng = Rng::seeded(3);
        for _ in 0..100 {
            assert_eq!(mode.pick(&mut rng), 50);
        }
    }

    #[test]
    fn amount_validation_rejects_bad_shapes() {
        assert!(AmountMode::Fixed(0).validate().is_err());
        assert!(AmountMode::Range { min: 10, max: 5 }.validate().is_err());
        assert!(AmountMode::Range { min: 0, max: 0 }.validate().is_err());
        assert!(AmountMode::Fixed(1).validate().is_ok());
        assert!(AmountMode::Range { min: 0, max: 1 }.validate().is_ok());
    }

    // ---- Tip mode + auction gating -------------------------------------

    #[test]
    fn tip_off_is_always_zero() {
        let mut rng = Rng::seeded(1);
        for _ in 0..100 {
            assert_eq!(TipMode::Off.pick(&mut rng), 0);
        }
    }

    #[test]
    fn tip_fixed_returns_the_fixed_value() {
        let mode = TipMode::Fixed(5_000);
        let mut rng = Rng::seeded(7);
        for _ in 0..100 {
            assert_eq!(mode.pick(&mut rng), 5_000);
        }
    }

    #[test]
    fn tip_range_stays_within_bounds_inclusive() {
        let mode = TipMode::Range {
            min: 1_000,
            max: 9_000,
        };
        mode.validate().unwrap();
        let mut rng = Rng::seeded(99);
        let (mut saw_min, mut saw_max) = (false, false);
        for _ in 0..20_000 {
            let v = mode.pick(&mut rng);
            assert!((1_000..=9_000).contains(&v), "tip {v} out of range");
            saw_min |= v == 1_000;
            saw_max |= v == 9_000;
        }
        assert!(saw_min && saw_max, "both inclusive endpoints reachable");
    }

    #[test]
    fn tip_validation_rejects_inverted_range() {
        assert!(TipMode::Range { min: 10, max: 5 }.validate().is_err());
        assert!(TipMode::Range { min: 0, max: 0 }.validate().is_ok());
        assert!(TipMode::Fixed(0).validate().is_ok());
        assert!(TipMode::Off.validate().is_ok());
    }

    #[test]
    fn transfer_action_wraps_only_when_auction_live_and_tip_nonzero() {
        let to = acct("sink.sov");
        // Dormant fork: NEVER a Tipped envelope, even with a nonzero bid — the
        // action is byte-identical to a pre-auction transfer.
        match transfer_action(to.clone(), 100, 5_000, false) {
            Action::Transfer { to: t, amount } => {
                assert_eq!(t, to);
                assert_eq!(amount, Balance::from_grains(100));
            }
            other => panic!("dormant fork must emit a bare Transfer, got {other:?}"),
        }
        // Live fork, zero tip: still bare (a zero bid is a legacy transaction).
        assert!(matches!(
            transfer_action(to.clone(), 100, 0, true),
            Action::Transfer { .. }
        ));
        // Live fork, nonzero tip: a Tipped envelope carrying the inner Transfer.
        match transfer_action(to.clone(), 100, 5_000, true) {
            Action::Tipped { tip, inner } => {
                assert_eq!(tip, Balance::from_grains(5_000));
                match *inner {
                    Action::Transfer { to: t, amount } => {
                        assert_eq!(t, to);
                        assert_eq!(amount, Balance::from_grains(100));
                    }
                    other => panic!("inner must be the Transfer, got {other:?}"),
                }
            }
            other => panic!("live auction + tip must emit Tipped, got {other:?}"),
        }
    }

    #[test]
    fn tipped_transfer_builds_signs_and_verifies() {
        // A tipped envelope from the real signing path verifies and carries the tip.
        let seed = [4u8; 32];
        let from = acct("cannon.sov");
        let to = acct("target.sov");
        let stx = build_signed_transfer(
            &seed,
            KeyScheme::Ed25519,
            &from,
            &to,
            42_000,
            7_000, // tip
            true,  // auction active
            3,
            None,
        )
        .unwrap();
        assert!(stx.verify_signature(), "tipped tx signature must verify");
        match &stx.transaction.action {
            Action::Tipped { tip, inner } => {
                assert_eq!(*tip, Balance::from_grains(7_000));
                assert!(matches!(**inner, Action::Transfer { .. }));
            }
            other => panic!("expected Tipped, got {other:?}"),
        }
        // Same inputs but a dormant fork: the SAME bytes as an untipped transfer,
        // proving the cannon never changes the wire form until the fork is live.
        let dormant = build_signed_transfer(
            &seed,
            KeyScheme::Ed25519,
            &from,
            &to,
            42_000,
            7_000, // tip requested…
            false, // …but auction dormant ⇒ ignored
            3,
            None,
        )
        .unwrap();
        let untipped = build_signed_transfer(
            &seed,
            KeyScheme::Ed25519,
            &from,
            &to,
            42_000,
            0,
            false,
            3,
            None,
        )
        .unwrap();
        assert_eq!(
            borsh::to_vec(&dormant).unwrap(),
            borsh::to_vec(&untipped).unwrap(),
            "a dormant fork must emit byte-identical (untipped) transactions"
        );
    }

    #[test]
    fn fee_auction_gate_reads_only_an_active_deployment() {
        use serde_json::json;
        // Active ⇒ true (the one shape that lets a tip be attached).
        let active = json!({
            "height": 11_600,
            "deployments": [
                {"name": "tx-domain", "state": "Active"},
                {"name": "fee-auction", "state": "Active"},
            ]
        });
        assert!(parse_fee_auction_active(&active));

        // Every non-Active state reads as dormant — fail-closed.
        for state in ["Defined", "Started", "LockedIn", "Failed"] {
            let v = json!({"deployments": [{"name": "fee-auction", "state": state}]});
            assert!(
                !parse_fee_auction_active(&v),
                "state {state} must not activate tips"
            );
        }
        // fee-auction absent ⇒ dormant (an older node signalling only tx-domain).
        let only_txd = json!({"deployments": [{"name": "tx-domain", "state": "Active"}]});
        assert!(!parse_fee_auction_active(&only_txd));
        // A node too old to report deployments at all ⇒ dormant.
        assert!(!parse_fee_auction_active(&json!({})));
        assert!(!parse_fee_auction_active(&json!({"deployments": []})));
        assert!(!parse_fee_auction_active(&json!("garbage")));
    }

    // ---- Tx construction + signing -------------------------------------

    #[test]
    fn derived_id_matches_node_derivation_and_is_not_the_label() {
        let seed = [9u8; 32];
        // Matches the node's rule exactly for both schemes.
        for scheme in [KeyScheme::Hybrid65, KeyScheme::Ed25519] {
            let got = derive_account_id(&seed, scheme);
            let want = scheme
                .keypair_from_seed(&seed)
                .public_key()
                .implicit_account_id();
            assert_eq!(got, want);
            // A 64-hex implicit id — never a human label like "my-wallet".
            assert_eq!(got.as_str().len(), 64);
            assert!(got.as_str().chars().all(|c| c.is_ascii_hexdigit()));
            assert_ne!(got.as_str(), "my-wallet");
        }
        // The two schemes derive DIFFERENT ids from the same seed.
        assert_ne!(
            derive_account_id(&seed, KeyScheme::Hybrid65),
            derive_account_id(&seed, KeyScheme::Ed25519)
        );
    }

    #[test]
    fn built_transfer_verifies_and_has_correct_fields() {
        // A deterministic test seed; ed25519/Sha256d-test scheme (never RandomX).
        let seed = [7u8; 32];
        let from = acct("cannon.sov");
        let to = acct("target.sov");
        let stx = build_signed_transfer(
            &seed,
            KeyScheme::Ed25519,
            &from,
            &to,
            42_000,
            0,
            false,
            9,
            None,
        )
        .unwrap();

        // Signature verifies against the committed public key.
        assert!(stx.verify_signature(), "signature must verify");

        // Fields are exactly what we asked for.
        assert_eq!(stx.transaction.signer, from);
        assert_eq!(stx.transaction.nonce, 9);
        match &stx.transaction.action {
            Action::Transfer { to: got_to, amount } => {
                assert_eq!(got_to, &to);
                assert_eq!(*amount, Balance::from_grains(42_000));
            }
            other => panic!("expected Transfer, got {other:?}"),
        }
        // The committed public key is the one derived from our seed.
        let expected_pk = Keypair::from_seed(seed).public_key();
        assert_eq!(stx.transaction.public_key, expected_pk);
    }

    #[test]
    fn domain_bound_transfer_verifies_only_under_its_domain() {
        use sov_primitives::Hash;
        let seed = [7u8; 32];
        let from = acct("cannon.sov");
        let to = acct("target.sov");
        let domain = SigningDomain::new("sov-mainnet", Hash::digest(b"g"));
        let bound = build_signed_transfer(
            &seed,
            KeyScheme::Ed25519,
            &from,
            &to,
            42_000,
            0,
            false,
            9,
            Some(&domain),
        )
        .unwrap();
        assert!(bound.verify_signature_in(Some(&domain)));
        assert!(!bound.verify_signature(), "bound sig must NOT pass legacy");
        // The tx id is domain-independent (hash of the un-framed body).
        let legacy = build_signed_transfer(
            &seed,
            KeyScheme::Ed25519,
            &from,
            &to,
            42_000,
            0,
            false,
            9,
            None,
        )
        .unwrap();
        assert_eq!(bound.id(), legacy.id());
    }

    #[test]
    fn built_transfer_round_trips_through_borsh_and_still_verifies() {
        let seed = [3u8; 32];
        let stx = build_signed_transfer(
            &seed,
            KeyScheme::Hybrid65,
            &acct("cannon.sov"),
            &acct("target.sov"),
            1,
            0,
            false,
            0,
            None,
        )
        .unwrap();
        let bytes = borsh::to_vec(&stx).unwrap();
        let decoded: SignedTransaction = borsh::from_slice(&bytes).unwrap();
        assert_eq!(decoded, stx);
        assert!(decoded.verify_signature());
    }

    #[test]
    fn hybrid_and_ed25519_derive_distinct_keys() {
        let seed = [5u8; 32];
        let ed = KeyScheme::Ed25519.keypair_from_seed(&seed).public_key();
        let hy = KeyScheme::Hybrid65.keypair_from_seed(&seed).public_key();
        assert_ne!(ed, hy);
    }

    #[test]
    fn key_scheme_parsing_matches_keystore_conventions() {
        assert_eq!(KeyScheme::from_keystore(None), Ok(KeyScheme::Ed25519));
        assert_eq!(
            KeyScheme::from_keystore(Some("ed25519")),
            Ok(KeyScheme::Ed25519)
        );
        assert_eq!(
            KeyScheme::from_keystore(Some("hybrid65")),
            Ok(KeyScheme::Hybrid65)
        );
        assert!(KeyScheme::from_keystore(Some("dilithium")).is_err());
    }

    // ---- Amount parsing -------------------------------------------------

    #[test]
    fn parse_xus_round_trips_common_values() {
        assert_eq!(parse_xus("1"), Some(100_000_000));
        assert_eq!(parse_xus("1.5"), Some(150_000_000));
        assert_eq!(parse_xus("0.00000001"), Some(1));
        assert_eq!(parse_xus("0"), Some(0));
        assert_eq!(parse_xus(""), None);
        assert_eq!(parse_xus("1.234567890"), None); // too many decimals
        assert_eq!(parse_xus("abc"), None);
        assert_eq!(grains_to_xus(150_000_000), "1.5");
        assert_eq!(grains_to_xus(100_000_000), "1");
        assert_eq!(grains_to_xus(1), "0.00000001");
    }

    // ---- Scope axis scaling (must be bounded + panic-free) ---------------

    #[test]
    fn nice_ceiling_climbs_the_1_2_5_ladder_and_never_hugs_the_data() {
        // The floor keeps a nearly-empty pool from drawing as a full-height trace.
        assert_eq!(nice_ceiling(0), 100);
        assert_eq!(nice_ceiling(3), 100);
        assert_eq!(nice_ceiling(100), 100);
        assert_eq!(nice_ceiling(101), 200);
        assert_eq!(nice_ceiling(200), 200);
        assert_eq!(nice_ceiling(201), 500);
        assert_eq!(nice_ceiling(500), 500);
        assert_eq!(nice_ceiling(501), 1_000);
        assert_eq!(nice_ceiling(16_384), 20_000);
        assert_eq!(nice_ceiling(20_001), 50_000);
        // Always >= the peak, always non-zero, for a wide sweep of inputs.
        for peak in (0..200_000u64).step_by(97) {
            let c = nice_ceiling(peak);
            assert!(c >= peak, "ceiling {c} below peak {peak}");
            assert!(c > 0);
        }
        // Extreme input saturates instead of overflowing.
        assert!(nice_ceiling(u64::MAX) >= u64::MAX / 2);
    }

    #[test]
    fn scope_x_is_right_anchored_and_clamped_to_the_axis() {
        let (l, r) = (10.0f32, 110.0f32);
        let now = 600_000u64;
        let win = 300_000u64;
        // "Now" sits on the right edge; a full window ago on the left edge.
        assert!((scope_x(now, now, win, l, r) - r).abs() < 1e-3);
        assert!((scope_x(now - win, now, win, l, r) - l).abs() < 1e-3);
        // Halfway is the midpoint.
        assert!((scope_x(now - win / 2, now, win, l, r) - 60.0).abs() < 1e-3);
        // Older than the window clamps to the left edge (never off-canvas).
        assert!((scope_x(0, now, win, l, r) - l).abs() < 1e-3);
        // A future stamp (clock skew) clamps to the right edge, not past it.
        assert!((scope_x(now + 90_000, now, win, l, r) - r).abs() < 1e-3);
        // Degenerate window: no division by zero, no NaN.
        let x = scope_x(5, 10, 0, l, r);
        assert!(x.is_finite() && (x - r).abs() < 1e-3);
    }

    #[test]
    fn scope_x_age_spreads_ticks_even_before_a_full_window_has_elapsed() {
        let (l, r) = (0.0f32, 300.0f32);
        let win = 300_000u64;
        // The minute ticks of a 5-minute axis are evenly spaced from the first
        // second the app is open — the failure mode this replaced bunched every
        // tick against the right edge until 5 minutes had passed.
        let xs: Vec<f32> = (0..=5)
            .map(|m| scope_x_age(m * 60_000, win, l, r))
            .collect();
        assert_eq!(xs, vec![300.0, 240.0, 180.0, 120.0, 60.0, 0.0]);
        // Older than the window still clamps onto the axis.
        assert!((scope_x_age(999_999, win, l, r) - l).abs() < 1e-3);
        assert!((scope_x_age(0, 0, l, r) - r).abs() < 1e-3);
    }

    #[test]
    fn scope_y_is_clamped_between_baseline_and_ceiling() {
        // egui's y grows downward: bottom > top.
        let (bottom, top) = (200.0f32, 20.0f32);
        assert!((scope_y(0, 1_000, bottom, top) - bottom).abs() < 1e-3);
        assert!((scope_y(1_000, 1_000, bottom, top) - top).abs() < 1e-3);
        assert!((scope_y(500, 1_000, bottom, top) - 110.0).abs() < 1e-3);
        // Above the ceiling clamps to the top rather than drawing off-canvas.
        assert!((scope_y(9_999, 1_000, bottom, top) - top).abs() < 1e-3);
        // Zero ceiling can't divide by zero.
        assert!((scope_y(7, 0, bottom, top) - bottom).abs() < 1e-3);
        // Never NaN or infinite, for any pair.
        for d in [0u64, 1, 12_345, u64::MAX] {
            for c in [0u64, 1, 16_384, u64::MAX] {
                assert!(scope_y(d, c, bottom, top).is_finite());
            }
        }
    }

    // ---- Pressure bucketing ----------------------------------------------

    #[test]
    fn pressure_buckets_match_the_saturation_line() {
        let cap = 16_384u64;
        assert_eq!(Pressure::of(0, cap), Pressure::Empty);
        assert_eq!(Pressure::of(1, cap), Pressure::Light);
        assert_eq!(Pressure::of(cap / 4 - 1, cap), Pressure::Light);
        assert_eq!(Pressure::of(cap / 4 + 1, cap), Pressure::Building);
        assert_eq!(Pressure::of(cap * 7 / 10, cap), Pressure::Heavy);
        assert_eq!(Pressure::of(cap * 96 / 100, cap), Pressure::Saturated);
        assert_eq!(Pressure::of(cap, cap), Pressure::Saturated);
        // Over capacity is still saturated, not something stranger.
        assert_eq!(Pressure::of(cap * 3, cap), Pressure::Saturated);
        // Unknown capacity is never rendered as a percentage.
        assert_eq!(Pressure::of(0, 0), Pressure::Empty);
        assert_eq!(Pressure::of(5, 0), Pressure::Building);
    }

    #[test]
    fn every_pressure_level_has_a_distinct_word_and_shape() {
        let levels = [
            Pressure::Empty,
            Pressure::Light,
            Pressure::Building,
            Pressure::Heavy,
            Pressure::Saturated,
        ];
        let labels: std::collections::HashSet<_> = levels.iter().map(|p| p.label()).collect();
        let glyphs: std::collections::HashSet<_> = levels.iter().map(|p| p.glyph()).collect();
        // Accessibility: state is never encoded by color alone.
        assert_eq!(labels.len(), levels.len());
        assert_eq!(glyphs.len(), levels.len());
    }

    // ---- Readiness --------------------------------------------------------

    #[test]
    fn first_blocker_reports_one_actionable_thing_at_a_time() {
        assert_eq!(first_blocker(0, 0, 0), Some(Blocker::UnlockWallet));
        assert_eq!(first_blocker(3, 0, 2), Some(Blocker::SelectWallet));
        assert_eq!(first_blocker(3, 1, 0), Some(Blocker::AddDestination));
        assert_eq!(first_blocker(3, 1, 1), None);
        // Each blocker states what to DO.
        for b in [
            Blocker::UnlockWallet,
            Blocker::SelectWallet,
            Blocker::AddDestination,
        ] {
            assert!(!b.message().is_empty());
        }
    }

    // ---- Formatting -------------------------------------------------------

    #[test]
    fn fmt_rate_is_stable_and_never_invents_a_zero() {
        assert_eq!(fmt_rate(0.0), "0.0");
        assert_eq!(fmt_rate(1.25), "1.2"); // banker-free, plain rounding
        assert_eq!(fmt_rate(99.94), "99.9");
        assert_eq!(fmt_rate(100.4), "100");
        assert_eq!(fmt_rate(12_345.6), "12346");
        // Unavailable stays unavailable — never rendered as 0.
        assert_eq!(fmt_rate(f64::NAN), "—");
        assert_eq!(fmt_rate(f64::INFINITY), "—");
        assert_eq!(fmt_rate(-1.0), "—");
    }

    #[test]
    fn fmt_count_groups_thousands() {
        assert_eq!(fmt_count(0), "0");
        assert_eq!(fmt_count(7), "7");
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_count(1_000), "1,000");
        assert_eq!(fmt_count(16_384), "16,384");
        assert_eq!(fmt_count(1_234_567), "1,234,567");
        assert_eq!(fmt_count(u64::MAX), "18,446,744,073,709,551,615");
    }

    #[test]
    fn fmt_pct_is_clamped_and_unknown_stays_unknown() {
        assert_eq!(fmt_pct(0, 100), "0%");
        assert_eq!(fmt_pct(50, 100), "50%");
        assert_eq!(fmt_pct(100, 100), "100%");
        assert_eq!(fmt_pct(300, 100), "100%"); // over cap clamps, never 300%
        assert_eq!(fmt_pct(5, 0), "—"); // unknown capacity, not "0%"
    }

    #[test]
    fn share_is_always_a_finite_fraction() {
        assert_eq!(share(1.0, 4.0), 0.25);
        assert_eq!(share(9.0, 4.0), 1.0);
        assert_eq!(share(0.0, 0.0), 0.0);
        assert_eq!(share(1.0, 0.0), 0.0);
        assert_eq!(share(f64::NAN, 1.0), 0.0);
        assert_eq!(share(1.0, f64::NAN), 0.0);
        assert_eq!(share(-3.0, 4.0), 0.0);
        for (p, t) in [(0.0, 1.0), (1e18, 1.0), (1.0, 1e18)] {
            let s = share(p, t);
            assert!(s.is_finite() && (0.0..=1.0).contains(&s));
        }
    }

    #[test]
    fn fmt_elapsed_reads_naturally_at_every_scale() {
        assert_eq!(fmt_elapsed(0), "0s");
        assert_eq!(fmt_elapsed(59), "59s");
        assert_eq!(fmt_elapsed(60), "1m 00s");
        assert_eq!(fmt_elapsed(127), "2m 07s");
        assert_eq!(fmt_elapsed(3_599), "59m 59s");
        assert_eq!(fmt_elapsed(3_600), "1h 00m");
        assert_eq!(fmt_elapsed(7_980), "2h 13m");
    }

    #[test]
    fn fmt_xus_is_grouped_trimmed_and_never_empty() {
        assert_eq!(fmt_xus(0), "0");
        assert_eq!(fmt_xus(100_000_000), "1");
        assert_eq!(fmt_xus(21_000), "0.00021");
        assert_eq!(fmt_xus(50_000), "0.0005");
        assert_eq!(fmt_xus(1_234_500_000_000), "12,345");
        assert_eq!(fmt_xus(1_234_500_000_001), "12,345.00000001");
        // Same value, two renderings: machine-readable vs grouped for display.
        assert_eq!(grains_to_xus(1_234_500_000_000), "12345");
    }

    // ---- Heartbeat: cadence ---------------------------------------------

    #[test]
    fn cadence_converts_human_terms_to_an_interval() {
        // 2 tx per 150 s block = one every 75 s.
        assert_eq!(Cadence::PerBlock(2.0).interval_ms(), Ok(75_000));
        assert_eq!(Cadence::PerBlock(1.0).interval_ms(), Ok(150_000));
        assert_eq!(Cadence::PerBlock(0.5).interval_ms(), Ok(300_000));
        assert_eq!(Cadence::EverySecs(30.0).interval_ms(), Ok(30_000));
        // Both framings describe the same cadence.
        assert_eq!(
            Cadence::PerBlock(2.0).interval_ms(),
            Cadence::EverySecs(75.0).interval_ms()
        );
        // Out of band, in either framing, is a refusal with a reason — not a
        // silently clamped firehose.
        assert!(Cadence::PerBlock(100.0).interval_ms().is_err());
        assert!(Cadence::EverySecs(1.0).interval_ms().is_err());
        assert!(Cadence::EverySecs(7_200.0).interval_ms().is_err());
        assert!(Cadence::PerBlock(0.0).interval_ms().is_err());
        assert!(Cadence::PerBlock(f64::NAN).interval_ms().is_err());
        assert!(Cadence::EverySecs(-5.0).interval_ms().is_err());
        // The description carries BOTH human framings.
        let d = Cadence::PerBlock(2.0).describe();
        assert!(d.contains("2.00 tx/block"), "{d}");
        assert!(d.contains("75 s"), "{d}");
    }

    /// Run a heartbeat against a scripted clock and return the instants at which
    /// it actually submitted. `step_ms` is the polling granularity of the worker
    /// loop; `stalls` inserts a jump of the given length at the given time.
    fn beat_times(hb: &mut Heartbeat, rng: &mut Rng, until_ms: u64, step_ms: u64) -> Vec<u64> {
        let mut fired = Vec::new();
        let mut now = 0u64;
        while now <= until_ms {
            // Exactly the worker's inner loop: fire every due beat, then wait.
            while hb.due(now) {
                fired.push(now);
                hb.on_submitted(now, rng);
            }
            now += step_ms;
        }
        fired
    }

    #[test]
    fn heartbeat_holds_the_target_cadence_and_never_bunches() {
        // One hour at one tx every 10 s, 20% jitter, polled 4× a second.
        let mut hb = Heartbeat::new(10_000, HEARTBEAT_JITTER_PCT);
        let mut rng = Rng::seeded(0xC0FFEE);
        let fired = beat_times(&mut hb, &mut rng, 3_600_000, 250);
        // 3,600 s / 10 s = 360 beats, ±1 for where the window ends.
        assert!(
            (359..=361).contains(&fired.len()),
            "expected ~360 beats, got {}",
            fired.len()
        );

        let gaps: Vec<u64> = fired.windows(2).map(|w| w[1] - w[0]).collect();
        // No bunching: jitter is ±20%, so consecutive beats can differ by at most
        // 40% of the interval — nothing may ever land back-to-back.
        let min = *gaps.iter().min().unwrap();
        let max = *gaps.iter().max().unwrap();
        assert!(min >= 5_500, "beats bunched: min gap {min} ms");
        assert!(max <= 14_500, "beat starved: max gap {max} ms");
        // And the MEAN is the target: jitter changes texture, not rate.
        let mean = gaps.iter().sum::<u64>() as f64 / gaps.len() as f64;
        assert!((mean - 10_000.0).abs() < 250.0, "mean gap {mean} ms");
        // Jitter is real (a metronome would show one single gap value).
        assert!(gaps.iter().collect::<std::collections::HashSet<_>>().len() > 10);
    }

    #[test]
    fn heartbeat_without_jitter_is_exact() {
        let mut hb = Heartbeat::new(10_000, 0);
        let mut rng = Rng::seeded(7);
        let fired = beat_times(&mut hb, &mut rng, 100_000, 250);
        assert_eq!(
            fired,
            vec![
                0, 10_000, 20_000, 30_000, 40_000, 50_000, 60_000, 70_000, 80_000, 90_000, 100_000
            ]
        );
        assert_eq!(hb.interval_ms(), 10_000);
    }

    #[test]
    fn heartbeat_makes_up_a_small_deficit_without_drifting() {
        // The submission was late (slow RPC): the NEXT beat stays on the ideal
        // schedule instead of drifting the whole stream later.
        let mut hb = Heartbeat::new(10_000, 0);
        let mut rng = Rng::seeded(1);
        assert!(hb.due(0));
        hb.on_submitted(0, &mut rng);
        assert_eq!(hb.wait_ms(0), 10_000);
        // Beat #2 goes out 3 s late…
        assert!(hb.due(13_000));
        hb.on_submitted(13_000, &mut rng);
        // …and beat #3 is still due at the ideal 20 s, not at 23 s. Exactly ONE
        // beat is due at a time — the deficit never becomes a burst.
        assert!(!hb.due(13_000));
        assert_eq!(hb.wait_ms(13_000), 7_000);
        assert!(hb.due(20_000));
    }

    #[test]
    fn heartbeat_drops_a_long_stall_instead_of_replaying_it() {
        // The node was unreachable for three minutes. Those beats are GONE: the
        // heartbeat re-anchors on now, it does not fire 18 transactions at once.
        let mut hb = Heartbeat::new(10_000, 0);
        let mut rng = Rng::seeded(2);
        hb.on_submitted(0, &mut rng);
        let mut fired = 0;
        let now = 200_000;
        while hb.due(now) {
            fired += 1;
            hb.on_submitted(now, &mut rng);
            assert!(fired < 5, "the heartbeat replayed a stalled backlog");
        }
        assert_eq!(fired, 1);
        assert_eq!(hb.wait_ms(now), 10_000);
        // And it is back on a clean cadence from here.
        let fired_after = beat_times(&mut Heartbeat::new(10_000, 0), &mut rng, 30_000, 250);
        assert_eq!(fired_after.len(), 4);
    }

    // ---- Heartbeat: safety rails ----------------------------------------

    #[test]
    fn heartbeat_pauses_at_the_balance_floor_and_resumes_when_funded() {
        let limits = HeartbeatLimits::reserve_only(100_000_000); // reserve 1 XUS
        let cost = 121_000; // 0.001 XUS + fee + tip
                            // Comfortably above the floor: send.
        assert_eq!(heartbeat_halt(&limits, Some(500_000_000), 0, 0, cost), None);
        // The send WOULD dip under the reserve: pause, do not drain.
        let halt = heartbeat_halt(&limits, Some(100_050_000), 42, 5_000_000, cost)
            .expect("must refuse to cross the floor");
        assert_eq!(
            halt,
            HeartbeatHalt::BalanceFloor {
                balance: 100_050_000,
                reserve: 100_000_000
            }
        );
        assert!(
            !halt.is_terminal(),
            "the floor pauses, it does not end the run"
        );
        assert!(halt.message().contains("balance floor"));
        // Exactly at the boundary (balance - cost == reserve) is still allowed.
        assert_eq!(
            heartbeat_halt(&limits, Some(100_000_000 + cost), 1, 0, cost),
            None
        );
        // One grain short is not.
        assert!(heartbeat_halt(&limits, Some(100_000_000 + cost - 1), 1, 0, cost).is_some());
        // Balance the worker has not read yet is UNKNOWN, not empty: the node's
        // mempool remains the authority and the heartbeat keeps going.
        assert_eq!(heartbeat_halt(&limits, None, 1, 0, cost), None);
        // Refunded (closed-loop recycle returns the principal): resumes by itself.
        assert_eq!(
            heartbeat_halt(&limits, Some(900_000_000), 42, 5_000_000, cost),
            None
        );
    }

    #[test]
    fn heartbeat_caps_are_off_by_default_and_terminal_when_set() {
        // Default rails: only the floor. A million transactions later, still fine.
        let open = HeartbeatLimits::reserve_only(0);
        assert_eq!(
            heartbeat_halt(&open, Some(u128::MAX), 1_000_000, u128::MAX / 2, 121_000),
            None
        );

        let capped = HeartbeatLimits {
            reserve_grains: 0,
            max_tx: Some(10),
            max_spend_grains: Some(1_000_000),
        };
        // Under the count cap: allowed.
        assert_eq!(heartbeat_halt(&capped, Some(u128::MAX), 9, 0, 1), None);
        // At the cap: stop, terminally.
        let halt = heartbeat_halt(&capped, Some(u128::MAX), 10, 0, 1).unwrap();
        assert_eq!(halt, HeartbeatHalt::TxCap(10));
        assert!(halt.is_terminal());
        // Spend cap bites BEFORE the spend happens, not after.
        assert_eq!(
            heartbeat_halt(&capped, Some(u128::MAX), 0, 900_000, 100_000),
            None
        );
        let halt = heartbeat_halt(&capped, Some(u128::MAX), 0, 900_001, 100_000).unwrap();
        assert_eq!(halt, HeartbeatHalt::SpendCap(900_001));
        assert!(halt.is_terminal());
        // Caps are checked ahead of the floor, so the reported reason is the one
        // that actually ended the session.
        let both = HeartbeatLimits {
            reserve_grains: u128::MAX,
            max_tx: Some(1),
            max_spend_grains: None,
        };
        assert_eq!(
            heartbeat_halt(&both, Some(0), 1, 0, 1),
            Some(HeartbeatHalt::TxCap(1))
        );
    }

    // ---- Heartbeat: the fee-auction three-way ---------------------------

    #[test]
    fn heartbeat_tip_choice_resolves_the_bid() {
        let manual = TipMode::Range {
            min: 1_000,
            max: 2_000,
        };
        assert_eq!(
            heartbeat_tip_mode(TipChoice::Auto, manual),
            TipMode::Fixed(SUGGESTED_TIP_GRAINS)
        );
        assert_eq!(heartbeat_tip_mode(TipChoice::Manual, manual), manual);
        assert_eq!(heartbeat_tip_mode(TipChoice::NoTip, manual), TipMode::Off);
    }

    #[test]
    fn no_tip_emits_the_bare_action_and_auto_tip_emits_the_envelope() {
        let mut rng = Rng::seeded(9);
        let to = acct("alice.sov");

        // Auto: a real bid, wrapped for the live auction.
        let tip = heartbeat_tip_mode(TipChoice::Auto, TipMode::Off).pick(&mut rng);
        assert_eq!(tip, SUGGESTED_TIP_GRAINS);
        match transfer_action(to.clone(), 1_000, tip, /* auction_active = */ true) {
            Action::Tipped { tip, inner } => {
                assert_eq!(tip.grains(), SUGGESTED_TIP_GRAINS);
                assert!(matches!(*inner, Action::Transfer { .. }));
            }
            other => panic!("auto tip must bid in the auction, got {other:?}"),
        }

        // No tip: the bare action even though the auction IS active — this is the
        // choice that deliberately does not exercise it.
        let tip = heartbeat_tip_mode(TipChoice::NoTip, TipMode::Fixed(9_999)).pick(&mut rng);
        assert_eq!(tip, 0);
        assert!(matches!(
            transfer_action(to.clone(), 1_000, tip, true),
            Action::Transfer { .. }
        ));

        // Dormant fork: byte-identical bare action whatever the operator chose —
        // the toggle can never emit an envelope a dormant chain would reject.
        for choice in [TipChoice::Auto, TipChoice::Manual, TipChoice::NoTip] {
            let tip = heartbeat_tip_mode(choice, TipMode::Fixed(9_999)).pick(&mut rng);
            assert!(
                matches!(
                    transfer_action(to.clone(), 1_000, tip, /* auction_active = */ false),
                    Action::Transfer { .. }
                ),
                "{choice:?} emitted a tipped action on a dormant chain"
            );
        }
    }

    // ---- Heartbeat: surviving the long haul ------------------------------

    #[test]
    fn heartbeat_resyncs_its_nonce_after_an_error_gap_without_wedging() {
        // The long-haul failure mode: the node goes away mid-stream (transport
        // errors, which are NOT proof the slot was consumed), then comes back with
        // the account moved on because our earlier txs mined. The heartbeat must
        // hold its nonce through the gap, resync forward, and keep going — never
        // reuse a committed nonce and never wedge on a burnt one.
        let mut seq = NonceSequencer::new();
        seq.reconcile(40);
        let submitted = drive(
            &mut seq,
            &[
                Sim::Accept,                             // 40 pooled
                Sim::Accept,                             // 41 pooled
                Sim::Reject(RejectClass::Other),         // 42: node unreachable → hold
                Sim::Reject(RejectClass::Other),         // 42 again → still held
                Sim::StaleWithNodeNonce(42),             // back up: 40+41 mined, next is 42
                Sim::Accept,                             // 42 pooled
                Sim::Reject(RejectClass::NonceOccupied), // 43 was our own retry
                Sim::Accept,                             // 44 pooled
            ],
        );
        assert_eq!(submitted, vec![40, 41, 42, 42, 42, 42, 43, 44]);
        let mut committed = submitted.clone();
        committed.dedup();
        assert_eq!(committed, vec![40, 41, 42, 43, 44]); // gap-free, nothing reused
        assert_eq!(seq.peek(), 45);
    }

    #[test]
    fn per_block_rate_reports_the_actual_landed_cadence() {
        // 12 transactions over six 150 s blocks = 2 per block.
        assert_eq!(per_block_rate(12, 900.0), Some(2.0));
        assert_eq!(per_block_rate(0, 900.0), Some(0.0)); // landed nothing IS the answer
                                                         // Too early to say: a fraction of a block is noise, not a rate.
        assert_eq!(per_block_rate(1, 10.0), None);
        assert_eq!(per_block_rate(1, f64::NAN), None);
        // A no-tip heartbeat submitting 4/block but landing 1/block reports both
        // honestly — the pacer holds submissions, the landed figure tells the truth.
        assert_eq!(per_block_rate(24, 900.0), Some(4.0));
        assert_eq!(per_block_rate(6, 900.0), Some(1.0));
    }

    // -- the auction duel ---------------------------------------------------

    #[test]
    fn duel_arms_only_with_exactly_two_wallets() {
        // One wallet is not a contest; three means the bid is no longer the only
        // variable. Both refuse, each with its own stated reason.
        assert_eq!(duel_wallet_check(0), Some(DuelBlock::TooFew(0)));
        assert_eq!(duel_wallet_check(1), Some(DuelBlock::TooFew(1)));
        assert_eq!(duel_wallet_check(3), Some(DuelBlock::TooMany(3)));
        assert_eq!(duel_wallet_check(7), Some(DuelBlock::TooMany(7)));
        // Exactly two arms.
        assert_eq!(duel_wallet_check(2), None);
        // The reasons say the number the operator actually selected.
        assert!(DuelBlock::TooFew(1).message().contains('1'));
        assert!(DuelBlock::TooMany(3).message().contains('3'));
        assert!(DuelBlock::TooFew(1).message().contains("EXACTLY two"));
    }

    #[test]
    fn duel_resolves_each_sides_bid_independently() {
        // The demonstrating default: A bids high, B bids nothing at all.
        let (a, b) = duel_bids(
            (TipChoice::Manual, TipMode::Fixed(DUEL_HIGH_BID_GRAINS)),
            (TipChoice::NoTip, TipMode::Fixed(DUEL_HIGH_BID_GRAINS)),
        );
        assert_eq!(a, TipMode::Fixed(DUEL_HIGH_BID_GRAINS));
        assert_eq!(b, TipMode::Off); // bare action: B's manual field is ignored
        assert!(duel_bid_note(a, b).is_none()); // a real contest
        assert_eq!(duel_bid_label(b), "no tip — bare action");

        // Auto resolves to the suggested tip on whichever side chose it, and a
        // range on one side does not disturb the other.
        let (a, b) = duel_bids(
            (TipChoice::Auto, TipMode::Off),
            (TipChoice::Manual, TipMode::Range { min: 1, max: 1_000 }),
        );
        assert_eq!(a, TipMode::Fixed(SUGGESTED_TIP_GRAINS));
        assert_eq!(b, TipMode::Range { min: 1, max: 1_000 });

        // Two identical bids is a null run, and says so rather than pretending to
        // measure the bid.
        let (a, b) = duel_bids(
            (TipChoice::Auto, TipMode::Off),
            (TipChoice::Auto, TipMode::Off),
        );
        assert_eq!(a, b);
        assert!(duel_bid_note(a, b).is_some());
    }

    #[test]
    fn duel_ledger_measures_landings_latency_and_pooling() {
        // A side RUNNING: three transactions submitted one block apart, two of
        // them found in mined blocks (so their index in the block is known) and
        // one only visible through the account nonce.
        let mut l = DuelLedger::new();
        l.on_submit(10, 0, 100);
        l.on_submit(11, 60_000, 100);
        l.on_submit(12, 120_000, 101);
        assert_eq!(l.stats().submitted, 3);
        assert_eq!(l.stats().pooled, 3);
        assert_eq!(l.stats().landed, 0);
        assert_eq!(l.stats().mean_blocks, None); // nothing landed ⇒ no wait to report

        // Block 101 held nonce 10 first of three transactions.
        assert!(l.on_block_hit(101, 10, 0, 3, 90_000));
        // Block 102 held nonce 11 second of four.
        assert!(l.on_block_hit(102, 11, 1, 4, 240_000));
        // A block we did not scan mined nonce 12: the node now reports nonce 13.
        assert_eq!(l.on_node_nonce(13, 400_000, 103), 1);
        // Nothing left to land, and a repeat sweep adds nothing.
        assert_eq!(l.on_node_nonce(13, 500_000, 104), 0);

        let s = l.stats();
        assert_eq!((s.submitted, s.landed, s.pooled), (3, 3, 0));
        // Waits: 101-100 = 1, 102-100 = 2, 103-101 = 2 blocks ⇒ mean 5/3.
        assert!((s.mean_blocks.unwrap() - 5.0 / 3.0).abs() < 1e-9);
        // Seconds: 90, 180, 280 ⇒ mean 550/3.
        assert!((s.mean_secs.unwrap() - 550.0 / 3.0).abs() < 1e-9);
        // The ordering is recorded where the block body gave it, and honestly
        // absent where it did not.
        let ls: Vec<Landing> = l.landings().iter().copied().collect();
        assert_eq!(ls[0].index, Some(0));
        assert_eq!(ls[0].txs, Some(3));
        assert_eq!(ls[1].index, Some(1));
        assert_eq!(ls[2].index, None);
        assert_eq!(
            l.positions(),
            vec![(101, Some(0)), (102, Some(1)), (103, None)]
        );

        // A retry of a nonce still in flight is the SAME transaction, not a second.
        let mut r = DuelLedger::new();
        r.on_submit(5, 0, 10);
        r.on_submit(5, 1_000, 11);
        assert_eq!(r.stats().submitted, 1);
        assert_eq!(r.stats().pooled, 1);
        // …and it is timed from the submit that actually stuck.
        assert!(r.on_block_hit(12, 5, 0, 1, 3_000));
        assert_eq!(r.landings()[0].blocks, 1);
        assert_eq!(r.landings()[0].ms, 2_000);
        // A block hit for something never submitted matches nothing.
        assert!(!r.on_block_hit(13, 99, 0, 1, 4_000));
    }

    #[test]
    fn duel_block_outcomes_count_wins_and_intra_block_ordering() {
        // Block 10: A only. 11: both, A ordered first. 12: B only. 13: both,
        // B first. 14: both, ordering unobserved.
        let a = [
            (10u64, Some(0usize)),
            (11, Some(1)),
            (13, Some(4)),
            (14, None),
        ];
        let b = [
            (11u64, Some(3usize)),
            (12, Some(0)),
            (13, Some(2)),
            (14, None),
        ];
        let o = block_outcomes(&a, &b);
        assert_eq!(o.len(), 5);
        assert_eq!(
            o[0],
            BlockOutcome {
                height: 10,
                a: 1,
                b: 0,
                first: None
            }
        );
        assert_eq!(
            o[1],
            BlockOutcome {
                height: 11,
                a: 1,
                b: 1,
                first: Some(DuelSide::A)
            }
        );
        assert_eq!(
            o[2],
            BlockOutcome {
                height: 12,
                a: 0,
                b: 1,
                first: None
            }
        );
        assert_eq!(o[3].first, Some(DuelSide::B));
        assert_eq!(o[4].first, None); // both landed, ordering not observed

        let t = tally_blocks(&o);
        assert_eq!(t.blocks, 5);
        assert_eq!((t.a_wins, t.b_wins, t.shared), (1, 1, 3));
        assert_eq!((t.a_first, t.b_first), (1, 1));

        // Two of a side's transactions in one block count as two, one block.
        let o = block_outcomes(&[(20, Some(0)), (20, Some(1))], &[]);
        assert_eq!(
            o,
            vec![BlockOutcome {
                height: 20,
                a: 2,
                b: 0,
                first: None
            }]
        );
        assert_eq!(tally_blocks(&o).a_wins, 1);
        // No landings at all is an empty sample, not a zero-zero block.
        assert!(block_outcomes(&[], &[]).is_empty());
        assert_eq!(tally_blocks(&[]), DuelTally::default());
    }

    #[test]
    fn duel_verdict_is_inconclusive_on_a_thin_sample() {
        // One landing each is not evidence of anything.
        let a = DuelStats {
            submitted: 2,
            landed: 1,
            pooled: 1,
            mean_blocks: Some(1.0),
            mean_secs: Some(150.0),
        };
        let b = DuelStats {
            submitted: 2,
            landed: 1,
            pooled: 1,
            mean_blocks: Some(4.0),
            mean_secs: Some(600.0),
        };
        let v = duel_verdict(&a, &b, &DuelTally::default());
        assert!(matches!(v, Verdict::Inconclusive(_)), "{v:?}");
        assert!(v.text().contains("inconclusive"));
        // It says how far off a verdict it is, and what each side has done.
        assert!(v.text().contains(&DUEL_MIN_LANDED.to_string()));
        // Nothing landed at all is also inconclusive, not "no difference".
        let none = DuelStats {
            submitted: 3,
            landed: 0,
            pooled: 3,
            ..DuelStats::default()
        };
        assert!(matches!(
            duel_verdict(&none, &none, &DuelTally::default()),
            Verdict::Inconclusive(_)
        ));
    }

    #[test]
    fn duel_verdict_states_only_what_was_measured() {
        let tally = DuelTally {
            blocks: 6,
            a_wins: 3,
            b_wins: 1,
            shared: 2,
            a_first: 2,
            b_first: 0,
        };
        let fast = DuelStats {
            submitted: 6,
            landed: 5,
            pooled: 1,
            mean_blocks: Some(1.2),
            mean_secs: Some(180.0),
        };
        let slow = DuelStats {
            submitted: 6,
            landed: 4,
            pooled: 2,
            mean_blocks: Some(3.4),
            mean_secs: Some(510.0),
        };

        // The higher bid waited 2.2 blocks less over 9 landings.
        let v = duel_verdict(&fast, &slow, &tally);
        assert!(matches!(v, Verdict::HigherBid(_)), "{v:?}");
        assert_eq!(v.word(), "HIGHER BID WINS");
        assert!(v.text().contains("2.2 blocks"));
        assert!(v.text().contains("blocks won A 3 · B 1 · shared 2"));
        assert!(v.text().contains("ordered A first in 2"));

        // Reversed, it is reported as CONTRARY rather than smoothed over.
        let v = duel_verdict(&slow, &fast, &tally);
        assert!(matches!(v, Verdict::Contrary(_)), "{v:?}");
        assert!(v.text().contains("LOWER bid landed sooner"));

        // Inside the noise floor it is honestly no difference — the common case
        // on a chain that is nowhere near capacity.
        let near = DuelStats {
            mean_blocks: Some(1.4),
            ..fast
        };
        let v = duel_verdict(&fast, &near, &tally);
        assert!(matches!(v, Verdict::NoDifference(_)), "{v:?}");
        assert!(v.text().contains("no measurable difference"));

        // One side landing and the other not at all: won outright, and the panel
        // still reports B's pooled backlog rather than implying it vanished.
        let stuck = DuelStats {
            submitted: 6,
            landed: 0,
            pooled: 6,
            mean_blocks: None,
            mean_secs: None,
        };
        let v = duel_verdict(&fast, &stuck, &tally);
        assert!(matches!(v, Verdict::HigherBid(_)), "{v:?}");
        assert!(v.text().contains("only the higher bid is landing"));
        assert!(v.text().contains('6'));
        let v = duel_verdict(&stuck, &fast, &tally);
        assert!(matches!(v, Verdict::Contrary(_)), "{v:?}");
    }

    #[test]
    fn a_running_duel_measures_the_race_and_reaches_a_verdict() {
        // The whole pure pipeline in its RUNNING state: the shared pacer issues a
        // PAIR of submissions per beat, blocks arrive, both sides' landings are
        // observed off the block bodies, and the verdict is computed from them.
        //
        // The scripted chain: a 150 s block time, one pair every 60 s. Side A (the
        // high bid) is included in the very next block; side B (no bid) waits two
        // further blocks and is then included after A in the shared blocks.
        let mut a = DuelLedger::new();
        let mut b = DuelLedger::new();
        let mut beat = Heartbeat::new(60_000, 0); // jitter OFF — both sides in phase
        let mut rng = Rng::seeded(7);
        let mut nonce = 0u64;
        let mut submitted: Vec<(u64, u64, u64)> = Vec::new(); // (nonce, ms, height)

        // Ten minutes of duel: the pacer decides WHEN, and both sides submit the
        // same nonce sequence at the same instant — the controlled part.
        for now in (0..600_000u64).step_by(1_000) {
            if beat.due(now) {
                let height = 100 + now / 150_000; // a block every 150 s
                a.on_submit(nonce, now, height);
                b.on_submit(nonce, now, height);
                submitted.push((nonce, now, height));
                nonce += 1;
                beat.on_submitted(now, &mut rng);
            }
        }
        assert_eq!(submitted.len(), 10); // one pair a minute for ten minutes
        assert_eq!(a.stats().submitted, b.stats().submitted); // held equal

        // Now the chain includes them. A lands in the next block after its submit;
        // B lands two blocks later than A, and after A when they share a block.
        for (n, ms, h) in &submitted {
            let a_h = h + 1;
            a.on_block_hit(a_h, *n, 0, 4, ms + 150_000);
            let b_h = h + 3;
            b.on_block_hit(b_h, *n, 2, 4, ms + 450_000);
        }

        let (sa, sb) = (a.stats(), b.stats());
        assert_eq!((sa.landed, sa.pooled), (10, 0));
        assert_eq!((sb.landed, sb.pooled), (10, 0));
        assert_eq!(sa.mean_blocks, Some(1.0));
        assert_eq!(sb.mean_blocks, Some(3.0));
        assert_eq!(sa.mean_secs, Some(150.0));
        assert_eq!(sb.mean_secs, Some(450.0));

        let outcomes = block_outcomes(&a.positions(), &b.positions());
        let tally = tally_blocks(&outcomes);
        // Every block in the sample was landed in by someone, and where both
        // sides share one, A was ordered first — which is the ordering claim the
        // block bodies actually support.
        assert_eq!(tally.blocks, outcomes.len());
        assert_eq!(tally.b_first, 0);
        assert!(tally.a_wins > 0, "{tally:?}");
        assert_eq!(tally.a_first, tally.shared);

        // The verdict: the higher bid landed two blocks sooner, stated from the
        // measured numbers.
        let v = duel_verdict(&sa, &sb, &tally);
        assert!(matches!(v, Verdict::HigherBid(_)), "{v:?}");
        assert!(v.text().contains("2.0 blocks"));
        assert!(v.text().contains("over 20 landings"));

        // And the same pipeline early in the run, after ONE pair, honestly refuses
        // to conclude anything.
        let (mut ea, mut eb) = (DuelLedger::new(), DuelLedger::new());
        ea.on_submit(0, 0, 100);
        eb.on_submit(0, 0, 100);
        ea.on_block_hit(101, 0, 0, 2, 150_000);
        let early_outcomes = block_outcomes(&ea.positions(), &eb.positions());
        let v = duel_verdict(&ea.stats(), &eb.stats(), &tally_blocks(&early_outcomes));
        assert!(matches!(v, Verdict::Inconclusive(_)), "{v:?}");
        assert!(v.text().contains("inconclusive so far"));
    }
}
