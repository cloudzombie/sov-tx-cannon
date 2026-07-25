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
pub fn build_signed_transfer(
    seed: &[u8; 32],
    scheme: KeyScheme,
    from: &AccountId,
    to: &AccountId,
    amount_grains: u128,
    nonce: u64,
    domain: Option<&SigningDomain>,
) -> Result<SignedTransaction, String> {
    let keypair = scheme.keypair_from_seed(seed);
    let tx = Transaction {
        signer: from.clone(),
        public_key: keypair.public_key(),
        nonce,
        action: Action::Transfer {
            to: to.clone(),
            amount: Balance::from_grains(amount_grains),
        },
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
        let stx =
            build_signed_transfer(&seed, KeyScheme::Ed25519, &from, &to, 42_000, 9, None).unwrap();

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
            9,
            Some(&domain),
        )
        .unwrap();
        assert!(bound.verify_signature_in(Some(&domain)));
        assert!(!bound.verify_signature(), "bound sig must NOT pass legacy");
        // The tx id is domain-independent (hash of the un-framed body).
        let legacy =
            build_signed_transfer(&seed, KeyScheme::Ed25519, &from, &to, 42_000, 9, None).unwrap();
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
}
