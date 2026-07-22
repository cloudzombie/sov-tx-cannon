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
//! None of this holds or logs secret material: the signing seed is passed in by
//! the caller only for the duration of a single [`build_signed_transfer`] call.

use std::collections::VecDeque;
use std::time::Duration;

use sov_crypto::Keypair;
use sov_primitives::{AccountId, Balance};
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
    /// Begin at `start_tps` and grow linearly to `max_tps` over `ramp_secs`,
    /// then keep pulsing at the ceiling until stopped.
    Pulse {
        start_tps: f64,
        max_tps: f64,
        ramp_secs: f64,
    },
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
    start_tps: f64,
    max_tps: f64,
    ramp_secs: f64,
    issued: u64,
}

impl Pacer {
    /// A pacer targeting `tps` submissions per second (must be > 0, enforced by
    /// the UI's validation).
    pub fn new(tps: f64) -> Self {
        Self::growing(tps, tps, 1.0)
    }

    /// A continuously growing pacer. The instantaneous rate rises linearly from
    /// `start_tps` to `max_tps` during `ramp_secs`, then remains at the ceiling.
    pub fn growing(start_tps: f64, max_tps: f64, ramp_secs: f64) -> Self {
        let start_tps = start_tps.max(f64::MIN_POSITIVE);
        let max_tps = max_tps.max(start_tps);
        Self {
            start_tps,
            max_tps,
            ramp_secs: ramp_secs.max(f64::MIN_POSITIVE),
            issued: 0,
        }
    }

    /// Integral of the configured rate curve: total transactions that should
    /// have been issued by `elapsed`.
    fn target(&self, elapsed: Duration) -> u64 {
        let t = elapsed.as_secs_f64();
        let ramp_t = t.min(self.ramp_secs);
        let slope = (self.max_tps - self.start_tps) / self.ramp_secs;
        let during_ramp = self.start_tps * ramp_t + 0.5 * slope * ramp_t * ramp_t;
        let after_ramp = (t - self.ramp_secs).max(0.0) * self.max_tps;
        (during_ramp + after_ramp) as u64
    }

    /// Instantaneous target rate at `elapsed`, used to bound catch-up bursts.
    fn current_tps(&self, elapsed: Duration) -> f64 {
        let progress = (elapsed.as_secs_f64() / self.ramp_secs).clamp(0.0, 1.0);
        self.start_tps + (self.max_tps - self.start_tps) * progress
    }

    /// The most sends one call may return: one second's worth (min 1).
    fn burst_cap(&self, elapsed: Duration) -> u64 {
        (self.current_tps(elapsed).ceil() as u64).max(1)
    }

    /// How many submissions are due at `elapsed` since the run started. Advances
    /// the internal cumulative counter; a backlog beyond [`burst_cap`] is
    /// dropped (counted as issued) so there is never a runaway burst.
    ///
    /// [`burst_cap`]: Self::burst_cap
    pub fn take_due(&mut self, elapsed: Duration) -> u64 {
        let target = self.target(elapsed);
        let shortfall = target.saturating_sub(self.issued);
        let due = shortfall.min(self.burst_cap(elapsed));
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
    /// This wallet cannot afford further traffic — stop its run and surface why.
    StopWallet,
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

pub fn build_signed_transfer(
    seed: &[u8; 32],
    scheme: KeyScheme,
    from: &AccountId,
    to: &AccountId,
    amount_grains: u128,
    nonce: u64,
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
    SignedTransaction::sign(tx, &keypair).map_err(|e| format!("signing failed: {e}"))
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
                    Disposition::StopWallet => break,
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
        let stx = build_signed_transfer(&seed, KeyScheme::Ed25519, &from, &to, 42_000, 9).unwrap();

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
    fn built_transfer_round_trips_through_borsh_and_still_verifies() {
        let seed = [3u8; 32];
        let stx = build_signed_transfer(
            &seed,
            KeyScheme::Hybrid65,
            &acct("cannon.sov"),
            &acct("target.sov"),
            1,
            0,
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
}
