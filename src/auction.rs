//! Pure, deterministic BLOCKSPACE-AUCTION logic — no network, no clock, no GUI.
//!
//! v0.1.98 gave SOV a fee auction: a transaction may carry a priority bid by
//! wrapping its real action in the [`sov_types::Action::Tipped`] envelope. The tip
//! is a pure signer → miner transfer (nothing minted, nothing burned — see
//! `chain/crates/runtime/src/execution.rs:69-70` and `:361-368`), and it is
//! *mempool policy*, not validity: an untipped transaction is never rejected for
//! bidding zero, it simply waits behind funded bids
//! (`chain/crates/mempool/src/lib.rs:170-176`).
//!
//! This module owns everything the cannon must DECIDE about that auction before it
//! touches the wire, so all of it is unit-testable in isolation:
//!   * [`TipPolicy`] / [`TipSelector`] — bid untipped, a fixed tip, or from a
//!     LADDER of rungs, so one run produces a mixed population of bids and the
//!     operator can check that inclusion order matches bid order.
//!   * [`bucket_of`] / [`TipBucket`] — which rung a bid cleared: the stable key the
//!     latency histogram reports its per-tip percentiles under.
//!   * [`wrap_tipped`] — build the envelope while refusing exactly what consensus
//!     refuses (nesting, and the two disallowed inner actions).
//!   * [`FloorProbe`] — a ramp-DOWN that turns accept/refuse observations into an
//!     empirically discovered bracket around the pool's dynamic price floor.
//!   * [`RbfPlan`] — the next bid that satisfies the node's strict-outbid rule at a
//!     contested `(signer, nonce)`, and whether a candidate bid would land.
//!
//! Nothing here talks to a node: the caller submits, and feeds back the node's
//! answers (and any randomness), exactly like the rest of the cannon's logic
//! layer. Every piece of arithmetic is saturating or checked — this crate never
//! overflows, divides by zero, or produces a NaN.

// The GUI wiring for these lives in `main.rs`, which this module does not own. A
// module fully exercised by its own tests but not yet mounted in the UI would
// otherwise trip `dead_code` under `-D warnings`.
#![allow(dead_code)]

use sov_primitives::Balance;
use sov_types::Action;

/// Minimum tip increase (in grains) a replace-by-fee must add over the pooled
/// transaction it displaces.
///
/// MIRRORS the node constant `MIN_RBF_BUMP_GRAINS` at
/// `chain/crates/mempool/src/lib.rs:183` (value `1_000`). The cannon must reproduce
/// the admission rule EXACTLY — a tool that guessed a different bump would report
/// perfectly good replacements as failures — so this is a deliberate mirror,
/// re-declared here rather than imported because the mempool crate is not a
/// dependency of this tool (only `sov-types`, `sov-primitives`, `sov-crypto` and
/// `sov-rpc` are).
pub const MIN_RBF_BUMP_GRAINS: u128 = 1_000;

// ---------------------------------------------------------------------------
// 1. Tip policy / tip ladder
// ---------------------------------------------------------------------------

/// How the ladder hands out its rungs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LadderMode {
    /// Cycle the rungs in ascending order. Deterministic, and exercises every rung
    /// the same number of times — the mode to use when the run must produce a
    /// balanced population across the whole ladder.
    RoundRobin,
    /// Pick a rung uniformly at random per transaction. Produces an unordered,
    /// realistic mix in which high and low bids contend at the same instant.
    Random,
}

/// What tip (if any) each generated transaction bids.
///
/// The three shapes are the three questions an operator asks of the auction: does
/// untipped traffic still flow at all; what does a single uniform bid do; and —
/// the interesting one — when a spread of bids contends for the same blocks, does
/// inclusion order follow bid order?
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TipPolicy {
    /// No envelope at all: the legacy bare action, bidding zero. This must stay
    /// available — untipped traffic is explicitly still admissible (it is never
    /// rejected for its zero bid, `chain/crates/mempool/src/lib.rs:174-176`) and
    /// the tool has to be able to demonstrate that against a live node.
    Untipped,
    /// Every transaction bids exactly this many grains.
    Fixed(u128),
    /// Bids are drawn from these rungs, in grains.
    Ladder {
        /// The rungs: ascending, distinct, all non-zero (enforced by
        /// [`TipPolicy::validate`]) so every bid maps to exactly one bucket.
        rungs: Vec<u128>,
        /// How a rung is chosen per transaction.
        mode: LadderMode,
    },
}

impl TipPolicy {
    /// Validate the policy's shape, mirroring `AmountMode::validate` in `logic.rs`:
    /// the UI calls this before arming, so a malformed ladder can never reach a
    /// worker.
    ///
    /// A zero fixed tip is rejected rather than silently accepted: an envelope with
    /// a zero tip is legal on chain (execution simply charges nothing —
    /// `chain/crates/runtime/src/execution.rs:361`) but it bids nothing, so it is a
    /// confusing way to spell [`TipPolicy::Untipped`] and would make the per-bucket
    /// latency comparison meaningless.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            TipPolicy::Untipped => Ok(()),
            TipPolicy::Fixed(v) => {
                if *v == 0 {
                    return Err("tip must be greater than zero (use Untipped for no tip)".into());
                }
                Ok(())
            }
            TipPolicy::Ladder { rungs, .. } => {
                if rungs.is_empty() {
                    return Err("the tip ladder needs at least one rung".into());
                }
                if rungs[0] == 0 {
                    return Err("ladder rungs must be greater than zero".into());
                }
                for w in rungs.windows(2) {
                    if w[1] <= w[0] {
                        return Err("ladder rungs must ascend and be distinct".into());
                    }
                }
                Ok(())
            }
        }
    }

    /// The rungs this policy bids on, ascending: empty for [`TipPolicy::Untipped`],
    /// the single value for [`TipPolicy::Fixed`], the ladder itself otherwise.
    ///
    /// This is what the latency histogram buckets against, so the buckets it
    /// reports are exactly the bids the run actually made — never an invented
    /// scale.
    pub fn rungs(&self) -> &[u128] {
        match self {
            TipPolicy::Untipped => &[],
            TipPolicy::Fixed(v) => std::slice::from_ref(v),
            TipPolicy::Ladder { rungs, .. } => rungs,
        }
    }

    /// The bucket a tip of `tip_grains` falls in under this policy's rungs.
    pub fn bucket(&self, tip_grains: u128) -> TipBucket {
        bucket_of(self.rungs(), tip_grains)
    }
}

/// Hands out the tip for each transaction under a validated [`TipPolicy`].
///
/// Randomness is deliberately NOT taken as a `logic::Rng`: that type's uniform
/// draw is private to its own module, and this module has no business owning a
/// second PRNG. The caller supplies one uniform `u128` per call instead (`Rng`'s
/// draw, or any other uniform source) and this module reduces it modulo the rung
/// count. That keeps the selector pure and exactly reproducible under test, and it
/// means the ladder is unbiased for any draw magnitude — including `u128::MAX`.
#[derive(Clone, Debug)]
pub struct TipSelector {
    policy: TipPolicy,
    cursor: usize,
}

impl TipSelector {
    /// Build a selector; errors exactly when [`TipPolicy::validate`] does.
    pub fn new(policy: TipPolicy) -> Result<Self, String> {
        policy.validate()?;
        Ok(Self { policy, cursor: 0 })
    }

    /// The policy this selector bids under (the histogram's bucket keys come from
    /// its [`TipPolicy::rungs`]).
    pub fn policy(&self) -> &TipPolicy {
        &self.policy
    }

    /// The tip bucket a bid of `tip_grains` falls in under this selector's policy.
    pub fn bucket(&self, tip_grains: u128) -> TipBucket {
        self.policy.bucket(tip_grains)
    }

    /// The bucket as the small opaque integer key `confirm.rs` distributes
    /// latency samples by.
    ///
    /// The mapping is deliberately POSITIONAL, not derived from the tip value:
    /// `0` = untipped, `1` = a non-zero bid below the lowest rung, and `2 + i`
    /// = the `i`-th rung of this policy's ladder. That keeps the key stable for
    /// a whole run (the policy is immutable per run), keeps it small enough for
    /// the tracker's bucket cap, and means the latency table's rows line up with
    /// the ladder the operator configured.
    ///
    /// A ladder longer than the key space saturates on the last key rather than
    /// wrapping — two very high rungs would then share a row, which is visible
    /// in the UI, whereas a wrapped key would silently mix the highest bids in
    /// with the untipped ones.
    pub fn bucket_key(&self, tip_grains: u128) -> crate::confirm::TipBucket {
        match self.bucket(tip_grains) {
            TipBucket::Untipped => 0,
            TipBucket::BelowLadder => 1,
            TipBucket::Rung(r) => {
                let idx = self
                    .policy
                    .rungs()
                    .iter()
                    .position(|&x| x == r)
                    .unwrap_or(0)
                    .min(usize::from(u8::MAX - 2));
                2u8.saturating_add(idx as u8)
            }
        }
    }

    /// The next bid, in grains; `None` means "send the bare action, no envelope".
    ///
    /// `draw` is consulted ONLY for [`LadderMode::Random`]; the other modes ignore
    /// it entirely, so a caller with no entropy handy may pass `0`.
    pub fn next_tip(&mut self, draw: u128) -> Option<u128> {
        match &self.policy {
            TipPolicy::Untipped => None,
            TipPolicy::Fixed(v) => Some(*v),
            TipPolicy::Ladder { rungs, mode } => {
                // `validate` guarantees a non-empty ladder, so neither the modulo
                // below nor the index can divide by zero or run out of range.
                let idx = match mode {
                    LadderMode::RoundRobin => {
                        let i = self.cursor;
                        self.cursor = (self.cursor + 1) % rungs.len();
                        i
                    }
                    LadderMode::Random => (draw % rungs.len() as u128) as usize,
                };
                Some(rungs[idx])
            }
        }
    }
}

/// Which rung of the ladder a bid cleared — the histogram's bucket key.
///
/// Bucket identity is the RUNG VALUE in grains, not an index: a run that changes
/// its ladder produces differently-labelled buckets rather than silently
/// re-labelling old data, and two buckets can never merge. Within a run the
/// mapping is total (every `u128` tip lands in exactly one bucket) and stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TipBucket {
    /// A zero bid: the bare, untipped action.
    Untipped,
    /// A non-zero bid that did not reach the lowest rung. Our own traffic never
    /// lands here (policy bids ARE rungs); it exists so a tip observed from
    /// elsewhere — another sender's pooled transaction — still classifies.
    BelowLadder,
    /// The highest rung this bid cleared, in grains: `rung ≤ tip < next rung`.
    Rung(u128),
}

impl TipBucket {
    /// A short, stable label for an axis tick or a table cell.
    pub fn label(self) -> String {
        match self {
            TipBucket::Untipped => "untipped".to_string(),
            TipBucket::BelowLadder => "<ladder".to_string(),
            TipBucket::Rung(g) => format!("≥{g}"),
        }
    }
}

/// Classify `tip_grains` against an ascending `rungs` ladder.
///
/// Zero is always [`TipBucket::Untipped`] — it is not a bid. Otherwise the bucket
/// is the HIGHEST rung the tip cleared, so a tip between two rungs is credited to
/// the lower one (it bought that rung's price, not the next one's). A tip below
/// every rung — or any tip at all when the ladder is empty — is
/// [`TipBucket::BelowLadder`]. Total and allocation-free.
pub fn bucket_of(rungs: &[u128], tip_grains: u128) -> TipBucket {
    if tip_grains == 0 {
        return TipBucket::Untipped;
    }
    let mut cleared: Option<u128> = None;
    for &r in rungs {
        if r <= tip_grains {
            cleared = Some(match cleared {
                Some(c) => c.max(r),
                None => r,
            });
        }
    }
    match cleared {
        Some(r) => TipBucket::Rung(r),
        None => TipBucket::BelowLadder,
    }
}

/// Wrap `inner` in a fee-auction envelope bidding `tip_grains`.
///
/// Refuses exactly what the node refuses, so the cannon can never build a
/// transaction that would make a block invalid:
///   * a nested envelope — `ExecutionError::NestedTip`,
///     `chain/crates/runtime/src/execution.rs:347-349` (and the type's own note at
///     `chain/crates/types/src/transaction.rs:362`);
///   * an inner `MultisigExec` or `RotateKey` — `ExecutionError::TipInnerNotAllowed`,
///     `chain/crates/runtime/src/execution.rs:352-357`.
///
/// A zero tip is permitted (execution charges nothing for it,
/// `chain/crates/runtime/src/execution.rs:361`) so the adversarial modes can submit
/// exactly that; policy-generated bids are non-zero by [`TipPolicy::validate`].
pub fn wrap_tipped(inner: Action, tip_grains: u128) -> Result<Action, String> {
    if matches!(inner, Action::Tipped { .. }) {
        return Err("fee-auction envelopes cannot be nested".into());
    }
    if matches!(
        inner,
        Action::MultisigExec { .. } | Action::RotateKey { .. }
    ) {
        return Err(
            "fee-auction envelope: inner action may not be MultisigExec or RotateKey".into(),
        );
    }
    Ok(Action::Tipped {
        tip: Balance::from_grains(tip_grains),
        inner: Box::new(inner),
    })
}

// ---------------------------------------------------------------------------
// 2. Empirical floor discovery
// ---------------------------------------------------------------------------

/// What the node did with a probe transaction.
///
/// The caller derives this from the node's real answer: an accepted submit is
/// [`Admission::Accepted`]; a capacity refusal (`MempoolError::BelowFloor`, or the
/// legacy `Full` at a zero floor — `chain/crates/mempool/src/lib.rs:515-545`) is
/// [`Admission::Refused`]. Anything else — a nonce or affordability rejection — is
/// NOT a price signal and must not be fed in at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The node admitted the transaction at this tip.
    Accepted,
    /// The node refused it: at capacity, this bid did not beat the floor.
    Refused,
}

/// The empirically discovered bracket around the pool's dynamic price floor.
///
/// The node's rule at capacity is a STRICT outbid — a newcomer gets in when
/// `new_tip > floor` (`chain/crates/mempool/src/lib.rs:515-545`). So an accept at
/// `A` proves `floor < A`, and a refusal at `R` proves `floor ≥ R`; with both, the
/// floor at probe time lay in `[highest_refused, lowest_accepted)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FloorBracket {
    /// The highest tip the node REFUSED — an inclusive lower bound on the floor.
    pub highest_refused: Option<u128>,
    /// The lowest tip the node ACCEPTED — an exclusive upper bound on the floor.
    pub lowest_accepted: Option<u128>,
    /// Set when `highest_refused ≥ lowest_accepted`: the two observations cannot
    /// both describe one instant, so the floor MOVED while we probed. See
    /// [`FloorBracket::advice`].
    pub inverted: bool,
}

impl FloorBracket {
    /// True once both ends are known — the only case in which the floor is pinned
    /// between two measured numbers.
    pub fn is_bracketed(&self) -> bool {
        self.highest_refused.is_some() && self.lowest_accepted.is_some()
    }

    /// How wide the bracket is, in grains. `None` unless it is both bracketed AND
    /// self-consistent: an inverted bracket spans two different market states, so
    /// reporting a width for it would be a fabricated precision. Saturating, so a
    /// bracket spanning the whole `u128` range cannot overflow.
    pub fn width(&self) -> Option<u128> {
        match (self.highest_refused, self.lowest_accepted, self.inverted) {
            (Some(lo), Some(hi), false) => Some(hi.saturating_sub(lo)),
            _ => None,
        }
    }

    /// What the operator should read from this bracket. Deliberately explicit
    /// about what is and is not known — the tool never reports a single "the floor
    /// is X" number it did not measure.
    pub fn advice(&self) -> &'static str {
        match (self.highest_refused, self.lowest_accepted, self.inverted) {
            (None, None, _) => "no probes recorded yet — the floor is unknown",
            (None, Some(_), _) => {
                "every probe was accepted — the floor is below the lowest tip probed \
                 (these prices are not contested); ramp lower"
            }
            (Some(_), None, _) => {
                "every probe was refused — the floor is at or above the highest tip \
                 probed; ramp higher"
            }
            (Some(_), Some(_), false) => {
                "the floor was between the highest refusal (inclusive) and the lowest \
                 accept (exclusive) at probe time"
            }
            (Some(_), Some(_), true) => {
                "NON-MONOTONIC: a tip below an earlier refusal was later accepted, so \
                 the floor FELL during the ramp (demand drained). These readings are \
                 from different instants and do not bracket one price — re-probe \
                 faster, or read the refusal as a stale high-water mark"
            }
        }
    }
}

/// Drives a ramp-DOWN probe of the mempool's dynamic price floor and turns the
/// node's accept/refuse answers into a [`FloorBracket`].
///
/// It starts at a tip the operator expects to clear, steps down by a fixed amount,
/// and records what happened at each rung. It invents no RPC and holds no
/// connection: the caller submits the probe transaction and feeds back only an
/// [`Admission`].
///
/// The floor is not a constant — it is the lowest tip among evictable pooled
/// transactions (`chain/crates/mempool/src/lib.rs:83-87`) and it moves as other
/// traffic arrives and drains. So the observations may be NON-MONOTONIC: a later,
/// lower tip accepted after a higher one was refused. That is a real market signal,
/// not a bug — it is recorded, flagged via [`FloorBracket::inverted`], and never
/// panics or silently discards either reading.
#[derive(Clone, Debug)]
pub struct FloorProbe {
    /// The next tip the ramp will probe; `None` once the ramp has bottomed out.
    next: Option<u128>,
    step: u128,
    highest_refused: Option<u128>,
    lowest_accepted: Option<u128>,
    observations: usize,
}

impl FloorProbe {
    /// A ramp from `start_tip` downward in `step_grains` increments.
    ///
    /// A zero step is rejected: it would probe the same tip forever.
    pub fn new(start_tip: u128, step_grains: u128) -> Result<Self, String> {
        if step_grains == 0 {
            return Err("floor probe step must be greater than zero".into());
        }
        Ok(Self {
            next: Some(start_tip),
            step: step_grains,
            highest_refused: None,
            lowest_accepted: None,
            observations: 0,
        })
    }

    /// The tip to probe next, or `None` once the ramp has probed zero. Peeking does
    /// not consume it — [`FloorProbe::record`] advances the ramp — so a probe whose
    /// submit failed for an unrelated reason (nonce, transport) is simply retried
    /// at the same tip.
    pub fn next_probe(&self) -> Option<u128> {
        self.next
    }

    /// How many price observations have been recorded.
    pub fn observations(&self) -> usize {
        self.observations
    }

    /// Record what the node did at `tip_grains`, and advance the ramp to the next
    /// rung below it.
    ///
    /// The ramp follows the tip actually recorded rather than an internal schedule,
    /// so an operator who probes a hand-picked tip still gets a coherent ladder
    /// afterwards. It stops after probing `0`, and the step down is saturating, so
    /// it can never underflow.
    pub fn record(&mut self, tip_grains: u128, outcome: Admission) {
        self.observations += 1;
        match outcome {
            Admission::Accepted => {
                self.lowest_accepted = Some(match self.lowest_accepted {
                    Some(cur) => cur.min(tip_grains),
                    None => tip_grains,
                });
            }
            Admission::Refused => {
                self.highest_refused = Some(match self.highest_refused {
                    Some(cur) => cur.max(tip_grains),
                    None => tip_grains,
                });
            }
        }
        self.next = if tip_grains == 0 {
            None
        } else {
            Some(tip_grains.saturating_sub(self.step))
        };
    }

    /// The bracket implied by everything recorded so far. Safe to call at any
    /// point, including with zero observations.
    pub fn bracket(&self) -> FloorBracket {
        let inverted = match (self.highest_refused, self.lowest_accepted) {
            (Some(r), Some(a)) => r >= a,
            _ => false,
        };
        FloorBracket {
            highest_refused: self.highest_refused,
            lowest_accepted: self.lowest_accepted,
            inverted,
        }
    }
}

// ---------------------------------------------------------------------------
// 3. RBF storm
// ---------------------------------------------------------------------------

/// Whether a candidate bid would replace the transaction currently pooled at a
/// `(signer, nonce)` slot. The three arms are the node's three outcomes, in the
/// node's own evaluation order (`chain/crates/mempool/src/lib.rs:456-465`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RbfVerdict {
    /// `new_tip ≥ old_tip + MIN_RBF_BUMP_GRAINS`: the pooled transaction is
    /// atomically replaced.
    Replaces,
    /// `old_tip < new_tip < required`: raised, but not by the anti-churn minimum.
    /// The node answers `RbfUnderpriced { required }`
    /// (`chain/crates/mempool/src/lib.rs:463-467`).
    Underpriced {
        /// The minimum tip a successful replacement must carry.
        required: u128,
    },
    /// `new_tip ≤ old_tip`: not a bid at all. The node answers `NonceTaken`
    /// (`chain/crates/mempool/src/lib.rs:456-461`) — and note it checks this
    /// BEFORE the bump, so an equal tip reads as a taken slot, never as an
    /// underpriced replacement.
    NotABid,
}

/// Plans a replace-by-fee storm at one `(signer, nonce)` slot.
///
/// The node's rule, read from `chain/crates/mempool/src/lib.rs:456-465`:
///
/// ```text
///   if new_tip <= old_tip                     → NonceTaken       (line 456)
///   required = old_tip.saturating_add(1_000)                     (line 462)
///   if new_tip < required                     → RbfUnderpriced   (line 463)
///   otherwise                                 → replace atomically
/// ```
///
/// So a bump of EXACTLY [`MIN_RBF_BUMP_GRAINS`] REPLACES — the comparison is
/// `new_tip < required`, not `≤` — and one grain less does not. Getting that
/// boundary backwards would make the cannon report the node's correct behavior as
/// a failure, so both sides of it are pinned by the tests below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RbfPlan {
    current_tip: u128,
}

impl RbfPlan {
    /// A plan against the tip currently in flight at the slot. Pass `0` for an
    /// untipped incumbent — note that even then the FULL bump is required, since
    /// `required = 0 + MIN_RBF_BUMP_GRAINS`.
    pub fn new(current_tip_grains: u128) -> Self {
        Self {
            current_tip: current_tip_grains,
        }
    }

    /// The tip currently pooled at the slot.
    pub fn current_tip(&self) -> u128 {
        self.current_tip
    }

    /// The minimum tip a replacement must carry.
    ///
    /// Saturating, mirroring the node's own `old_tip.saturating_add(...)`
    /// (`chain/crates/mempool/src/lib.rs:462`), so near `u128::MAX` this tool
    /// agrees with the node exactly instead of overflowing.
    pub fn required_tip(&self) -> u128 {
        self.current_tip.saturating_add(MIN_RBF_BUMP_GRAINS)
    }

    /// Would `candidate_grains` replace the incumbent? Evaluated in the node's
    /// order, so an equal tip is [`RbfVerdict::NotABid`], not underpriced.
    pub fn verdict(&self, candidate_grains: u128) -> RbfVerdict {
        if candidate_grains <= self.current_tip {
            return RbfVerdict::NotABid;
        }
        let required = self.required_tip();
        if candidate_grains < required {
            return RbfVerdict::Underpriced { required };
        }
        RbfVerdict::Replaces
    }

    /// Convenience predicate: does this candidate bid land?
    pub fn would_replace(&self, candidate_grains: u128) -> bool {
        self.verdict(candidate_grains) == RbfVerdict::Replaces
    }

    /// The cheapest bid that replaces the incumbent, or `None` when no such bid is
    /// representable — i.e. the incumbent already tips `u128::MAX`, where every
    /// candidate is `≤ old_tip` and hits the `NonceTaken` arm. (Just below the
    /// maximum, `required` saturates to `u128::MAX`, which IS admissible and is
    /// exactly what the node computes, so it is returned.)
    pub fn next_bid(&self) -> Option<u128> {
        let required = self.required_tip();
        if required <= self.current_tip {
            None
        } else {
            Some(required)
        }
    }

    /// Advance the plan after a replacement landed at `tip_grains`: that bid is now
    /// the slot's incumbent. Never moves backwards, so a stale or losing bid cannot
    /// lower the price to beat.
    pub fn landed(&mut self, tip_grains: u128) {
        if tip_grains > self.current_tip {
            self.current_tip = tip_grains;
        }
    }

    /// The escalating bid ladder for a storm of `rounds` successive replacements at
    /// this slot: each entry is the minimum that displaces the previous one. Stops
    /// early (returning a shorter vector) when the ladder saturates, so it is
    /// bounded and allocation-safe.
    pub fn storm(&self, rounds: usize) -> Vec<u128> {
        let mut plan = *self;
        let mut bids = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            match plan.next_bid() {
                Some(bid) => {
                    bids.push(bid);
                    plan.landed(bid);
                }
                None => break,
            }
        }
        bids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Tip policy -------------------------------------------------------

    #[test]
    fn untipped_policy_never_produces_an_envelope() {
        let mut sel = TipSelector::new(TipPolicy::Untipped).unwrap();
        for draw in [0u128, 7, u128::MAX] {
            assert_eq!(sel.next_tip(draw), None);
        }
        assert!(sel.policy().rungs().is_empty());
    }

    #[test]
    fn fixed_policy_bids_the_same_tip_every_time() {
        let mut sel = TipSelector::new(TipPolicy::Fixed(25_000)).unwrap();
        for draw in [0u128, 1, u128::MAX] {
            assert_eq!(sel.next_tip(draw), Some(25_000));
        }
        assert_eq!(sel.policy().rungs(), &[25_000]);
    }

    #[test]
    fn ladder_round_robin_cycles_every_rung_in_ascending_order() {
        let mut sel = TipSelector::new(TipPolicy::Ladder {
            rungs: vec![1_000, 5_000, 25_000],
            mode: LadderMode::RoundRobin,
        })
        .unwrap();
        let bids: Vec<u128> = (0..7).map(|_| sel.next_tip(0).unwrap()).collect();
        assert_eq!(
            bids,
            vec![1_000, 5_000, 25_000, 1_000, 5_000, 25_000, 1_000]
        );
    }

    #[test]
    fn ladder_random_stays_on_the_ladder_and_reaches_every_rung() {
        let rungs = vec![1_000u128, 5_000, 25_000, 100_000];
        let mut sel = TipSelector::new(TipPolicy::Ladder {
            rungs: rungs.clone(),
            mode: LadderMode::Random,
        })
        .unwrap();
        let mut seen = std::collections::HashSet::new();
        // A deterministic sweep of draws stands in for the caller's PRNG.
        for draw in 0..4_000u128 {
            let bid = sel.next_tip(draw.wrapping_mul(2_654_435_761)).unwrap();
            assert!(rungs.contains(&bid), "bid {bid} is not a ladder rung");
            seen.insert(bid);
        }
        assert_eq!(seen.len(), rungs.len(), "not every rung was reachable");
    }

    #[test]
    fn ladder_random_handles_an_extreme_draw_without_overflow_or_panic() {
        let mut sel = TipSelector::new(TipPolicy::Ladder {
            rungs: vec![1_000, 2_000, 3_000],
            mode: LadderMode::Random,
        })
        .unwrap();
        for draw in [0, 1, u128::MAX - 1, u128::MAX] {
            let bid = sel.next_tip(draw).unwrap();
            assert!([1_000, 2_000, 3_000].contains(&bid));
        }
    }

    #[test]
    fn tip_policy_validation_rejects_bad_shapes() {
        assert!(TipPolicy::Untipped.validate().is_ok());
        assert!(TipPolicy::Fixed(1).validate().is_ok());
        // A zero fixed tip is Untipped spelled confusingly.
        assert!(TipPolicy::Fixed(0).validate().is_err());
        let ladder = |rungs: Vec<u128>| TipPolicy::Ladder {
            rungs,
            mode: LadderMode::RoundRobin,
        };
        assert!(ladder(vec![]).validate().is_err());
        assert!(ladder(vec![0, 1_000]).validate().is_err());
        assert!(ladder(vec![5_000, 1_000]).validate().is_err()); // descending
        assert!(ladder(vec![1_000, 1_000]).validate().is_err()); // duplicate
        assert!(ladder(vec![1_000]).validate().is_ok());
        assert!(ladder(vec![1, 2, 3]).validate().is_ok());
        // The selector refuses exactly what validate refuses.
        assert!(TipSelector::new(ladder(vec![])).is_err());
        assert!(TipSelector::new(ladder(vec![1_000, 2_000])).is_ok());
    }

    // ---- Bucketing --------------------------------------------------------

    #[test]
    fn a_tip_is_bucketed_by_the_highest_rung_it_cleared() {
        let rungs = [1_000u128, 5_000, 25_000];
        assert_eq!(bucket_of(&rungs, 1_000), TipBucket::Rung(1_000));
        assert_eq!(bucket_of(&rungs, 4_999), TipBucket::Rung(1_000));
        assert_eq!(bucket_of(&rungs, 5_000), TipBucket::Rung(5_000));
        assert_eq!(bucket_of(&rungs, 24_999), TipBucket::Rung(5_000));
        assert_eq!(bucket_of(&rungs, 25_000), TipBucket::Rung(25_000));
        // Above the top rung stays in the top bucket — never an invented one.
        assert_eq!(bucket_of(&rungs, u128::MAX), TipBucket::Rung(25_000));
    }

    #[test]
    fn zero_is_untipped_and_a_sub_ladder_bid_has_its_own_bucket() {
        let rungs = [1_000u128, 5_000];
        assert_eq!(bucket_of(&rungs, 0), TipBucket::Untipped);
        assert_eq!(bucket_of(&rungs, 1), TipBucket::BelowLadder);
        assert_eq!(bucket_of(&rungs, 999), TipBucket::BelowLadder);
        // An empty ladder still classifies every tip (total mapping, no panic).
        assert_eq!(bucket_of(&[], 0), TipBucket::Untipped);
        assert_eq!(bucket_of(&[], 12_345), TipBucket::BelowLadder);
    }

    #[test]
    fn every_bid_a_policy_generates_lands_in_its_own_rung_bucket() {
        let policy = TipPolicy::Ladder {
            rungs: vec![1_000, 5_000, 25_000],
            mode: LadderMode::RoundRobin,
        };
        let mut sel = TipSelector::new(policy.clone()).unwrap();
        for _ in 0..12 {
            let bid = sel.next_tip(0).unwrap();
            assert_eq!(policy.bucket(bid), TipBucket::Rung(bid));
        }
        // A fixed policy too: its single bid is its own bucket.
        assert_eq!(TipPolicy::Fixed(7).bucket(7), TipBucket::Rung(7));
        // Untipped has no rungs, so its own (zero) bid is the untipped bucket.
        assert_eq!(TipPolicy::Untipped.bucket(0), TipBucket::Untipped);
        assert_eq!(TipPolicy::Untipped.bucket(1), TipBucket::BelowLadder);
    }

    #[test]
    fn bucket_labels_are_distinct_per_bucket() {
        let labels: std::collections::HashSet<String> = [
            TipBucket::Untipped,
            TipBucket::BelowLadder,
            TipBucket::Rung(1_000),
            TipBucket::Rung(5_000),
        ]
        .iter()
        .map(|b| b.label())
        .collect();
        assert_eq!(labels.len(), 4);
        assert_eq!(TipBucket::Rung(1_000).label(), "≥1000");
        assert_eq!(TipBucket::Untipped.label(), "untipped");
    }

    // ---- Envelope construction -------------------------------------------

    #[test]
    fn wrap_tipped_builds_the_envelope_the_node_expects() {
        let inner = Action::OracleUpdate { price: 1 };
        let wrapped = wrap_tipped(inner.clone(), 4_200).unwrap();
        match &wrapped {
            Action::Tipped { tip, inner: got } => {
                assert_eq!(*tip, Balance::from_grains(4_200));
                assert_eq!(got.as_ref(), &inner);
            }
            other => panic!("expected Tipped, got {other:?}"),
        }
        // A zero tip is legal on chain, so the builder allows it.
        assert!(wrap_tipped(Action::OracleUpdate { price: 1 }, 0).is_ok());
    }

    #[test]
    fn wrap_tipped_refuses_exactly_what_consensus_refuses() {
        let tipped = wrap_tipped(Action::OracleUpdate { price: 1 }, 10).unwrap();
        // Nesting: ExecutionError::NestedTip.
        assert!(wrap_tipped(tipped, 20).is_err());
        // Inner MultisigExec / RotateKey: ExecutionError::TipInnerNotAllowed.
        let ms = Action::MultisigExec {
            action: Box::new(Action::OracleUpdate { price: 1 }),
            approvals: Vec::new(),
        };
        assert!(wrap_tipped(ms, 10).is_err());
    }

    // ---- Floor probe ------------------------------------------------------

    #[test]
    fn a_fresh_probe_reports_an_unknown_floor_not_a_zero() {
        let probe = FloorProbe::new(10_000, 1_000).unwrap();
        let b = probe.bracket();
        assert_eq!(probe.observations(), 0);
        assert_eq!(b, FloorBracket::default());
        assert!(!b.is_bracketed());
        assert_eq!(b.width(), None);
        assert!(b.advice().contains("unknown"));
        assert_eq!(probe.next_probe(), Some(10_000));
    }

    #[test]
    fn a_zero_step_ramp_is_rejected_so_the_probe_cannot_stall() {
        assert!(FloorProbe::new(10_000, 0).is_err());
        assert!(FloorProbe::new(10_000, 1).is_ok());
    }

    #[test]
    fn the_ramp_steps_down_by_the_step_and_bottoms_out_at_zero() {
        let mut probe = FloorProbe::new(2_500, 1_000).unwrap();
        let mut probed = Vec::new();
        while let Some(tip) = probe.next_probe() {
            probed.push(tip);
            probe.record(tip, Admission::Accepted);
        }
        // 2500 → 1500 → 500 → 0 (saturating, never underflowing) → done.
        assert_eq!(probed, vec![2_500, 1_500, 500, 0]);
        assert_eq!(probe.observations(), 4);
        assert_eq!(probe.next_probe(), None);
    }

    #[test]
    fn an_all_accepted_ramp_reports_only_an_upper_bound() {
        let mut probe = FloorProbe::new(5_000, 1_000).unwrap();
        for tip in [5_000u128, 4_000, 3_000] {
            probe.record(tip, Admission::Accepted);
        }
        let b = probe.bracket();
        assert_eq!(b.lowest_accepted, Some(3_000));
        assert_eq!(b.highest_refused, None);
        assert!(!b.is_bracketed());
        assert!(!b.inverted);
        assert_eq!(b.width(), None);
        assert!(b.advice().contains("accepted"));
    }

    #[test]
    fn an_all_refused_ramp_reports_only_a_lower_bound() {
        let mut probe = FloorProbe::new(3_000, 1_000).unwrap();
        for tip in [3_000u128, 2_000, 1_000] {
            probe.record(tip, Admission::Refused);
        }
        let b = probe.bracket();
        assert_eq!(b.highest_refused, Some(3_000));
        assert_eq!(b.lowest_accepted, None);
        assert!(!b.is_bracketed());
        assert_eq!(b.width(), None);
        assert!(b.advice().contains("refused"));
    }

    #[test]
    fn a_clean_ramp_brackets_the_true_floor_between_the_refusal_and_the_accept() {
        // A stable floor of 2_500: the node admits a strict outbid (tip > floor)
        // and refuses anything at or below it.
        let floor = 2_500u128;
        let mut probe = FloorProbe::new(6_000, 1_000).unwrap();
        while let Some(tip) = probe.next_probe() {
            let outcome = if tip > floor {
                Admission::Accepted
            } else {
                Admission::Refused
            };
            probe.record(tip, outcome);
            if outcome == Admission::Refused {
                break; // an operator stops at the first refusal
            }
        }
        let b = probe.bracket();
        // 6000, 5000, 4000, 3000 accepted; 2000 refused.
        assert_eq!(b.lowest_accepted, Some(3_000));
        assert_eq!(b.highest_refused, Some(2_000));
        assert!(b.is_bracketed());
        assert!(!b.inverted);
        assert_eq!(b.width(), Some(1_000));
        // The true floor really does lie in [highest_refused, lowest_accepted).
        assert!(b.highest_refused.unwrap() <= floor && floor < b.lowest_accepted.unwrap());
        assert!(b.advice().contains("between"));
    }

    #[test]
    fn a_non_monotonic_ramp_is_flagged_inverted_and_never_panics() {
        // The floor DROPS mid-probe: 4_000 refused, then 1_000 accepted.
        let mut probe = FloorProbe::new(4_000, 1_000).unwrap();
        probe.record(4_000, Admission::Refused);
        probe.record(3_000, Admission::Refused);
        probe.record(1_000, Admission::Accepted);
        let b = probe.bracket();
        assert_eq!(b.highest_refused, Some(4_000));
        assert_eq!(b.lowest_accepted, Some(1_000));
        assert!(b.is_bracketed());
        assert!(b.inverted, "an accept below an earlier refusal is inverted");
        // An inverted bracket has no width — it does not describe one price.
        assert_eq!(b.width(), None);
        assert!(b.advice().contains("NON-MONOTONIC"));
    }

    #[test]
    fn the_same_tip_refused_then_accepted_is_inverted_not_zero_width() {
        let mut probe = FloorProbe::new(1_000, 500).unwrap();
        probe.record(1_000, Admission::Refused);
        probe.record(1_000, Admission::Accepted);
        let b = probe.bracket();
        assert_eq!(b.highest_refused, Some(1_000));
        assert_eq!(b.lowest_accepted, Some(1_000));
        assert!(b.inverted);
        assert_eq!(b.width(), None);
    }

    #[test]
    fn out_of_order_observations_keep_the_extremes_not_the_last_seen() {
        let mut probe = FloorProbe::new(9_000, 1_000).unwrap();
        probe.record(9_000, Admission::Accepted);
        probe.record(500, Admission::Refused);
        probe.record(7_000, Admission::Accepted); // a higher accept must not win
        probe.record(100, Admission::Refused); // a lower refusal must not win
        let b = probe.bracket();
        assert_eq!(b.lowest_accepted, Some(7_000));
        assert_eq!(b.highest_refused, Some(500));
        assert!(!b.inverted);
        assert_eq!(b.width(), Some(6_500));
        assert_eq!(probe.observations(), 4);
    }

    #[test]
    fn recording_a_hand_picked_tip_re_anchors_the_ramp_below_it() {
        let mut probe = FloorProbe::new(50_000, 1_000).unwrap();
        probe.record(3_000, Admission::Accepted); // the operator jumped the ramp
        assert_eq!(probe.next_probe(), Some(2_000));
    }

    #[test]
    fn a_step_larger_than_the_start_tip_lands_on_zero_without_underflow() {
        let mut probe = FloorProbe::new(100, 1_000_000).unwrap();
        probe.record(100, Admission::Refused);
        assert_eq!(probe.next_probe(), Some(0));
        probe.record(0, Admission::Refused);
        assert_eq!(probe.next_probe(), None);
        assert_eq!(probe.bracket().highest_refused, Some(100));
    }

    // ---- RBF storm --------------------------------------------------------

    #[test]
    fn required_tip_mirrors_the_nodes_minimum_bump() {
        assert_eq!(MIN_RBF_BUMP_GRAINS, 1_000);
        assert_eq!(RbfPlan::new(0).required_tip(), 1_000);
        assert_eq!(RbfPlan::new(5_000).required_tip(), 6_000);
        assert_eq!(RbfPlan::new(0).next_bid(), Some(1_000));
    }

    #[test]
    fn a_bump_one_grain_short_of_the_minimum_is_underpriced() {
        let plan = RbfPlan::new(5_000);
        assert_eq!(
            plan.verdict(5_999),
            RbfVerdict::Underpriced { required: 6_000 }
        );
        assert!(!plan.would_replace(5_999));
        // The smallest possible raise is still underpriced, never a replacement.
        assert_eq!(
            plan.verdict(5_001),
            RbfVerdict::Underpriced { required: 6_000 }
        );
    }

    #[test]
    fn a_bump_of_exactly_the_minimum_replaces() {
        // The node compares `new_tip < required` (mempool lib.rs:463), so the
        // boundary itself LANDS. This is the case a wrong `<=` would break.
        let plan = RbfPlan::new(5_000);
        assert_eq!(plan.verdict(6_000), RbfVerdict::Replaces);
        assert!(plan.would_replace(6_000));
        assert_eq!(plan.next_bid(), Some(6_000));
    }

    #[test]
    fn a_bump_one_grain_past_the_minimum_replaces() {
        let plan = RbfPlan::new(5_000);
        assert_eq!(plan.verdict(6_001), RbfVerdict::Replaces);
        assert!(plan.would_replace(6_001));
    }

    #[test]
    fn an_equal_or_lower_tip_is_not_a_bid_at_all() {
        // Checked BEFORE the bump (mempool lib.rs:456), so these are NonceTaken,
        // not RbfUnderpriced — the distinction the operator sees in the error.
        let plan = RbfPlan::new(5_000);
        assert_eq!(plan.verdict(5_000), RbfVerdict::NotABid);
        assert_eq!(plan.verdict(4_999), RbfVerdict::NotABid);
        assert_eq!(plan.verdict(0), RbfVerdict::NotABid);
        // Against an untipped incumbent, a zero bid is likewise not a bid, and a
        // raise still owes the full bump.
        assert_eq!(RbfPlan::new(0).verdict(0), RbfVerdict::NotABid);
        assert_eq!(
            RbfPlan::new(0).verdict(999),
            RbfVerdict::Underpriced { required: 1_000 }
        );
        assert_eq!(RbfPlan::new(0).verdict(1_000), RbfVerdict::Replaces);
    }

    #[test]
    fn the_rule_saturates_near_u128_max_without_overflowing() {
        // Just below the maximum: `required` saturates to u128::MAX exactly as the
        // node's own saturating_add does, and that bid IS admissible.
        let plan = RbfPlan::new(u128::MAX - 500);
        assert_eq!(plan.required_tip(), u128::MAX);
        assert_eq!(plan.verdict(u128::MAX), RbfVerdict::Replaces);
        assert_eq!(
            plan.verdict(u128::MAX - 1),
            RbfVerdict::Underpriced {
                required: u128::MAX
            }
        );
        assert_eq!(plan.next_bid(), Some(u128::MAX));
        // At the maximum itself, no replacement is representable at all.
        let maxed = RbfPlan::new(u128::MAX);
        assert_eq!(maxed.required_tip(), u128::MAX);
        assert_eq!(maxed.next_bid(), None);
        assert_eq!(maxed.verdict(u128::MAX), RbfVerdict::NotABid);
    }

    #[test]
    fn a_storm_escalates_by_exactly_the_minimum_each_round() {
        let plan = RbfPlan::new(2_000);
        let bids = plan.storm(4);
        assert_eq!(bids, vec![3_000, 4_000, 5_000, 6_000]);
        // Strictly increasing, and each bid replaces the previous incumbent.
        let mut incumbent = RbfPlan::new(2_000);
        for bid in &bids {
            assert!(incumbent.would_replace(*bid));
            incumbent.landed(*bid);
        }
        assert_eq!(incumbent.current_tip(), 6_000);
        assert!(plan.storm(0).is_empty());
    }

    #[test]
    fn a_storm_stops_instead_of_overflowing_at_the_ceiling() {
        let plan = RbfPlan::new(u128::MAX - 500);
        let bids = plan.storm(10);
        // One representable bid (the saturated maximum), then the ladder ends.
        assert_eq!(bids, vec![u128::MAX]);
        assert!(RbfPlan::new(u128::MAX).storm(10).is_empty());
    }

    #[test]
    fn landing_never_lowers_the_price_to_beat() {
        let mut plan = RbfPlan::new(5_000);
        plan.landed(4_000); // a stale/losing bid must not rewind the incumbent
        assert_eq!(plan.current_tip(), 5_000);
        plan.landed(6_000);
        assert_eq!(plan.current_tip(), 6_000);
    }
}
