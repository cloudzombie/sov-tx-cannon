//! Adversarial probes — pure, deterministic *expectations* the cannon asserts
//! against a live node, so a run is evidence instead of a guess.
//!
//! Two independent probe families live here, sharing one verdict vocabulary:
//!
//! * **Part A — adversarial nonce scenarios** ([`Scenario`], [`plan`]). The
//!   ordinary cannon only ever fires a strictly monotonic, gap-free nonce run
//!   (see [`NonceSequencer`](crate::logic::NonceSequencer)), which never
//!   exercises the mempool's nonce rules at all. [`plan`] emits a scripted
//!   sequence that deliberately opens a hole, submits out of order, and replays
//!   a nonce, each step carrying the outcome the node MUST produce.
//! * **Part B — tx-domain A/B** ([`ActivationPhase`], [`SignedUnder`],
//!   [`expected_domain_outcome`]). A decision table over (activation phase ×
//!   which domain the signature was framed under) with one non-negotiable cell:
//!   a WRONG-domain signature is refused in every phase. That is the entire
//!   point of the `tx-domain` fork, and it is the one property worth asserting
//!   against mainnet directly.
//!
//! Everything here is pure: no network, no filesystem, no clock, no globals.
//! The caller does the I/O and feeds the observations back in.
//!
//! # Sourcing
//!
//! Every claim below about node behavior is cited to the pinned chain source
//! (the `v0.2.0` tag this crate depends on). Line numbers are of that revision:
//!
//! | Claim | Source |
//! |---|---|
//! | Gap-free admission: `nonce > current_nonce + pooled_count` ⇒ `NonceGap`, never queued | `chain/crates/mempool/src/lib.rs:420-436` (and the crate doc, `:12-15`) |
//! | `NonceGap` display text — `"nonce gap: next mineable nonce is {expected}, transaction used {got}"` | `chain/crates/mempool/src/lib.rs:105-116` |
//! | Byte-identical resubmission ⇒ `Duplicate`, `"transaction already in the pool"` | `chain/crates/mempool/src/lib.rs:65-68`, checked at `:437-439` |
//! | A different tx in a taken `(signer, nonce)` slot that does not out-bid ⇒ `NonceTaken`, `"…is already pooled"` | `chain/crates/mempool/src/lib.rs:117-125`, `:455-460` |
//! | Selection walks each signer's contiguous run and stops at the first hole | `chain/crates/mempool/src/lib.rs:678-717` |
//! | STF requires strict nonce EQUALITY (`tx.nonce != signer.nonce` ⇒ reject) | `chain/crates/runtime/src/execution.rs:222-226` |
//! | `sov_getNonce` reports the first FREE slot at/above the on-chain nonce (mempool-aware) | `chain/crates/mempool/src/lib.rs:278-317`, `chain/crates/node/src/node.rs:100-103` |
//! | Grace window `[H_a, H_a + G)` accepts legacy OR bound; `>= H_a + G` bound only; `< H_a` legacy only | `chain/crates/primitives/src/signing_domain.rs:76-140`, `chain/crates/chain/src/blockchain.rs:862-895` |
//! | A bad signature (any wrong preimage) ⇒ `"invalid transaction signature"` | `chain/crates/mempool/src/lib.rs:52-56`, checked first at `:410-412` |
//!
//! Anything NOT verifiable from the pinned source is marked "UNVERIFIED" in the
//! doc comment that relies on it. This tool is pointed at live mainnet: a wrong
//! expectation here would manufacture a false accusation of a consensus bug, so
//! the verdict function below is deliberately biased toward *inconclusive*.

// This module is a self-contained decision surface: it is exercised by its own
// tests and consumed by the adversarial run modes. Allowing dead code keeps the
// API complete (every cell of both tables is reachable by a caller) without the
// binary having to name each item.
#![allow(dead_code)]

use std::cmp::Ordering;

use sov_primitives::{Hash, SigningDomain, TxDomainMode};

use crate::logic::{classify_reject, RejectClass};

// ---------------------------------------------------------------------------
// Shared vocabulary
// ---------------------------------------------------------------------------

/// What a probe step expects the node to do.
///
/// Rejections are expressed in the EXISTING [`RejectClass`] vocabulary — the
/// same buckets the live meters use — plus a `marker`, a lowercase substring of
/// the node's real error text. The marker matters because [`RejectClass::Other`]
/// is a catch-all that also swallows transport failures: without it, a dead
/// socket would "confirm" a gap rejection. With it, an `Other` that does not
/// carry the expected wording is reported as inconclusive rather than as a pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// The node must accept the transaction into its pool.
    Accepted,
    /// The node must refuse it, in this class, with this wording.
    Rejected {
        /// The bucket [`classify_reject`] must place the node's message in.
        class: RejectClass,
        /// A lowercase substring the node's real message must contain.
        marker: &'static str,
    },
}

/// The node's real answer to one submission, as the caller observed it.
///
/// `Rejected` carries the raw, unparsed error string (RPC wrapping and all) so
/// the verdict can apply both [`classify_reject`] and the marker test to exactly
/// what the node said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observed {
    /// `sov_submitTransaction` returned success.
    Accepted,
    /// It returned an error; this is the full message.
    Rejected(String),
}

/// One probe's observation, bracketed by two reads of the node's next free
/// nonce (`sov_getNonce`) — immediately BEFORE and immediately AFTER the submit.
///
/// The bracket is what makes a `Mismatch` defensible. `sov_getNonce` is the
/// mempool-aware first-free-slot walk from the account's on-chain nonce
/// (`chain/crates/mempool/src/lib.rs:278-317`), and it is INVARIANT under the
/// account's own mining: when a pooled tx at nonce `n` is mined the on-chain
/// nonce rises by one and the pooled entry is pruned, so the first free slot is
/// unchanged. It moves only when something genuinely confounds the probe —
/// a third party spending from the same account, another worker submitting on
/// it, or the capacity auction evicting our tail. Bracketing therefore detects
/// precisely the races that could otherwise be mistaken for a node bug, while
/// not firing on the benign one (our own transactions confirming).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    /// What the node did with the submission.
    pub outcome: Observed,
    /// `sov_getNonce` for this signer, read immediately before submitting.
    pub next_nonce_before: u64,
    /// `sov_getNonce` for this signer, read immediately after the submit returned.
    pub next_nonce_after: u64,
}

/// The result of scoring one observation against its expectation.
///
/// Three states, not two, on purpose: on a live mainnet a false FAIL is far
/// worse than an admission of ignorance, so any outcome with a benign
/// concurrent-state explanation is [`Inconclusive`](Verdict::Inconclusive), and
/// [`Mismatch`](Verdict::Mismatch) is reserved for observations that no race can
/// account for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The node did exactly what the rule requires.
    Match,
    /// The probe did not resolve: the account or pool moved under it, or the
    /// node refused for an unrelated (environmental) reason. Not a failure.
    Inconclusive(String),
    /// The node violated a documented rule, and no concurrent-state story
    /// explains the observation. Still worth reproducing before reporting it:
    /// see [`verdict`] for the residual (sub-bracket) race window.
    Mismatch(String),
}

impl Verdict {
    /// A short, fixed-width word for the run log.
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Match => "MATCH",
            Verdict::Inconclusive(_) => "INCONCL",
            Verdict::Mismatch(_) => "MISMATCH",
        }
    }

    /// The explanation, empty for a clean match.
    pub fn reason(&self) -> &str {
        match self {
            Verdict::Match => "",
            Verdict::Inconclusive(r) | Verdict::Mismatch(r) => r,
        }
    }

    /// Whether this verdict should fail a run. ONLY a [`Mismatch`](Verdict::Mismatch)
    /// does; an inconclusive probe is noise, not evidence.
    pub fn is_failure(&self) -> bool {
        matches!(self, Verdict::Mismatch(_))
    }
}

/// Case-insensitive substring test, matching how [`classify_reject`] reads the
/// node's messages through the RPC/client wrapping.
fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_ascii_lowercase().contains(needle)
}

// ---------------------------------------------------------------------------
// Part A — adversarial nonce scenarios
// ---------------------------------------------------------------------------

/// The rejection expected for a transaction submitted above a nonce hole.
///
/// SOV has **no Ethereum-style future/queued tier**: a nonce beyond
/// `on_chain + pooled_run` is refused at the door with `MempoolError::NonceGap`
/// rather than parked for later (`chain/crates/mempool/src/lib.rs:420-436`). Its
/// text — `"nonce gap: next mineable nonce is {expected}, transaction used
/// {got}"` (`:110`) — buckets as [`RejectClass::NonceGap`], a class this
/// module's first draft could not use because the taxonomy lacked it; it was
/// added to `logic.rs` precisely so a deliberate gap probe is never confused
/// with a transport failure. The `marker` still pins the exact node text, so a
/// future message change is caught rather than silently passing.
pub const EXPECT_NONCE_GAP: Expect = Expect::Rejected {
    class: RejectClass::NonceGap,
    marker: "nonce gap",
};

/// The rejection expected for a byte-identical resubmission of a pooled tx:
/// `MempoolError::Duplicate`, `"transaction already in the pool"`
/// (`chain/crates/mempool/src/lib.rs:65-68`, checked at `:437-439`), which
/// [`classify_reject`] buckets as [`RejectClass::NonceOccupied`].
pub const EXPECT_DUPLICATE: Expect = Expect::Rejected {
    class: RejectClass::NonceOccupied,
    marker: "already in the pool",
};

/// A scripted adversarial nonce probe for ONE signer.
///
/// Each scenario is a short, self-healing script: it ends with the signer's
/// nonce run contiguous again, so a run can loop scenarios back-to-back without
/// wedging the account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scenario {
    /// Skip a nonce: submit two above the next free slot, then fill the hole
    /// from the bottom. Proves the gap is refused *against the contiguous run*
    /// (not merely "one above"), and that filling it unsticks the account.
    Gap,
    /// Submit N+1 before N. Proves the out-of-order transaction is REFUSED
    /// outright rather than queued until N arrives — the property that most
    /// distinguishes SOV's mempool from Ethereum's.
    Reorder,
    /// Submit the same nonce twice with byte-identical bytes. Proves the slot is
    /// held (and that the duplicate does not silently displace the incumbent).
    Duplicate,
}

impl Scenario {
    /// Every scenario, for a run that sweeps all of them.
    pub fn all() -> [Scenario; 3] {
        [Scenario::Gap, Scenario::Reorder, Scenario::Duplicate]
    }

    /// The operator-facing name.
    pub fn label(self) -> &'static str {
        match self {
            Scenario::Gap => "GAP",
            Scenario::Reorder => "REORDER",
            Scenario::Duplicate => "DUPLICATE",
        }
    }

    /// One line describing what the scenario proves.
    pub fn probes(self) -> &'static str {
        match self {
            Scenario::Gap => "a tx above a nonce hole is refused, not queued",
            Scenario::Reorder => "N+1 before N is refused; N then N+1 both land",
            Scenario::Duplicate => "a replayed nonce is refused, slot unchanged",
        }
    }
}

/// One step of a [`Scenario`]: what to submit, and what must come back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    /// The nonce to build and sign this transaction at.
    pub nonce: u64,
    /// What `sov_getNonce` must report for this signer immediately before the
    /// submit for the step's expectation to hold exactly. If the node reports
    /// anything else, the account moved and [`verdict`] declines to score.
    pub assumed_next_nonce: u64,
    /// What this step is probing, in words, for the run log.
    pub probe: &'static str,
    /// The outcome the node's own rules require.
    pub expect: Expect,
    /// If true, the caller MUST resubmit the byte-identical signed transaction
    /// from the earlier step at this nonce — not a freshly built one.
    ///
    /// This matters: a *different* transaction in an occupied slot enters the
    /// replace-by-fee path (`chain/crates/mempool/src/lib.rs:440-476`), where a
    /// tip above `old_tip + MIN_RBF_BUMP_GRAINS` would legitimately REPLACE the
    /// incumbent and be accepted. Replaying the exact bytes hits the `by_id`
    /// duplicate check first (`:437-439`) and is unambiguous.
    pub resubmit: bool,
}

/// Build the step script for `scenario`, starting from `base_nonce` — the
/// signer's next free nonce as the node reports it (`sov_getNonce`).
///
/// Nonce arithmetic saturates. At `u64::MAX` the steps degenerate to the same
/// nonce (the plan stops being adversarial) but nothing overflows or panics;
/// that height of nonce is unreachable in practice — an account would have to
/// send 2^64 transactions.
pub fn plan(scenario: Scenario, base_nonce: u64) -> Vec<Step> {
    let n0 = base_nonce;
    let n1 = base_nonce.saturating_add(1);
    let n2 = base_nonce.saturating_add(2);
    match scenario {
        Scenario::Gap => vec![
            Step {
                nonce: n2,
                assumed_next_nonce: n0,
                probe: "two above the run: must be refused as a nonce gap",
                expect: EXPECT_NONCE_GAP,
                resubmit: false,
            },
            Step {
                nonce: n0,
                assumed_next_nonce: n0,
                probe: "the bottom of the run: must be accepted",
                expect: Expect::Accepted,
                resubmit: false,
            },
            Step {
                nonce: n2,
                assumed_next_nonce: n1,
                probe: "still one above the run: the hole at N+1 keeps it out",
                expect: EXPECT_NONCE_GAP,
                resubmit: false,
            },
            Step {
                nonce: n1,
                assumed_next_nonce: n1,
                probe: "filling the hole: must be accepted",
                expect: Expect::Accepted,
                resubmit: false,
            },
            Step {
                nonce: n2,
                assumed_next_nonce: n2,
                probe: "now contiguous: the once-refused nonce must be accepted",
                expect: Expect::Accepted,
                resubmit: false,
            },
        ],
        Scenario::Reorder => vec![
            Step {
                nonce: n1,
                assumed_next_nonce: n0,
                probe: "N+1 before N: refused outright, never queued",
                expect: EXPECT_NONCE_GAP,
                resubmit: false,
            },
            Step {
                nonce: n0,
                assumed_next_nonce: n0,
                probe: "N in order: accepted",
                expect: Expect::Accepted,
                resubmit: false,
            },
            Step {
                nonce: n1,
                assumed_next_nonce: n1,
                probe: "N+1 resubmitted after N: accepted",
                expect: Expect::Accepted,
                resubmit: false,
            },
        ],
        Scenario::Duplicate => vec![
            Step {
                nonce: n0,
                assumed_next_nonce: n0,
                probe: "the original at N: accepted",
                expect: Expect::Accepted,
                resubmit: false,
            },
            Step {
                nonce: n0,
                assumed_next_nonce: n1,
                probe: "the identical bytes replayed at N: refused, slot held",
                expect: EXPECT_DUPLICATE,
                resubmit: true,
            },
        ],
    }
}

/// Score one observation against its planned expectation.
///
/// The scoring is deliberately layered, and each layer can only *downgrade* the
/// verdict toward inconclusive:
///
/// 1. **Bracket check.** If `next_nonce_before` is not the value the plan
///    assumed, the account moved before the probe even ran — no score.
/// 2. **Movement check.** The `next_nonce_after` reading must be exactly what
///    the observed outcome implies: unchanged after a rejection; `before + 1`
///    after an acceptance AT the first free slot; and — the interesting case —
///    unchanged after an acceptance ABOVE the first free slot, because the hole
///    below it is still the first free slot. Anything else means a third party
///    touched the account mid-probe, so no score. (Our own mining cannot trip
///    this: `sov_getNonce` is invariant under it — see [`Observation`].)
/// 3. **Expectation match.**
///    * Expected accept, got accept → [`Verdict::Match`].
///    * Expected reject, got a reject of the same class carrying the marker →
///      [`Verdict::Match`]. Same class, different wording → inconclusive (the
///      class alone is too coarse — `Other` includes transport failures).
///      Different class → inconclusive.
///    * Expected accept, got a reject → **always inconclusive**. Every rejection
///      class has a benign story that the bracket cannot exclude: capacity and
///      affordability rejections do not move the next free nonce at all, and a
///      third party who takes our slot and has it mined within the bracket
///      leaves the nonce reading unchanged while making our submission stale.
///      A cannon that FAILED here would fail on ordinary mainnet contention.
///    * Expected reject, got an accept → [`Verdict::Mismatch`] **only** when the
///      accepted nonce sat above the node's own reported first free slot and the
///      hole below it survived the submit. That is gap-free admission
///      (`chain/crates/mempool/src/lib.rs:420-436`) being violated, and no
///      concurrent state explains it: had someone filled the hole, the after
///      reading would have jumped past it and layer 2 would already have
///      declined to score. Otherwise → inconclusive.
///
/// Residual risk, stated honestly: the bracket cannot see a change that occurs
/// and is undone *between* the two reads (e.g. our tail evicted and immediately
/// re-admitted). A single `Mismatch` should therefore be reproduced before it is
/// reported as a consensus bug.
pub fn verdict(step: &Step, obs: &Observation) -> Verdict {
    let before = obs.next_nonce_before;
    if before != step.assumed_next_nonce {
        return Verdict::Inconclusive(format!(
            "account moved before the probe: node reports next nonce {before}, the plan assumed {}",
            step.assumed_next_nonce
        ));
    }

    // What the after-reading must be, given what the node actually did.
    let implied_after = match (&obs.outcome, step.nonce.cmp(&before)) {
        (Observed::Rejected(_), _) => before,
        // Accepted at the first free slot: that slot is now taken.
        (Observed::Accepted, Ordering::Equal) => before.saturating_add(1),
        // Accepted ABOVE the first free slot: the hole below is still first-free.
        (Observed::Accepted, Ordering::Greater) => before,
        // Accepted BELOW the first free slot (the duplicate replay): the slot was
        // already taken, so accepting it means an in-place replacement happened —
        // the first free slot is unchanged.
        (Observed::Accepted, Ordering::Less) => before,
    };
    if obs.next_nonce_after != implied_after {
        return Verdict::Inconclusive(format!(
            "account moved during the probe: next nonce went {before} → {}, but this outcome implies {implied_after}",
            obs.next_nonce_after
        ));
    }

    match (&step.expect, &obs.outcome) {
        (Expect::Accepted, Observed::Accepted) => Verdict::Match,

        (Expect::Accepted, Observed::Rejected(msg)) => Verdict::Inconclusive(format!(
            "expected acceptance at nonce {}, node refused ({:?}); contention (capacity, \
             affordability, or a third party taking and mining this slot) explains this \
             without any rule being broken: {msg}",
            step.nonce,
            classify_reject(msg)
        )),

        (Expect::Rejected { class, marker }, Observed::Rejected(msg)) => {
            let got = classify_reject(msg);
            if got != *class {
                Verdict::Inconclusive(format!(
                    "expected a {class:?} rejection, got {got:?}: {msg}"
                ))
            } else if !contains_ci(msg, marker) {
                Verdict::Inconclusive(format!(
                    "rejection is in the expected class ({class:?}) but does not carry the \
                     expected wording ({marker:?}) — the class alone is too coarse to score: {msg}"
                ))
            } else {
                Verdict::Match
            }
        }

        (Expect::Rejected { class, marker }, Observed::Accepted) => {
            if step.nonce > before {
                Verdict::Mismatch(format!(
                    "the node ACCEPTED nonce {} while its own next mineable nonce was {before}, \
                     and the hole below survived the submit. Gap-free admission requires a \
                     {class:?}/{marker:?} rejection (mempool: nonce > current + pooled ⇒ NonceGap)",
                    step.nonce
                ))
            } else {
                Verdict::Inconclusive(format!(
                    "expected a {class:?}/{marker:?} rejection at nonce {}, node accepted; \
                     with the first free nonce at {before} this is consistent with an in-place \
                     replacement rather than a broken rule",
                    step.nonce
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Part B — tx-domain A/B expectations
// ---------------------------------------------------------------------------

/// Which signature-verification regime the node is in at a given height — the
/// three states of the miner-signaled `tx-domain` hard fork.
///
/// Mirrors `sov_primitives::TxDomainMode`
/// (`chain/crates/primitives/src/signing_domain.rs:76-112`) without carrying a
/// domain value, so a plan can be built before any node is reachable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationPhase {
    /// `height < H_a`, or the fork is dormant/unscheduled: legacy signatures
    /// only. Byte-identical to the pre-fork path.
    Legacy,
    /// `H_a <= height < H_a + G`: a legacy OR a chain-bound signature verifies.
    Grace,
    /// `height >= H_a + G`: chain-bound only; a legacy signature is rejected.
    Bound,
}

impl ActivationPhase {
    /// Every phase, for a table sweep.
    pub fn all() -> [ActivationPhase; 3] {
        [
            ActivationPhase::Legacy,
            ActivationPhase::Grace,
            ActivationPhase::Bound,
        ]
    }

    /// The operator-facing name.
    pub fn label(self) -> &'static str {
        match self {
            ActivationPhase::Legacy => "LEGACY",
            ActivationPhase::Grace => "GRACE",
            ActivationPhase::Bound => "BOUND",
        }
    }
}

/// Resolve the phase at `height`, given the fork's activation height (`None` =
/// dormant or not yet active) and the node's grace-window length in blocks.
///
/// Mirrors `Blockchain::resolved_tx_domain_mode_with`
/// (`chain/crates/chain/src/blockchain.rs:874-895`) exactly, including its
/// `saturating_add` on `activation + grace` so an absurd grace length can never
/// wrap into an accidental early cliff. `grace_blocks == 0` degenerates to the
/// original cliff: [`Bound`](ActivationPhase::Bound) immediately at `H_a`.
///
/// **Caveat (partly UNVERIFIABLE over RPC).** `sov_getSigningDomain` reports only
/// `active: true|false` — it returns `resolved_tx_domain`, which is `Some` for
/// BOTH `Grace` and `Bound` (`chain/crates/rpc/src/lib.rs:1123-1146` over
/// `chain/crates/chain/src/blockchain.rs:800-817`). Distinguishing the two
/// therefore needs the activation height (from `sov_getDeployments`) AND the
/// node's configured grace length, which no RPC exposes: it defaults to
/// `TX_DOMAIN_GRACE_BLOCKS = 576` (`chain/crates/chain/src/blockchain.rs:498`)
/// but is settable per node (`:690`). A caller that only knows `active` should
/// pass the phase as `Legacy` or `Grace` and rely on the wrong-domain row, which
/// is phase-independent.
pub fn phase_at(activation: Option<u64>, grace_blocks: u64, height: u64) -> ActivationPhase {
    match activation {
        None => ActivationPhase::Legacy,
        Some(h_a) => {
            if height < h_a {
                ActivationPhase::Legacy
            } else if height < h_a.saturating_add(grace_blocks) {
                ActivationPhase::Grace
            } else {
                ActivationPhase::Bound
            }
        }
    }
}

/// Which preimage the A/B probe framed its signature under.
///
/// Modeled as an enum rather than a `SigningDomain` so a plan is buildable with
/// no live node; the caller supplies the concrete domains at signing time
/// (`SignedTransaction::sign_in(tx, &kp, domain)` — see
/// [`build_signed_action`](crate::logic::build_signed_action)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedUnder {
    /// `sign_in(.., None)` — the legacy, un-framed preimage.
    Legacy,
    /// `sign_in(.., Some(d))` where `d` is the network's own domain.
    CorrectDomain,
    /// `sign_in(.., Some(w))` where `w` is a deliberately wrong domain — see
    /// [`wrong_domain`].
    WrongDomain,
}

impl SignedUnder {
    /// Every variant, for a table sweep.
    pub fn all() -> [SignedUnder; 3] {
        [
            SignedUnder::Legacy,
            SignedUnder::CorrectDomain,
            SignedUnder::WrongDomain,
        ]
    }

    /// The operator-facing name.
    pub fn label(self) -> &'static str {
        match self {
            SignedUnder::Legacy => "legacy",
            SignedUnder::CorrectDomain => "bound(correct)",
            SignedUnder::WrongDomain => "bound(WRONG)",
        }
    }
}

/// What the node must do with a signature, at the signature gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainOutcome {
    /// The signature verifies under this phase; the transaction proceeds (and is
    /// then subject to every other admission rule).
    Accepted,
    /// The signature does not verify under this phase; the node must refuse it.
    Refused,
}

/// The marker for a signature refusal: `MempoolError::InvalidSignature` renders
/// as `"invalid transaction signature"` (`chain/crates/mempool/src/lib.rs:52-56`)
/// and is the FIRST check `Mempool::insert` performs (`:410-412`), so a
/// domain-refused transaction never reaches the nonce or balance gates.
/// [`classify_reject`] buckets it as [`RejectClass::Other`].
pub const EXPECT_BAD_SIGNATURE: Expect = Expect::Rejected {
    class: RejectClass::Other,
    marker: "invalid transaction signature",
};

/// The tx-domain decision table.
///
/// Derived directly from `TxDomainMode::verifies`
/// (`chain/crates/primitives/src/signing_domain.rs:124-130`):
/// `Legacy → verify(None)`, `Grace(d) → verify(Some(d)) || verify(None)`,
/// `Bound(d) → verify(Some(d))`.
///
/// | phase \ signed under | legacy | bound(correct) | bound(WRONG) |
/// |---|---|---|---|
/// | `Legacy` | accepted | refused | refused |
/// | `Grace`  | accepted | accepted | refused |
/// | `Bound`  | refused  | accepted | refused |
///
/// The wrong-domain column is `Refused` in every row, and that is the property
/// the fork exists to provide: a verifier always frames with ITS OWN chain id
/// and genesis (`signing_domain.rs:24-28`), so a signature made for another
/// network can never match, in any phase.
pub fn expected_domain_outcome(phase: ActivationPhase, signed: SignedUnder) -> DomainOutcome {
    match (phase, signed) {
        // Wrong domain: never, in any phase. No exceptions.
        (_, SignedUnder::WrongDomain) => DomainOutcome::Refused,
        // Pre-activation: only the un-framed preimage is checked at all.
        (ActivationPhase::Legacy, SignedUnder::Legacy) => DomainOutcome::Accepted,
        (ActivationPhase::Legacy, SignedUnder::CorrectDomain) => DomainOutcome::Refused,
        // Grace window: either preimage.
        (ActivationPhase::Grace, SignedUnder::Legacy) => DomainOutcome::Accepted,
        (ActivationPhase::Grace, SignedUnder::CorrectDomain) => DomainOutcome::Accepted,
        // Post-grace: bound only.
        (ActivationPhase::Bound, SignedUnder::Legacy) => DomainOutcome::Refused,
        (ActivationPhase::Bound, SignedUnder::CorrectDomain) => DomainOutcome::Accepted,
    }
}

/// The full A/B probe set for a phase: all three signing variants with the
/// outcome each must produce.
pub fn domain_probes(phase: ActivationPhase) -> Vec<(SignedUnder, DomainOutcome)> {
    SignedUnder::all()
        .into_iter()
        .map(|s| (s, expected_domain_outcome(phase, s)))
        .collect()
}

/// The `TxDomainMode` a node in `phase` enforces, for locally predicting a
/// verification result without a node.
///
/// `Legacy` carries no domain (`signing_domain.rs:104-106`), so `domain` is
/// ignored there.
pub fn verification_mode(phase: ActivationPhase, domain: &SigningDomain) -> TxDomainMode {
    match phase {
        ActivationPhase::Legacy => TxDomainMode::Legacy,
        ActivationPhase::Grace => TxDomainMode::Grace(domain.clone()),
        ActivationPhase::Bound => TxDomainMode::Bound(domain.clone()),
    }
}

/// Score one A/B observation.
///
/// Same conservatism as [`verdict`], with ONE hard failure:
///
/// * A **wrong-domain signature that the node ACCEPTED** is always a
///   [`Verdict::Mismatch`]. There is no benign explanation and no race: the
///   accepted preimage set in every phase is `{legacy}`, `{legacy, this domain}`
///   or `{this domain}` (`signing_domain.rs:124-130`), and a signature framed
///   with a different chain id or genesis is in none of them
///   (`signing_domain.rs:20-30`). Phase misreads cannot rescue it either, since
///   the expectation is `Refused` in all three phases.
/// * Every other divergence is [`Verdict::Inconclusive`]. The legacy and
///   correct-domain rows depend on the phase, and the phase is only as good as
///   the activation height and grace length the caller supplied — neither fully
///   observable over RPC (see [`phase_at`]). Near a boundary, a "wrong" answer
///   is more likely our arithmetic than the node's.
/// * An expected refusal that arrives as some OTHER rejection (capacity,
///   affordability, a transport error) is inconclusive, not a match: the
///   signature gate may never have been reached.
pub fn domain_verdict(phase: ActivationPhase, signed: SignedUnder, observed: &Observed) -> Verdict {
    let expected = expected_domain_outcome(phase, signed);
    match (expected, observed) {
        (DomainOutcome::Accepted, Observed::Accepted) => Verdict::Match,

        (DomainOutcome::Refused, Observed::Rejected(msg)) => {
            let Expect::Rejected { class, marker } = EXPECT_BAD_SIGNATURE else {
                unreachable!("EXPECT_BAD_SIGNATURE is a rejection")
            };
            let got = classify_reject(msg);
            if got == class && contains_ci(msg, marker) {
                Verdict::Match
            } else {
                Verdict::Inconclusive(format!(
                    "a {} signature in phase {} was refused, but not at the signature gate \
                     ({got:?}) — the probe never reached the rule it tests: {msg}",
                    signed.label(),
                    phase.label()
                ))
            }
        }

        (DomainOutcome::Refused, Observed::Accepted) => match signed {
            SignedUnder::WrongDomain => Verdict::Mismatch(format!(
                "the node ACCEPTED a transaction signed under a DIFFERENT network's domain \
                 (phase {}). Cross-network replay protection is not in force: a verifier frames \
                 with its own chain id and genesis, so this signature must not verify in ANY phase",
                phase.label()
            )),
            _ => Verdict::Inconclusive(format!(
                "a {} signature was accepted where phase {} predicts refusal; the phase is \
                 derived from the activation height and the node's grace length (not fully \
                 observable over RPC), so a boundary misread is the likelier explanation",
                signed.label(),
                phase.label()
            )),
        },

        (DomainOutcome::Accepted, Observed::Rejected(msg)) => Verdict::Inconclusive(format!(
            "a {} signature was refused where phase {} predicts acceptance ({:?}); this is \
             either contention or a phase-boundary misread, not proof of a rule violation: {msg}",
            signed.label(),
            phase.label(),
            classify_reject(msg)
        )),
    }
}

/// How to derive a deliberately WRONG signing domain from the correct one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrongDomainKind {
    /// Keep the genesis, change the chain id — the "sibling network" case
    /// (mainnet signature replayed onto testnet and vice versa).
    ChainId,
    /// Keep the chain id, change the genesis hash — the "forked/ghost chain"
    /// case: same name, different history.
    Genesis,
}

impl WrongDomainKind {
    /// Both kinds, so an A/B sweep covers each half of the binding.
    pub fn all() -> [WrongDomainKind; 2] {
        [WrongDomainKind::ChainId, WrongDomainKind::Genesis]
    }

    /// The operator-facing name.
    pub fn label(self) -> &'static str {
        match self {
            WrongDomainKind::ChainId => "wrong chain id",
            WrongDomainKind::Genesis => "wrong genesis",
        }
    }
}

/// The prefix that makes a wrong chain id wrong. Any non-empty prefix works; a
/// prefixed string is STRICTLY LONGER than the original, so the result can never
/// coincide with the correct chain id — whatever the correct one happens to be.
const WRONG_CHAIN_PREFIX: &str = "not-";

/// Derive a domain that is guaranteed NOT to be `correct` — what the A/B mode
/// signs its wrong-domain probe with.
///
/// Both constructions are total and provably non-identity:
/// * [`WrongDomainKind::ChainId`] prefixes the chain id, which strictly
///   increases its length, so the ids can never be equal.
/// * [`WrongDomainKind::Genesis`] XORs every bit of the genesis hash's first
///   byte, which always changes that byte, so the hashes can never be equal.
///
/// Both are asserted over adversarial inputs in the tests, including an empty
/// chain id, `Hash::ZERO`, and an all-`0xFF` genesis.
pub fn wrong_domain(correct: &SigningDomain, kind: WrongDomainKind) -> SigningDomain {
    match kind {
        WrongDomainKind::ChainId => SigningDomain::new(
            format!("{WRONG_CHAIN_PREFIX}{}", correct.chain_id()),
            correct.genesis(),
        ),
        WrongDomainKind::Genesis => {
            let mut bytes = *correct.genesis().as_bytes();
            bytes[0] ^= 0xFF;
            SigningDomain::new(correct.chain_id(), Hash::from_bytes(bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use sov_primitives::AccountId;

    use crate::logic::{build_signed_action, KeyScheme};
    use sov_primitives::Balance;
    use sov_types::Action;

    /// The plain transfer these signing tests build around.
    fn transfer(to: &sov_primitives::AccountId, grains: u128) -> Action {
        Action::Transfer {
            to: to.clone(),
            amount: Balance::from_grains(grains),
        }
    }

    fn domain(chain: &str) -> SigningDomain {
        SigningDomain::new(chain, Hash::digest(chain.as_bytes()))
    }

    fn acct(name: &str) -> AccountId {
        AccountId::new(name).unwrap()
    }

    /// The node's real wrapping around a `MempoolError`, as the client sees it.
    fn wrap(inner: &str) -> String {
        format!("rpc error -32000: rejected: mempool rejected transaction: {inner}")
    }

    fn rejected(inner: &str) -> Observed {
        Observed::Rejected(wrap(inner))
    }

    fn gap_msg(expected: u64, got: u64) -> String {
        format!("nonce gap: next mineable nonce is {expected}, transaction used {got}")
    }

    // ---- Part A: plan shape ---------------------------------------------

    #[test]
    fn every_scenario_ends_with_a_contiguous_gap_free_run() {
        // A scenario must not wedge the account: the set of nonces it expects to
        // be ACCEPTED has to be exactly the contiguous run from the base.
        for scenario in Scenario::all() {
            let steps = plan(scenario, 40);
            let mut accepted: Vec<u64> = steps
                .iter()
                .filter(|s| s.expect == Expect::Accepted)
                .map(|s| s.nonce)
                .collect();
            accepted.sort_unstable();
            accepted.dedup();
            let expected: Vec<u64> = (40..40 + accepted.len() as u64).collect();
            assert_eq!(accepted, expected, "{} left a hole", scenario.label());
        }
    }

    #[test]
    fn gap_plan_probes_above_the_run_then_heals_it_from_the_bottom() {
        let steps = plan(Scenario::Gap, 7);
        let shape: Vec<(u64, Expect)> = steps.iter().map(|s| (s.nonce, s.expect)).collect();
        assert_eq!(
            shape,
            vec![
                (9, EXPECT_NONCE_GAP), // two above the run
                (7, Expect::Accepted), // fill the bottom
                (9, EXPECT_NONCE_GAP), // still one hole below it
                (8, Expect::Accepted), // fill the hole
                (9, Expect::Accepted), // now contiguous
            ]
        );
        // The assumed next-nonce column tracks exactly what the node will report.
        let assumed: Vec<u64> = steps.iter().map(|s| s.assumed_next_nonce).collect();
        assert_eq!(assumed, vec![7, 7, 8, 8, 9]);
    }

    #[test]
    fn reorder_plan_submits_n_plus_one_before_n_and_expects_refusal_not_queueing() {
        let steps = plan(Scenario::Reorder, 100);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].nonce, 101);
        assert_eq!(steps[0].expect, EXPECT_NONCE_GAP);
        assert_eq!((steps[1].nonce, steps[1].expect), (100, Expect::Accepted));
        assert_eq!((steps[2].nonce, steps[2].expect), (101, Expect::Accepted));
        // Step 3 is a fresh submission, NOT a replay of the refused bytes: the
        // refused tx was never pooled, so there is nothing to duplicate.
        assert!(steps.iter().all(|s| !s.resubmit));
    }

    #[test]
    fn duplicate_plan_replays_identical_bytes_to_avoid_the_rbf_path() {
        let steps = plan(Scenario::Duplicate, 3);
        assert_eq!(steps.len(), 2);
        assert_eq!(
            steps[0],
            Step {
                nonce: 3,
                assumed_next_nonce: 3,
                probe: steps[0].probe,
                expect: Expect::Accepted,
                resubmit: false,
            }
        );
        assert_eq!(steps[1].nonce, 3);
        assert_eq!(steps[1].assumed_next_nonce, 4); // the slot is taken now
        assert_eq!(steps[1].expect, EXPECT_DUPLICATE);
        // Without byte-identical bytes the probe would enter replace-by-fee and a
        // higher tip would be legitimately ACCEPTED — the flag is load-bearing.
        assert!(steps[1].resubmit);
    }

    #[test]
    fn plans_saturate_at_the_nonce_ceiling_without_panicking() {
        for scenario in Scenario::all() {
            let steps = plan(scenario, u64::MAX);
            assert!(!steps.is_empty());
            assert!(steps.iter().all(|s| s.nonce == u64::MAX));
        }
    }

    #[test]
    fn expected_gap_rejection_uses_the_existing_reject_vocabulary() {
        // The node's real NonceGap text has its own bucket, so a deliberate gap
        // probe is never confused with a transport failure; the marker pins the
        // exact wording on top of the class.
        let Expect::Rejected { class, marker } = EXPECT_NONCE_GAP else {
            panic!("gap expectation must be a rejection")
        };
        assert_eq!(classify_reject(&wrap(&gap_msg(7, 9))), class);
        assert_eq!(class, RejectClass::NonceGap);
        assert!(wrap(&gap_msg(7, 9)).contains(marker));
    }

    #[test]
    fn expected_duplicate_rejection_matches_the_nodes_real_string() {
        let Expect::Rejected { class, marker } = EXPECT_DUPLICATE else {
            panic!("duplicate expectation must be a rejection")
        };
        assert_eq!(
            classify_reject(&wrap("transaction already in the pool")),
            class
        );
        assert_eq!(class, RejectClass::NonceOccupied);
        assert!(wrap("transaction already in the pool").contains(marker));
        // The `NonceTaken` wording a non-identical resubmission would produce
        // lands in the SAME class, so a caller that cannot replay exact bytes
        // still never gets a false failure — only a weaker verdict.
        assert_eq!(
            classify_reject(&wrap(
                "a transaction with signer cannon.sov and nonce 3 is already pooled"
            )),
            RejectClass::NonceOccupied
        );
    }

    // ---- Part A: verdicts -----------------------------------------------

    #[test]
    fn a_correct_gap_rejection_is_a_match() {
        let step = plan(Scenario::Gap, 7)[0];
        let v = verdict(
            &step,
            &Observation {
                outcome: rejected(&gap_msg(7, 9)),
                next_nonce_before: 7,
                next_nonce_after: 7,
            },
        );
        assert_eq!(v, Verdict::Match);
        assert!(!v.is_failure());
    }

    #[test]
    fn an_accepted_contiguous_nonce_is_a_match() {
        let step = plan(Scenario::Reorder, 100)[1];
        assert_eq!(
            verdict(
                &step,
                &Observation {
                    outcome: Observed::Accepted,
                    next_nonce_before: 100,
                    next_nonce_after: 101,
                },
            ),
            Verdict::Match
        );
    }

    #[test]
    fn admitting_a_tx_above_a_surviving_hole_is_the_one_hard_nonce_failure() {
        // The node accepted nonce 9 while reporting 7 as next mineable, and the
        // hole at 7 was still there afterwards. Nothing benign explains that.
        let step = plan(Scenario::Gap, 7)[0];
        let v = verdict(
            &step,
            &Observation {
                outcome: Observed::Accepted,
                next_nonce_before: 7,
                next_nonce_after: 7,
            },
        );
        assert!(v.is_failure(), "expected a MISMATCH, got {v:?}");
        assert!(v.reason().contains("Gap-free admission"));
    }

    #[test]
    fn a_hole_filled_by_someone_else_mid_probe_is_never_scored_as_a_failure() {
        // Same acceptance, but the after-reading jumped to 10: a third party
        // filled 7 and 8 while we were submitting 9, which makes the acceptance
        // legitimate. This MUST NOT be a failure.
        let step = plan(Scenario::Gap, 7)[0];
        let v = verdict(
            &step,
            &Observation {
                outcome: Observed::Accepted,
                next_nonce_before: 7,
                next_nonce_after: 10,
            },
        );
        assert!(!v.is_failure());
        assert!(matches!(v, Verdict::Inconclusive(_)));
    }

    #[test]
    fn a_stale_account_before_the_probe_is_never_scored() {
        // The plan assumed 7; the node reports 12 (someone else spent). No score,
        // whatever the outcome — including the outcome that would otherwise fail.
        let step = plan(Scenario::Gap, 7)[0];
        for outcome in [Observed::Accepted, rejected(&gap_msg(12, 9))] {
            let v = verdict(
                &step,
                &Observation {
                    outcome,
                    next_nonce_before: 12,
                    next_nonce_after: 12,
                },
            );
            assert!(!v.is_failure());
            assert!(v.reason().contains("moved before the probe"));
        }
    }

    #[test]
    fn contention_rejections_where_we_expected_acceptance_are_inconclusive_not_failures() {
        // Every rejection an ordinary busy mainnet produces must be survivable:
        // the cannon is a load tool, and failing here would fail on every run.
        let step = plan(Scenario::Reorder, 100)[1];
        for msg in [
            "mempool is full (16384 transactions)",
            "sender cannon.sov has reached its mempool limit of 256 pending transactions",
            "mempool at capacity: tip does not beat the current floor of 1000 — raise the tip and resubmit",
            "insufficient balance: pooled transfers would move 500 grains but only 100 are held",
            "stale transaction: account is at nonce 101, transaction used 100",
        ] {
            let v = verdict(
                &step,
                &Observation {
                    outcome: rejected(msg),
                    next_nonce_before: 100,
                    next_nonce_after: 100,
                },
            );
            assert!(!v.is_failure(), "{msg} produced a false failure: {v:?}");
        }
        // A dead socket is likewise never a consensus accusation.
        let v = verdict(
            &step,
            &Observation {
                outcome: Observed::Rejected("transport: Connection refused (os error 61)".into()),
                next_nonce_before: 100,
                next_nonce_after: 100,
            },
        );
        assert!(!v.is_failure());
    }

    #[test]
    fn a_transport_error_never_masquerades_as_the_expected_gap_rejection() {
        // A transport failure buckets as `Other`, the gap refusal as `NonceGap`,
        // so the class alone already separates them — and it must NEVER be
        // scored as a passing gap probe. It is inconclusive, not a failure: the
        // node never answered, so it neither honoured nor broke the rule.
        let step = plan(Scenario::Gap, 7)[0];
        let v = verdict(
            &step,
            &Observation {
                outcome: Observed::Rejected("transport: Connection refused (os error 61)".into()),
                next_nonce_before: 7,
                next_nonce_after: 7,
            },
        );
        assert_ne!(v, Verdict::Match);
        assert!(!v.is_failure(), "an unanswered probe must not accuse");
        assert!(
            v.reason().contains("NonceGap") && v.reason().contains("Other"),
            "the reason must name both classes: {}",
            v.reason()
        );
    }

    #[test]
    fn a_rejection_in_the_wrong_class_is_inconclusive() {
        let step = plan(Scenario::Gap, 7)[0];
        let v = verdict(
            &step,
            &Observation {
                outcome: rejected("mempool is full (16384 transactions)"),
                next_nonce_before: 7,
                next_nonce_after: 7,
            },
        );
        assert!(matches!(v, Verdict::Inconclusive(_)));
        assert!(v.reason().contains("Capacity"));
    }

    #[test]
    fn an_accepted_duplicate_replay_is_inconclusive_not_a_failure() {
        // Accepting a replay at a slot BELOW the first free nonce is consistent
        // with a legitimate in-place replacement (RBF), so it must not fail.
        let step = plan(Scenario::Duplicate, 3)[1];
        let v = verdict(
            &step,
            &Observation {
                outcome: Observed::Accepted,
                next_nonce_before: 4,
                next_nonce_after: 4,
            },
        );
        assert!(!v.is_failure());
        assert!(matches!(v, Verdict::Inconclusive(_)));
    }

    #[test]
    fn a_correct_duplicate_rejection_is_a_match() {
        let step = plan(Scenario::Duplicate, 3)[1];
        assert_eq!(
            verdict(
                &step,
                &Observation {
                    outcome: rejected("transaction already in the pool"),
                    next_nonce_before: 4,
                    next_nonce_after: 4,
                },
            ),
            Verdict::Match
        );
    }

    #[test]
    fn a_rejection_that_moved_the_free_nonce_is_never_scored() {
        // A rejection cannot itself change the first free slot; if it moved,
        // something else did, and the probe is void.
        let step = plan(Scenario::Gap, 7)[0];
        let v = verdict(
            &step,
            &Observation {
                outcome: rejected(&gap_msg(7, 9)),
                next_nonce_before: 7,
                next_nonce_after: 8,
            },
        );
        assert!(matches!(v, Verdict::Inconclusive(_)));
        assert!(v.reason().contains("moved during the probe"));
    }

    #[test]
    fn a_full_clean_gap_run_scores_every_step_as_a_match() {
        // Walk the whole scenario against a node that behaves exactly as the
        // pinned source says, and require an unbroken MATCH.
        let steps = plan(Scenario::Gap, 20);
        let mut free = 20u64; // the node's first free slot
        for step in &steps {
            let (outcome, after) = if step.nonce == free {
                (Observed::Accepted, free + 1)
            } else {
                (rejected(&gap_msg(free, step.nonce)), free)
            };
            let v = verdict(
                step,
                &Observation {
                    outcome,
                    next_nonce_before: free,
                    next_nonce_after: after,
                },
            );
            assert_eq!(v, Verdict::Match, "step {step:?}");
            free = after;
        }
        assert_eq!(free, 23); // 20, 21, 22 all landed
    }

    // ---- Part B: phase resolution ----------------------------------------

    #[test]
    fn a_dormant_fork_is_legacy_at_every_height() {
        for height in [0u64, 1, 11_520, u64::MAX] {
            assert_eq!(phase_at(None, 576, height), ActivationPhase::Legacy);
        }
    }

    #[test]
    fn phase_boundaries_are_activation_inclusive_and_grace_exclusive() {
        let (h_a, g) = (11_520u64, 576u64);
        assert_eq!(phase_at(Some(h_a), g, h_a - 1), ActivationPhase::Legacy);
        assert_eq!(phase_at(Some(h_a), g, h_a), ActivationPhase::Grace);
        assert_eq!(phase_at(Some(h_a), g, h_a + g - 1), ActivationPhase::Grace);
        assert_eq!(phase_at(Some(h_a), g, h_a + g), ActivationPhase::Bound);
        assert_eq!(phase_at(Some(h_a), g, u64::MAX), ActivationPhase::Bound);
    }

    #[test]
    fn zero_grace_degenerates_to_the_original_cliff() {
        assert_eq!(phase_at(Some(100), 0, 99), ActivationPhase::Legacy);
        assert_eq!(phase_at(Some(100), 0, 100), ActivationPhase::Bound);
    }

    #[test]
    fn an_absurd_grace_length_saturates_instead_of_wrapping_into_an_early_cliff() {
        // Wrapping would put `activation + grace` at MAX-2, below the height, and
        // read as Bound — the exact failure the node's saturating_add prevents.
        assert_eq!(
            phase_at(Some(u64::MAX - 1), u64::MAX, u64::MAX - 1),
            ActivationPhase::Grace
        );
        // The one height saturation cannot rescue is the ceiling itself: with the
        // window clamped to `[H_a, u64::MAX)`, height u64::MAX is Bound. The node
        // resolves it identically, so the expectation is honest, not idealized.
        assert_eq!(
            phase_at(Some(u64::MAX - 1), u64::MAX, u64::MAX),
            ActivationPhase::Bound
        );
    }

    // ---- Part B: the decision table --------------------------------------

    #[test]
    fn the_domain_table_matches_the_chains_own_verifier_in_all_nine_cells() {
        // The strongest available check: sign a REAL transaction under each
        // preimage and run the chain's own `TxDomainMode::verifies` over it.
        let seed = [11u8; 32];
        let (from, to) = (acct("cannon.sov"), acct("target.sov"));
        let correct = domain("sov-mainnet");
        let wrong = wrong_domain(&correct, WrongDomainKind::ChainId);

        let sign = |d: Option<&SigningDomain>| {
            build_signed_action(&seed, KeyScheme::Ed25519, &from, transfer(&to, 1_000), 4, d)
                .unwrap()
        };
        let txs = [
            (SignedUnder::Legacy, sign(None)),
            (SignedUnder::CorrectDomain, sign(Some(&correct))),
            (SignedUnder::WrongDomain, sign(Some(&wrong))),
        ];

        for phase in ActivationPhase::all() {
            let mode = verification_mode(phase, &correct);
            for (signed, stx) in &txs {
                let verifies = mode.verifies(|d| stx.verify_signature_in(d));
                let expected = expected_domain_outcome(phase, *signed) == DomainOutcome::Accepted;
                assert_eq!(
                    verifies,
                    expected,
                    "cell (phase {}, signed {}) disagrees with the chain",
                    phase.label(),
                    signed.label()
                );
            }
        }
    }

    #[test]
    fn a_wrong_domain_signature_is_refused_in_every_phase() {
        for phase in ActivationPhase::all() {
            assert_eq!(
                expected_domain_outcome(phase, SignedUnder::WrongDomain),
                DomainOutcome::Refused,
                "phase {} must refuse a wrong-domain signature",
                phase.label()
            );
        }
    }

    #[test]
    fn the_legacy_phase_accepts_only_legacy_signatures() {
        assert_eq!(
            expected_domain_outcome(ActivationPhase::Legacy, SignedUnder::Legacy),
            DomainOutcome::Accepted
        );
        assert_eq!(
            expected_domain_outcome(ActivationPhase::Legacy, SignedUnder::CorrectDomain),
            DomainOutcome::Refused
        );
    }

    #[test]
    fn the_grace_phase_accepts_both_legacy_and_correctly_bound_signatures() {
        assert_eq!(
            expected_domain_outcome(ActivationPhase::Grace, SignedUnder::Legacy),
            DomainOutcome::Accepted
        );
        assert_eq!(
            expected_domain_outcome(ActivationPhase::Grace, SignedUnder::CorrectDomain),
            DomainOutcome::Accepted
        );
    }

    #[test]
    fn the_bound_phase_accepts_only_correctly_bound_signatures() {
        assert_eq!(
            expected_domain_outcome(ActivationPhase::Bound, SignedUnder::Legacy),
            DomainOutcome::Refused
        );
        assert_eq!(
            expected_domain_outcome(ActivationPhase::Bound, SignedUnder::CorrectDomain),
            DomainOutcome::Accepted
        );
    }

    #[test]
    fn domain_probes_enumerate_the_whole_row_for_a_phase() {
        for phase in ActivationPhase::all() {
            let probes = domain_probes(phase);
            assert_eq!(probes.len(), 3);
            for (signed, outcome) in probes {
                assert_eq!(outcome, expected_domain_outcome(phase, signed));
            }
        }
    }

    // ---- Part B: verdicts -------------------------------------------------

    #[test]
    fn an_accepted_wrong_domain_signature_is_a_hard_failure_in_every_phase() {
        for phase in ActivationPhase::all() {
            let v = domain_verdict(phase, SignedUnder::WrongDomain, &Observed::Accepted);
            assert!(
                v.is_failure(),
                "phase {} did not fail: {v:?}",
                phase.label()
            );
            assert!(v.reason().contains("DIFFERENT network's domain"));
        }
    }

    #[test]
    fn a_refused_wrong_domain_signature_matches_only_at_the_signature_gate() {
        for phase in ActivationPhase::all() {
            assert_eq!(
                domain_verdict(
                    phase,
                    SignedUnder::WrongDomain,
                    &rejected("invalid transaction signature")
                ),
                Verdict::Match
            );
            // Refused for an unrelated reason: the probe never reached the gate.
            let v = domain_verdict(
                phase,
                SignedUnder::WrongDomain,
                &rejected("mempool is full (16384 transactions)"),
            );
            assert!(matches!(v, Verdict::Inconclusive(_)));
            assert!(!v.is_failure());
        }
    }

    #[test]
    fn a_phase_boundary_misread_never_becomes_a_consensus_accusation() {
        // We believe the node is Bound and it accepted a legacy signature (it is
        // really still in grace), or we believe Legacy and it accepted a bound
        // one (it has activated). Both are OUR arithmetic, not its bug.
        for (phase, signed) in [
            (ActivationPhase::Bound, SignedUnder::Legacy),
            (ActivationPhase::Legacy, SignedUnder::CorrectDomain),
        ] {
            let v = domain_verdict(phase, signed, &Observed::Accepted);
            assert!(!v.is_failure(), "{phase:?}/{signed:?} falsely failed");
            assert!(v.reason().contains("boundary misread"));
        }
    }

    #[test]
    fn an_expected_acceptance_that_was_refused_is_inconclusive() {
        let v = domain_verdict(
            ActivationPhase::Grace,
            SignedUnder::Legacy,
            &rejected("invalid transaction signature"),
        );
        assert!(!v.is_failure());
        assert!(matches!(v, Verdict::Inconclusive(_)));
    }

    #[test]
    fn an_accepted_correctly_signed_transaction_is_a_match() {
        assert_eq!(
            domain_verdict(
                ActivationPhase::Bound,
                SignedUnder::CorrectDomain,
                &Observed::Accepted
            ),
            Verdict::Match
        );
    }

    // ---- Part B: the wrong-domain helper ----------------------------------

    #[test]
    fn a_wrong_domain_can_never_come_back_equal_to_the_correct_one() {
        // Adversarial inputs: empty chain id, already-prefixed chain id, the zero
        // hash, the all-ones hash, and a spread of real digests.
        let mut cases = vec![
            SigningDomain::new("", Hash::ZERO),
            SigningDomain::new("not-", Hash::ZERO),
            SigningDomain::new("not-not-sov", Hash::from_bytes([0xFF; 32])),
            SigningDomain::new("sov-mainnet", Hash::from_bytes([0x00; 32])),
        ];
        for i in 0..64u8 {
            cases.push(SigningDomain::new(format!("chain-{i}"), Hash::digest(&[i])));
        }
        for correct in &cases {
            for kind in WrongDomainKind::all() {
                let w = wrong_domain(correct, kind);
                assert_ne!(&w, correct, "{kind:?} returned the CORRECT domain");
                // And the framed preimage differs, which is what actually decides
                // whether a signature verifies.
                assert_ne!(
                    w.frame(b"sov:tx:v1", b"body"),
                    correct.frame(b"sov:tx:v1", b"body")
                );
            }
        }
    }

    #[test]
    fn each_wrong_domain_kind_changes_exactly_the_half_it_names() {
        let correct = domain("sov-mainnet");
        let wrong_id = wrong_domain(&correct, WrongDomainKind::ChainId);
        assert_ne!(wrong_id.chain_id(), correct.chain_id());
        assert_eq!(wrong_id.genesis(), correct.genesis());

        let wrong_genesis = wrong_domain(&correct, WrongDomainKind::Genesis);
        assert_eq!(wrong_genesis.chain_id(), correct.chain_id());
        assert_ne!(wrong_genesis.genesis(), correct.genesis());
    }

    #[test]
    fn a_wrong_domain_signature_verifies_under_nothing_the_node_accepts() {
        // End to end, with real signatures: a tx signed under either flavor of
        // wrong domain fails the legacy preimage, fails the correct domain, and
        // fails all three verification modes.
        let seed = [23u8; 32];
        let correct = domain("sov-mainnet");
        for kind in WrongDomainKind::all() {
            let wrong = wrong_domain(&correct, kind);
            let stx = build_signed_action(
                &seed,
                KeyScheme::Ed25519,
                &acct("cannon.sov"),
                transfer(&acct("target.sov"), 7),
                0,
                Some(&wrong),
            )
            .unwrap();
            assert!(
                !stx.verify_signature(),
                "{kind:?} passed the legacy preimage"
            );
            assert!(
                !stx.verify_signature_in(Some(&correct)),
                "{kind:?} passed the correct domain"
            );
            for phase in ActivationPhase::all() {
                assert!(
                    !verification_mode(phase, &correct).verifies(|d| stx.verify_signature_in(d)),
                    "{kind:?} passed in phase {}",
                    phase.label()
                );
            }
            // It does verify under its own (wrong) domain — proving the failure
            // above is the BINDING working, not a broken signature.
            assert!(stx.verify_signature_in(Some(&wrong)));
        }
    }
}
