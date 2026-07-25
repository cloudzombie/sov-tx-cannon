//! Confirmation tracking — the difference between "the node took it" and "the
//! chain kept it".
//!
//! The cannon's meters count SUBMISSIONS: attempted, accepted, rejected. Accepted
//! only means a transaction entered someone's mempool; it says nothing about
//! whether a miner ever included it, how long that took, or whether a reorg later
//! threw it back out. This module closes that gap and turns the tool into a
//! measuring instrument:
//!
//!   * [`ConfirmTracker::register`] — an accepted submission goes IN FLIGHT with
//!     its id, submit time, submit height, tip and tip bucket.
//!   * [`ConfirmTracker::observe_block`] — observed blocks are matched against the
//!     in-flight set, producing [`Confirmed`] events carrying blocks-to-inclusion
//!     and milliseconds-to-inclusion.
//!   * A height re-observed with a DIFFERENT block hash is a reorg: everything
//!     confirmed only in the superseded blocks is reported [`Unmined`] and put
//!     back in flight. Silently keeping those "confirmations" would make the tool
//!     lie in exactly the situation an operator most needs the truth.
//!   * [`ConfirmTracker::expire`] — anything in flight past the caller's TTL is a
//!     [`Dropped`], counted separately from confirmations.
//!   * [`ConfirmTracker::latency`] — per-tip-bucket count/min/max/p50/p95 of the
//!     measured inclusion latencies, which is the number that actually
//!     characterizes a fee market (an aggregate p50 across mixed tips describes
//!     nothing).
//!
//! Everything here is pure and deterministic: no network, no filesystem, no
//! clock. Time arrives as caller-supplied milliseconds (the same convention as
//! [`crate::logic::RateMeter`]), blocks arrive as `(height, hash, txids)`, and the
//! tip BUCKET arrives as an opaque [`TipBucket`] key. This module deliberately
//! does NOT know how tips map to buckets — `auction.rs` owns that labelling; here
//! a bucket is just a small integer the caller chose, and any consistent
//! assignment works.
//!
//! Chain types are deliberately absent: a transaction id and a block hash are
//! both a 32-byte digest on this chain (`SignedTransaction::id()` and
//! `Block::hash()` both return `sov_primitives::Hash`, whose `Hash::LEN` is 32),
//! so [`TxId`] and [`BlockId`] are plain 32-byte newtypes the caller fills from
//! `hash.as_bytes()`. That keeps this module compilable and testable without the
//! chain, and free of any assumption about chain behavior beyond the digest width.
//!
//! Memory is bounded by construction — see [`MAX_IN_FLIGHT`],
//! [`MAX_CONFIRMED_TRACKED`], [`MAX_TRACKED_HEIGHTS`], [`MAX_DROP_MEMORY`],
//! [`MAX_TIP_BUCKETS`] and [`MAX_SAMPLES_PER_BUCKET`] — so a multi-day soak
//! cannot grow the tracker without limit. All arithmetic is saturating or
//! checked; no unwrap on any caller-reachable path.

// The tracker is a self-contained instrument: its full surface is exercised by
// the tests below, and the GUI consumes only part of it at any given moment.
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap, VecDeque};

/// A transaction id: the chain's 32-byte transaction hash, opaque to this module.
///
/// Taken as raw bytes rather than a chain type so the tracker carries no chain
/// dependency and can be exercised exhaustively in tests with synthetic ids.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxId([u8; 32]);

impl TxId {
    /// Wrap a 32-byte transaction hash (`SignedTransaction::id().as_bytes()`).
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw digest, for display or for handing back to chain code.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The leading 8 hex characters — what an operator reads in a log line.
    pub fn short(&self) -> String {
        hex8(&self.0)
    }
}

impl std::fmt::Debug for TxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tx:{}", self.short())
    }
}

/// A block hash: the chain's 32-byte header hash, opaque to this module.
///
/// Identity is what matters here — two observations of the same height carrying
/// DIFFERENT ids mean a reorg replaced that block.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockId([u8; 32]);

impl BlockId {
    /// Wrap a 32-byte block hash (`Block::hash().as_bytes()`).
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The leading 8 hex characters, for logs.
    pub fn short(&self) -> String {
        hex8(&self.0)
    }
}

impl std::fmt::Debug for BlockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "blk:{}", self.short())
    }
}

/// The first four bytes of a digest as 8 lowercase hex characters — the prefix
/// operators recognize digests by. Total: any 32-byte input has those bytes.
fn hex8(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(8);
    for b in &bytes[..4] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// An opaque tip-bucket key supplied by the caller.
///
/// CONTRACT: this module never interprets the value. It only requires that the
/// caller assign the same key to transactions it wants pooled in one latency
/// distribution, and keep the assignment stable across a run. The tip→bucket
/// labelling belongs to `auction.rs`; keeping it out of here means the two modules
/// evolve independently and this one stays testable with bare integers.
pub type TipBucket = u8;

/// Maximum transactions held in flight at once.
///
/// Four times the node's default mempool capacity (16,384): the cannon cannot have
/// more than the pool's worth genuinely pending, and the headroom absorbs multiple
/// wallets firing at a pool that is draining slowly. At the cap, the OLDEST
/// registration is evicted and reported as [`DropReason::CapacityEvicted`] — the
/// tracker sheds the least useful measurement rather than growing or refusing.
pub const MAX_IN_FLIGHT: usize = 65_536;

/// Maximum confirmations retained for reorg rollback.
///
/// Confirmations older than this are pruned oldest-height-first. They REMAIN
/// counted as confirmed; they simply can no longer be un-mined, which is the
/// explicit price of a bounded footprint.
pub const MAX_CONFIRMED_TRACKED: usize = 131_072;

/// Maximum distinct block heights retained for reorg rollback.
///
/// A reorg deeper than this many OBSERVED heights cannot be detected — the
/// superseded confirmations are already pruned. Stated rather than hidden.
pub const MAX_TRACKED_HEIGHTS: usize = 256;

/// Maximum dropped transactions remembered so a late inclusion can still be
/// recognized (see [`ConfirmTracker::observe_block`]). Oldest drops are forgotten
/// first; a forgotten drop that later appears is ignored like any stranger's tx.
pub const MAX_DROP_MEMORY: usize = 16_384;

/// Maximum distinct tip buckets the histogram will allocate. Samples for a bucket
/// key beyond this are counted in [`Stats::unbucketed_samples`] and NOT recorded,
/// so a caller that accidentally uses a high-cardinality key degrades visibly
/// instead of consuming memory silently.
pub const MAX_TIP_BUCKETS: usize = 32;

/// Maximum latency samples retained per tip bucket. Beyond this the OLDEST sample
/// is evicted, so the reported distribution is a rolling window of the most recent
/// samples — see [`BucketLatency`].
pub const MAX_SAMPLES_PER_BUCKET: usize = 4_096;

/// What the caller told us when a transaction was accepted into the pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Submission {
    /// Caller-supplied millisecond stamp of the accepted submission.
    pub submitted_ms: u64,
    /// The chain height at the moment of submission — the baseline for
    /// blocks-to-inclusion.
    pub submitted_height: u64,
    /// The tip offered, in grains. Recorded for reporting only; bucketing uses
    /// [`Submission::bucket`].
    pub tip_grains: u128,
    /// The caller's opaque tip-bucket key for this transaction.
    pub bucket: TipBucket,
}

/// A transaction observed in a block that we had in flight (or had dropped).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Confirmed {
    /// The transaction.
    pub txid: TxId,
    /// What we recorded at submission.
    pub submission: Submission,
    /// Height of the block it appeared in.
    pub height: u64,
    /// Hash of that block — the identity a later reorg is detected against.
    pub block: BlockId,
    /// `height - submitted_height`, saturating (never negative, never panics even
    /// if the caller feeds an older height than the submission baseline).
    pub blocks_to_inclusion: u64,
    /// Observation time minus submission time, saturating.
    pub latency_ms: u64,
    /// True when this transaction had already been written off as
    /// [`DropReason::Expired`] and turned up anyway. Its latency IS recorded: the
    /// TTL was our arbitrary cutoff, the latency is chain truth.
    pub late: bool,
}

/// A previously-confirmed transaction whose block was replaced by a reorg. It is
/// back in flight and may confirm again, possibly at a different height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unmined {
    /// The transaction, now in flight again.
    pub txid: TxId,
    /// Its original submission record, restored unchanged.
    pub submission: Submission,
    /// The height it had been confirmed at.
    pub height: u64,
    /// The block that no longer exists on the observed chain.
    pub block: BlockId,
}

/// Why a transaction left the in-flight set without being included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// It exceeded the caller's TTL without ever appearing in a block.
    Expired,
    /// The in-flight set was at [`MAX_IN_FLIGHT`] and this, the oldest
    /// registration, was shed to make room. A measurement lost to our own
    /// bookkeeping limit, NOT evidence about the node — hence its own reason.
    CapacityEvicted,
}

/// A transaction that left the in-flight set unconfirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dropped {
    /// The transaction.
    pub txid: TxId,
    /// What we recorded at submission.
    pub submission: Submission,
    /// How long it had been in flight when it was dropped, saturating.
    pub age_ms: u64,
    /// Why it was dropped.
    pub reason: DropReason,
}

/// Everything the tracker reports, in one stream so a caller can append it to a
/// single event log in the order it happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackerEvent {
    /// Included in a block.
    Confirmed(Confirmed),
    /// Un-included by a reorg; back in flight.
    Unmined(Unmined),
    /// Gone without inclusion.
    Dropped(Dropped),
}

/// Live counts. The classification counters (`in_flight`, `confirmed`,
/// `dropped_expired`, `dropped_evicted`) describe where each tracked transaction
/// stands RIGHT NOW and therefore go down as well as up — a reorg un-confirms, a
/// late inclusion un-drops. The `*_total` counters are monotonic tallies of those
/// transitions, so nothing is silently rewritten out of history.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Currently awaiting inclusion.
    pub in_flight: u64,
    /// Currently believed included.
    pub confirmed: u64,
    /// Currently written off as never-included.
    pub dropped_expired: u64,
    /// Shed because the in-flight set hit [`MAX_IN_FLIGHT`].
    pub dropped_evicted: u64,
    /// Monotonic count of un-mining events (reorg depth in transactions).
    pub unmined_total: u64,
    /// Monotonic count of inclusions that arrived after we had given up.
    pub late_total: u64,
    /// Latency samples discarded because the caller used more than
    /// [`MAX_TIP_BUCKETS`] distinct bucket keys.
    pub unbucketed_samples: u64,
    /// Latency samples evicted from a bucket's rolling window by newer samples.
    pub evicted_samples: u64,
}

/// The nearest-rank percentile of an ASCENDING-sorted sample slice, in whatever
/// unit the samples carry.
///
/// DEFINITION (exact, total, integer-only — no interpolation, no floats, hence no
/// NaN and no rounding drift): for `n` samples the `p`-th percentile is the sample
/// at 1-based rank `r = ceil(p × n / 100)`, clamped into `[1, n]`; the value
/// returned is `sorted[r - 1]`. Equivalently: the smallest sample that is greater
/// than or equal to at least `p` percent of the data.
///
/// The consequences, all deliberate:
///   * empty slice → `None`. An unmeasured percentile is unknown, never `0`.
///   * `n == 1` → that one sample for every `p`, including `p = 0`.
///   * even `n` → never an average of the two middle values: `p50` of `[10, 20]`
///     is `10`. Every number this reports is a latency that was actually
///     OBSERVED, never one synthesized between observations.
///   * `p = 0` → the minimum (the rank clamps up to 1); `p >= 100` → the maximum.
pub fn percentile_ms(sorted: &[u64], p: u8) -> Option<u64> {
    let n = sorted.len() as u128;
    if n == 0 {
        return None;
    }
    // ceil(p·n/100) in integer arithmetic, in u128 so the product cannot overflow.
    let rank = ((u128::from(p) * n).saturating_add(99) / 100).clamp(1, n);
    let idx = (rank - 1) as usize;
    sorted.get(idx).copied()
}

/// The inclusion-latency distribution of one tip bucket.
///
/// All figures are over the bucket's RETAINED window — the most recent
/// [`MAX_SAMPLES_PER_BUCKET`] samples — not over all time; `count` is the size of
/// that window. On a long soak the window is what the fee market looks like now,
/// which is the honest thing to report; all-time tallies live in [`Stats`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BucketLatency {
    /// Samples in the retained window (always ≥ 1 — an empty bucket is reported
    /// as `None` rather than as a zeroed struct).
    pub count: usize,
    /// Fastest retained inclusion.
    pub min_ms: u64,
    /// Slowest retained inclusion.
    pub max_ms: u64,
    /// Median, by [`percentile_ms`].
    pub p50_ms: u64,
    /// 95th percentile, by [`percentile_ms`].
    pub p95_ms: u64,
}

/// Per-bucket rolling latency samples.
#[derive(Clone, Debug, Default)]
struct Histogram {
    /// A `BTreeMap` (not a `HashMap`) so [`ConfirmTracker::buckets`] enumerates in
    /// a deterministic, operator-friendly order.
    buckets: BTreeMap<TipBucket, VecDeque<u64>>,
}

impl Histogram {
    /// Record one latency. Returns `(unbucketed, evicted)` so the caller can keep
    /// the honest tallies in [`Stats`].
    fn record(&mut self, bucket: TipBucket, latency_ms: u64) -> (u64, u64) {
        if !self.buckets.contains_key(&bucket) && self.buckets.len() >= MAX_TIP_BUCKETS {
            return (1, 0);
        }
        let samples = self.buckets.entry(bucket).or_default();
        samples.push_back(latency_ms);
        let mut evicted = 0;
        while samples.len() > MAX_SAMPLES_PER_BUCKET {
            samples.pop_front();
            evicted += 1;
        }
        (0, evicted)
    }

    /// Withdraw one sample after a reorg un-mined the confirmation that produced
    /// it. Removes the FIRST occurrence of that exact value in the bucket — the
    /// samples are interchangeable, so which identical copy goes is immaterial. If
    /// the sample has already aged out of the retained window there is nothing to
    /// withdraw and this is a no-op: that is the only way the window can retain a
    /// latency whose confirmation was later reversed.
    fn retract(&mut self, bucket: TipBucket, latency_ms: u64) {
        let Some(samples) = self.buckets.get_mut(&bucket) else {
            return;
        };
        if let Some(pos) = samples.iter().position(|&v| v == latency_ms) {
            samples.remove(pos);
        }
        if samples.is_empty() {
            // Free the slot so a long run cannot permanently exhaust
            // MAX_TIP_BUCKETS with buckets that hold nothing.
            self.buckets.remove(&bucket);
        }
    }

    fn stats(&self, bucket: TipBucket) -> Option<BucketLatency> {
        let samples = self.buckets.get(&bucket)?;
        let mut sorted: Vec<u64> = samples.iter().copied().collect();
        sorted.sort_unstable();
        // Every access below is total: `?` on the first one returns `None` for an
        // empty bucket, so nothing here can panic.
        let min_ms = *sorted.first()?;
        let max_ms = *sorted.last()?;
        Some(BucketLatency {
            count: sorted.len(),
            min_ms,
            max_ms,
            p50_ms: percentile_ms(&sorted, 50)?,
            p95_ms: percentile_ms(&sorted, 95)?,
        })
    }
}

/// A confirmation as retained for possible rollback.
#[derive(Clone, Copy, Debug)]
struct ConfirmedRecord {
    txid: TxId,
    submission: Submission,
    latency_ms: u64,
}

/// Tracks submitted transactions through to inclusion, reorg and expiry.
///
/// Pure and deterministic: identical call sequences produce identical event
/// sequences, including their order. See the module docs for the model.
#[derive(Clone, Debug, Default)]
pub struct ConfirmTracker {
    /// Awaiting inclusion.
    in_flight: HashMap<TxId, Submission>,
    /// Registration order, used for oldest-first eviction and for a deterministic
    /// expiry scan. Ids removed from `in_flight` linger here as tombstones and are
    /// compacted lazily, so no removal is ever O(n) on the hot path.
    order: VecDeque<TxId>,
    /// Confirmations per observed height, lowest height first; the per-height list
    /// preserves the order the ids appeared in the block.
    by_height: BTreeMap<u64, (BlockId, Vec<ConfirmedRecord>)>,
    /// Height index for the confirmations retained in `by_height`.
    confirmed_at: HashMap<TxId, u64>,
    /// Recently dropped, so a late inclusion is still recognizable.
    dropped: HashMap<TxId, Submission>,
    /// Drop order, oldest first, for bounded forgetting.
    dropped_order: VecDeque<TxId>,
    hist: Histogram,
    stats: Stats,
}

impl ConfirmTracker {
    /// A fresh tracker with the module's documented bounds.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an accepted submission.
    ///
    /// Ignored (returns `None`, changes nothing) if this id is already in flight or
    /// already confirmed: a resubmission of the same transaction is the SAME
    /// transaction, and the first submission time is the honest one to measure
    /// from. A previously dropped id MAY be registered again — it leaves the drop
    /// memory and starts a fresh measurement.
    ///
    /// Returns `Some(TrackerEvent::Dropped { reason: CapacityEvicted, .. })` when
    /// the in-flight set was at [`MAX_IN_FLIGHT`] and the oldest registration had
    /// to be shed to admit this one.
    pub fn register(
        &mut self,
        txid: TxId,
        submitted_ms: u64,
        submitted_height: u64,
        tip_grains: u128,
        bucket: TipBucket,
    ) -> Option<TrackerEvent> {
        if self.in_flight.contains_key(&txid) || self.confirmed_at.contains_key(&txid) {
            return None;
        }
        // Re-registering something we had written off: it is in flight again.
        if self.dropped.remove(&txid).is_some() {
            self.stats.dropped_expired = self.stats.dropped_expired.saturating_sub(1);
            if let Some(pos) = self.dropped_order.iter().position(|&t| t == txid) {
                self.dropped_order.remove(pos);
            }
        }

        let evicted = if self.in_flight.len() >= MAX_IN_FLIGHT {
            self.evict_oldest(submitted_ms)
        } else {
            None
        };

        let submission = Submission {
            submitted_ms,
            submitted_height,
            tip_grains,
            bucket,
        };
        self.in_flight.insert(txid, submission);
        self.order.push_back(txid);
        self.stats.in_flight = self.in_flight.len() as u64;
        self.compact_order();
        evicted
    }

    /// Shed the oldest live in-flight registration. Only called at the cap, where
    /// the scan is guaranteed to find a victim.
    fn evict_oldest(&mut self, now_ms: u64) -> Option<TrackerEvent> {
        while let Some(victim) = self.order.pop_front() {
            if let Some(submission) = self.in_flight.remove(&victim) {
                self.stats.dropped_evicted = self.stats.dropped_evicted.saturating_add(1);
                self.stats.in_flight = self.in_flight.len() as u64;
                return Some(TrackerEvent::Dropped(Dropped {
                    txid: victim,
                    submission,
                    age_ms: now_ms.saturating_sub(submission.submitted_ms),
                    reason: DropReason::CapacityEvicted,
                }));
            }
        }
        None
    }

    /// Drop tombstones once the order queue holds more than twice the cap, so it
    /// stays O(MAX_IN_FLIGHT) without paying a removal on every confirmation.
    fn compact_order(&mut self) {
        if self.order.len() > 2 * MAX_IN_FLIGHT {
            let live = &self.in_flight;
            self.order.retain(|t| live.contains_key(t));
        }
    }

    /// Observe a block: match its transactions against what we are tracking.
    ///
    /// Handling, in order:
    ///   1. If this height is already recorded with the SAME `block` id, the
    ///      observation is a duplicate and produces no events — re-feeding a block
    ///      is harmless.
    ///   2. If this height is recorded with a DIFFERENT id, a reorg has replaced
    ///      it: that height and EVERY recorded height above it are rolled back, tip
    ///      first, each of their confirmations reported [`Unmined`] and returned to
    ///      the in-flight set with its original submission record, and its latency
    ///      sample withdrawn from the histogram.
    ///   3. Each id in `txids`, in the given order, is matched: in flight →
    ///      [`Confirmed`]; recently dropped → [`Confirmed`] with `late = true` (see
    ///      [`Confirmed::late`]); anything else → ignored in silence, because most
    ///      transactions in a block belong to other people.
    ///
    /// `now_ms` is the observation time used for the latency measurement.
    pub fn observe_block(
        &mut self,
        height: u64,
        block: BlockId,
        txids: &[TxId],
        now_ms: u64,
    ) -> Vec<TrackerEvent> {
        let mut events = Vec::new();

        match self.by_height.get(&height) {
            Some((known, _)) if *known == block => return events,
            Some(_) => self.rollback_from(height, &mut events),
            None => {}
        }

        let mut recorded: Vec<ConfirmedRecord> = Vec::new();
        for &txid in txids {
            let (submission, late) = match self.in_flight.remove(&txid) {
                Some(s) => (s, false),
                None => match self.dropped.remove(&txid) {
                    Some(s) => {
                        if let Some(pos) = self.dropped_order.iter().position(|&t| t == txid) {
                            self.dropped_order.remove(pos);
                        }
                        self.stats.dropped_expired = self.stats.dropped_expired.saturating_sub(1);
                        self.stats.late_total = self.stats.late_total.saturating_add(1);
                        (s, true)
                    }
                    // Not ours (or already confirmed, or long forgotten): ignore.
                    None => continue,
                },
            };

            let latency_ms = now_ms.saturating_sub(submission.submitted_ms);
            let blocks_to_inclusion = height.saturating_sub(submission.submitted_height);
            let (unbucketed, evicted) = self.hist.record(submission.bucket, latency_ms);
            self.stats.unbucketed_samples =
                self.stats.unbucketed_samples.saturating_add(unbucketed);
            self.stats.evicted_samples = self.stats.evicted_samples.saturating_add(evicted);

            recorded.push(ConfirmedRecord {
                txid,
                submission,
                latency_ms,
            });
            self.confirmed_at.insert(txid, height);
            self.stats.confirmed = self.stats.confirmed.saturating_add(1);
            events.push(TrackerEvent::Confirmed(Confirmed {
                txid,
                submission,
                height,
                block,
                blocks_to_inclusion,
                latency_ms,
                late,
            }));
        }

        // The height is recorded even when it held nothing of ours, so a later
        // hash change at that height is still recognized as a reorg.
        self.by_height.insert(height, (block, recorded));
        self.prune_history();
        self.stats.in_flight = self.in_flight.len() as u64;
        events
    }

    /// Roll back every recorded height `>= from`, tip first (in a deep reorg the
    /// newest loss is reported first, the order an operator reads a log in).
    fn rollback_from(&mut self, from: u64, events: &mut Vec<TrackerEvent>) {
        let heights: Vec<u64> = self
            .by_height
            .range(from..)
            .map(|(h, _)| *h)
            .rev()
            .collect();
        for h in heights {
            let Some((block, records)) = self.by_height.remove(&h) else {
                continue;
            };
            for rec in records.into_iter().rev() {
                self.confirmed_at.remove(&rec.txid);
                self.hist.retract(rec.submission.bucket, rec.latency_ms);
                self.stats.confirmed = self.stats.confirmed.saturating_sub(1);
                self.stats.unmined_total = self.stats.unmined_total.saturating_add(1);
                // Back in flight with the ORIGINAL submission record: the tx really
                // was submitted then, and it may well be mined again.
                if self.in_flight.insert(rec.txid, rec.submission).is_none() {
                    self.order.push_back(rec.txid);
                }
                events.push(TrackerEvent::Unmined(Unmined {
                    txid: rec.txid,
                    submission: rec.submission,
                    height: h,
                    block,
                }));
            }
        }
        self.stats.in_flight = self.in_flight.len() as u64;
    }

    /// Forget the oldest heights once either retention bound is exceeded. Pruned
    /// confirmations stay counted; they merely stop being reorg-trackable.
    fn prune_history(&mut self) {
        while self.by_height.len() > MAX_TRACKED_HEIGHTS
            || self.confirmed_at.len() > MAX_CONFIRMED_TRACKED
        {
            let Some((&oldest, _)) = self.by_height.iter().next() else {
                break;
            };
            if let Some((_, records)) = self.by_height.remove(&oldest) {
                for rec in records {
                    self.confirmed_at.remove(&rec.txid);
                }
            }
        }
    }

    /// Report everything in flight for at least `ttl_ms` as [`DropReason::Expired`].
    ///
    /// The comparison is `now_ms - submitted_ms >= ttl_ms` (saturating, so a
    /// submission stamped in the future is simply not expired). A `ttl_ms` of 0
    /// expires everything, the only sane reading of "no time allowed". Events come
    /// back in registration order, and each dropped id is remembered (bounded by
    /// [`MAX_DROP_MEMORY`]) so a late inclusion is still recognized.
    pub fn expire(&mut self, now_ms: u64, ttl_ms: u64) -> Vec<TrackerEvent> {
        let mut events = Vec::new();
        let expired: Vec<TxId> = self
            .order
            .iter()
            .copied()
            .filter(|t| {
                self.in_flight
                    .get(t)
                    .is_some_and(|s| now_ms.saturating_sub(s.submitted_ms) >= ttl_ms)
            })
            .collect();
        for txid in expired {
            let Some(submission) = self.in_flight.remove(&txid) else {
                continue;
            };
            self.remember_drop(txid, submission);
            self.stats.dropped_expired = self.stats.dropped_expired.saturating_add(1);
            events.push(TrackerEvent::Dropped(Dropped {
                txid,
                submission,
                age_ms: now_ms.saturating_sub(submission.submitted_ms),
                reason: DropReason::Expired,
            }));
        }
        self.stats.in_flight = self.in_flight.len() as u64;
        self.compact_order();
        events
    }

    fn remember_drop(&mut self, txid: TxId, submission: Submission) {
        self.dropped.insert(txid, submission);
        self.dropped_order.push_back(txid);
        while self.dropped_order.len() > MAX_DROP_MEMORY {
            if let Some(old) = self.dropped_order.pop_front() {
                self.dropped.remove(&old);
            }
        }
    }

    /// Live classification counts and monotonic event tallies.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Transactions currently awaiting inclusion.
    pub fn in_flight_len(&self) -> usize {
        self.in_flight.len()
    }

    /// The submission record of an in-flight transaction, if we hold one.
    pub fn in_flight(&self, txid: &TxId) -> Option<Submission> {
        self.in_flight.get(txid).copied()
    }

    /// The height a transaction is currently believed confirmed at, if that
    /// confirmation is still retained (see [`MAX_TRACKED_HEIGHTS`]).
    pub fn confirmed_height(&self, txid: &TxId) -> Option<u64> {
        self.confirmed_at.get(txid).copied()
    }

    /// The tip buckets that currently hold samples, ascending.
    pub fn buckets(&self) -> Vec<TipBucket> {
        self.hist.buckets.keys().copied().collect()
    }

    /// The inclusion-latency distribution of one tip bucket, or `None` if that
    /// bucket has no retained samples — an unmeasured bucket reports nothing
    /// rather than a fabricated zero.
    pub fn latency(&self, bucket: TipBucket) -> Option<BucketLatency> {
        self.hist.stats(bucket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(n: u64) -> TxId {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&n.to_le_bytes());
        TxId::new(b)
    }

    fn blk(n: u64) -> BlockId {
        let mut b = [0xffu8; 32];
        b[..8].copy_from_slice(&n.to_le_bytes());
        BlockId::new(b)
    }

    fn confirmations(events: &[TrackerEvent]) -> Vec<Confirmed> {
        events
            .iter()
            .filter_map(|e| match e {
                TrackerEvent::Confirmed(c) => Some(*c),
                _ => None,
            })
            .collect()
    }

    fn unmines(events: &[TrackerEvent]) -> Vec<Unmined> {
        events
            .iter()
            .filter_map(|e| match e {
                TrackerEvent::Unmined(u) => Some(*u),
                _ => None,
            })
            .collect()
    }

    fn drops(events: &[TrackerEvent]) -> Vec<Dropped> {
        events
            .iter()
            .filter_map(|e| match e {
                TrackerEvent::Dropped(d) => Some(*d),
                _ => None,
            })
            .collect()
    }

    // ---- Percentile definition -------------------------------------------

    #[test]
    fn percentile_of_an_empty_sample_is_unknown_not_zero() {
        assert_eq!(percentile_ms(&[], 50), None);
        assert_eq!(percentile_ms(&[], 95), None);
        assert_eq!(percentile_ms(&[], 0), None);
    }

    #[test]
    fn percentile_of_one_sample_is_that_sample_for_every_p() {
        for p in [0u8, 1, 50, 95, 99, 100, 255] {
            assert_eq!(percentile_ms(&[1_234], p), Some(1_234), "p{p}");
        }
    }

    #[test]
    fn percentile_of_an_even_count_takes_the_lower_middle_never_an_average() {
        // p50 of [10,20]: rank = ceil(0.5×2) = 1 → the FIRST sample. 15 would be a
        // number that was never observed.
        assert_eq!(percentile_ms(&[10, 20], 50), Some(10));
        assert_eq!(percentile_ms(&[10, 20, 30, 40], 50), Some(20));
        assert_eq!(percentile_ms(&[10, 20], 95), Some(20));
    }

    #[test]
    fn percentile_uses_nearest_rank_over_a_known_hundred_sample_set() {
        let sorted: Vec<u64> = (1..=100).collect();
        // rank = ceil(p×100/100) = p, so the p-th percentile is the value p.
        assert_eq!(percentile_ms(&sorted, 50), Some(50));
        assert_eq!(percentile_ms(&sorted, 95), Some(95));
        assert_eq!(percentile_ms(&sorted, 99), Some(99));
        // p = 0 clamps up to rank 1 (the minimum); p >= 100 is the maximum.
        assert_eq!(percentile_ms(&sorted, 0), Some(1));
        assert_eq!(percentile_ms(&sorted, 100), Some(100));
        assert_eq!(percentile_ms(&sorted, 255), Some(100));
    }

    #[test]
    fn percentile_is_monotonic_in_p_and_always_an_observed_value() {
        let sorted: Vec<u64> = vec![3, 3, 7, 11, 11, 42, 1_000];
        let mut prev = 0;
        for p in 0..=100u8 {
            let v = percentile_ms(&sorted, p).expect("non-empty");
            assert!(v >= prev, "p{p} went backwards");
            assert!(sorted.contains(&v), "p{p} invented the value {v}");
            prev = v;
        }
    }

    #[test]
    fn percentile_does_not_overflow_on_a_large_sample_count() {
        // The rank product is computed in u128, so a large n with p = 255 is fine.
        let sorted = vec![7u64; 100_000];
        assert_eq!(percentile_ms(&sorted, 255), Some(7));
        assert_eq!(percentile_ms(&sorted, 50), Some(7));
    }

    // ---- Registration + confirmation --------------------------------------

    #[test]
    fn confirmation_reports_blocks_and_milliseconds_to_inclusion() {
        let mut t = ConfirmTracker::new();
        assert!(t.register(tx(1), 1_000, 100, 500, 2).is_none());
        let ev = t.observe_block(103, blk(103), &[tx(1)], 4_500);
        let c = confirmations(&ev);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].txid, tx(1));
        assert_eq!(c[0].height, 103);
        assert_eq!(c[0].block, blk(103));
        assert_eq!(c[0].blocks_to_inclusion, 3); // 103 - 100
        assert_eq!(c[0].latency_ms, 3_500); // 4500 - 1000
        assert!(!c[0].late);
        assert_eq!(c[0].submission.tip_grains, 500);
        assert_eq!(c[0].submission.bucket, 2);
        assert_eq!(t.in_flight_len(), 0);
        assert_eq!(t.confirmed_height(&tx(1)), Some(103));
        assert_eq!(t.stats().confirmed, 1);
        assert_eq!(t.stats().in_flight, 0);
    }

    #[test]
    fn transactions_we_never_registered_are_ignored_silently() {
        let mut t = ConfirmTracker::new();
        t.register(tx(1), 0, 10, 0, 0);
        // A block full of other people's traffic plus one of ours.
        let ev = t.observe_block(11, blk(11), &[tx(90), tx(91), tx(1), tx(92)], 1_000);
        let c = confirmations(&ev);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].txid, tx(1));
        assert_eq!(t.stats().confirmed, 1);
    }

    #[test]
    fn out_of_order_heights_and_stamps_saturate_instead_of_underflowing() {
        let mut t = ConfirmTracker::new();
        // Submitted at height 50 / 9_000 ms but observed at height 40 / 1_000 ms:
        // nonsensical input must produce zeros, never a panic or a wrapped huge.
        t.register(tx(1), 9_000, 50, 0, 0);
        let ev = t.observe_block(40, blk(40), &[tx(1)], 1_000);
        let c = confirmations(&ev);
        assert_eq!(c[0].blocks_to_inclusion, 0);
        assert_eq!(c[0].latency_ms, 0);
    }

    #[test]
    fn re_registering_an_in_flight_or_confirmed_tx_changes_nothing() {
        let mut t = ConfirmTracker::new();
        t.register(tx(1), 1_000, 10, 5, 1);
        // A duplicate registration must not overwrite the first submit time.
        assert!(t.register(tx(1), 9_000, 20, 99, 3).is_none());
        assert_eq!(t.in_flight(&tx(1)).map(|s| s.submitted_ms), Some(1_000));
        assert_eq!(t.in_flight_len(), 1);

        let ev = t.observe_block(12, blk(12), &[tx(1)], 3_000);
        assert_eq!(confirmations(&ev).len(), 1);
        // Once confirmed, re-registration is also a no-op.
        assert!(t.register(tx(1), 9_000, 20, 99, 3).is_none());
        assert_eq!(t.in_flight_len(), 0);
        assert_eq!(t.stats().confirmed, 1);
    }

    #[test]
    fn re_observing_the_same_block_is_idempotent() {
        let mut t = ConfirmTracker::new();
        t.register(tx(1), 0, 1, 0, 0);
        let first = t.observe_block(2, blk(2), &[tx(1)], 1_000);
        assert_eq!(confirmations(&first).len(), 1);
        let again = t.observe_block(2, blk(2), &[tx(1)], 5_000);
        assert!(again.is_empty(), "duplicate observation must emit nothing");
        assert_eq!(t.stats().confirmed, 1);
        assert_eq!(t.stats().unmined_total, 0);
        // And the latency retained is still the FIRST observation's.
        assert_eq!(t.latency(0).map(|l| l.p50_ms), Some(1_000));
    }

    // ---- Reorg / un-mining -------------------------------------------------

    #[test]
    fn a_replaced_block_unmines_its_txs_and_returns_them_to_flight() {
        let mut t = ConfirmTracker::new();
        t.register(tx(1), 0, 1, 10, 0);
        t.register(tx(2), 0, 1, 10, 0);
        t.observe_block(2, blk(2), &[tx(1), tx(2)], 1_000);
        assert_eq!(t.stats().confirmed, 2);
        assert_eq!(t.latency(0).map(|l| l.count), Some(2));

        // Height 2 comes back with a different hash carrying only tx(1).
        let ev = t.observe_block(2, blk(999), &[tx(1)], 2_000);
        let u = unmines(&ev);
        assert_eq!(u.len(), 2, "both prior confirmations must be reported");
        assert!(u.iter().any(|x| x.txid == tx(1)));
        assert!(u.iter().any(|x| x.txid == tx(2)));
        assert_eq!(u[0].height, 2);
        assert_eq!(u[0].block, blk(2));

        // tx(1) re-confirms in the replacement block; tx(2) is back in flight.
        let c = confirmations(&ev);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].txid, tx(1));
        assert_eq!(c[0].block, blk(999));
        assert_eq!(c[0].latency_ms, 2_000, "measured from the ORIGINAL submit");
        assert_eq!(t.in_flight_len(), 1);
        assert!(t.in_flight(&tx(2)).is_some());
        assert_eq!(t.confirmed_height(&tx(2)), None);
        assert_eq!(t.stats().confirmed, 1);
        assert_eq!(t.stats().unmined_total, 2);
        // The withdrawn samples leave only the re-confirmation behind.
        assert_eq!(t.latency(0).map(|l| l.count), Some(1));
        assert_eq!(t.latency(0).map(|l| l.p50_ms), Some(2_000));
    }

    #[test]
    fn a_multi_block_rollback_unmines_every_height_above_the_fork_point() {
        let mut t = ConfirmTracker::new();
        for n in 1..=6u64 {
            t.register(tx(n), 0, 10, 1, 0);
        }
        t.observe_block(11, blk(11), &[tx(1), tx(2)], 1_000);
        t.observe_block(12, blk(12), &[tx(3), tx(4)], 2_000);
        t.observe_block(13, blk(13), &[tx(5), tx(6)], 3_000);
        assert_eq!(t.stats().confirmed, 6);
        assert_eq!(t.in_flight_len(), 0);

        // A 3-deep reorg: height 11 is replaced, so 11, 12 and 13 all die.
        let ev = t.observe_block(11, blk(911), &[], 4_000);
        let u = unmines(&ev);
        assert_eq!(u.len(), 6);
        // Tip first: heights 13, 12, 11 in that order.
        assert_eq!(
            u.iter().map(|x| x.height).collect::<Vec<_>>(),
            vec![13, 13, 12, 12, 11, 11]
        );
        assert_eq!(t.in_flight_len(), 6);
        assert_eq!(t.stats().confirmed, 0);
        assert_eq!(t.stats().unmined_total, 6);
        // Every latency sample from the dead branch was withdrawn.
        assert_eq!(t.latency(0), None);
        for n in 1..=6u64 {
            assert_eq!(t.confirmed_height(&tx(n)), None);
        }
    }

    #[test]
    fn a_tx_reincluded_at_a_different_height_measures_from_its_original_submit() {
        let mut t = ConfirmTracker::new();
        t.register(tx(1), 500, 10, 7, 3);
        t.observe_block(11, blk(11), &[tx(1)], 1_500);
        assert_eq!(t.confirmed_height(&tx(1)), Some(11));

        // A reorg replaces height 11 with an empty block, then tx(1) lands at 13.
        let ev = t.observe_block(11, blk(911), &[], 2_500);
        assert_eq!(unmines(&ev).len(), 1);
        assert!(t.in_flight(&tx(1)).is_some());
        t.observe_block(12, blk(912), &[], 3_000);
        let ev = t.observe_block(13, blk(913), &[tx(1)], 4_000);
        let c = confirmations(&ev);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].height, 13);
        assert_eq!(c[0].blocks_to_inclusion, 3); // 13 - 10, not 13 - 11
        assert_eq!(c[0].latency_ms, 3_500); // 4000 - 500, the original submit
        assert_eq!(t.stats().confirmed, 1);
        assert_eq!(t.stats().unmined_total, 1);
        assert_eq!(t.latency(3).map(|l| l.count), Some(1));
        assert_eq!(t.latency(3).map(|l| l.p50_ms), Some(3_500));
    }

    #[test]
    fn a_reorg_at_an_empty_height_still_rolls_back_the_heights_above_it() {
        let mut t = ConfirmTracker::new();
        t.register(tx(1), 0, 1, 0, 0);
        // Height 5 held nothing of ours but is still recorded...
        t.observe_block(5, blk(5), &[tx(77)], 1_000);
        t.observe_block(6, blk(6), &[tx(1)], 2_000);
        assert_eq!(t.stats().confirmed, 1);
        // ...so replacing it is recognized and height 6 is rolled back too.
        let ev = t.observe_block(5, blk(905), &[], 3_000);
        assert_eq!(unmines(&ev).len(), 1);
        assert_eq!(t.stats().confirmed, 0);
        assert_eq!(t.in_flight_len(), 1);
    }

    #[test]
    fn extending_the_chain_never_unmines_anything() {
        let mut t = ConfirmTracker::new();
        for n in 1..=5u64 {
            t.register(tx(n), 0, 0, 1, 0);
            let ev = t.observe_block(n, blk(n), &[tx(n)], n * 1_000);
            assert_eq!(confirmations(&ev).len(), 1);
            assert!(unmines(&ev).is_empty());
        }
        assert_eq!(t.stats().confirmed, 5);
        assert_eq!(t.stats().unmined_total, 0);
    }

    // ---- Expiry -------------------------------------------------------------

    #[test]
    fn expiry_drops_only_what_has_outlived_the_ttl_in_registration_order() {
        let mut t = ConfirmTracker::new();
        t.register(tx(1), 0, 1, 0, 0);
        t.register(tx(2), 1_000, 1, 0, 0);
        t.register(tx(3), 5_000, 1, 0, 0);
        // At t=6_000 with a 5_000 ms TTL: tx(1) (6_000 old) and tx(2) (5_000 old,
        // exactly at the boundary) go; tx(3) (1_000 old) stays.
        let ev = t.expire(6_000, 5_000);
        let d = drops(&ev);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].txid, tx(1));
        assert_eq!(d[0].age_ms, 6_000);
        assert_eq!(d[0].reason, DropReason::Expired);
        assert_eq!(d[1].txid, tx(2));
        assert_eq!(d[1].age_ms, 5_000);
        assert_eq!(t.in_flight_len(), 1);
        assert_eq!(t.stats().dropped_expired, 2);
        assert_eq!(t.stats().in_flight, 1);
        // A second sweep at the same instant finds nothing more to drop.
        assert!(t.expire(6_000, 5_000).is_empty());
    }

    #[test]
    fn a_zero_ttl_expires_everything_and_a_future_stamp_expires_nothing() {
        let mut t = ConfirmTracker::new();
        t.register(tx(1), 1_000, 1, 0, 0);
        t.register(tx(2), 1_000, 1, 0, 0);
        assert_eq!(drops(&t.expire(1_000, 0)).len(), 2);

        let mut t = ConfirmTracker::new();
        // Submitted "in the future" relative to now: the age saturates to 0.
        t.register(tx(1), 9_000, 1, 0, 0);
        assert!(t.expire(1_000, 1).is_empty());
        assert_eq!(t.in_flight_len(), 1);
    }

    #[test]
    fn a_dropped_tx_that_shows_up_anyway_is_counted_as_a_late_confirmation() {
        let mut t = ConfirmTracker::new();
        t.register(tx(1), 0, 10, 4, 1);
        assert_eq!(drops(&t.expire(60_000, 30_000)).len(), 1);
        assert_eq!(t.stats().dropped_expired, 1);
        assert_eq!(t.stats().confirmed, 0);

        // It lands anyway. The TTL was OUR cutoff, so the drop is reclassified and
        // the (long) latency IS recorded — hiding it would flatter the p95.
        let ev = t.observe_block(15, blk(15), &[tx(1)], 90_000);
        let c = confirmations(&ev);
        assert_eq!(c.len(), 1);
        assert!(c[0].late);
        assert_eq!(c[0].latency_ms, 90_000);
        assert_eq!(c[0].blocks_to_inclusion, 5);
        assert_eq!(t.stats().dropped_expired, 0);
        assert_eq!(t.stats().confirmed, 1);
        assert_eq!(t.stats().late_total, 1);
        assert_eq!(t.latency(1).map(|l| l.max_ms), Some(90_000));
        // And it is a normal confirmation from then on: a reorg un-mines it back
        // into flight, not back into the drop pile.
        let ev = t.observe_block(15, blk(915), &[], 95_000);
        assert_eq!(unmines(&ev).len(), 1);
        assert!(t.in_flight(&tx(1)).is_some());
        assert_eq!(t.stats().dropped_expired, 0);
    }

    #[test]
    fn a_dropped_tx_can_be_registered_again_and_leaves_the_drop_pile() {
        let mut t = ConfirmTracker::new();
        t.register(tx(1), 0, 1, 0, 0);
        t.expire(10_000, 1_000);
        assert_eq!(t.stats().dropped_expired, 1);
        // A fresh submission of the same id restarts the measurement.
        assert!(t.register(tx(1), 20_000, 5, 0, 0).is_none());
        assert_eq!(t.stats().dropped_expired, 0);
        assert_eq!(t.in_flight(&tx(1)).map(|s| s.submitted_ms), Some(20_000));
        let ev = t.observe_block(6, blk(6), &[tx(1)], 21_000);
        let c = confirmations(&ev);
        assert!(!c[0].late, "re-registered, so not a late arrival");
        assert_eq!(c[0].latency_ms, 1_000);
    }

    // ---- Latency histogram --------------------------------------------------

    #[test]
    fn latency_percentiles_are_reported_per_tip_bucket_not_pooled() {
        let mut t = ConfirmTracker::new();
        // Bucket 0 (low tip): 100 txs taking 1_000..=100_000 ms.
        // Bucket 1 (high tip): 100 txs taking 10..=1_000 ms.
        for i in 1..=100u64 {
            t.register(tx(i), 0, 0, 1, 0);
            t.observe_block(i, blk(i), &[tx(i)], i * 1_000);
        }
        for i in 1..=100u64 {
            let id = tx(1_000 + i);
            t.register(id, 0, 0, 999, 1);
            t.observe_block(1_000 + i, blk(1_000 + i), &[id], i * 10);
        }
        let low = t.latency(0).expect("bucket 0 measured");
        let high = t.latency(1).expect("bucket 1 measured");
        assert_eq!(low.count, 100);
        assert_eq!(low.min_ms, 1_000);
        assert_eq!(low.max_ms, 100_000);
        assert_eq!(low.p50_ms, 50_000);
        assert_eq!(low.p95_ms, 95_000);
        assert_eq!(high.count, 100);
        assert_eq!(high.min_ms, 10);
        assert_eq!(high.max_ms, 1_000);
        assert_eq!(high.p50_ms, 500);
        assert_eq!(high.p95_ms, 950);
        assert_eq!(t.buckets(), vec![0, 1]);
        // An unmeasured bucket is unknown, never a zeroed distribution.
        assert_eq!(t.latency(2), None);
    }

    #[test]
    fn a_single_sample_bucket_reports_that_sample_for_every_statistic() {
        let mut t = ConfirmTracker::new();
        t.register(tx(1), 0, 0, 1, 7);
        t.observe_block(1, blk(1), &[tx(1)], 4_242);
        assert_eq!(
            t.latency(7),
            Some(BucketLatency {
                count: 1,
                min_ms: 4_242,
                max_ms: 4_242,
                p50_ms: 4_242,
                p95_ms: 4_242,
            })
        );
    }

    #[test]
    fn bucket_keys_beyond_the_cap_are_counted_not_stored() {
        let mut t = ConfirmTracker::new();
        // Fill every allowed bucket, then use one more key.
        for b in 0..MAX_TIP_BUCKETS {
            let id = tx(b as u64);
            t.register(id, 0, 0, 1, b as TipBucket);
            t.observe_block(b as u64, blk(b as u64), &[id], 1_000);
        }
        assert_eq!(t.buckets().len(), MAX_TIP_BUCKETS);
        let overflow = tx(9_999);
        t.register(overflow, 0, 0, 1, 200);
        let ev = t.observe_block(9_999, blk(9_999), &[overflow], 2_000);
        // The confirmation is still reported in full...
        assert_eq!(confirmations(&ev).len(), 1);
        // ...but the sample is not stored, and the loss is visible.
        assert_eq!(t.latency(200), None);
        assert_eq!(t.buckets().len(), MAX_TIP_BUCKETS);
        assert_eq!(t.stats().unbucketed_samples, 1);
    }

    // ---- Bounded memory -----------------------------------------------------

    #[test]
    fn the_in_flight_set_never_exceeds_its_cap_and_sheds_the_oldest() {
        let mut t = ConfirmTracker::new();
        for i in 0..MAX_IN_FLIGHT as u64 {
            assert!(t.register(tx(i), i, 0, 1, 0).is_none());
        }
        assert_eq!(t.in_flight_len(), MAX_IN_FLIGHT);
        // One past the cap evicts the very first registration.
        let ev = t
            .register(tx(MAX_IN_FLIGHT as u64), 1_000_000, 0, 1, 0)
            .expect("capacity eviction is reported");
        match ev {
            TrackerEvent::Dropped(d) => {
                assert_eq!(d.txid, tx(0));
                assert_eq!(d.reason, DropReason::CapacityEvicted);
                assert_eq!(d.age_ms, 1_000_000);
            }
            other => panic!("expected a capacity drop, got {other:?}"),
        }
        assert_eq!(t.in_flight_len(), MAX_IN_FLIGHT);
        assert!(t.in_flight(&tx(0)).is_none());
        assert!(t.in_flight(&tx(MAX_IN_FLIGHT as u64)).is_some());
        assert_eq!(t.stats().dropped_evicted, 1);
        // An evicted tx is NOT in the drop memory, so its later inclusion is not
        // claimed as a late confirmation of something we stopped tracking.
        let ev = t.observe_block(1, blk(1), &[tx(0)], 1_000_001);
        assert!(confirmations(&ev).is_empty());
    }

    #[test]
    fn history_retention_is_bounded_by_heights_and_by_confirmations() {
        let mut t = ConfirmTracker::new();
        let blocks = MAX_TRACKED_HEIGHTS as u64 + 50;
        for h in 1..=blocks {
            t.register(tx(h), h, h, 1, 0);
            t.observe_block(h, blk(h), &[tx(h)], h * 10);
        }
        // Every confirmation still COUNTS...
        assert_eq!(t.stats().confirmed, blocks);
        // ...but only the most recent window is retained for rollback.
        assert_eq!(t.confirmed_height(&tx(1)), None);
        assert_eq!(t.confirmed_height(&tx(blocks)), Some(blocks));
        // A reorg at a pruned height cannot resurrect what was forgotten: nothing
        // is un-mined, and nothing is fabricated either.
        let ev = t.observe_block(1, blk(901), &[], 999_999);
        assert!(unmines(&ev).is_empty());
        assert_eq!(t.stats().unmined_total, 0);
    }

    #[test]
    fn a_long_soak_keeps_every_structure_inside_its_documented_bound() {
        let mut t = ConfirmTracker::new();
        // 20_000 submissions across 400 blocks: some confirm, some expire, and one
        // reorg strikes midway. Nothing may grow without limit.
        let mut id = 0u64;
        for h in 1..=400u64 {
            let mut batch = Vec::new();
            for _ in 0..50 {
                id += 1;
                t.register(tx(id), h * 1_000, h, u128::from(id), (id % 4) as TipBucket);
                if id.is_multiple_of(2) {
                    batch.push(tx(id));
                }
            }
            t.observe_block(h, blk(h), &batch, h * 1_000 + 500);
            if h == 200 {
                t.observe_block(h, blk(h + 100_000), &batch, h * 1_000 + 900);
            }
            t.expire(h * 1_000, 30_000);
        }
        assert!(t.in_flight_len() <= MAX_IN_FLIGHT);
        assert!(t.buckets().len() <= MAX_TIP_BUCKETS);
        for b in t.buckets() {
            let l = t.latency(b).expect("non-empty bucket");
            assert!(l.count <= MAX_SAMPLES_PER_BUCKET);
            assert!(l.min_ms <= l.p50_ms && l.p50_ms <= l.p95_ms && l.p95_ms <= l.max_ms);
        }
        let s = t.stats();
        assert_eq!(s.in_flight, t.in_flight_len() as u64);
        assert!(s.unmined_total > 0, "the injected reorg must be visible");
        // Confirmed + in-flight + dropped never exceeds what we registered.
        assert!(s.confirmed + s.in_flight + s.dropped_expired + s.dropped_evicted <= id);
    }

    #[test]
    fn per_bucket_samples_are_a_bounded_rolling_window() {
        let mut t = ConfirmTracker::new();
        let n = MAX_SAMPLES_PER_BUCKET as u64 + 100;
        for i in 1..=n {
            t.register(tx(i), 0, 0, 1, 0);
            t.observe_block(i, blk(i), &[tx(i)], i);
        }
        let l = t.latency(0).expect("measured");
        assert_eq!(l.count, MAX_SAMPLES_PER_BUCKET);
        // The window holds the most RECENT samples: 101..=n.
        assert_eq!(l.min_ms, 101);
        assert_eq!(l.max_ms, n);
        assert_eq!(t.stats().evicted_samples, 100);
    }

    #[test]
    fn drop_memory_forgets_the_oldest_drops_first() {
        let mut t = ConfirmTracker::new();
        let n = MAX_DROP_MEMORY as u64 + 10;
        for i in 1..=n {
            t.register(tx(i), 0, 0, 1, 0);
        }
        assert_eq!(drops(&t.expire(1_000, 100)).len() as u64, n);
        // The oldest 10 drops are forgotten: their later inclusion reads as a
        // stranger's transaction rather than being counted twice.
        let ev = t.observe_block(1, blk(1), &[tx(1)], 2_000);
        assert!(confirmations(&ev).is_empty());
        // A still-remembered drop is recognized as a late inclusion.
        let ev = t.observe_block(2, blk(2), &[tx(n)], 2_000);
        let c = confirmations(&ev);
        assert_eq!(c.len(), 1);
        assert!(c[0].late);
    }

    // ---- Determinism ---------------------------------------------------------

    #[test]
    fn identical_input_sequences_produce_identical_event_sequences() {
        let run = || {
            let mut t = ConfirmTracker::new();
            let mut log = Vec::new();
            for i in 1..=200u64 {
                if let Some(e) = t.register(tx(i), i * 10, i, u128::from(i), (i % 5) as TipBucket) {
                    log.push(e);
                }
            }
            let all: Vec<TxId> = (1..=100).map(tx).collect();
            let some: Vec<TxId> = (1..=40).map(tx).collect();
            log.extend(t.observe_block(50, blk(50), &all, 5_000));
            log.extend(t.observe_block(50, blk(950), &some, 6_000));
            log.extend(t.expire(9_000, 1_000));
            (log, t.stats(), t.latency(0), t.latency(3))
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn ids_render_as_short_hex_prefixes_for_logs() {
        assert_eq!(tx(0).short(), "00000000");
        assert_eq!(tx(1).short(), "01000000");
        assert_eq!(blk(1).short(), "01000000");
        assert_eq!(format!("{:?}", tx(1)), "tx:01000000");
        assert_eq!(format!("{:?}", blk(1)), "blk:01000000");
        assert_eq!(tx(1).as_bytes()[0], 1);
        assert_eq!(blk(1).as_bytes()[31], 0xff);
    }
}
