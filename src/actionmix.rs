//! Weighted **action mix** — traffic that is not all plain transfers.
//!
//! A cannon that only fires `Action::Transfer` measures one number: how many
//! minimum-sized transparent payments the chain absorbs. Real block space is
//! consumed by a *population* of action types with very different encoded sizes
//! and very different execution costs. This module lets a run draw its action
//! from a weighted mix, so the operator can measure **block-space cost per
//! action type** instead of extrapolating from transfers.
//!
//! Everything here is pure: it decides *which* action to build and *builds* it,
//! using the chain's own [`Action`] type and the chain's own [`AccountId`]
//! validation. It performs no I/O, holds no key material, and signs nothing —
//! signing stays in `logic::build_signed_action`, which uses the chain's real
//! signer. The size of a built transaction is likewise measured with the chain's
//! own encoder ([`SignedTransaction::serialized_size`]), never with a
//! reimplementation of Borsh.
//!
//! # What is deliberately NOT in the mix
//!
//! The kinds below are the ones a traffic generator can build *self-containedly*
//! — each one is valid on its own, from any funded account, with no prior
//! on-chain state to discover and no value left stranded. Excluded, with reasons:
//!
//! * `Shielded` — requires a real Orchard/Halo2 bundle built against the live
//!   note commitment tree and a witness for a note the tool owns. That is a
//!   shielded *wallet*, not a traffic generator, and building one here would
//!   mean reimplementing wallet logic this crate has a hard rule against. A
//!   shielded mode has to be driven by the real shielded wallet path.
//! * `Deploy` / `Call` — need contract bytecode and a deployed contract address;
//!   an arbitrary WASM blob is not traffic, it is a separate fuzzing project.
//! * `HtlcLock` / `VaultDeposit` / `VaultMint` — these LOCK value. A load tool
//!   that escrows funds on every draw would strand XUS behind timeouts and
//!   collateral ratios, which violates the tool's own safety posture.
//! * `TokenTransfer` / `TokenBurn` / `NftTransfer` / `TransferName` — need an
//!   asset id, token id, or name that already exists on chain and is owned by
//!   the signer. Deriving those ids here would mean reimplementing chain id
//!   derivation, which this crate forbids.
//! * `MultisigExec` / `ProposeMultisig` / `ApproveMultisig` / `RotateKey` /
//!   `OracleUpdate` / `IntentSettle` — either require a policy/proposal that
//!   already exists, or mutate the signer's own authorization. Neither belongs
//!   in unattended load traffic.

use sov_primitives::{AccountId, Balance};
use sov_types::Action;

/// The action kinds a traffic run can draw from.
///
/// Each is self-contained: buildable from a funded account with no prior
/// on-chain state, and leaving nothing locked. The variants are ordered by
/// increasing "footprint" — encoded size and/or execution cost — which is the
/// axis the mix exists to explore.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActionKind {
    /// A plain transparent payment — the cannon's original traffic, and the
    /// smallest useful transaction on the chain.
    Transfer,
    /// Issue units of an asset the signer owns. The asset is bound to its issuer
    /// by derivation, so re-issuing the same symbol mints more of the SAME asset
    /// rather than failing — which makes it safely repeatable traffic. Token
    /// units are their own denomination and never touch the 21M SOV supply.
    TokenIssue,
    /// Mint an NFT with a metadata blob. The metadata is the point: it is the
    /// only kind here whose encoded size the operator can dial directly, so it
    /// is how a run explores the block-space cap rather than the tx-count cap.
    NftMint,
    /// Claim a `*.sov` name.
    ///
    /// **This kind costs a real one-time registration fee on top of gas** (see
    /// `NAME_REGISTRATION_FEE_GRAINS` in the chain's execution module, charged
    /// at `chain/crates/runtime/src/execution.rs:1078-1086`, paid to the miner —
    /// it is not burned). At traffic rates that is a meaningful, irreversible
    /// spend, so it is never in a default mix and the caller must opt in
    /// explicitly. Names are unique and first-come, so each draw must use a
    /// fresh name or the action executes and FAILS as "name already registered"
    /// — still consuming the nonce and the gas fee.
    RegisterName,
}

impl ActionKind {
    /// Every kind, for UI enumeration and exhaustive tests.
    pub const ALL: [ActionKind; 4] = [
        ActionKind::Transfer,
        ActionKind::TokenIssue,
        ActionKind::NftMint,
        ActionKind::RegisterName,
    ];

    /// A short label for the UI and the per-kind cost table.
    pub fn label(self) -> &'static str {
        match self {
            ActionKind::Transfer => "Transfer",
            ActionKind::TokenIssue => "TokenIssue",
            ActionKind::NftMint => "NftMint",
            ActionKind::RegisterName => "RegisterName",
        }
    }

    /// Whether this kind spends XUS beyond the intrinsic gas fee.
    ///
    /// `Transfer` moves value but (in recycle mode) to an account the operator
    /// controls; `RegisterName` burns a fee to the miner that never comes back.
    /// The UI uses this to require an explicit acknowledgement.
    pub fn has_extra_xus_cost(self) -> bool {
        matches!(self, ActionKind::RegisterName)
    }
}

/// A weighted distribution over [`ActionKind`].
///
/// Weights are relative and need not sum to anything in particular; a kind with
/// weight zero is never drawn. Construction rejects a mix that could never
/// produce an action, so [`pick`](Self::pick) is total and never panics.
#[derive(Clone, Debug)]
pub struct ActionMix {
    /// `(kind, cumulative_weight)`, ascending. Cumulative form makes the draw a
    /// single scan with no division and no modulo bias beyond the caller's own
    /// uniform draw.
    cumulative: Vec<(ActionKind, u64)>,
    total: u64,
}

impl ActionMix {
    /// Build a mix from `(kind, weight)` pairs.
    ///
    /// Errors if the list is empty, if every weight is zero (nothing could ever
    /// be drawn), or if a kind appears twice (almost always a UI bug, and it
    /// makes the effective weight silently different from the one displayed).
    pub fn new(weights: &[(ActionKind, u64)]) -> Result<Self, String> {
        if weights.is_empty() {
            return Err("choose at least one action kind".into());
        }
        let mut seen: Vec<ActionKind> = Vec::new();
        for (kind, _) in weights {
            if seen.contains(kind) {
                return Err(format!("action kind {} listed twice", kind.label()));
            }
            seen.push(*kind);
        }
        let mut cumulative = Vec::with_capacity(weights.len());
        let mut total: u64 = 0;
        for (kind, w) in weights {
            if *w == 0 {
                continue;
            }
            // Saturating: a caller cannot make the accumulator wrap.
            total = total.saturating_add(*w);
            cumulative.push((*kind, total));
        }
        if total == 0 {
            return Err("at least one action kind needs a weight above zero".into());
        }
        Ok(Self { cumulative, total })
    }

    /// The sum of the non-zero weights (the draw's modulus).
    pub fn total_weight(&self) -> u64 {
        self.total
    }

    /// The kind selected by a uniform draw.
    ///
    /// `draw` is supplied by the caller (the worker's RNG) so this stays pure and
    /// deterministically testable, exactly like `AmountMode::pick` in `logic`.
    /// Any `draw` is valid: it is reduced modulo the total weight, and the final
    /// rung is returned if the scan somehow falls through, so this is total.
    pub fn pick(&self, draw: u128) -> ActionKind {
        let point = (draw % u128::from(self.total)) as u64;
        for (kind, cum) in &self.cumulative {
            if point < *cum {
                return *kind;
            }
        }
        // Unreachable while `total` is the last cumulative value, but returning
        // the last rung keeps this total rather than panicking.
        self.cumulative
            .last()
            .map(|(k, _)| *k)
            .unwrap_or(ActionKind::Transfer)
    }

    /// The kinds in the mix that carry an extra irreversible XUS cost.
    pub fn costly_kinds(&self) -> Vec<ActionKind> {
        self.cumulative
            .iter()
            .map(|(k, _)| *k)
            .filter(|k| k.has_extra_xus_cost())
            .collect()
    }
}

/// The per-draw inputs an action needs beyond its kind.
///
/// `unique` is what keeps repeatable kinds from colliding: it becomes the NFT's
/// token id and the registered name's discriminator. The caller supplies a value
/// that is unique within the run (the transaction nonce is a natural choice —
/// it is unique per signer by construction).
#[derive(Clone, Debug)]
pub struct ActionParams {
    /// Recipient for the kinds that have one.
    pub to: AccountId,
    /// Value in grains for the kinds that move value.
    pub amount_grains: u128,
    /// Per-draw uniqueness discriminator (see the struct docs).
    pub unique: u64,
    /// The asset/collection symbol used by `TokenIssue` and `NftMint`.
    ///
    /// Must satisfy the chain's symbol rule (1–16 ASCII alphanumeric bytes);
    /// [`validate_symbol`] checks it before a run starts.
    pub symbol: String,
    /// Extra padding bytes attached to `NftMint` metadata, so a run can dial
    /// transaction size directly and probe the block-space cap.
    pub metadata_bytes: usize,
}

/// The chain's symbol rule: 1–16 ASCII alphanumeric bytes.
///
/// Stated at `Action::TokenIssue` in `chain/crates/types/src/transaction.rs`
/// ("1–16 ASCII alphanumeric bytes, namespaced under the issuer"). Checked here
/// so an unusable mix is refused before the run starts rather than producing a
/// stream of failed executions that still burn nonces and gas.
pub fn validate_symbol(symbol: &str) -> Result<(), String> {
    if symbol.is_empty() || symbol.len() > 16 {
        return Err("symbol must be 1–16 characters".into());
    }
    if !symbol.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("symbol must be ASCII letters and digits only".into());
    }
    Ok(())
}

/// The largest metadata padding a single draw may request.
///
/// The chain caps transaction data under BIP-110; this bound exists so the UI
/// cannot ask for a transaction the node will certainly refuse, and so a typo
/// cannot allocate an enormous buffer on the client. It is a CLIENT-side sanity
/// bound, deliberately well under any consensus limit — it is not a claim about
/// what the chain accepts.
pub const MAX_METADATA_BYTES: usize = 64 * 1024;

/// Build the `*.sov` name a `RegisterName` draw will claim.
///
/// The name is validated with the chain's OWN [`AccountId`] rules — this crate
/// does not reimplement the naming grammar. A name that the chain would not
/// accept as a registrable id is an error here, before it costs a fee on chain.
pub fn cannon_name(prefix: &str, unique: u64) -> Result<String, String> {
    if prefix.is_empty() || !prefix.chars().all(|c| c.is_ascii_lowercase()) {
        return Err("name prefix must be lowercase ASCII letters".into());
    }
    let name = format!("{prefix}{unique}.sov");
    match AccountId::new(&name) {
        Err(e) => Err(format!("generated name `{name}` is not a valid id: {e}")),
        Ok(id) if !id.is_registrable_name() => {
            Err(format!("generated name `{name}` is not registrable"))
        }
        Ok(_) => Ok(name),
    }
}

/// Build the concrete [`Action`] for one draw.
///
/// Pure and infallible except for the two validated inputs (symbol, name), which
/// are checked with the chain's own rules. Nothing here signs, and nothing here
/// touches key material.
pub fn build_action(
    kind: ActionKind,
    params: &ActionParams,
    name_prefix: &str,
) -> Result<Action, String> {
    match kind {
        ActionKind::Transfer => Ok(Action::Transfer {
            to: params.to.clone(),
            amount: Balance::from_grains(params.amount_grains),
        }),
        ActionKind::TokenIssue => {
            validate_symbol(&params.symbol)?;
            Ok(Action::TokenIssue {
                symbol: params.symbol.clone(),
                amount: Balance::from_grains(params.amount_grains),
                to: params.to.clone(),
            })
        }
        ActionKind::NftMint => {
            validate_symbol(&params.symbol)?;
            if params.metadata_bytes > MAX_METADATA_BYTES {
                return Err(format!(
                    "metadata padding must be at most {MAX_METADATA_BYTES} bytes"
                ));
            }
            Ok(Action::NftMint {
                symbol: params.symbol.clone(),
                // The token id is the uniqueness discriminator in big-endian
                // bytes: distinct per draw, fixed width, no allocation surprises.
                token_id: params.unique.to_be_bytes().to_vec(),
                to: params.to.clone(),
                // Deterministic padding, not entropy: the operator is measuring
                // SIZE, and a fixed byte makes two runs of the same shape
                // byte-comparable.
                metadata: vec![b'x'; params.metadata_bytes],
            })
        }
        ActionKind::RegisterName => Ok(Action::RegisterName {
            name: cannon_name(name_prefix, params.unique)?,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest() -> AccountId {
        // A 64-hex implicit id: the shape the cannon actually fires at.
        AccountId::new("ab".repeat(32)).expect("valid implicit id")
    }

    fn params(unique: u64) -> ActionParams {
        ActionParams {
            to: dest(),
            amount_grains: 1_000,
            unique,
            symbol: "CANNON".into(),
            metadata_bytes: 0,
        }
    }

    #[test]
    fn an_empty_mix_is_refused() {
        assert!(ActionMix::new(&[]).is_err());
    }

    #[test]
    fn an_all_zero_mix_is_refused_because_nothing_could_ever_be_drawn() {
        let err = ActionMix::new(&[(ActionKind::Transfer, 0), (ActionKind::NftMint, 0)])
            .expect_err("all-zero weights must not build");
        assert!(err.contains("weight"), "unexpected message: {err}");
    }

    #[test]
    fn a_duplicated_kind_is_refused() {
        let err = ActionMix::new(&[(ActionKind::Transfer, 1), (ActionKind::Transfer, 2)])
            .expect_err("a duplicate kind must not build");
        assert!(err.contains("twice"), "unexpected message: {err}");
    }

    #[test]
    fn a_zero_weight_kind_is_never_drawn() {
        let mix = ActionMix::new(&[(ActionKind::Transfer, 3), (ActionKind::NftMint, 0)])
            .expect("mix builds");
        assert_eq!(mix.total_weight(), 3);
        for draw in 0..100u128 {
            assert_eq!(mix.pick(draw), ActionKind::Transfer);
        }
    }

    #[test]
    fn draws_land_in_each_kind_in_proportion_to_its_weight() {
        let mix = ActionMix::new(&[
            (ActionKind::Transfer, 1),
            (ActionKind::TokenIssue, 2),
            (ActionKind::NftMint, 7),
        ])
        .expect("mix builds");
        assert_eq!(mix.total_weight(), 10);
        let mut counts = [0usize; 3];
        for draw in 0..10u128 {
            match mix.pick(draw) {
                ActionKind::Transfer => counts[0] += 1,
                ActionKind::TokenIssue => counts[1] += 1,
                ActionKind::NftMint => counts[2] += 1,
                ActionKind::RegisterName => unreachable!("not in this mix"),
            }
        }
        assert_eq!(counts, [1, 2, 7]);
    }

    #[test]
    fn pick_is_total_for_any_draw_including_the_maximum() {
        let mix = ActionMix::new(&[(ActionKind::Transfer, 1), (ActionKind::NftMint, 1)])
            .expect("mix builds");
        // Must not panic and must return a kind that is actually in the mix.
        for draw in [0u128, 1, u128::MAX / 2, u128::MAX] {
            let k = mix.pick(draw);
            assert!(matches!(k, ActionKind::Transfer | ActionKind::NftMint));
        }
    }

    #[test]
    fn a_single_kind_mix_always_draws_that_kind() {
        let mix = ActionMix::new(&[(ActionKind::TokenIssue, 1)]).expect("mix builds");
        assert_eq!(mix.total_weight(), 1);
        assert_eq!(mix.pick(0), ActionKind::TokenIssue);
        assert_eq!(mix.pick(u128::MAX), ActionKind::TokenIssue);
    }

    #[test]
    fn only_register_name_is_flagged_as_an_extra_xus_cost() {
        for kind in ActionKind::ALL {
            assert_eq!(
                kind.has_extra_xus_cost(),
                kind == ActionKind::RegisterName,
                "{} misreports its cost",
                kind.label()
            );
        }
        let mix = ActionMix::new(&[
            (ActionKind::Transfer, 1),
            (ActionKind::RegisterName, 1),
            (ActionKind::NftMint, 1),
        ])
        .expect("mix builds");
        assert_eq!(mix.costly_kinds(), vec![ActionKind::RegisterName]);
    }

    #[test]
    fn every_kind_has_a_distinct_label() {
        let mut labels: Vec<&str> = ActionKind::ALL.iter().map(|k| k.label()).collect();
        labels.sort_unstable();
        let before = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), before, "labels must be distinct");
    }

    #[test]
    fn symbol_validation_matches_the_chains_one_to_sixteen_alphanumeric_rule() {
        assert!(validate_symbol("A").is_ok());
        assert!(validate_symbol("CANNON1").is_ok());
        assert!(validate_symbol(&"A".repeat(16)).is_ok());
        assert!(validate_symbol("").is_err());
        assert!(validate_symbol(&"A".repeat(17)).is_err());
        assert!(validate_symbol("CAN-NON").is_err());
        assert!(validate_symbol("CANNÖN").is_err());
    }

    #[test]
    fn a_transfer_carries_exactly_the_requested_recipient_and_amount() {
        let p = params(7);
        match build_action(ActionKind::Transfer, &p, "cannon").expect("builds") {
            Action::Transfer { to, amount } => {
                assert_eq!(to, dest());
                assert_eq!(amount.grains(), 1_000);
            }
            other => panic!("wrong action: {other:?}"),
        }
    }

    #[test]
    fn a_token_issue_refuses_a_symbol_the_chain_would_reject() {
        let mut p = params(1);
        p.symbol = "not a symbol".into();
        assert!(build_action(ActionKind::TokenIssue, &p, "cannon").is_err());
    }

    #[test]
    fn nft_token_ids_are_distinct_per_draw_so_mints_do_not_collide() {
        let a = build_action(ActionKind::NftMint, &params(1), "cannon").expect("builds");
        let b = build_action(ActionKind::NftMint, &params(2), "cannon").expect("builds");
        let id = |act: &Action| match act {
            Action::NftMint { token_id, .. } => token_id.clone(),
            other => panic!("wrong action: {other:?}"),
        };
        assert_ne!(id(&a), id(&b));
    }

    #[test]
    fn nft_metadata_padding_is_exactly_the_requested_size() {
        let mut p = params(1);
        p.metadata_bytes = 1_024;
        match build_action(ActionKind::NftMint, &p, "cannon").expect("builds") {
            Action::NftMint { metadata, .. } => assert_eq!(metadata.len(), 1_024),
            other => panic!("wrong action: {other:?}"),
        }
    }

    #[test]
    fn oversized_metadata_padding_is_refused_client_side() {
        let mut p = params(1);
        p.metadata_bytes = MAX_METADATA_BYTES + 1;
        assert!(build_action(ActionKind::NftMint, &p, "cannon").is_err());
    }

    #[test]
    fn generated_names_are_registrable_under_the_chains_own_rules() {
        let name = cannon_name("cannon", 42).expect("valid name");
        assert_eq!(name, "cannon42.sov");
        let id = AccountId::new(&name).expect("chain accepts it");
        assert!(id.is_registrable_name());
    }

    #[test]
    fn generated_names_are_distinct_per_draw() {
        assert_ne!(
            cannon_name("cannon", 1).expect("valid"),
            cannon_name("cannon", 2).expect("valid")
        );
    }

    #[test]
    fn a_bad_name_prefix_is_refused_before_it_can_cost_a_registration_fee() {
        assert!(cannon_name("", 1).is_err());
        assert!(cannon_name("Cannon", 1).is_err());
        assert!(cannon_name("cannon.sov", 1).is_err());
        assert!(cannon_name("cannon-1", 1).is_err());
    }
}
