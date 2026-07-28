//! **Prove the defenses hold** — a front-door adversarial battery.
//!
//! This mode fires a fixed set of HOSTILE, malformed transactions at a live node
//! the only way an outside attacker can: through `sov_submitTransaction`. Every
//! probe is rejected before admission — at decode, at authorization, or at
//! signature verification — so NOTHING lands in the mempool. The load-bearing
//! verdict is **no residue**: the probe reads `sov_getMempoolSize` before and
//! after the whole battery and PASSes only if the pool did not grow AND every
//! attack drew an explicit rejection. That flat mempool line beside a stream of
//! rejections is the whole point — you watch every attack bounce.
//!
//! It reuses the cannon's OWN transaction-construction and signing path (the same
//! real `sov-crypto` / `sov-types` code every honest send uses), then deliberately
//! corrupts one thing per attack. There is no dependency on the chain's red-team
//! crate — the cannon already knows how to build and sign these transactions.
//!
//! SAFETY. These are deliberately hostile bytes. One payload in this family (a
//! recursive-`Action` decode) was a LIVE mainnet crash before it was patched, so:
//!   * the probe detects mainnet (`sov_chainId`) and REFUSES to fire there without
//!     an explicit typed confirmation (default OFF);
//!   * every attack is engineered to be rejected for a reason INDEPENDENT of chain
//!     state (a broken signature, a foreign key, or a decode failure), so none can
//!     ever be admitted regardless of balances or nonces;
//!   * if the mempool grows anyway, that is a LOUD failure surfaced to the operator,
//!     never a silent pass.
//!
//! The classes mirror the chain's own live-fire probe:
//!   crypto   — signature integrity and the post-quantum hybrid conjunction
//!              (Ed25519 AND ML-DSA-65): a tampered or spliced signature is refused.
//!   authz    — control of the account: wrong-key and keyless-account spends.
//!   replay   — a signed authorization cannot be re-bound to a different nonce.
//!   value    — value-from-nothing / balance-overflow amounts are refused at the parser.
//!   encoding — the parser: type confusion, missing fields, over-length ids.
//!   rpc      — protocol resilience: unknown methods and oversized bodies don't crash it.

use serde_json::{json, to_value, Value};

use sov_crypto::{Keypair, Signature};
use sov_primitives::{AccountId, Balance};
use sov_rpc::{RpcClient, RpcClientError};
use sov_types::{Action, SignedTransaction, Transaction};

/// The exact phrase an operator must type to arm the battery against a mainnet
/// node. Case- and whitespace-trimmed but otherwise exact — a deliberate speed
/// bump, not a secret.
pub const MAINNET_CONFIRM_PHRASE: &str = "FIRE ON MAINNET";

/// Whether a chain id names a mainnet network — i.e. probing it hits the LIVE
/// chain, where the mainnet guard applies.
pub fn is_mainnet(chain_id: &str) -> bool {
    chain_id.contains("mainnet")
}

/// The mainnet guard, as one pure decision: the battery may fire when the target
/// is NOT mainnet, or when the operator has explicitly confirmed mainnet.
pub fn may_fire(is_mainnet: bool, confirmed: bool) -> bool {
    !is_mainnet || confirmed
}

/// Whether a typed confirmation string satisfies the mainnet guard.
pub fn confirmation_ok(typed: &str) -> bool {
    typed.trim() == MAINNET_CONFIRM_PHRASE
}

// ── verdict ──────────────────────────────────────────────────────────────────

/// The judgment on one attack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The door held: the node rejected the attack before admission. This is the
    /// expected, healthy outcome for every probe.
    Defended,
    /// The node ADMITTED the adversarial transaction — a real finding.
    Vulnerable,
    /// The node could not be reached for this probe (transport error); neither a
    /// pass nor a fail, but the battery did not complete.
    Info,
}

/// One attack's result: what it was, and how the node answered.
#[derive(Clone, Debug)]
pub struct AttackOutcome {
    pub category: &'static str,
    pub name: &'static str,
    pub verdict: Verdict,
    pub detail: String,
}

// ── signature tampering ──────────────────────────────────────────────────────

/// Which half of a hybrid signature to corrupt.
#[derive(Clone, Copy, Debug)]
pub enum Half {
    Ed25519,
    MlDsa,
}

/// Flip a byte in one half of a hybrid signature, returning the corrupted sig.
/// A `V1Ed25519` signature has no post-quantum half, so `MlDsa` is a no-op there
/// (the constructors only tamper hybrid signatures).
pub fn tamper_signature(sig: Signature, half: Half) -> Signature {
    match sig {
        Signature::V2HybridMlDsa65 {
            mut ed25519,
            mut ml_dsa,
        } => {
            match half {
                Half::Ed25519 => ed25519[0] ^= 0xff,
                Half::MlDsa => ml_dsa[0] ^= 0xff,
            }
            Signature::V2HybridMlDsa65 { ed25519, ml_dsa }
        }
        other => other,
    }
}

/// Extract the Ed25519 half of a signature (for the downgrade probe).
fn ed_half(sig: &Signature) -> [u8; 64] {
    match sig {
        Signature::V2HybridMlDsa65 { ed25519, .. } => *ed25519,
        Signature::V1Ed25519(b) => *b,
    }
}

// ── tx builders (the cannon's own real signing path) ─────────────────────────

/// The throwaway recipient every probe pays: a fresh implicit account nobody
/// controls. No probe ever moves value (all are rejected), so the sink is inert.
fn sink() -> AccountId {
    Keypair::hybrid_from_seed([200; 32])
        .public_key()
        .implicit_account_id()
}

/// A signed transfer whose declared account is the implicit id of `account_seed`,
/// signed by `key_seed`'s hybrid keypair (its `public_key` field is also
/// `key_seed`, so the signature itself is valid). When the seeds match this is a
/// well-formed self-certifying tx (a base to corrupt); when they differ, the
/// account is spent by a key that is NOT its own.
pub fn signed(account_seed: u8, key_seed: u8, nonce: u64, amount_sov: u64) -> SignedTransaction {
    let account_kp = Keypair::hybrid_from_seed([account_seed; 32]);
    let key_kp = Keypair::hybrid_from_seed([key_seed; 32]);
    let tx = Transaction {
        signer: account_kp.public_key().implicit_account_id(),
        public_key: key_kp.public_key(),
        nonce,
        action: Action::Transfer {
            to: sink(),
            amount: Balance::from_sov(amount_sov as u128).unwrap(),
        },
    };
    // `public_key` == the signing key, so `sign` succeeds even when the *account*
    // differs — that mismatch is exactly the wrong-key attack.
    SignedTransaction::sign(tx, &key_kp).unwrap()
}

/// A well-formed, self-certifying transfer from a throwaway implicit account.
pub fn base(seed: u8) -> SignedTransaction {
    signed(seed, seed, 0, 1)
}

// ── the attack set ───────────────────────────────────────────────────────────

/// What a single attack submits: an (intentionally corrupt) signed transaction,
/// or a raw JSON-RPC call for the malformed-protocol probes.
#[derive(Clone, Debug)]
pub enum Payload {
    /// Submit this signed transaction via `sov_submitTransaction`.
    Signed(Box<SignedTransaction>),
    /// Make this raw JSON-RPC call (method + params), for encoding / protocol
    /// attacks that never form a valid `SignedTransaction`.
    Call { method: &'static str, params: Value },
}

/// One named attack, ready to fire.
#[derive(Clone, Debug)]
pub struct Attack {
    pub category: &'static str,
    pub name: &'static str,
    pub payload: Payload,
}

impl Attack {
    fn signed(category: &'static str, name: &'static str, stx: SignedTransaction) -> Self {
        Attack {
            category,
            name,
            payload: Payload::Signed(Box::new(stx)),
        }
    }
    fn submit_raw(category: &'static str, name: &'static str, params: Value) -> Self {
        Attack {
            category,
            name,
            payload: Payload::Call {
                method: "sov_submitTransaction",
                params,
            },
        }
    }
    fn call(
        category: &'static str,
        name: &'static str,
        method: &'static str,
        params: Value,
    ) -> Self {
        Attack {
            category,
            name,
            payload: Payload::Call { method, params },
        }
    }
}

/// The full, deterministic battery. Pure: it constructs every hostile payload
/// without touching the network, so the corruption logic is unit-testable in
/// isolation. Each attack is rejected for a reason INDEPENDENT of chain state.
pub fn battery() -> Vec<Attack> {
    let mut a = Vec::new();

    // ---- crypto: the hybrid conjunction (Ed25519 AND ML-DSA-65) --------------
    // Forge the Ed25519 half only.
    let mut s = base(9);
    s.signature = tamper_signature(s.signature, Half::Ed25519);
    a.push(Attack::signed("crypto", "forge Ed25519 half", s));

    // Forge ONLY the post-quantum half, leaving Ed25519 valid — the verifier ANDs
    // both, so a future break of Ed25519 alone still cannot forge.
    let mut s = base(10);
    s.signature = tamper_signature(s.signature, Half::MlDsa);
    a.push(Attack::signed(
        "crypto",
        "forge post-quantum half only (keep Ed25519 valid)",
        s,
    ));

    // Forge BOTH halves.
    let mut s = base(11);
    s.signature = tamper_signature(tamper_signature(s.signature, Half::Ed25519), Half::MlDsa);
    a.push(Attack::signed("crypto", "forge both signature halves", s));

    // Downgrade: present a V1 Ed25519-only signature against a hybrid key. Scheme
    // mismatch — the verifier must not fall back to the classical half alone.
    let mut s = base(13);
    s.signature = Signature::V1Ed25519(ed_half(&s.signature));
    a.push(Attack::signed(
        "crypto",
        "downgrade to Ed25519-only vs a hybrid key",
        s,
    ));

    // ---- authz: control of the account --------------------------------------
    // Spend an implicit account with a key that is NOT its own.
    a.push(Attack::signed(
        "authz",
        "impersonate an implicit account (wrong key)",
        signed(3, 4, 0, 1),
    ));

    // Spend from a keyless NAMED account we do not control (only a first-claim
    // RotateKey is permitted on such an account, never a Transfer).
    let attacker = Keypair::hybrid_from_seed([21; 32]);
    let tx = Transaction {
        signer: AccountId::new("attacker.sov").unwrap(),
        public_key: attacker.public_key(),
        nonce: 0,
        action: Action::Transfer {
            to: sink(),
            amount: Balance::from_sov(1).unwrap(),
        },
    };
    a.push(Attack::signed(
        "authz",
        "spend from a keyless named account",
        SignedTransaction::sign(tx, &attacker).unwrap(),
    ));

    // ---- replay: a signed authorization is bound to its exact nonce ----------
    // Splice a signature valid for a DIFFERENT nonce onto this transaction — the
    // classic replay of a spent authorization. It cannot verify over these bytes.
    let donor = signed(14, 14, 7, 3);
    let mut victim = signed(14, 14, 0, 1);
    victim.signature = donor.signature;
    a.push(Attack::signed(
        "replay",
        "replay a signature from another nonce (splice)",
        victim,
    ));

    // Mutate the nonce AFTER signing — the signature binds the body, so a replay
    // at a tampered nonce no longer verifies.
    let mut s = base(15);
    s.transaction.nonce = s.transaction.nonce.wrapping_add(1);
    a.push(Attack::signed(
        "replay",
        "replay a signed tx at a tampered nonce",
        s,
    ));

    // ---- value: value-from-nothing / balance overflow -----------------------
    // Both are expressed as raw payloads so the node refuses them at the PARSER,
    // before any admission — leaving no residue regardless of the affordability
    // gate. `Balance` decodes from a decimal grain STRING, so a negative number
    // and a value one past u128::MAX both fail to decode.
    let valid = to_value(base(30)).unwrap();

    let mut v = valid.clone();
    v["transaction"]["action"]["amount"] = json!(-1);
    a.push(Attack::submit_raw(
        "value",
        "negative transfer amount (value from nothing)",
        v,
    ));

    let mut v = valid.clone();
    // 2^128 — one past the u128 grain ceiling: overflows balance arithmetic.
    v["transaction"]["action"]["amount"] = json!("340282366920938463463374607431768211456");
    a.push(Attack::submit_raw(
        "value",
        "amount overflows u128 balance arithmetic",
        v,
    ));

    // ---- encoding: the parser / validator -----------------------------------
    a.push(Attack::submit_raw(
        "encoding",
        "payload is not a transaction",
        json!("not-a-transaction"),
    ));

    let mut v = valid.clone();
    v["transaction"]["nonce"] = json!("not-a-number");
    a.push(Attack::submit_raw(
        "encoding",
        "nonce as a string (type confusion)",
        v,
    ));

    let mut v = valid.clone();
    if let Some(obj) = v.as_object_mut() {
        obj.remove("signature");
    }
    a.push(Attack::submit_raw("encoding", "missing signature field", v));

    let mut v = valid.clone();
    v["transaction"]["signer"] = json!("a".repeat(96));
    a.push(Attack::submit_raw(
        "encoding",
        "over-length account id (>64 chars)",
        v,
    ));

    // ---- rpc: protocol resilience -------------------------------------------
    a.push(Attack::call(
        "rpc",
        "unknown method",
        "sov_thisMethodDoesNotExist",
        json!({}),
    ));
    // ~1 MB of junk as the params — must be bounded/rejected, never a hang or crash.
    a.push(Attack::submit_raw(
        "rpc",
        "oversized request body (~1MB)",
        json!("x".repeat(1_000_000)),
    ));

    a
}

// ── firing + verdict ─────────────────────────────────────────────────────────

/// Trim a node error to one tidy line.
fn trim(s: &str) -> String {
    let first = s.trim().lines().next().unwrap_or("").trim();
    let first = first.strip_prefix("rejected: ").unwrap_or(first);
    if first.chars().count() > 130 {
        let cut: String = first.chars().take(129).collect();
        format!("{cut}…")
    } else {
        first.to_string()
    }
}

/// Judge a submit/call result: an `Rpc` rejection is a DEFENSE (the door held);
/// an `Io` error is INFO (couldn't reach); an `Ok` means the payload was ADMITTED
/// — a real finding.
fn judge(
    category: &'static str,
    name: &'static str,
    res: Result<Value, RpcClientError>,
) -> AttackOutcome {
    let (verdict, detail) = match res {
        Err(RpcClientError::Rpc { message, .. }) => {
            (Verdict::Defended, format!("REJECTED — {}", trim(&message)))
        }
        Err(RpcClientError::Io(e)) => (Verdict::Info, format!("could not reach node: {e}")),
        Err(e) => (
            Verdict::Defended,
            format!("REJECTED — {}", trim(&e.to_string())),
        ),
        Ok(_) => (
            Verdict::Vulnerable,
            "ADMITTED to the mempool — the door did not reject it".to_string(),
        ),
    };
    AttackOutcome {
        category,
        name,
        verdict,
        detail,
    }
}

/// Fire one attack at the node and judge the answer.
fn fire(client: &RpcClient, attack: &Attack) -> AttackOutcome {
    let res = match &attack.payload {
        Payload::Signed(stx) => client.submit_transaction(stx).map(|h| json!(h.to_hex())),
        Payload::Call { method, params } => client.call(method, params.clone()),
    };
    judge(attack.category, attack.name, res)
}

/// The full result of pointing the battery at a node.
#[derive(Clone, Debug, Default)]
pub struct ProbeReport {
    /// The `host:port` targeted.
    pub target: String,
    /// True once a `sov_getHeight` answered — we are talking to a live node.
    pub reachable: bool,
    /// The node's chain id, if it reported one.
    pub chain_id: Option<String>,
    /// True if the chain id names mainnet.
    pub is_mainnet: bool,
    /// True if the battery was BLOCKED by the mainnet guard (mainnet, unconfirmed):
    /// no attack was fired, so there is nothing to pass or fail.
    pub blocked: bool,
    /// Mempool size before the battery (residue baseline).
    pub mempool_before: Option<usize>,
    /// Mempool size after the battery — must equal `mempool_before`.
    pub mempool_after: Option<usize>,
    /// One outcome per attack.
    pub outcomes: Vec<AttackOutcome>,
}

impl ProbeReport {
    /// The probe left NO residue in the mempool (before == after). Unknown sizes
    /// (a node that would not answer `sov_getMempoolSize`) do not fabricate a pass.
    pub fn no_residue(&self) -> bool {
        match (self.mempool_before, self.mempool_after) {
            (Some(before), Some(after)) => after <= before,
            _ => false,
        }
    }

    /// Count of each verdict across the fired attacks.
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut defended = 0;
        let mut vulnerable = 0;
        let mut info = 0;
        for o in &self.outcomes {
            match o.verdict {
                Verdict::Defended => defended += 1,
                Verdict::Vulnerable => vulnerable += 1,
                Verdict::Info => info += 1,
            }
        }
        (defended, vulnerable, info)
    }

    /// The battery PASSED: it actually ran, every attack drew an explicit
    /// rejection (no vulnerable, no unreached), and the mempool did not grow.
    pub fn passed(&self) -> bool {
        if self.blocked || !self.reachable || self.outcomes.is_empty() {
            return false;
        }
        let (defended, vulnerable, info) = self.counts();
        vulnerable == 0 && info == 0 && defended == self.outcomes.len() && self.no_residue()
    }

    /// A residue was detected — the LOUD failure the operator must see: the pool
    /// grew across the battery, so something was admitted.
    pub fn residue_detected(&self) -> bool {
        matches!(
            (self.mempool_before, self.mempool_after),
            (Some(before), Some(after)) if after > before
        )
    }
}

/// Point the battery at `client`'s node and run it, honoring the mainnet guard.
///
/// `confirmed` is the operator's typed mainnet confirmation (see
/// [`confirmation_ok`]); it is consulted ONLY when the target is mainnet. On a
/// mainnet node without confirmation the battery does not fire a single payload —
/// the report comes back `blocked`, with the identity it detected so the UI can
/// prompt for confirmation.
pub fn run_probe(client: &RpcClient, target: String, confirmed: bool) -> ProbeReport {
    let reachable = client.height().is_ok();
    let chain_id = client.chain_id().ok();
    let is_mainnet = chain_id.as_deref().map(is_mainnet).unwrap_or(false);

    let mut report = ProbeReport {
        target,
        reachable,
        chain_id,
        is_mainnet,
        ..ProbeReport::default()
    };

    if !reachable {
        return report;
    }

    // The mainnet guard: refuse to fire hostile bytes at the live chain without an
    // explicit typed confirmation. Nothing is submitted on the blocked path.
    if !may_fire(is_mainnet, confirmed) {
        report.blocked = true;
        return report;
    }

    report.mempool_before = client.mempool_size().ok();
    for attack in battery() {
        report.outcomes.push(fire(client, &attack));
    }
    report.mempool_after = client.mempool_size().ok();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- mainnet guard --------------------------------------------------

    #[test]
    fn mainnet_is_detected_from_the_chain_id() {
        assert!(is_mainnet("sov-mainnet"));
        assert!(is_mainnet("mainnet"));
        assert!(!is_mainnet("sov-testnet"));
        assert!(!is_mainnet("sov-dev"));
        assert!(!is_mainnet("sov-testnet-1"));
    }

    #[test]
    fn guard_blocks_unconfirmed_mainnet_only() {
        // Non-mainnet: always allowed, confirmation irrelevant.
        assert!(may_fire(false, false));
        assert!(may_fire(false, true));
        // Mainnet: only with confirmation.
        assert!(!may_fire(true, false));
        assert!(may_fire(true, true));
    }

    #[test]
    fn confirmation_phrase_must_match_exactly() {
        assert!(confirmation_ok(MAINNET_CONFIRM_PHRASE));
        assert!(confirmation_ok("  FIRE ON MAINNET  ")); // trimmed
        assert!(!confirmation_ok("fire on mainnet")); // case matters
        assert!(!confirmation_ok("FIRE"));
        assert!(!confirmation_ok(""));
    }

    // ---- the battery is live: attacks are genuinely corrupt -------------

    #[test]
    fn the_base_transaction_is_valid_before_corruption() {
        // Liveness of the fixture: the un-corrupted base MUST verify and be a
        // proper self-certifying transfer — otherwise the attacks below would be
        // "rejected" for the wrong reason and prove nothing.
        let b = base(9);
        assert!(b.verify_signature(), "base tx must verify before tampering");
        assert_eq!(
            b.transaction.signer,
            b.transaction.public_key.implicit_account_id(),
            "base tx must be self-certifying"
        );
    }

    #[test]
    fn tampering_each_half_breaks_verification() {
        // Ed25519 half.
        let mut s = base(9);
        assert!(s.verify_signature());
        s.signature = tamper_signature(s.signature, Half::Ed25519);
        assert!(!s.verify_signature(), "forged Ed25519 half must not verify");

        // Post-quantum half only — the conjunction still fails closed.
        let mut s = base(10);
        s.signature = tamper_signature(s.signature, Half::MlDsa);
        assert!(
            !s.verify_signature(),
            "forged ML-DSA half must not verify (hybrid is an AND)"
        );

        // Both halves.
        let mut s = base(11);
        s.signature = tamper_signature(tamper_signature(s.signature, Half::Ed25519), Half::MlDsa);
        assert!(!s.verify_signature());
    }

    #[test]
    fn downgrade_to_ed25519_only_does_not_verify_against_a_hybrid_key() {
        let mut s = base(13);
        assert!(s.verify_signature());
        s.signature = Signature::V1Ed25519(ed_half(&s.signature));
        assert!(
            !s.verify_signature(),
            "an Ed25519-only sig must not pass for a hybrid key"
        );
    }

    #[test]
    fn wrong_key_spend_is_signed_but_not_self_certifying() {
        // The wrong-key attack: the signature is VALID (the key signed its own
        // public_key), but the declared account is not that key's account — the
        // property the node's authorization must catch.
        let s = signed(3, 4, 0, 1);
        assert!(s.verify_signature(), "the signature itself is valid");
        assert_ne!(
            s.transaction.signer,
            s.transaction.public_key.implicit_account_id(),
            "the spent account is NOT the signing key's own account"
        );
    }

    #[test]
    fn spliced_and_tampered_nonce_replays_do_not_verify() {
        // Splice: a signature valid for nonce 7 pasted onto a nonce-0 tx.
        let donor = signed(14, 14, 7, 3);
        let mut victim = signed(14, 14, 0, 1);
        assert!(victim.verify_signature());
        victim.signature = donor.signature;
        assert!(
            !victim.verify_signature(),
            "spliced signature must not verify"
        );

        // Tampered nonce: mutate the body after signing.
        let mut s = base(15);
        assert!(s.verify_signature());
        s.transaction.nonce = s.transaction.nonce.wrapping_add(1);
        assert!(
            !s.verify_signature(),
            "a nonce changed after signing must not verify"
        );
    }

    #[test]
    fn raw_value_and_encoding_payloads_do_not_deserialize() {
        // Every raw `sov_submitTransaction` attack must fail to decode into a
        // SignedTransaction — that is what makes it rejected at the parser, before
        // admission, with no residue. We assert the corruption actually landed.
        let mut checked = 0;
        for a in battery() {
            if let Payload::Call { method, params } = &a.payload {
                if *method != "sov_submitTransaction" {
                    continue; // the unknown-method probe targets a different method
                }
                let decoded: Result<SignedTransaction, _> = serde_json::from_value(params.clone());
                assert!(
                    decoded.is_err(),
                    "attack '{}' must NOT decode to a valid SignedTransaction",
                    a.name
                );
                checked += 1;
            }
        }
        assert!(
            checked >= 6,
            "expected several raw submit attacks, got {checked}"
        );
    }

    #[test]
    fn a_pristine_base_would_decode_so_the_corruption_is_what_breaks_it() {
        // Control: the UN-corrupted base DOES decode — proving the failures above
        // come from the deliberate corruption, not from a wrong JSON shape.
        let valid = to_value(base(30)).unwrap();
        let decoded: Result<SignedTransaction, _> = serde_json::from_value(valid);
        assert!(decoded.is_ok(), "the pristine base must decode cleanly");
    }

    // ---- battery coverage -----------------------------------------------

    #[test]
    fn battery_covers_every_attack_class() {
        let b = battery();
        assert!(
            b.len() >= 12,
            "expected a substantial battery, got {}",
            b.len()
        );
        let cats: std::collections::HashSet<_> = b.iter().map(|a| a.category).collect();
        for expected in ["crypto", "authz", "replay", "value", "encoding", "rpc"] {
            assert!(cats.contains(expected), "battery missing class {expected}");
        }
    }

    // ---- no-residue + pass/fail verdict ---------------------------------

    fn defended(n: usize) -> Vec<AttackOutcome> {
        (0..n)
            .map(|_| AttackOutcome {
                category: "crypto",
                name: "x",
                verdict: Verdict::Defended,
                detail: String::new(),
            })
            .collect()
    }

    #[test]
    fn passes_only_when_it_ran_defended_everything_and_left_no_residue() {
        let ok = ProbeReport {
            reachable: true,
            mempool_before: Some(42),
            mempool_after: Some(42),
            outcomes: defended(16),
            ..ProbeReport::default()
        };
        assert!(ok.no_residue());
        assert!(ok.passed());
        assert!(!ok.residue_detected());
    }

    #[test]
    fn residue_is_a_loud_failure_never_a_pass() {
        let grew = ProbeReport {
            reachable: true,
            mempool_before: Some(10),
            mempool_after: Some(11), // something landed
            outcomes: defended(16),
            ..ProbeReport::default()
        };
        assert!(!grew.no_residue());
        assert!(!grew.passed());
        assert!(grew.residue_detected());
    }

    #[test]
    fn a_single_vulnerable_or_unreached_attack_fails_the_run() {
        let mut outcomes = defended(15);
        outcomes.push(AttackOutcome {
            category: "crypto",
            name: "x",
            verdict: Verdict::Vulnerable,
            detail: String::new(),
        });
        let vuln = ProbeReport {
            reachable: true,
            mempool_before: Some(1),
            mempool_after: Some(1),
            outcomes,
            ..ProbeReport::default()
        };
        assert!(vuln.no_residue()); // pool didn't grow…
        assert!(!vuln.passed()); // …but an attack was admitted ⇒ fail
        let (_, vulnerable, _) = vuln.counts();
        assert_eq!(vulnerable, 1);

        // An unreached attack (Info) also blocks a pass — the battery is incomplete.
        let mut outcomes = defended(15);
        outcomes.push(AttackOutcome {
            category: "rpc",
            name: "x",
            verdict: Verdict::Info,
            detail: String::new(),
        });
        let partial = ProbeReport {
            reachable: true,
            mempool_before: Some(1),
            mempool_after: Some(1),
            outcomes,
            ..ProbeReport::default()
        };
        assert!(!partial.passed());
    }

    #[test]
    fn a_blocked_or_unreachable_report_never_passes() {
        let blocked = ProbeReport {
            reachable: true,
            is_mainnet: true,
            blocked: true,
            ..ProbeReport::default()
        };
        assert!(!blocked.passed());

        let unreachable = ProbeReport {
            reachable: false,
            ..ProbeReport::default()
        };
        assert!(!unreachable.passed());

        // Unknown mempool sizes must not fabricate a "no residue" pass.
        let unknown = ProbeReport {
            reachable: true,
            mempool_before: None,
            mempool_after: None,
            outcomes: defended(16),
            ..ProbeReport::default()
        };
        assert!(!unknown.no_residue());
        assert!(!unknown.passed());
    }
}
