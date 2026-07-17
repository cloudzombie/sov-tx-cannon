//! Pure, deterministic traffic-generation logic — no GUI, no network.
//!
//! Everything the "TX cannon" decides before it touches the wire lives here so it
//! can be unit-tested in isolation:
//!   * [`NonceSequencer`] — strictly monotonic, gap-free, never-reused nonces,
//!     reconciled against the node each block.
//!   * [`DestSelector`] — round-robin or random choice over the destination list.
//!   * [`AmountMode`] — a fixed value or a uniform draw in `[min, max]` inclusive.
//!   * [`build_signed_transfer`] — reuses the chain's real `SignedTransaction::sign`
//!     (no reimplemented crypto) to produce a verifiable transfer.
//!   * [`DecodedWallet`] / [`decode_keystore`] / [`merge_wallets`] — turn keystore
//!     entries into spendable wallets keyed by the **seed-derived on-chain id**
//!     (never the display label), deduplicated across merged keystore files.
//!
//! Secret hygiene: seeds decoded here go straight into `Zeroizing` buffers; the
//! signing seed is otherwise passed in by the caller only for the duration of a
//! single [`build_signed_transfer`] call. Nothing secret is retained or logged.

use sov_crypto::Keypair;
use sov_primitives::{AccountId, Balance};
use sov_rpc::Keystore;
use sov_types::{Action, SignedTransaction, Transaction};
use zeroize::Zeroizing;

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

    /// The nonce that would be handed out next (for display/tests).
    pub fn peek(&self) -> u64 {
        self.pending
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

/// Derive the wallet's REAL on-chain account id from its signing seed — the
/// implicit (key-derived) id, exactly as the node and SOV-Station compute it:
/// `Keypair::{from_seed|hybrid_from_seed}(seed).public_key().implicit_account_id()`.
///
/// The keystore's `account` field is a DISPLAY LABEL, never an on-chain id;
/// balances, nonces, and the tx `signer` must all use this derived id.
pub fn derive_account_id(seed: &[u8; 32], scheme: KeyScheme) -> AccountId {
    scheme
        .keypair_from_seed(seed)
        .public_key()
        .implicit_account_id()
    // The transient keypair drops here; the caller retains only the seed.
}

/// One spendable wallet decoded from a keystore entry.
///
/// `account` is always the seed-derived implicit id ([`derive_account_id`]);
/// `label` is the keystore's human display string, shown alongside it in the UI.
/// The seed lives in a `Zeroizing` buffer, wiped when the wallet drops.
pub struct DecodedWallet {
    pub label: String,
    pub account: AccountId,
    pub scheme: KeyScheme,
    pub seed: Zeroizing<[u8; 32]>,
}

/// Decode a keystore's entries into spendable wallets keyed by their DERIVED
/// on-chain id. Watch-only entries (no seed), undecodable seeds, and unknown
/// schemes are skipped — they cannot sign. Transient seed copies are wiped.
pub fn decode_keystore(ks: &Keystore) -> Vec<DecodedWallet> {
    let mut out = Vec::new();
    for (i, entry) in ks.miners.iter().enumerate() {
        // Watch-only: empty seed, public key only. Cannot sign — skip.
        if entry.seed_hex.trim().is_empty() {
            continue;
        }
        let Ok(scheme) = KeyScheme::from_keystore(entry.scheme.as_deref()) else {
            continue;
        };
        let Ok(mut seed_bytes) = hex::decode(entry.seed_hex.trim()) else {
            continue;
        };
        let seed_arr: [u8; 32] = match seed_bytes.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => {
                wipe_bytes(&mut seed_bytes);
                continue;
            }
        };
        // Move the seed into a zeroizing buffer, then wipe the transient copy.
        let seed = Zeroizing::new(seed_arr);
        wipe_bytes(&mut seed_bytes);
        // The REAL on-chain id comes from the seed, NOT the label.
        let account = derive_account_id(&seed, scheme);
        let label = if entry.account.trim().is_empty() {
            format!("wallet #{i}")
        } else {
            entry.account.trim().to_string()
        };
        out.push(DecodedWallet {
            label,
            account,
            scheme,
            seed,
        });
    }
    out
}

/// Merge `extra` wallets into `wallets`, deduplicating by DERIVED account id
/// (the same key in two files is the same wallet, whatever its labels say).
/// Duplicates drop here, wiping their `Zeroizing` seeds.
pub fn merge_wallets(wallets: &mut Vec<DecodedWallet>, extra: Vec<DecodedWallet>) {
    for w in extra {
        if wallets.iter().any(|x| x.account == w.account) {
            continue; // duplicate key → its Zeroizing seed wipes on drop
        }
        wallets.push(w);
    }
}

/// Best-effort overwrite of a transient secret byte buffer before it is freed.
fn wipe_bytes(v: &mut Vec<u8>) {
    for b in v.iter_mut() {
        *b = 0;
    }
    v.clear();
}

/// Short display form of an account id: `a35755d3…4c1e24`.
pub fn short_account(a: &AccountId) -> String {
    let s = a.as_str();
    if s.len() > 16 {
        format!("{}…{}", &s[..8], &s[s.len() - 6..])
    } else {
        s.to_string()
    }
}

/// Build and sign a transparent transfer using the chain's real signing path.
///
/// The seed is used only to derive a transient [`Keypair`] for this one signature.
/// Returns the signed transaction, whose signature is guaranteed to verify (the
/// public key committed in the tx is the one that signed it).
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

    // ---- Account-id derivation (Bug 2 regression guards) -----------------

    #[test]
    fn derived_id_matches_the_node_derivation_and_is_not_the_label() {
        // The exact path the node/SOV-Station uses for the default scheme:
        // hybrid_from_seed(seed).public_key().implicit_account_id().
        let seed = [7u8; 32];
        let expected = Keypair::hybrid_from_seed(seed)
            .public_key()
            .implicit_account_id();
        let got = derive_account_id(&seed, KeyScheme::Hybrid65);
        assert_eq!(got, expected, "tool must derive the id the node derives");
        // …and NEVER a display label.
        assert_ne!(got, acct("my-wallet.sov"));
        // The implicit id is 64 lowercase hex chars.
        assert_eq!(got.as_str().len(), 64);
        assert!(got.as_str().chars().all(|c| c.is_ascii_hexdigit()));

        // Ed25519 scheme follows its own derivation and differs from hybrid.
        let ed_expected = Keypair::from_seed(seed).public_key().implicit_account_id();
        let ed_got = derive_account_id(&seed, KeyScheme::Ed25519);
        assert_eq!(ed_got, ed_expected);
        assert_ne!(ed_got, got, "schemes must derive distinct ids");
    }

    #[test]
    fn keystore_wallets_are_keyed_by_derived_id_not_label() {
        // Entries whose `account` fields are LABELS (what SOV-Station saves).
        let seed_a = [1u8; 32];
        let seed_b = [2u8; 32];
        let ks = Keystore {
            miners: vec![
                sov_rpc::KeystoreEntry {
                    account: "my-wallet".into(), // display label, NOT an id
                    seed_hex: hex::encode(seed_a),
                    scheme: Some("hybrid65".into()),
                    mnemonic: None,
                    public_key: None,
                },
                sov_rpc::KeystoreEntry {
                    account: "legacy".into(),
                    seed_hex: hex::encode(seed_b),
                    scheme: None, // absent = ed25519, matching the node
                    mnemonic: None,
                    public_key: None,
                },
                // Watch-only: no seed → must be skipped, cannot sign.
                sov_rpc::KeystoreEntry {
                    account: "watch".into(),
                    seed_hex: String::new(),
                    scheme: Some("hybrid65".into()),
                    mnemonic: None,
                    public_key: Some("hybrid65:0xdead".into()),
                },
            ],
        };
        let wallets = decode_keystore(&ks);
        assert_eq!(wallets.len(), 2, "watch-only entries are skipped");

        let expect_a = Keypair::hybrid_from_seed(seed_a)
            .public_key()
            .implicit_account_id();
        let expect_b = Keypair::from_seed(seed_b)
            .public_key()
            .implicit_account_id();
        assert_eq!(wallets[0].account, expect_a);
        assert_eq!(wallets[1].account, expect_b);
        // The labels survive for display but are NOT the account.
        assert_eq!(wallets[0].label, "my-wallet");
        assert_eq!(wallets[1].label, "legacy");
        assert_ne!(wallets[0].account.as_str(), "my-wallet");
        assert_ne!(wallets[1].account.as_str(), "legacy");
        // And the retained seed still signs as that derived account.
        let stx = build_signed_transfer(
            &wallets[0].seed,
            wallets[0].scheme,
            &wallets[0].account,
            &acct("target.sov"),
            1,
            0,
        )
        .unwrap();
        assert!(stx.verify_signature());
        assert_eq!(stx.transaction.signer, expect_a);
    }

    #[test]
    fn merging_keystores_dedups_by_derived_id() {
        let seed_a = [9u8; 32];
        let seed_b = [10u8; 32];
        let entry = |label: &str, seed: [u8; 32]| sov_rpc::KeystoreEntry {
            account: label.into(),
            seed_hex: hex::encode(seed),
            scheme: Some("hybrid65".into()),
            mnemonic: None,
            public_key: None,
        };
        // Auto-store has A; the backup has the SAME key under a different label
        // plus a genuinely different key B.
        let auto = Keystore {
            miners: vec![entry("main", seed_a)],
        };
        let backup = Keystore {
            miners: vec![entry("main-backup-copy", seed_a), entry("second", seed_b)],
        };
        let mut wallets = decode_keystore(&auto);
        merge_wallets(&mut wallets, decode_keystore(&backup));
        assert_eq!(wallets.len(), 2, "same key must appear once");
        assert_eq!(wallets[0].label, "main", "first-seen label wins");
        assert_eq!(
            wallets[1].account,
            Keypair::hybrid_from_seed(seed_b)
                .public_key()
                .implicit_account_id()
        );
    }

    #[test]
    fn short_account_abbreviates_long_ids_only() {
        let long = derive_account_id(&[4u8; 32], KeyScheme::Hybrid65);
        let short = short_account(&long);
        assert!(short.len() < long.as_str().len());
        assert!(short.contains('…'));
        assert!(long.as_str().starts_with(&short[..8]));
        assert_eq!(short_account(&acct("bob.sov")), "bob.sov");
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
