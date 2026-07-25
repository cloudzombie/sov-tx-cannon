# Security policy

The supported code is the latest commit on `main`.

Report suspected vulnerabilities through GitHub's private vulnerability
reporting for `cloudzombie/sov-tx-cannon`. Include the platform, the tool
version, the pinned SOV chain tag from `Cargo.toml`, and a minimal reproduction.

**Never include a wallet seed, a keystore file, a master passphrase, or any
private key in a report.** Nothing about this tool requires them from you, and
the maintainers will not ask for them. Strip account identifiers, LAN addresses,
and unrelated logs.

## What this tool holds

TX Cannon is a *signing* tool. It unlocks a real SOV Station keystore and
produces real, spendable transactions. Its security posture is therefore about
key material in memory and about not spending what you did not mean to spend.

- `#![forbid(unsafe_code)]` at the crate root. There is no native boundary and
  no allowance for one.
- The **master passphrase** is held in a `zeroize::Zeroizing<String>` and is
  explicitly `zeroize()`d as soon as the keystore has been decrypted, and again
  on lock. It is never written to disk, never placed in a config file, never
  included in a log line or an error message, and never sent over the network.
- Every **wallet signing seed** is held in a `Zeroizing<[u8; 32]>`. Each firing
  worker gets its own zeroizing copy, and that copy is wiped when the worker's
  config drops as the worker exits. Locking the tool drops every unlocked
  wallet, wiping its seed.
- **No key material ever goes on the wire.** The tool signs locally and submits
  only the already-signed transaction, over the same key-free JSON-RPC surface
  any wallet uses. The node never sees a seed or a passphrase.
- **No reimplemented cryptography.** Keystore decryption, key derivation,
  account-id derivation, transaction encoding, signing domains, and signature
  construction all come from the pinned SOV chain crates (`sov-rpc`,
  `sov-crypto`, `sov-types`, `sov-primitives`). This crate contains no
  substitute for any of it. The account id a wallet fires from is *derived from
  its seed*, never taken from the keystore's display label.
- The crate's own PRNG (a small xorshift used to pick a destination and an
  amount in random modes) is **not** used for any key, nonce-secret, or
  signature material, and is documented as such at its definition.

## Operational cautions

- Every transaction this tool submits is real. On mainnet it spends real XUS
  and pays real fees, and it cannot be undone. Confirm the endpoint before you
  start firing.
- The JSON-RPC connection is plaintext HTTP. Use it against a local node or
  across a trusted LAN, or tunnel it — do not send a keystore-signed traffic
  run across the public Internet in the clear.
- Recycle mode confines destinations to the unlocked wallets so value cannot
  leave the set, but fees still leave. It bounds the loss, it does not remove
  it.

## Change classes that require extra scrutiny

Keystore loading and decryption, seed handling and zeroization, signing-domain
selection, nonce sequencing, reject classification, the chain dependency pin,
`Cargo.lock`, `rust-toolchain.toml`, and the GitHub workflows. All of these must
pass fmt, clippy `-D warnings`, the full test suite, and a release build on both
CI platforms before merge.

## Releases

There is no binary release channel for this tool today; it is built from source.
Introducing one — signed tags, checksummed artifacts, provenance attestation —
is a separate, explicitly scoped task, and until it exists no tag in this
repository should be treated as a distribution artifact.
