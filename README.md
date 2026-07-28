# SOV TX Cannon

`sov-tx-cannon` is a standalone native desktop tool that generates **real
transaction traffic** on a SOV network. It unlocks wallets from a SOV Station
keystore, watches the chain tip over JSON-RPC, and fires signed transparent
transfers at a rate you choose — so you can measure what a node, a mempool, and
the block-space auction actually do under load, with real transactions rather
than a simulation.

> **This tool spends real XUS.** Every transaction it submits is a genuine
> signed transfer from a real account, indistinguishable on-chain from one sent
> by a wallet. On mainnet the fees are real and the sends are irreversible.
> Point it at a dev/test network unless you specifically intend otherwise, and
> read [Closed-loop recycle mode](#closed-loop-recycle-mode) first.

This is an independent repository. It is not part of the SOV workspace. It
consumes the SOV chain crates as **pinned git dependencies** — see
[Chain dependency pin](#chain-dependency-pin) — and never modifies them. The
repository boundary is stated in [AGENTS.md](AGENTS.md).

## What it does

- **Unlocks SOV Station's own keystore.** It reads `~/.sov-station/wallets.auto`
  (SOV Station's primary auto-loaded store) and, as a fallback, the
  `~/.sov-station/wallets.keystore` backup, merging both and deduping by the
  account id *derived from the seed* — the keystore's `account` label is treated
  as display text only, never as authority.
- **Signs with the chain's own code.** Transactions are built and signed through
  the real `sov-types` / `sov-crypto` `SignedTransaction::sign`, including the
  tx-domain (`SigningDomain`) the node reports via `sov_getSigningDomain`. There
  is **no reimplemented crypto, keystore, id, or codec logic in this crate** —
  that is the single most important property of this tool and it is enforced by
  the dependency pin, not by convention.
- **Three rate modes.**
  - *Per block* — fire N transactions on each new chain tip.
  - *Target TX/s* — a paced, block-independent rate (cumulative-due scheduler
    with bounded catch-up).
  - *Firehose* — submit as fast as sign-and-POST allows; mempool capacity
    rejections are the only brake, and the cannon holds and retries the **same**
    nonce on those, self-pacing to the node's drain rate.
- **Blockspace-auction tips.** Optionally attach a priority tip to each
  transaction (SOV v0.1.98 `Action::Tipped`), fixed or drawn from a range so a
  fleet spreads a realistic spectrum of bids across the dynamic fee floor. The
  tip is **only** attached when the node reports the `fee-auction` deployment
  `Active` (queried via `sov_getDeployments`, exactly as SOV Station gates the
  envelope); while the fork is dormant the cannon emits a byte-identical untipped
  transaction, so the same configuration is safe across the activation.
- **Parallel wallets.** One worker per unlocked wallet, each with its own
  gap-free nonce sequencer and its own zeroizing copy of the signing seed.
- **Live operator telemetry.** Attempted / accepted / rejected per second, a
  rejection breakdown mapped from the node's real reject strings, mempool depth
  with a saturation flag, a rolling throughput scope, and the network id the node
  reports (mainnet is flagged in the caution color).
- **"Prove the defenses hold" adversarial mode.** A dedicated one-shot battery
  that fires HOSTILE, malformed transactions at the node over
  `sov_submitTransaction` and proves each is refused *before* admission — see
  [Adversarial mode](#adversarial-mode).

It only READS chain state and SUBMITS already-signed transactions over the same
key-free RPC surface any wallet uses. It touches no consensus, mining,
block-encoding, or genesis code.

### Closed-loop recycle mode

Recycle mode restricts destinations to the unlocked wallets themselves, so value
circulates among accounts you control and no XUS can leave the set. Fees are
still spent (they go to miners), so the closed loop drains slowly at the fee
rate; it is a containment property, not a perpetual-motion machine.

### Adversarial mode

The **Prove the defenses hold** panel fires a fixed battery of deliberately
hostile transactions at the target node and proves the node rejects every one
*before admission* — the mempool must not grow. It reuses the cannon's own
construction and signing path with one deliberate corruption per attack, so it
adds no dependency on the chain's red-team crate. The classes mirror the chain's
own live-fire probe:

- **crypto** — a tampered Ed25519 half, a tampered post-quantum (ML-DSA-65) half
  *with the Ed25519 half left valid* (the hybrid signature is a conjunction, so
  this must still fail), both halves forged, and a downgrade to an Ed25519-only
  signature against a hybrid key.
- **authz** — spending an implicit account with the wrong key, and spending from
  a keyless named account nobody controls.
- **replay** — splicing a signature valid for a different nonce, and mutating the
  nonce after signing: a signed authorization cannot be re-bound to another nonce.
- **value** — a negative amount and an amount past the `u128` grain ceiling, both
  refused at the parser (so they leave no residue regardless of admission gates).
- **encoding / rpc** — a non-numeric nonce, a missing signature, an over-length
  account id, an unknown RPC method, and a ~1 MB body: the node rejects cleanly
  and keeps serving.

The load-bearing verdict is **no residue**: the battery records
`sov_getMempoolSize` before and after and PASSes only if the pool did not grow
**and** every attack drew an explicit rejection. If the pool grows, that is a
loud failure, never a silent pass.

> **Mainnet guard.** These are deliberately hostile bytes, and one payload in
> this family was once a live crash-DoS before it was patched. When the target
> reports a mainnet chain id the battery will **not** fire until you type the
> exact confirmation phrase (`FIRE ON MAINNET`); it is off and guarded by
> default. Every attack is engineered to be rejected for a reason independent of
> chain state, so none can be admitted regardless of balances or nonces.

## Build and run

```sh
git clone https://github.com/cloudzombie/sov-tx-cannon.git
cd sov-tx-cannon
cargo build --locked --release
./target/release/sov-tx-cannon
```

The pinned toolchain is in `rust-toolchain.toml` (Rust 1.97.0); `rustup` picks it
up automatically.

**Build prerequisites.** The pinned chain crates pull in SOV's RandomX proof-of-work
crate, which builds native C/C++ code, so a C/C++ toolchain and **CMake** must be
on `PATH`. On Debian/Ubuntu the tool additionally needs the standard `egui`
X11/Wayland development packages to link the native GUI. CI installs exactly
these — see [.github/workflows/ci.yml](.github/workflows/ci.yml) for the
authoritative list.

In the GUI: set the node RPC endpoint (default `127.0.0.1:8645`), enter your SOV
Station **master passphrase** to unlock the keystore, pick the wallets to fire
from, set destinations, amount mode, and rate mode, then start.

## Chain dependency pin

Unlike a wallet-free tool, TX Cannon must sign real transactions, so it uses the
chain's real signing code rather than a copy of it. `Cargo.toml` therefore depends
on four SOV chain crates:

```toml
sov-rpc = { git = "https://github.com/cloudzombie/sov", tag = "v0.2.0" }
sov-crypto = { git = "https://github.com/cloudzombie/sov", tag = "v0.2.0" }
sov-types = { git = "https://github.com/cloudzombie/sov", tag = "v0.2.0" }
sov-primitives = { git = "https://github.com/cloudzombie/sov", tag = "v0.2.0" }
```

Rules for this pin:

- **Pin by tag, never by branch or `main`.** A branch pin would silently change
  the signing rules this tool applies. A tag is a released, reviewed consensus
  surface.
- **All four crates stay on the same tag.** Mixing tags can produce a
  type-compatible but semantically inconsistent signer.
- **Never replace the pin with a path dependency, submodule, or vendored copy.**
  Copying signing, keystore, id, or codec code into this repository would be a
  real downgrade in safety and is prohibited by [AGENTS.md](AGENTS.md).
- **`Cargo.lock` is committed and CI builds `--locked`,** so the exact chain
  commit behind the tag is recorded and cannot drift.

### Bumping the pin

Bumping to a newer SOV release is a deliberate, reviewed step, not routine
maintenance — a chain release can change the transaction domain, the signature
scheme set, the keystore format, or reject strings, all of which this tool
depends on. The procedure:

1. Confirm the target tag exists in `cloudzombie/sov` and is a real release.
2. Change the tag on **all four** stanzas in `Cargo.toml` in one commit.
3. If the chain release moved the Rust toolchain, update `rust-toolchain.toml`
   in the same commit.
4. `cargo update -p sov-rpc -p sov-crypto -p sov-types -p sov-primitives` and
   commit the resulting `Cargo.lock`.
5. Run the full local gate (below) and re-verify against a live node that a
   transaction actually lands — a signing-domain change is invisible to the
   compiler and shows up only as on-chain rejections.

## Local gate

Run all of this before pushing:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release
```

CI runs the same four steps on Linux (`ubuntu-24.04`) and Apple Silicon
(`macos-15`).

## Releases

Releases are cut by pushing a version tag; the owner/coordinator does that, not
CI. The release is **Apple-Silicon-native**: the headline artifact is an arm64
macOS binary **built and tested on an Apple Silicon runner** (`macos-15`), never
cross-compiled. A Linux x86_64 build rides along but never gates the macOS one.

The release is **tag-only and version-guarded**. `.github/workflows/release.yml`
fires only on a `vX.Y.Z` tag (or a `workflow_dispatch` naming one) and refuses to
run unless the tag equals `Cargo.toml`'s `version` exactly — so a mis-versioned
tag cannot produce a release. CI checks the same contract on any tagged push.

Each artifact is a `.tar.gz` named `sov-tx-cannon-v<version>-<target>` with a
companion `.sha256` checksum, both attached to the GitHub Release for the tag.
The macOS job runs `cargo test --locked` on the arm64 runner before packaging,
so a published binary is one that passed its tests natively on Apple Silicon.

To cut a release:

1. Bump `version` in `Cargo.toml`, refresh `Cargo.lock` (`cargo update -p sov-tx-cannon`), and merge that through a PR.
2. Push a matching tag: `git tag v0.2.0 && git push origin v0.2.0`.
3. The release workflow builds, tests on arm64, packages, and publishes the
   assets. Do not create tags for unreleased or mismatched versions.

## Boundary

This repository never modifies SOV. If a TX Cannon change appears to require a
chain change, stop and raise it as a separate, explicitly authorized task in the
`cloudzombie/sov` repository. See [AGENTS.md](AGENTS.md).

## Security

See [SECURITY.md](SECURITY.md). In short: `#![forbid(unsafe_code)]`, the master
passphrase and every signing seed live only in `zeroize`-wiped buffers for the
session, nothing secret is written to disk or logged, and no key material ever
goes on the wire — only already-signed transactions do.

## License

Apache-2.0.
