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
- **Parallel wallets.** One worker per unlocked wallet, each with its own
  gap-free nonce sequencer and its own zeroizing copy of the signing seed.
- **Live operator telemetry.** Attempted / accepted / rejected per second, a
  rejection breakdown mapped from the node's real reject strings, mempool depth
  with a saturation flag, and a rolling throughput scope.
- **It drives the blockspace auction, not just throughput.** Each transaction can
  carry a priority tip — one fixed bid, or a *ladder* of bids in a single run —
  and the tool reports inclusion latency per bid, so "does inclusion order follow
  bid order?" is answerable from measurement rather than assumption.
- **It measures confirmation, not just acceptance.** Every accepted submission is
  followed to inclusion in a real block, with reorg detection: a transaction
  un-mined by a reorg is reported as un-mined, not left counted as confirmed.
- **It fires more than transfers.** A weighted action mix draws from the action
  kinds a traffic generator can build self-containedly, including one whose
  encoded size you dial directly — which is what probes the block-space cap
  rather than the transaction-count cap.

### The auction: bids, floors and replacement

The fee auction (v0.1.98) is mempool policy: a tip rides inside
`Action::Tipped`, is a pure signer→miner transfer, and an untipped transaction is
never rejected for bidding zero — it simply waits behind funded bids. The tool
mirrors the node's rules exactly rather than guessing them:

- **Tip ladder** (`src/auction.rs`) — bids drawn from ascending rungs,
  round-robin or random. Round-robin gives every rung the same population, which
  is what makes a latency comparison across rungs meaningful.
- **Floor discovery** — a ramp-down that turns accept/refuse answers into a
  *bracket* around the pool's dynamic floor: the highest bid refused and the
  lowest accepted. The floor moves while you probe, so a non-monotonic result is
  reported as inverted with an explanation instead of a fabricated number.
- **Replace-by-fee** — the node requires a strict outbid, and a bump of exactly
  `MIN_RBF_BUMP_GRAINS` (1,000) *does* replace: the comparison is `<`, not `<=`
  (`chain/crates/mempool/src/lib.rs:456-463`). The tool reproduces that boundary
  precisely, and a losing bid gets its own meter row rather than being buried in
  "other".

### Adversarial probes

Two probe families produce a **verdict**, not just a log line — and are
deliberately biased toward *inconclusive*, because this tool is pointed at a live
mainnet and a false accusation of a consensus bug is worse than an admission of
ignorance:

- **Nonce scenarios** (`src/adversary.rs`) — deliberately open a hole, submit out
  of order, replay a nonce. SOV's mempool is gap-free (there is no
  future/queued tier), so each step has an outcome the node MUST produce. Every
  probe is bracketed by two `sov_getNonce` reads so a third party spending from
  the same account cannot be mistaken for a node bug.
- **tx-domain A/B** — the 3×3 table over (activation phase × which domain the
  signature was framed under). One cell is non-negotiable: a **wrong-domain
  signature must be refused in every phase**. That assertion is phase-independent
  on purpose, so it stays meaningful even though no RPC currently exposes the
  grace-window length needed to distinguish Grace from Bound.

**Wiring status, stated plainly.** The tip ladder, the action mix and the
confirmation/latency tracking are wired end to end: configurable in the GUI,
driven by the worker, and reported live. The floor probe, the RBF plan, the
nonce scenarios and the tx-domain A/B table are complete, cited and unit-tested
decision surfaces that do not yet have their own GUI run mode — they are
consumed today by the classifier and the meters, not by a dedicated "probe" button.
Do not read this section as claiming a one-click probe run exists.

It only READS chain state and SUBMITS already-signed transactions over the same
key-free RPC surface any wallet uses. It touches no consensus, mining,
block-encoding, or genesis code.

### Closed-loop recycle mode

Recycle mode restricts destinations to the unlocked wallets themselves, so value
circulates among accounts you control and no XUS can leave the set. Fees are
still spent (they go to miners), so the closed loop drains slowly at the fee
rate; it is a containment property, not a perpetual-motion machine.

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
