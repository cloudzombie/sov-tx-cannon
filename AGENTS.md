# SOV TX Cannon repository boundary

This repository owns only the standalone SOV TX Cannon operator tool.

## The boundary

- **This repository never modifies SOV.** Work only inside this repository.
  Never edit, stage, commit, push, or run a write-capable tool against
  `cloudzombie/sov` or any sibling repository from a TX Cannon task.
- If a TX Cannon change appears to require a chain change, **stop and ask the
  user to authorize a separate task in the `sov` repository**. Do not cross the
  boundary from here.
- Never add a local path dependency, symlink, submodule, or workspace
  membership pointing into a SOV checkout. The chain crates are consumed only as
  the tagged git dependencies in `Cargo.toml`.

## The chain dependency pin

TX Cannon signs real transactions, so it deliberately uses the chain's real
signing code instead of a copy. Four crates — `sov-rpc`, `sov-crypto`,
`sov-types`, `sov-primitives` — are pinned by **tag** to a released SOV version.

- **Never** reimplement, vendor, copy, or stub keystore, signing, key-derivation,
  account-id, signing-domain, or codec logic in this crate. That would be a real
  downgrade in safety, not a simplification.
- **Never** pin to a branch, to `main`, or to a bare revision without a tag.
- Keep all four crates on the **same** tag.
- Bumping the tag is a deliberate, reviewed change. Follow the procedure in
  README.md ("Bumping the pin"), change all four stanzas plus `Cargo.lock` (and
  `rust-toolchain.toml` if the chain release moved the toolchain) in one commit,
  and re-verify against a live node — a signing-domain change is invisible to
  the compiler.

## Code rules

- `#![forbid(unsafe_code)]` stays. Do not add a native boundary.
- The master passphrase and every signing seed stay in `zeroize` buffers, are
  wiped on drop or on lock, and are never logged, persisted, or transmitted.
- Deterministic decision logic (nonce sequencing, pacing, reject
  classification, metering, destination and amount selection, and all
  presentation arithmetic) lives in `src/logic.rs` and stays unit-tested there.
  Do not move arithmetic into the drawing code, where it could divide by zero,
  produce `NaN`, or reach egui's geometry unbounded.
- Nonces must remain strictly monotonic and gap-free, reconciled against the
  node, and committed only when consumed.

## Required local gate before pushing

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release
```

CI runs the same four steps on `ubuntu-24.04` and Apple Silicon `macos-15`. The
owner runs Apple Silicon; the macOS leg is not optional.

## Releases

Do not create, move, or delete a tag in this repository. There is no release
process here yet; establishing one is a separate, explicitly authorized task.
