---
paths:
  - ".github/workflows/*.yml"
  - "Cargo.toml"
  - "crates/*/Cargo.toml"
  - "deny.toml"
  - "crates/gmcrypto-core/tests/**"
---

# Features, manifests, CI wiring

## New opt-in feature → seven places; two fail late

`Cargo.toml` (dep + feature), `deny.toml`, `ci.yml` (test / clippy / MSRV /
wasm32), **`api-stability.yml` cargo-doc feature list** (missing = never
doc-checked), and a `[[test]]` with `required-features` needs its **own**
`ci.yml` leg (`cargo test --workspace` will not run it — `rustcrypto_aead_traits`
is the precedent; don't fold it into `rustcrypto_traits.rs`, which would
silently unwire that leg). Each opt-in feature gets its own clippy pass.

## Manifests

- Workspace version is `[workspace.package].version`; crates inherit
  `version.workspace = true`. Sibling path-deps are pinned `=X.Y.Z`.
- Don't add an `authors` field. Don't add `all-features = true` to
  `gmcrypto-c`'s docs.rs metadata (it would run cbindgen in the docs build).
  Don't point `gmcrypto-simd`'s `readme` at `../../README.md`.
- `sm4-xts = []` — no dep. `gmcrypto-simd` is reached only via
  `sm4-bitsliced-simd` / `sm4-aead`.
- Don't pull `getrandom`'s `wasm_js` into core's default graph; wasm callers
  enable it in *their* `Cargo.toml`.
- A public-API change (any `pub` item in core or simd) must regenerate
  `docs/api-baseline/*.txt` with the pinned `cargo-public-api` on the pinned
  nightly, or the enforced drift-check fails. `cargo-semver-checks` runs
  against the crates.io baseline.

## CI

- Five `ci.yml` jobs on `macos-14`; `simd-x86` on `ubuntu-latest`;
  `interop-gmssl` on `ubuntu-24.04`. Dudect stays on `ubuntu-24.04`
  (`.claude/rules/dudect.md`).
- `cargo deny`: `taiki-e/install-action@v2` with `cargo-deny@0.20.2` — don't
  switch to `cargo install --locked cargo-deny`. Locally: `cargo generate-lockfile`
  first.
- `dtolnay/rust-toolchain@master` + `targets:` is flaky; pair with an explicit
  `rustup target add wasm32-unknown-unknown --toolchain ${MSRV}`.
- The cargo-doc job is `RUSTDOCFLAGS="-D warnings -A rustdoc::private_intra_doc_links"`
  with an explicit feature list. **Never** add `--cfg docsrs` to that stable
  job (`#![feature(doc_cfg)]` would fail to compile). Plain `-D warnings` +
  `--all-features` locally reports ~12 pre-existing private-link errors and is
  a false red.
- `ci.yml` states the `c_smoke` test count in a comment; update it when the
  count moves. Fuzz workflow lists: `.claude/rules/fuzz.md`.

## Tests

- Integration-test scratch: `env!("CARGO_TARGET_TMPDIR")` (no `tempfile`).
- RustCrypto 0.11/0.5: inherent vs trait `finalize` / `encrypt_block` — use
  UFCS. HMAC via `<HmacSm3 as digest::KeyInit>::new_from_slice` (`Mac` no
  longer carries `KeyInit`).
- gmssl interop pins `DEFAULT_GMSSL_VERSION`; a mismatch gates, oracle infra
  does not. `gmssl sm2keygen -out priv.pem` also prints SPKI to stdout — use
  `-pubout`; `gmssl sm2encrypt` emits GM/T 0009 DER only (no `-binary` in
  3.1.1).
