# CLAUDE.md

Pure-Rust SM2/SM3/SM4 SDK. Three-crate workspace, lockstep version, path-deps
pinned **exactly** (`=X.Y.Z`); publish order **simd → core → c**:

- `crates/gmcrypto-core/` — `no_std` crypto core (default-member)
- `crates/gmcrypto-c/` — FFI shim (cdylib + staticlib + cbindgen header)
- `crates/gmcrypto-simd/` — SIMD backend (rlib-only; opt-in via core's
  `sm4-bitsliced-simd` or `sm4-aead`)

Read `README.md`, `SECURITY.md`, `CONTRIBUTING.md` for the user-facing posture.
This file holds only what **every** session needs. Area-specific constraints
are path-scoped in `.claude/rules/` and load when you read matching files:
`dudect`, `ffi`, `simd`, `sm4`, `sm2-sm3`, `protocols`, `fuzz`,
`features-and-ci`, `docs-and-release`. Cycle history: `docs/version-history.md`.

Test for new prose here: *would an agent that never read it break something,
in any area?* If it bites in one area, it goes in that rule; if it is
history, file it.

## Release state

| | |
|---|---|
| Live on crates.io | **`1.12.0`** — all three crates, 2026-09-04 from `b0c6679` (publish delegated for this release). The SSH-signed tag `v1.12.0` was **not yet on `origin`** when this row was written; verify with `git ls-remote --tags origin v1.12.0` before citing it. Previous: `1.11.2` 2026-08-23 from `0de98e2` |
| Workspace version | `1.12.0` = live. The next bump is the v1.13 release-prep PR. A new minor does not always mean crates.io (v0.14 / v1.10 were assurance cycles); don't bump or publish for a no-crate-change cycle |
| Gate #1 | `docs/ECOSYSTEM.md` §8 must PASS before every publish; latest record `docs/v1.12.0-gate1-evidence.md` (PASS against `9ccb262`). The gated SHA is never the release SHA: the gate attaches to any tip where `git diff <gated-sha> <tip> --stat -- crates/ Cargo.toml` is empty, and a PR touching those re-owes it. Running the gate script is ordinary agent work; publishing is not |

`cargo publish` and the SSH-signed tag are the **maintainer's authenticated
call** — the agent path is branch + PR. The 1.11.0 and 1.12.0 publishes were
explicit per-release delegations, not a standing grant.

### v1.13 — next cycle (not started; spec first)

Two items in one scope: the streaming-CCM FFI projection
(`gmcrypto_sm4_ccm_encryptor_t` / `_decryptor_t` over the v1.12 Rust types,
the GCM handle family as the template — `.claude/rules/ffi.md`) and bringing
the whole SM4 streaming family under `Zeroize` + `ZeroizeOnDrop` (GCM
encryptor/decryptor + `GhashAcc`, CTR, CBC pair; today only `Sm4Cipher` and
`Sm4CcmEncryptor` wipe — `.claude/rules/sm4.md`). Write `docs/v1.13-scope.md`,
get the maintainer's must-pin review, then plan. The v1.12 CCM constraints
are in the `sm4` rule.

## Open backlog

- AVX-512 `sbox_x64`; **F21** `ct_sm4_cbc_unpad` (composite window is blind —
  `docs/v1.10-scope.md` Q10.9).
- `noise_twin_class_split` is required non-blocking telemetry, **not** a
  relative gate until hosted-runner calibration + injected-leak controls pass.

## Hard constraints (non-negotiable)

- `unsafe_code = "forbid"` on `gmcrypto-core`. Don't add `unsafe`.
  Exceptions (`unsafe_code = "warn"`, `// SAFETY:` on every block):
  `gmcrypto-c` (raw-pointer FFI) and `gmcrypto-simd` (`core::arch` +
  `#[target_feature]` on MSRV 1.85).
- `#![no_std]` + `alloc` only in `crates/gmcrypto-core/src/`. No `std::` paths.
  No generic `std` feature. A future file helper would be named like
  `std-file-io`. `gmcrypto-c` is `std`-OK.
- **Constant-time on secrets.** Never `==` / `if` / Rust `bool` on a
  secret-derived value. Use `subtle::{Choice, ConditionallySelectable,
  ConstantTimeEq, ConstantTimeLess, CtOption}`. SM2 sign retry is fixed `K=2`.
- **Failure-mode invariant.** `verify_with_id` returns `bool`. Every fallible
  `Result` uses `gmcrypto_core::Error` with a single `Failed` variant (module
  aliases point at the same type). DER decode returns `Option`. C ABI returns
  `GMCRYPTO_FAILED` only. PRs that distinguish failure modes are rejected —
  see `SECURITY.md`.
- **No logging.** No `log`/`tracing`/`defmt` or any diagnostic output in the
  shipped crates (SECURITY.md "Logging & observability"); dev observability
  lives in tests/benches/workflows only.
- `Cargo.lock` is gitignored (lib-crate). Don't `git add` it. Anchor is
  `/Cargo.lock` (root only) so `fuzz/Cargo.lock` stays committed.
- MSRV **1.85**, edition **2024**. Don't use `Integer::is_multiple_of` (1.87).
- `sign_raw_with_id` is `#[doc(hidden)] pub` for dudect only — **not SemVer**.

## Commands

Not `cargo test --all-targets` (runs benches; CI 15-min timeout). `cargo build
--all-targets` is fine. `rustcrypto_aead_traits` is `required-features`-gated —
`cargo test --workspace` never builds it.

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features digest-traits,cipher-traits --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features sm4-bitsliced --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features sm4-aead --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features sm4-xts --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features sm2-key-exchange,crypto-bigint-scalar --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features x509 --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features tlcp --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features tlcp,x509 --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features aead-traits --all-targets -- -D warnings
cargo test -p gmcrypto-core --features aead-traits

cargo deny --exclude-dev check   # cargo generate-lockfile first
cargo deny --features gmcrypto-core/digest-traits,gmcrypto-core/cipher-traits,gmcrypto-core/sm4-bitsliced,gmcrypto-core/sm4-bitsliced-simd,gmcrypto-core/sm4-aead,gmcrypto-core/sm4-xts,gmcrypto-core/crypto-bigint-scalar,gmcrypto-core/sm2-key-exchange,gmcrypto-core/x509,gmcrypto-core/tlcp,gmcrypto-core/aead-traits --exclude-dev check

cargo +1.85 build -p gmcrypto-core
cargo +1.85 build -p gmcrypto-core --features digest-traits,cipher-traits,sm4-bitsliced,sm4-bitsliced-simd,sm4-aead,sm4-xts,crypto-bigint-scalar,sm2-key-exchange,x509,tlcp,aead-traits
cargo build -p gmcrypto-core --no-default-features

# wasm32: caller-supplied RNG; these features are pure-core/no_std.
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --no-default-features
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --no-default-features --features sm4-xts,sm2-key-exchange,x509,tlcp,aead-traits
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --no-default-features --features sm4-bitsliced-simd
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --no-default-features --features sm4-aead,sm4-bitsliced-simd

# C ABI: AEAD/XTS FFI is always-on. regen-header must not drift.
cargo build -p gmcrypto-c --release
cargo build -p gmcrypto-c --features regen-header
git diff --exit-code crates/gmcrypto-c/include/gmcrypto.h
cargo test -p gmcrypto-c
cargo clippy -p gmcrypto-c --all-targets -- -D warnings

# Dudect (gate |tau|; rules in .claude/rules/dudect.md)
DUDECT_SAMPLES=10000 cargo bench --bench timing_leaks --features crypto-bigint-scalar
DUDECT_SAMPLES=10000 cargo bench --bench timing_leaks --features sm2-key-exchange,sm4-xts,sm4-aead,sm4-bitsliced-simd,crypto-bigint-scalar

# gmssl interop
GMCRYPTO_GMSSL=1 cargo test --test interop_gmssl
GMCRYPTO_GMSSL=1 cargo test --test interop_gmssl --features sm4-aead

# Fuzz (own workspace, nightly; see .claude/rules/fuzz.md for run syntax)
cargo +nightly fuzz build
cargo +nightly fuzz build --features simd

# Disclosure boundary (P1 blocks; P2 advisory)
python3 .github/scripts/check_disclosure_boundary.py --worktree
```

## Architecture

```
crates/gmcrypto-core/   no_std primitives (sm2/sm3/sm4, asn1, pkcs8, opt-in
                        x509/tlcp/aead-traits). benches/timing_leaks.rs = dudect
crates/gmcrypto-c/      C ABI; committed include/gmcrypto.h; tests/c_smoke.rs
crates/gmcrypto-simd/   AVX2/NEON + GHASH; unsafe quarantined here
fuzz/                   own workspace; seeds committed, corpus not
.github/workflows/      ci / dudect-pr / dudect-nightly / fuzz-* / api-stability
                        / gitleaks / disclosure-boundary
docs/                   scope + version-history + api-baseline; not session scratch
.claude/rules/          path-scoped agent constraints (committed)
```

`getrandom` is a direct workspace dep (`sys_rng`). `spin` (`once`) is the
no_std comb-table lazy init.

## Workflow

- Agent path: **branch + PR**, squash-merge, stage explicit paths (never
  `git add -A`). Direct `main` only for trivial time-sensitive fixes. WIP skip:
  `[skip ci]` in the **PR title**.
- Never merge with an unexplained red check. For dudect, read the
  `RUNNER-CPU:` line first (`.claude/rules/dudect.md`).
- Stacked PRs: merge parents **without** `--delete-branch` or GitHub closes
  the child and refuses reopen/retarget. After squash, rebase the child
  `--onto main`. CI on non-`main` bases: `gh workflow run ci.yml --ref <branch>`.
- Publish (maintainer, or explicit per-release delegation): simd → core → c
  from the tip the gate attaches to; `cd` inside the command; tag a named SHA
  (`.claude/rules/docs-and-release.md`).
- Worktree sessions: the guard refuses compound `git` commands and `cd` into
  the shared checkout — split into plain single commands. Share the warm
  cache with `CARGO_TARGET_DIR=<repo>/target`.

## Don't (every session)

- Don't add a `Cargo.toml` `authors` field.
- Don't reference any external "Java prototype" / `gm-crypto-lite-java` repo.
- Don't cite an absolute local path as KAT/evidence provenance, and don't
  commit session working documents into `docs/` (`docs/disclosure-boundary.md`).

## Gotchas (every session)

- Fuzz crate is a **separate workspace**: `cargo fmt --all` / `clippy
  --workspace` / `test --workspace` do **not** touch it.
- `cargo fmt` and `cargo fuzz build` may dirty `fuzz/Cargo.lock` or reformat
  an untouched fuzz target — restore with `git checkout --`, never stage it
  from a feature task.
- `pub(crate) const` inside `pub(crate) mod` trips clippy::pub-in-priv — use
  `pub` on inner items.
- Integration-test scratch: `env!("CARGO_TARGET_TMPDIR")` (no `tempfile` dep).
