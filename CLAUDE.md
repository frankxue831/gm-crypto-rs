# CLAUDE.md

Pure-Rust SM2/SM3/SM4 SDK. Three-crate workspace:
`crates/gmcrypto-core/` (the no_std crypto core; default-member) +
`crates/gmcrypto-c/` (FFI shim; cdylib + staticlib + cbindgen header) +
`crates/gmcrypto-simd/` (SIMD backend; rlib-only, opt-in via
`gmcrypto-core`'s `sm4-bitsliced-simd` or `sm4-aead` feature).
The three **always release together at one lockstep version**, intra-workspace
path-deps pinned **exactly** (`=X.Y.Z`); publish order simd → core → c.

Read `README.md`, `SECURITY.md`, `CONTRIBUTING.md` for the user-facing posture.
This file lists the constraints a coding agent will violate by default.
**Per-cycle history (v0.8 → v1.11, newest-first) lives in
`docs/version-history.md`. Don't re-add it here** — see the `Don't` section.

## Release state

| | |
|---|---|
| Workspace version | `1.9.1` |
| Live on crates.io | `1.9.0` (2026-06-16) — **`1.9.1` is prepped but NOT published** |
| Last landed cycle | **v1.11** — RustCrypto `aead` 0.6 trait fit (merged to `main`) |
| Next steps | publish `1.9.1` **from `530013b`**, then bump `1.9.1` → `1.11.0` (crates.io skips `1.10.0`, the v0.14→v0.15 precedent) |

`cargo publish` and the SSH-signed tag are the **maintainer's authenticated
call, never the agent's** — the agent path stays branch + PR. Tag the release
SHA explicitly (`git tag -s v1.9.1 530013b`): `main` has moved on since the
release candidate was frozen, so a bare `git tag` would point at a tree
crates.io never received.

### v1.11 — the current, unpublished cycle

Opt-in **`aead-traits = ["sm4-aead", "dep:aead"]`** adds `sm4::Sm4Gcm` (fixed
U12 nonce / U16 postfix tag — the canonical profile; truncated tags + arbitrary
nonces stay inherent-only) and `sm4::Sm4Ccm<M = U16, N = U12>` (tag + nonce as
typenum params bounded by the **sealed** `CcmTagSize`/`CcmNonceSize`, admitting
exactly the RFC 3610 §2.1 sets — so an invalid combination is a COMPILE error,
not a runtime `None`). Default build byte-identical; `aead` is absent from the
default dep graph. Scope + forks: `docs/v1.11-scope.md` Q11.1–Q11.10.

Two things that look like defects but are load-bearing:

- **The trait set is not a free choice.** `aead` 0.6 blanket-implements `Aead`
  for every `AeadInOut`, so a direct `impl Aead for Sm4Gcm` **cannot compile**.
  Implement `KeySizeUser` + `KeyInit` + `AeadCore` + `AeadInOut`; the
  Vec-returning `Aead` and the `Buffer`-based in-place methods arrive free.
  (`AeadInPlace` is DEPRECATED in 0.6, and there is NO `aead::stream` module —
  it moved to its own crate — so `gcm_streaming` stays inherent-only.)
- **Both types are THIN wrappers** over `mode_gcm`/`mode_ccm`, which is the
  entire reason v1.11 adds **no new dudect target** (count stays 23): the
  measured bodies are byte-identical on the trait path. That premise is
  guarded by the differential fuzz target `fuzz_sm4_aead_traits`, **not by
  prose** — so don't refactor the wrappers into re-implementations, and treat
  a divergence there as invalidating the assurance claim, not as a wrapper bug.

Stated costs, not hidden: a fresh key schedule per call (the structs hold key
bytes) and allocation inside the methods named "in place". **SM4-XTS gets no
aead fit, ever** — confidentiality-only, no tag.

## Open backlog / deferred

post-1.0 / deferred = class-split-aware "noise-twin" dudect reference (the only design that could re-promote `ct_fn_invert`/`ct_fp_invert`) + round-trip/differential parser fuzzing + RustCrypto aead trait fit (blocked: aead still 0.6.0-rc.10) + AVX-512 sbox_x64 + CCM buffered input + (from the v1.0.1 synthesis, all non-blocking) a `ct_sm4_cbc_unpad` dudect target for the PKCS#7-strip path (**F21 — STILL OPEN, and v1.10 ATTEMPTED IT AND STOPPED: the composite window is blind.** A `mode_cbc::decrypt`-over-32-bytes window measured |tau| 0.0129 constant-time vs **0.0185 with a deliberately early-return leaky strip** — indistinguishable — while a 10 000× amplified control hit 11.6, proving the measurement path works and the null is a real sensitivity limit. Cause: the default `subtle` linear-scan S-box costs ~256 ops **per byte**, so one CBC decrypt is ~10⁵ masked ops vs ~15 byte-compares for the leak — 0.015%, and no ciphertext length fixes it because the key schedule alone dominates. **Landing it would have produced a gate that cannot fail.** Follow-up: time `Sm4CbcDecryptor::finalize()` instead (public; the SM4 work sits in `update()`, outside the window) — blocked on `CtRunner::run_one` taking `Fn` while `finalize(self)` consumes, so it needs interior mutability whose own in-window cost must be measured, not assumed. Re-run the three-way constant-time/leaky/amplified control before trusting any number. Full record: `docs/v1.10-scope.md` Q10.9). **F16 (gmssl interop in CI) is CLOSED in v1.10** — `ci.yml`'s `interop-gmssl` job runs the suite against a pinned from-source GmSSL build. (NB: the §3.A crypto-bigint-exposure decision was **pre-1.0** and is now **resolved in v0.22** — see the **Earlier — v0.22 —** paragraph in `docs/version-history.md`; nothing pre-1.0 remains outstanding.)

## Hard constraints (non-negotiable)

- `unsafe_code = "forbid"` on `gmcrypto-core`. Don't add `unsafe`.
  **Exceptions** (both `unsafe_code = "warn"`, both with `// SAFETY:`
  comments per `unsafe` block):
  - `gmcrypto-c` (v0.4 W4 FFI shim) — raw-pointer FFI primitives
    (`Box::from_raw`, `#[unsafe(no_mangle)]`, slice reconstruction)
    cannot be expressed without `unsafe`.
  - `gmcrypto-simd` (v0.5 W4 phase 2 SIMD backend) — AVX2 (x86_64)
    and later NEON (aarch64) intrinsics from `core::arch::*` are
    `unsafe fn`; `#[target_feature(enable = "...")] unsafe fn` is
    the only stable-Rust mechanism on MSRV 1.85 to combine runtime
    CPU dispatch with intrinsic calls. See `docs/v0.5-scope.md`
    Q5.11 addendum for the architectural reset that landed
    alongside W4 phase 2.
- `#![no_std]` + `alloc` only inside `crates/gmcrypto-core/src/`. No `std::` paths.
  The reserved `std` Cargo feature flag was **removed in v0.5 W5
  (Q5.18)** — a no-op feature flag had negative documentation value.
  A future file-I/O helper would land under a specific name like
  `std-file-io`, not the generic `std`. `gmcrypto-c` is `std`-OK
  (it's the language-binding layer, not the no_std crypto primitives).
- **Constant-time discipline on secrets.** Never `==` / `if` / Rust `bool` on a
  secret-derived value. Use `subtle::{Choice, ConditionallySelectable,
  ConstantTimeEq, ConstantTimeLess, CtOption}`. The SM2 sign retry loop runs
  a fixed `K=2` iterations regardless of which (if any) candidate is valid.
- **Failure-mode invariant.** `verify_with_id` returns `bool` (never `Result`).
  Every fallible `Result`-returning public API uses the workspace-wide
  `gmcrypto_core::Error` (v0.5 W5) with a single `Failed` variant. Module
  aliases `sm2::Error`, `pem::Error`, `pkcs8::Error` all point at the same
  type. DER decode returns `Option`, never specific error variants. PRs
  that distinguish failure modes get rejected on sight — see
  `SECURITY.md`. Don't make errors "more helpful."
- `Cargo.lock` is **gitignored** (lib-crate policy). Don't `git add` it.
  For `cargo deny` runs, generate via `cargo generate-lockfile` first.
- MSRV is **1.85**, edition **2024** (post-publish bump in `89abfb9`).
  `crypto-bigint 0.7` requires 1.85.
- `sign_raw_with_id` is `#[doc(hidden)] pub` for the dudect harness only and is
  **not covered by SemVer**. Don't expand its surface or expose it publicly.

## Commands (project-specific gotchas)

```bash
# Tests — note: NOT --all-targets. That runs benches in test mode and the
# CI 15-min timeout was hit during v0.1 prep. `cargo build --all-targets`
# is fine; `cargo test --all-targets` is not.
cargo test --workspace

# Format / lint — match CI exactly.
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
# v0.4 W2 / W3 / v0.8 W2-W3 — opt-in features each get their own clippy pass.
cargo clippy -p gmcrypto-core --features digest-traits,cipher-traits --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features sm4-bitsliced --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features sm4-aead --all-targets -- -D warnings
# v0.12 — SM4-XTS opt-in clippy pass.
cargo clippy -p gmcrypto-core --features sm4-xts --all-targets -- -D warnings
# v1.1 — SM2 key-exchange opt-in clippy pass (crypto-bigint-scalar added so
# the bench target, which has required-features on it, also lints).
cargo clippy -p gmcrypto-core --features sm2-key-exchange,crypto-bigint-scalar --all-targets -- -D warnings
# v1.3 — X.509 opt-in clippy pass.
cargo clippy -p gmcrypto-core --features x509 --all-targets -- -D warnings
# v1.6 — TLCP opt-in clippy pass.
cargo clippy -p gmcrypto-core --features tlcp --all-targets -- -D warnings
# v1.8 — tlcp::chain needs BOTH tlcp+x509; its own clippy pass.
cargo clippy -p gmcrypto-core --features tlcp,x509 --all-targets -- -D warnings
# v1.11 — aead 0.6 trait fit. NOTE the test leg is NOT optional: the
# rustcrypto_aead_traits [[test]] is required-features-gated, so a plain
# `cargo test --workspace` never builds or runs it.
cargo clippy -p gmcrypto-core --features aead-traits --all-targets -- -D warnings
cargo test -p gmcrypto-core --features aead-traits

# Supply chain — note: --exclude-dev (dev-deps are exempt from the ban list).
cargo deny check --exclude-dev
# v0.4 W2 / W3 / v0.8 W2-W3 / v0.12 — second pass under the opt-in runtime
# feature flags (digest/cipher/inout/crypto-common allowlisted in deny.toml;
# sm4-aead pulls gmcrypto-simd::ghash which has no new transitive deps; sm4-xts
# adds NO new dep — pure-core).
cargo deny --features gmcrypto-core/digest-traits,gmcrypto-core/cipher-traits,gmcrypto-core/sm4-bitsliced,gmcrypto-core/sm4-bitsliced-simd,gmcrypto-core/sm4-aead,gmcrypto-core/sm4-xts,gmcrypto-core/crypto-bigint-scalar,gmcrypto-core/sm2-key-exchange,gmcrypto-core/x509,gmcrypto-core/tlcp,gmcrypto-core/aead-traits check --exclude-dev

# MSRV reproducibility.
cargo +1.85 build -p gmcrypto-core
cargo +1.85 build -p gmcrypto-core --features digest-traits,cipher-traits,sm4-bitsliced,sm4-bitsliced-simd,sm4-aead,sm4-xts,crypto-bigint-scalar,sm2-key-exchange,x509,tlcp,aead-traits
cargo build -p gmcrypto-core --no-default-features  # confirms no_std posture

# v0.4 W1 — wasm32 build (caller-supplied RNG only).
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --no-default-features
# v0.12 — sm4-xts is pure-core/no_std, so it must build on wasm32 too.
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --features sm4-xts --no-default-features
# v1.1 — sm2-key-exchange is pure-core/no_std too (caller-supplied RNG).
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --features sm2-key-exchange --no-default-features
# v1.3 — x509 is pure-core/no_std too (public-input parse+verify).
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --features x509 --no-default-features
# v1.6 — tlcp is pure-core/no_std too (key schedule: byte-in/byte-out).
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --features tlcp --no-default-features
# v1.8 — tlcp::chain (cert-pair verify) is pure-core/no_std; needs tlcp+x509.
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --features tlcp,x509 --no-default-features
# v1.11 — the aead trait fit is pure-core/no_std too (aead 0.6 is no_std).
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --features aead-traits --no-default-features

# v0.4 W4 — C ABI shim build + header drift check.
cargo build -p gmcrypto-c --release
cargo build -p gmcrypto-c --features regen-header   # regenerates include/gmcrypto.h
git diff --exit-code crates/gmcrypto-c/include/gmcrypto.h
cargo test -p gmcrypto-c                            # c_smoke Rust-equivalence tests
# v0.9 W4 / v0.10 — AEAD FFI surface (single-shot + streaming SM4-GCM).
# v0.23 W3 — AEAD/XTS FFI is now ALWAYS-ON in gmcrypto-c (the forwarding
# sm4-aead/sm4-xts cargo features were dropped from the C shim); the default
# build exports every symbol, so no --features flag is needed.
cargo test -p gmcrypto-c                            # all c_smoke tests incl. AEAD (single-shot + streaming) + XTS (single-shot + multi-sector)
cargo clippy -p gmcrypto-c --all-targets -- -D warnings

# Dudect harness. Default 100K samples (~75s); CI smoke uses 10K.
# v0.5 W5 — the bench uses Sm2PrivateKey::from_scalar (renamed from
# `new`) which is gated on `crypto-bigint-scalar`. The [[bench]] entry
# in gmcrypto-core/Cargo.toml has required-features set, so cargo
# auto-enables it — but explicit is safer.
DUDECT_SAMPLES=10000  cargo bench --bench timing_leaks --features crypto-bigint-scalar  # PR-smoke budget
DUDECT_SAMPLES=100000 cargo bench --bench timing_leaks --features crypto-bigint-scalar  # nightly budget

# v0.8 W4 — AEAD dudect under the most-demanding cipher path
# (also runnable standalone via `--features sm4-aead,crypto-bigint-scalar`).
DUDECT_SAMPLES=10000  cargo bench --bench timing_leaks --features sm4-aead,sm4-bitsliced-simd,crypto-bigint-scalar
# Gate: |tau| < 0.20 on ct_sm4_gcm_decrypt + ct_sm4_ccm_decrypt.
# v0.12 W3 — SM4-XTS dudect (the CI matrix's 4th slot carries all three).
DUDECT_SAMPLES=10000  cargo bench --bench timing_leaks --features sm4-xts,sm4-aead,sm4-bitsliced-simd,crypto-bigint-scalar
# Gate: |tau| < 0.20 on ct_sm4_xts_decrypt (CTS-length data unit).
# v1.1 W3 — SM2 key-exchange dudect (the CI matrix's 4th slot carries all four).
DUDECT_SAMPLES=10000  cargo bench --bench timing_leaks --features sm2-key-exchange,sm4-xts,sm4-aead,sm4-bitsliced-simd,crypto-bigint-scalar
# Gate: |tau| < 0.20 on ct_sm2_key_exchange (full initiator side, class-split by static d_A).

# gmssl interop (gated; needs gmssl 3.2.0 — what Homebrew ships today).
# The suite PINS its oracle version (DEFAULT_GMSSL_VERSION in the test) and
# fails with "ORACLE DRIFT" on any other build: GmSSL 3.2.0 renamed `pbkdf2`
# -> `sm3_pbkdf2`, split `sm4 -cbc/-ctr/-gcm` into `sm4_cbc`/`sm4_ctr`/
# `sm4_gcm`, and narrowed `sm3hmac` keys to 12..=32 bytes. v1.10 wired this
# into ci.yml's `interop-gmssl` job (pinned from-source build, non-gating).
GMCRYPTO_GMSSL=1 cargo test --test interop_gmssl                      # 11 tests
GMCRYPTO_GMSSL=1 cargo test --test interop_gmssl --features sm4-aead  # 13 tests
# Deliberately probe a different build (does not edit the pin):
GMCRYPTO_GMSSL=1 GMCRYPTO_GMSSL_VERSION="GmSSL 3.1.1" cargo test --test interop_gmssl

# v0.14 — parser fuzzing (cargo-fuzz / libFuzzer). NIGHTLY-ONLY toolchain.
# One-time: rustup toolchain install nightly && cargo install cargo-fuzz --version 0.13.1 --locked
# Run from the REPO ROOT (the dir containing fuzz/). The fuzz crate is its
# OWN workspace + parent exclude=["fuzz"], so it does NOT affect any
# `cargo ... --workspace` / `cargo deny` / publish of the 3 crates.
cargo +nightly fuzz build                          # build all 29 targets
cargo +nightly fuzz run fuzz_pem fuzz/corpus/fuzz_pem fuzz/seeds/fuzz_pem -- \
    -max_len=16384 -rss_limit_mb=2048 -timeout=25 -max_total_time=60
# Dir order: corpus FIRST (gitignored, libFuzzer writes new units here),
# seeds SECOND (committed, read-only). A crash → fuzz/artifacts/<target>/;
# minimize with `cargo +nightly fuzz tmin <target> <crash>` and commit the
# minimized input under fuzz/seeds/<target>/ as a regression seed.
```

## Dudect harness gate

Located at `crates/gmcrypto-core/benches/timing_leaks.rs`. **Fifteen
targets at the default / `sm4-bitsliced` budget; seventeen under
`sm4-bitsliced-simd`; twenty under `sm4-bitsliced-simd,sm4-aead`;
twenty-one under `sm4-bitsliced-simd,sm4-aead,sm4-xts`; twenty-two under
`sm4-bitsliced-simd,sm4-aead,sm4-xts,sm2-key-exchange`; twenty-three under
`…,sm2-key-exchange,tlcp` — v1.7 W3 added `ct_tlcp_cbc_deprotect` cfg-gated
on `tlcp` (the Lucky13 CBC-deprotect residual guard); v1.1 W3 added
`ct_sm2_key_exchange` cfg-gated on `sm2-key-exchange`. **v1.8 (G4
chain/pair verification) adds NO dudect target — public-inputs-only (certs +
anchors + comparison time are public; the v1.3 `x509` rationale extends), so
the count stays twenty-three. v1.9 (the TLCP toolkit C FFI) also adds NO dudect
target — a thin shim riding existing targets (record → `ct_tlcp_cbc_deprotect`,
KX → `ct_sm2_key_exchange`, key schedule → `ct_hmac_sm3`; chain/pair is
public-inputs), so the count stays twenty-three. v1.11 (the `aead` 0.6 trait
fit) adds NO dudect target either — `Sm4Gcm`/`Sm4Ccm` delegate to
`mode_gcm`/`mode_ccm`, so `ct_sm4_gcm_decrypt` / `ct_sm4_ccm_decrypt` measure
byte-identical code on the trait path; the thinness that argument rests on is
guarded by the differential `fuzz_sm4_aead_traits`, NOT by prose. Count stays
twenty-three.** (v0.3 added
`ct_pkcs8_decrypt`; v0.5 W4 phase 1 added
`ct_sm4_encrypt_block_bitsliced_simd` cfg-gated on `sm4-bitsliced-simd`;
v0.6 W6 added `ct_sm4_cbc_decrypt_fanout` cfg-gated on the same feature
per Q6.7 of `docs/v0.6-scope.md`; v0.7 W3 added `ct_sm4_ctr_encrypt`
NOT cfg-gated — runs under all three pre-W4 matrix entries per
Q7.2; v0.8 W4 added `ct_sm4_gcm_decrypt` and `ct_sm4_ccm_decrypt`
cfg-gated on `sm4-aead` per Q8.7 of `docs/v0.7-aead-scope.md`;
v0.9 W3 added `ct_sm4_gcm_decrypt_buffered` cfg-gated on `sm4-aead`
per Q9.5 of `docs/v0.9-scope.md`; v0.12 W3 added `ct_sm4_xts_decrypt`
cfg-gated on `sm4-xts` per Q12.9 of `docs/v0.12-scope.md`; v0.19 added the
two base `noise_floor_f{n,p}_invert` fix-vs-fix telemetry probes — non-cfg-gated,
so the base count is now 15, NOT gating per Q19.5).
**v0.12 W3 also fixed a latent bug**: `MATRIX_FEATURES` was `env`-scoped
to the dudect bench step, so the parse step's feature-conditional gates
(`sm4-bitsliced-simd` / `sm4-aead` / `sm4-xts`) never fired — now
re-declared on the parse step in both workflows.
**v0.18 hardened the gate** (PRs #75/#76, `docs/v0.18-scope.md`): the dudect
workflows are pinned to `ubuntu-24.04` (OS-label) + `dtolnay/rust-toolchain@1.95.0`,
and the bench is looped **N times** per job (PR N=3 / nightly N=5) into numbered
logs (`dudect-$i.log` / `dudect-nightly-$i.log`) — the inline Python gates the
per-target **median** `|tau|` (`required_low` + the nightly sentinel) and the
**min** (`negative_control`, must fire every run), and FAILs any required target
measured `< N` runs (completeness). `timing_leaks.rs` stays **byte-unchanged**;
the loop + median live entirely in the workflow. A 100K×5 calibration showed
`ct_fn_invert`/`ct_fp_invert` back near the ~0.006 baseline (medians 0.006–0.028)
but they were **kept on the sentinel (NOT re-promoted)** — the noise is
image-sensitive and a tight gate would re-flake if it returns (see the table
notes below + the v0.18 resolution in `docs/v0.5-dudect-recalibration.md`).
**v0.19 tried to re-promote them via a self-calibrating relative gate
(`median(target) ≤ max(0.20, 4·median(noise_floor_probe))`) and FALSIFIED it**:
the 100K calibration showed the fix-vs-fix probes uniformly quiet (~0.005) while
the class-split targets spiked to [0.26–0.32] (`ct_fp_invert` median 0.2606 on the
simd leg, ratio 50) — the noise is in the **two-input class split**, not the
operation a same-input probe sees, so the probe can't track it. The relative gate
is now **non-blocking `REL-TELEMETRY`**; the two targets stay on telemetry (PR) /
sentinel @0.55 (nightly); the probes are kept as telemetry. A class-split-aware
"noise-twin" is the v0.21+ revisit-door candidate (Q19.5 → v0.20 §5/§6;
`docs/v0.5-dudect-recalibration.md` v0.19 resolution).
The PR-smoke and nightly workflows run the harness under a matrix
over
`features=[default, sm4-bitsliced, sm4-bitsliced-simd,
sm4-bitsliced-simd,sm4-aead,sm4-xts]` so the `ct_sm4_key_schedule`,
`ct_sm4_encrypt_block`, and `ct_sm4_ctr_encrypt` targets gate
under every cipher dispatch path:

| Target | Gate | Meaning |
|---|---|---|
| `negative_control` | `\|tau\| > 1.0` (v0.18: gated on the **min** across the N runs) | MUST fire on EVERY run — proves harness wiring (a liveness check, so the floor-across-runs is the correct gate). |
| `ct_mul_g` | `\|tau\| < 0.20` | Fixed-base scalar mult. v0.3 W6 replaced the body with a comb-table walk; constant-time-designed lookup preserved. 10K-sample smoke after W6: `\|tau\| ≈ 0.04`. |
| `ct_mul_var` | `\|tau\| < 0.20` | Variable-base scalar mult. |
| `ct_sign` | `\|tau\| < 0.20` | `sign_raw_with_id`, class-split by private key `d` (NOT `sign_with_id` — DER is variable-time on public output). |
| `ct_sign_k_class` | PR-smoke: not gated. Nightly: gross-regression **sentinel @0.55** (median-gated). | `sign_raw_with_id`, class-split by nonce `k` magnitude with `d` held fixed (W0; both retry nonces class-tied). v0.4 release-prep **dropped it from the PR-smoke (10K) allowlist** (observed [0.21–0.37], no structure tied to code changes); the 100K nightly `0.25` gate was retained on a "SNR meaningful at 100K" rationale. **v1.0.x (2026-06-07) DEMOTED it to the nightly `@0.55` sentinel** (Codex-reviewed; `docs/v0.5-dudect-recalibration.md` 2026-06-07 resolution): post-1.0 the 100K nightly median reached 0.2570–0.2768 for ~2 weeks (the regression watch was mostly red) while the authoritative direct invert diagnostics stayed at ~0.005–0.012 — the same two-input class-split image-noise as the invert pair (v0.19), not a leak. `ct_fn_invert`/`ct_fp_invert` remain the invert-leak guards; `ct_sign_k_class` is a composite that dilutes invert signal ~50× (v0.2 W0). **Honest trade:** a medium `k`-only full-sign leak in [0.25, 0.55] is unguarded until a class-split-aware "noise-twin" exists. The bench still runs (telemetry + the sentinel); demoted sentinels stay **completeness-gated** so a "not measured" can't pass green. |
| `ct_fn_invert` | PR-smoke: **telemetry only**. Nightly: gross-regression sentinel at `\|tau\| ≥ 0.55` (v0.18: **median-gated**). | Direct `Fn::invert((1+d) mod n)` diagnostic (W0). Recalibrated 2026-05-13. **v0.18 100K×5 calibration on the pinned runner: median 0.006–0.011** (back near baseline) — but kept on the sentinel, NOT re-promoted (image-noise robustness; Q18.7). **v0.19**: the relative gate vs a fix-vs-fix probe (`noise_floor_fn_invert`) was implemented and falsified — the probe stays quiet (~0.005) while this target's noise is in its class split — so it stays on telemetry/sentinel. See `docs/v0.5-dudect-recalibration.md` (v0.19 resolution). |
| `ct_fp_invert` | PR-smoke: **telemetry only**. Nightly: gross-regression sentinel at `\|tau\| ≥ 0.55` (v0.18: **median-gated**). | Direct `Fp::invert(Z)` diagnostic (W0). The 2026-05-12 GH Actions `ubuntu-24.04` runner-image update (image `20260413.86.1` → `20260512.134.1`, kernel `6.17.0-1010-azure` → `6.17.0-1013-azure`, Rust toolchain `1.94.1` → `1.95.0`) shifted the 100K noise floor on this target from ~0.006 (v0.2 baseline) to intermittent values in [0.29–0.40]. The 0.20 gate is no longer authoritative on the current shared runner; the gross-regression sentinel at 0.55 retains protection against a real cryptographic leak (the v0.1 `ConstMontyForm::invert` regression at `\|tau\| ≈ 0.70` would still fire). The v0.5 doc's authoritative fix (a noise-isolated self-hosted runner) is **off the table** post-v0.17 (RCE on a public repo); **v0.18** instead pinned the toolchain + image and added the multi-run median. v0.18 100K×5 calibration: **median 0.014–0.028** (back near baseline) — but kept on the sentinel, NOT re-promoted (the noise is image-sensitive; a tight median gate would re-flake if it returns; Q18.7). A self-calibrating relative gate (v0.19) is the change that could safely re-promote. **v0.19 IMPLEMENTED and FALSIFIED it**: the 100K calibration showed the fix-vs-fix probe `noise_floor_fp_invert` quiet (~0.005) while this target's median hit **0.2606** on the `sm4-bitsliced-simd` leg (ratio 50) — the noise is in the **two-input class split** (`z_small` vs `z_large`), not the operation a same-input probe sees, so the probe can't track it. Reverted to telemetry/sentinel; a class-split-aware "noise-twin" is the v0.21+ revisit-door candidate (v0.20 codified this as the settled v1.0 baseline). See `docs/v0.5-dudect-recalibration.md` (v0.19 resolution). |
| `noise_floor_fn_invert` | **telemetry only** (non-blocking `REL-TELEMETRY`) | v0.19 — fix-vs-fix `Fn::invert` noise-floor probe: both dudect classes get one identical input, so `|tau|` is pure measurement noise (cannot leak by construction). Built as the matched reference for the (falsified) relative gate; KEPT as a longitudinal noise-floor diagnostic. Measures ~0.005 (uniformly quiet — the evidence the `ct_fn_invert` noise is class-split-specific). |
| `noise_floor_fp_invert` | **telemetry only** (non-blocking `REL-TELEMETRY`) | v0.19 — fix-vs-fix `Fp::invert` noise-floor probe; same construction over `Fp`. Measures ~0.005 even when `ct_fp_invert` spikes to 0.26 — the proof that the runner noise is in the two-input class split, not the operation. Input to a v0.21+ class-split-aware reference. |
| `ct_sm4_key_schedule` | `\|tau\| < 0.20` | SM4 key schedule, class-split by master key bytes (v0.2 W1). v0.4 CI also gates this under `features=sm4-bitsliced`. |
| `ct_sm4_encrypt_block` | `\|tau\| < 0.20` | SM4 "construct cipher + encrypt one block" timed under one window, class-split by master key bytes (v0.2 W1). v0.4 CI also gates this under `features=sm4-bitsliced`; 10K-sample smoke on the bitsliced path: `\|tau\| ≈ 0.025`. |
| `ct_sm4_ctr_encrypt` | `\|tau\| < 0.20` | v0.7 W3 — SM4-CTR encrypt timed over a fixed 256-byte plaintext (16 blocks), class-split by master key bytes. Dispatches through `Sm4Cipher::encrypt_blocks` (v0.7 W1), so this gates the constant-time discipline on every cipher path — linear-scan under default, gate-only under `sm4-bitsliced`, SIMD-packed batches under `sm4-bitsliced-simd` (two AVX2 batches on x86_64, four NEON batches on aarch64). **Not** cfg-gated on `sm4-bitsliced-simd` — runs under all three matrix entries. 5K-sample local smoke: `\|tau\| ≈ 0.064`. Per Q7.2 of `docs/v0.6-scope.md`. |
| `ct_hmac_sm3` | PR-smoke: **telemetry only**. Nightly: gross-regression **sentinel @0.55** (median-gated). | HMAC-SM3 keyed MAC, class-split by two fixed keys over a fixed-length message (v0.2 W3); structurally exercises PBKDF2-HMAC-SM3's inner PRF, the v0.3 W5 streaming `HmacSm3`, and the v0.3 W2 PKCS#8 PBKDF2 sub-path. **DEMOTED 2026-06-17 (Codex+Grok-reviewed; `docs/v0.5-dudect-recalibration.md` 2026-06-17 resolution)** — the 4th two-input class-split target hit by the `ubuntu-24.04` image-noise. Constant-time **by construction** (two fixed keys, fixed message ⇒ identical SM3 compression count), so it can only measure two-input noise; the 06-14 nightly **median itself crossed 0.20** (runs 0.014/0.2375/0.016/0.2196/0.2135, 3/5 spiked) co-spiking with the invert pair (`ct_fp_invert` 0.47/0.33), 06-16 quiet — so a partial fix (keep nightly @0.20) is falsified. **Honest residual:** unlike the invert pair (backstopped by `ct_sign`), the HMAC primitive has **NO direct non-composite backstop** — only the diluted `ct_pkcs8_decrypt` (iterated PBKDF2) covers key-byte HMAC; `ct_tlcp_cbc_deprotect` does NOT (fixed key, equalized Lucky13). The TLCP `p_sm3` key schedule that rode this loses its direct guard; a class-split-aware "noise-twin" is the re-promotion path (B, deferred). Completeness-gated (a "not measured" can't pass green). |
| `ct_sm2_decrypt` | `\|tau\| < 0.20` | SM2 decrypt, class-split by recipient `d_B`, fixed ciphertext encrypted to a third party so both classes fail at MAC via identical control flow (v0.2 Phase 3). |
| `ct_pkcs8_decrypt` | `\|tau\| < 0.20` | Encrypted-PKCS#8 decrypt + parse, class-split by password bytes; both classes' blobs are valid for their class's password so both succeed via identical control flow (v0.3 W2). 10K-sample smoke: `\|tau\| ≈ 0.04`. |
| `ct_sm4_encrypt_block_bitsliced_simd` | `\|tau\| < 0.20` (cfg-gated on `sm4-bitsliced-simd`) | SM4 "construct cipher + encrypt one block" timed under the SIMD-packed dispatch path (v0.5 W4). Phase 1 transparently delegates to the v0.4 single-block bitslice — byte-identical output, identical timing profile to `ct_sm4_encrypt_block` under `--features sm4-bitsliced`. Phase 2 swaps in AVX2 8-way intrinsics (runtime detect; silent fallback on non-AVX2 CPUs); phase 3 adds NEON 4-way. Same gate across all three phases. |
| `ct_sm4_cbc_decrypt_fanout` | `\|tau\| < 0.20` (cfg-gated on `sm4-bitsliced-simd`) | v0.6 W6 — Sm4CbcDecryptor's batched fanout path (`decrypt_batch`) timed under load. Class-split by master key; both classes' ciphertexts are valid encrypts under their own keys so both decrypt paths share identical control flow. Exercises `sbox_x32` (x86_64 AVX2; 8 blocks × 4 tau bytes per round = 32 bytes packed) or `sbox_x16` (aarch64 NEON; 4 blocks × 4 tau bytes per round = 16 bytes packed). Per Q6.7 of `docs/v0.6-scope.md`. |
| `ct_sm4_gcm_decrypt` | `\|tau\| < 0.20` (cfg-gated on `sm4-aead`) | v0.8 W4 — SM4-GCM decrypt timed over a fixed 256-byte plaintext + 16-byte AAD + 12-byte canonical nonce. Class-split by master key; both classes' `(ct, tag)` tuples are valid encrypts under their own keys so both decrypt paths reach tag-compare via identical control flow. Exercises key schedule, H = SM4_E(key, 0^128), GHASH chain (rides CLMUL on x86_64 / PMULL on aarch64 / software Karatsuba elsewhere), GCTR, `subtle::ConstantTimeEq`. 5K-sample local smoke on aarch64: `\|tau\| ≈ 0.073`. Per Q8.7 of `docs/v0.7-aead-scope.md`. |
| `ct_sm4_ccm_decrypt` | `\|tau\| < 0.20` (cfg-gated on `sm4-aead`) | v0.8 W4 — SM4-CCM decrypt timed under the same shape as `ct_sm4_gcm_decrypt`, fixed `tag_len = 16` and 12-byte nonce. Class-split by master key; valid `(ct‖tag)` pair per class. Exercises CBC-MAC chain (sequential `Sm4Cipher::encrypt_block` loop) + CTR stream (rides v0.7 W1 batch API + v0.6 SIMD fanout under `sm4-bitsliced-simd`) + constant-time tag compare. 5K-sample local smoke on aarch64: `\|tau\| ≈ 0.063`. Per Q8.7 of `docs/v0.7-aead-scope.md`. |
| `ct_sm4_gcm_decrypt_buffered` | `\|tau\| < 0.20` (cfg-gated on `sm4-aead`) | v0.9 W3 — incremental-input buffered SM4-GCM decrypt via `Sm4GcmDecryptor`, timed over a fixed 256-byte plaintext + 16-byte AAD + 12-byte nonce fed in two chunks (100 bytes + rest) to straddle block boundaries. Class-split by master key; both classes' `(chunked ct, tag)` verify under their own keys so both reach `finalize_verify` (commit-on-verify) via identical control flow. Exercises the running-GHASH accumulator (`GhashAcc`) + the buffered-then-decrypt path. 5K-sample local smoke on aarch64: `\|tau\| ≈ 0.029`. Per Q9.5 of `docs/v0.9-scope.md`. |
| `ct_sm4_xts_decrypt` | `\|tau\| < 0.20` (cfg-gated on `sm4-xts`) | v0.12 W3 — SM4-XTS decrypt via `mode_xts::decrypt`, timed over a fixed **CTS (non-block-multiple) data unit** (100 B = 6 blocks + 4) so the final-pair ciphertext-stealing path — the riskiest tweak arithmetic — gates, not just whole-block. Class-split by master key; both classes' data units are valid encrypts under their own 32-byte key so both decrypt via identical control flow. Exercises key schedule, `T_0 = SM4_E(Key2, tweak)`, the constant-time bit-reflected α-doubling chain (`mul_alpha`: right-shift + masked `0xE1`), the `decrypt_blocks` batch path (rides SIMD fanout under `sm4-bitsliced-simd`), and the CTS tail. 10K-sample local smoke on aarch64: `\|tau\| ≈ 0.03`. Per Q12.9 of `docs/v0.12-scope.md`. **v0.15** reuses this target for the multi-sector helper (`encrypt_sectors`/`decrypt_sectors`) — the per-sector secret-dependent work is the same `split_keys`/`encrypt_blocks`/`mul_alpha` path; the only new logic is the sector-number→LE-128-tweak arithmetic, which is on **public** sector addresses, so no new target (Q15.9). |
| `ct_sm2_key_exchange` | `\|tau\| < 0.20` (cfg-gated on `sm2-key-exchange`) | v1.1 W3 — full SM2-KX initiator side (constructor `Z` hashing + `produce_ephemeral` + `confirm`) class-split by the static `d_A`; the ephemeral is one fixed scalar for both classes so the label identifies only `d_A`. Each class confirms against its own precomputed **valid** responder transcript (the `ct_pkcs8_decrypt` per-class-valid pattern), so both classes succeed via identical control flow — `t = (d + x̄·r) mod n`, the secret-scalar `mul_var`, the KDF, and both CT tag computations/compares all execute every sample. 10K-sample local smoke on aarch64: `\|tau\| ≈ 0.02`. |

Gate on **`|tau|`** (scale-free), not `|t|` (grows as `tau · sqrt(N)` so any
fixed `|t|` threshold is budget-dependent). Same gate at every sample budget;
more samples = tighter empirical confidence on the same threshold.

## v0.1 timing-leak narrative — resolved on main by the 0.7 upgrade

Published v0.1.0 (on `crypto-bigint = 0.6`) measured `|tau| ≈ 0.70` directly
on `ConstMontyForm::invert`. Main is on `0.7.3` and the v0.2 W0 harness
expansion (`ct_sign_k_class`, `ct_fn_invert`, `ct_fp_invert`) closed the
structural blind spot. At 100K samples on main:

| target | `\|tau\|` |
|---|---|
| `ct_fn_invert` | 0.0071 |
| `ct_fp_invert` | 0.0063 |
| `ct_sign_k_class` | 0.0708 |
| `ct_sign` | 0.0044 |

All four under the 0.10 W5 Branch A threshold; two orders of magnitude under
the 0.20 gate. The v0.2 Fermat-invert workstream was dropped on this evidence.
`pow_bounded_exp` remains a fallback if a future `crypto-bigint` release
regresses on this gate. See `SECURITY.md` for the full posture.

**2026-05-13 recalibration note:** the 100K-sample baseline shown above
was measured against the GH Actions `ubuntu-24.04` image `20260413.86.1`
(kernel `6.17.0-1010-azure`, Rust toolchain `1.94.1`). After the
2026-05-12 image update to `20260512.134.1` (kernel `6.17.0-1013-azure`,
Rust toolchain `1.95.0`), `ct_fn_invert` and `ct_fp_invert` started
producing intermittent `|tau|` values in [0.29–0.40] on the same source
code, with same-commit pass/fail across consecutive nightly runs. The
PR-smoke gates and 100K nightly gates for these two targets were
relaxed; see `docs/v0.5-dudect-recalibration.md` for the data + the
new sentinel posture. The CODE is unchanged from v0.2 baseline; the
CI noise floor is the moving piece. **v0.18 update (2026-05-30):** pinned
the OS label (`ubuntu-24.04`, not an exact-image freeze) + toolchain
(`@1.95.0`) and added a CI-level
multi-run median; a 100K×5 calibration measured these two back near the
~0.006 baseline (medians 0.006–0.028), but they were KEPT on the
telemetry/median-sentinel posture (NOT re-promoted) for image-noise
robustness — see the v0.18 resolution in `docs/v0.5-dudect-recalibration.md`.

The three secret-touching `invert` sites:

1. `Fn::invert((1+d) mod n)` in `sign_raw_with_id` — secret-dependent. Now
   directly diagnosable via `ct_fn_invert`.
2. `Fp::invert(Z)` in `to_affine()` after `mul_g(k)` — nonce-dependent. Now
   directly diagnosable via `ct_fp_invert`; sign-level diagnosable via
   `ct_sign_k_class`.
3. `Fp::invert(Z)` in `to_affine()` from `compute_z` — public input, harmless.

## Architecture map

```
crates/gmcrypto-core/
  src/
    lib.rs
    sm3.rs                  # single-file SM3 hash (impls v0.3 W5 in-crate Hash trait; v0.4 W2 impls digest::Digest under `digest-traits` — v0.11: digest 0.11, impl unchanged (Output is hybrid_array::Array))
    sm2/
      curve.rs              # Fp, Fn (ConstMontyForm wrappers), curve constants
      point.rs              # ProjectivePoint + RCB add/double (eprint 2015/1060)
      scalar_mul.rs         # mul_g (v0.3 W6: comb-table walk) + mul_var
      comb_table.rs         # v0.3 W6 — precomputed 64×16 table for k·G, spin::Once lazy init
      private_key.rs        # Sm2PrivateKey + ZeroizeOnDrop; v0.5 W5 renames `new` → `from_scalar` (under `crypto-bigint-scalar`), `from_sec1_be` → `from_bytes_be` (always-on), `to_sec1_be` → `to_bytes_be` (always-on, promoted from #[doc(hidden)])
      public_key.rs         # Sm2PublicKey; v0.3 W2 adds from_sec1_bytes / to_sec1_uncompressed + ConstantTimeEq
      sign.rs               # sign_with_id, sign_raw_with_id, compute_z, MAX_ID_LEN
      verify.rs             # verify_with_id (returns bool, rejects identity pubkey + over-long ID)
      encrypt.rs            # v0.2 Phase 3 — encrypt() + KDF + point_on_curve (pub(crate) for W2/W4)
      decrypt.rs            # v0.2 Phase 3 — decrypt() with constant-time MAC compare, zeroize on fail
      raw_ciphertext.rs     # v0.3 W4 — encode_c1c3c2 / decode_c1c3c2 / decode_c1c2c3_legacy
    sm4/                    # v0.2 W1
      cipher.rs             # Sm4Cipher (block cipher) + subtle linear-scan S-box; v0.3 W5 impls in-crate BlockCipher trait; v0.4 W2 impls cipher BlockEncrypt/Decrypt under `cipher-traits` (v0.11: cipher 0.5 BlockCipherEncrypt/Decrypt via separate Sm4Enc/DecBackend)
      sbox_bitsliced.rs     # v0.4 W3 — bitsliced GF(2^8) Itoh-Tsujii inversion; opt-in via `sm4-bitsliced`; byte-identical to linear-scan
      sbox_bitsliced_simd.rs # v0.5 W4 phase 1 — SIMD-packed dispatch path (scaffolding); opt-in via `sm4-bitsliced-simd`; phase 1 transparently delegates to sbox_bitsliced. Phase 2 (AVX2) / phase 3 (NEON) swap in real intrinsics behind the same path.
      mode_cbc.rs           # encrypt/decrypt with PKCS#7 padding; caller-supplied unpredictable IV
      cbc_streaming.rs      # v0.3 W5 — Sm4CbcEncryptor / Sm4CbcDecryptor (buffer-back-by-one on decrypt); v0.6 W6 adds decrypt_batch SIMD-fanout path
      mode_ctr.rs           # v0.7 W2 — encrypt/decrypt SM4-CTR (GM/T 0002-2012 §5.4; caller-supplied unique-per-key counter; no padding; no Option return)
      ctr_streaming.rs      # v0.7 W3 — Sm4CtrCipher (symmetric — single struct serves both directions; 16-byte leftover-keystream + position cursor state machine)
      mode_gcm.rs           # v0.8 W2 — SM4-GCM single-shot AEAD (NIST SP 800-38D / GM/T 0009 / RFC 8998; cfg-gated on `sm4-aead`); (Vec<u8>, [u8; 16]) encrypt + Option<Vec<u8>> decrypt; 12-byte canonical + arbitrary-length nonce paths; constant-time tag compare via subtle; byte-identical to gmssl 3.1.1 `sm4 -gcm`. v0.9 W1 adds GcmTagLen newtype + encrypt_with_tag_len/decrypt_with_tag_len (NIST §5.2.1.2 truncated tags {4,8,12,13,14,15,16}); inc32/derive_j0 widened to pub(super) for gcm_streaming
      mode_ccm.rs           # v0.8 W3 — SM4-CCM single-shot AEAD (NIST SP 800-38C / RFC 3610 / GM/T 0009 OID 1.2.156.10197.1.104.9; cfg-gated on `sm4-aead`); Option<Vec<u8>> encrypt (output: ct||tag) + Option<Vec<u8>> decrypt; tag_len ∈ {4,6,8,10,12,14,16}; nonce.len() ∈ [7,13]; pure-Rust CBC-MAC + CTR (no GHASH); byte-identical to OpenSSL 3.x EVP `SM4-CCM`
      gcm_streaming.rs      # v0.9 W2 — incremental-input buffered SM4-GCM (cfg-gated on `sm4-aead`). Sm4GcmEncryptor (output-streaming: update->Option<Vec<u8>>, None on >2^36-32-byte ceiling + poison; finalize/finalize_with_tag_len) + Sm4GcmDecryptor (input-incremental/output-BUFFERED: update buffers + folds GHASH, finalize_verify releases plaintext only after constant-time tag check = commit-on-verify). AAD at construction. GhashAcc incremental accumulator == single-shot ghash_a_c_lens. Differential-KAT-equal to mode_gcm across arbitrary chunking. NOT "streaming" (decryptor is O(message) memory)
      mode_xts.rs           # v0.12 — SM4-XTS single-shot tweakable mode (GB/T 17964-2021 / GM-T OID 1.2.156.10197.1.104.10; cfg-gated on `sm4-xts`; pure-core, no gmcrypto-simd dep). encrypt/decrypt(&[u8;32] Key1‖Key2, &[u8;16] tweak, &[u8] data_unit) -> Option<Vec<u8>>; full ciphertext stealing; lengths [16 B,16 MiB]; single None (len out of range or Key1==Key2). GB α-doubling = mul_alpha (bit-reflected: right-shift, masked 0xE1 into byte0 — NOT IEEE's <<1/0x87, NOT GHASH's full multiply). Whole-block bulk via Sm4Cipher::encrypt_blocks/decrypt_blocks (rides SIMD fanout). Confidentiality only, no auth. Byte-identical to OpenSSL EVP SM4-XTS xts_standard=GB. XTS_KEY_SIZE=32 re-exported. v0.15 adds encrypt_sectors/decrypt_sectors (in-place &mut [u8] -> Option<()> over a run of equal-size sectors, tweak_i = LE-128(start_sector+i); ciphers built once via split_keys + reused [[u8;16]] scratch via xts_sector_in_place; whole-block / no CTS; all validation pre-flighted so buf untouched on None; empty buf -> Some(()); no new dep/dudect target) — byte-identical to looping the single-shot per sector
    hmac.rs                 # v0.2 W3 — single-shot hmac_sm3; v0.3 W5 — streaming HmacSm3 (impls in-crate Mac trait); v0.4 W2 impls digest::Mac under `digest-traits` (v0.11: digest 0.11 — Mac is a blanket impl over Update+FixedOutput+MacMarker; HmacSm3 keeps KeyInit, construct via KeyInit::new_from_slice; crypto_common→common import)
    kdf.rs                  # v0.2 W4 — PBKDF2-HMAC-SM3 (caller-supplied output buffer)
    asn1/
      reader.rs             # v0.3 W1 — strict-canonical DER reader primitives
      writer.rs             # v0.3 W1 — DER writer primitives (16 MiB ceiling)
      oid.rs                # v0.3 W1 — const-fn OID encoder + 7 algorithm-identifier OIDs
      sig.rs                # SEQUENCE { r, s } — ports over W1 reader/writer in v0.3
      ciphertext.rs         # GM/T 0009 SM2 ciphertext SEQUENCE — ports over W1 in v0.3
    pem.rs                  # v0.3 W2 — RFC 7468 PEM + embedded base64 (hand-rolled, no_std)
    spki.rs                 # v0.3 W2 — RFC 5280 SubjectPublicKeyInfo for SM2
    x509.rs                 # v1.3 — X.509-with-SM2 LEAF cert parse + sig verify (opt-in `x509` feature; GM/T 0015 profile, v3-only, strict in-repo DER). Certificate::from_der -> Option (exact wire tbs span; sm2-sign-with-sm3 AlgId absent-or-NULL params + FULL-SPAN outer==inner; negative serial REJECT; pad-stripped serial 1..=20; one-level extensions shape-check, ZERO interpretation at parse time; BIT STRING unused==0) + verify_signature(_with_id) -> bool via verify_with_id over tbs_raw (default ID 1234567812345678; RFC 8998 §3.2.1). Parse/single-verify make NO TRUST DECISIONS (X509Time exposed, no clock). Composes asn1::reader + spki::decode + verify_with_id; public inputs only -> NO dudect target. **v1.8 (G4): KeyUsage + BasicConstraints readers (BIT STRING bit-0=MSB; path_len parsed-not-enforced) + Certificate::{key_usage,basic_constraints} accessors + MAX_CHAIN_DEPTH=8 + verify_chain(chain leaf-first, anchors, Option<X509Time>) -> bool** = single linear caller-ordered walk (per-edge verify_signature + raw-Name link + intermediate keyCertSign+CA=TRUE + try-all-anchors[sig authoritative] + unknown-CRITICAL reject {keyUsage,basicConstraints} + optional window + depth cap; anchor trusted by fiat = Name+sig+window only). private KeyUsage::parse/BasicConstraints::parse/find_extension/has_unknown_critical; #[cfg(test)] pub(crate) test_support mints SM2 certs (shared with tlcp::chain tests). Structural trust only — NOT endpoint auth; still NO dudect (public inputs)
      chain.rs (tlcp/)        # v1.8 — GB/T 38636 §4 certificate-PAIR verification (cfg-gated all(tlcp,x509)). verify_pair(sign_chain, enc_chain, anchors, Option<X509Time>) -> bool over x509::verify_chain: role keyUsage (sign digitalSignature; enc keyEncipherment|keyAgreement; keyUsage MUST be present) + leaf-NOT-CA + pair binding (non-empty + byte-equal subject + byte-equal issuer Name + SAME issuing chain = equal len + tbs_raw-equal from idx 1, the S1 closure). Single bool; endpoint identity binding stays the caller's PERMANENTLY. KATs vs GmSSL 3-level fixtures; NO dudect; fuzz_x509_chain
    tlcp/
      mod.rs                # v1.6 — TLCP (GB/T 38636-2020) crypto toolkit umbrella (opt-in `tlcp` feature; pure-core, no new dep). NOT a protocol implementation (no 5-byte header framing); grows per docs/tlcp-decomposition.md §7 (v1.7 record protection added; v1.8 chain/pair verification joins here)
      record.rs             # v1.7 — GB/T 38636 §6.3 record protection (opt-in `tlcp`; GCM parts cfg-gated on `sm4-aead`). RecordKeysCbc/RecordKeysGcm (ZeroizeOnDrop; client_half/server_half/from_key_block carve) + protect_cbc/deprotect_cbc + protect_gcm/deprotect_gcm + TLCP_RECORD_VERSION. Engine-shaped: caller-held seq:u64, injected IV RNG, type:u8/version:[u8;2] explicit, length computed internally (NEVER a deprotect param — secret post-strip length). CBC: explicit IV, MAC-then-encrypt, TLS padding; deprotect_cbc = the Lucky13 ONE-op CT path over 3 equalized surfaces (inner-hash compress count via dummy compressions on a throwaway state to public max=body−33, black_box'd; min(256,body) CT pad scan; CT MAC extraction at secret offset), bad-pad-still-MACs, single None, body.zeroize on fail; public-length guards (<48/non-16-mult/>2^14+48) before secret arithmetic. mac_equalized + inner_blocks + check_tls_padding_ct + extract_mac_ct pub(crate)/private. GCM: RFC 5288 thin wrapper over mode_gcm (salt(4)‖seq-nonce(8); AAD seq‖type‖version‖length; wire explicit_nonce(8)‖ct‖tag(16)). Widens sm3::compress to pub(crate) (reuse the audited loop). KATs = OpenSSL EVP SM4-CBC + GmSSL sm3hmac (CBC) / GmSSL sm4 -gcm (GCM); dudect ct_tlcp_cbc_deprotect + constant-blocks==HmacSm3 equivalence test; fuzz_tlcp_{cbc,gcm}_deprotect
      key_schedule.rs       # v1.6 — GB/T 38636 §6.5 key schedule: private p_sm3 (RFC 5246 §5 P_hash over HmacSm3; A-chain + blocks wiped; public loop bounds) + derive_master_secret(pre_master: &[u8;48] TYPED — TLCP pins PMS to 48 in both KX variants) + derive_key_block (seed order FLIPS server-first §6.5.2; suite-agnostic caller-carved out: CBC 128 B, GCM 40 B) + finished_verify_data/TlcpRole (12 B) + MASTER_SECRET_LEN/FINISHED_VERIFY_DATA_LEN. Engine-shaped: caller-supplied outs (pbkdf2 discipline), ZERO failure modes. KATs = OpenSSL 3.x TLS1-PRF digest:SM3 (docs/v1.6-kat-sourcing.md). NO dudect target (ct_hmac_sm3 covers the keyed primitive); NO fuzz target (typed fixed-length inputs)
    sec1.rs                 # v0.3 W2 — RFC 5915 ECPrivateKey + SEC1 uncompressed point (04||X||Y)
    pkcs8.rs                # v0.3 W2 — RFC 5958 OneAsymmetricKey + RFC 8018 PBES2 (PBKDF2-HMAC-SM3 + SM4-CBC)
    traits.rs               # v0.3 W5 — in-crate Hash / Mac / BlockCipher traits (v0.4 W2 lands RustCrypto-trait fit alongside)
  benches/timing_leaks.rs   # dudect harness — 12 targets (v0.3 added ct_pkcs8_decrypt)
  tests/                    # integration tests
    interop_gmssl.rs        # v0.2 HMAC/PBKDF2 + v0.3 W3 bidirectional SM2 sign/verify, SM2 encrypt/decrypt, SM4-CBC; v0.7 W2 adds SM4-CTR bidirectional
    v0_3_pkcs8_kat.rs       # v0.3 W2 — gmssl 3.1.1 PKCS#8/SPKI fixture round-trip
    rustcrypto_traits.rs    # v0.4 W2 — required-features-gated (digest-traits + cipher-traits); 11 trait integration tests using UFCS (v0.4 base 9 + v0.11's cipher-0.5 multi-block backend + HMAC KeyInit key-length)
    sm4_batch_api.rs        # v0.7 W1 — encrypt_blocks/decrypt_blocks byte-equivalence vs per-block + round-trip; exhaustive 0..=33
    sm4_ctr_kat.rs          # v0.7 W2 — CTR derived from SM4-ECB primitive; counter-wrap KAT; encrypt/decrypt symmetry
    sm4_gcm_kat.rs          # v0.8 W2 — SM4-GCM byte-identical to gmssl 3.1.1 across 4 KAT scenarios + tamper detection (cfg-gated on `sm4-aead`)
    sm4_ccm_kat.rs          # v0.8 W3 — SM4-CCM byte-identical to OpenSSL 3.x EVP across 8 KAT scenarios (nonce_len ∈ {7,12,13}, tag_len ∈ {4,10,16}, empty PT, empty AAD, long AAD crossing block); cfg-gated on `sm4-aead`
    x509_kat.rs             # v1.3 — gmssl-fixture KAT + adversarial negatives (cfg-gated on `x509`): field exposure vs exported SPKI keys, CA self-verify + leaf-vs-CA + wrong-key/wrong-ID rejects, FULL per-byte tbs tamper sweep, truncation sweep, negative-serial reject, serial pad-strip pin, OID swap (inner/outer/both), unused-bits reject, garbage-sig parses-but-never-verifies
    sm2_kx_kat.rs           # v1.1 — GM/T 0003.5 recommended-curve worked example, staged assertions (statics/Z -> ephemerals -> K/S_A/S_B); v1.6 adds unconfirmed_paths_reproduce_standard_k (K precedes tags so the same vector pins both completers) + confirmed-vs-unconfirmed differential at klen 16 AND 48 + invalid-peer-point rejects on both roles
    tlcp_key_schedule_kat.rs # v1.6 — key-schedule KATs vs OpenSSL TLS1-PRF digest:SM3 (cfg-gated on `tlcp`): master secret, key block 128/40/200 B (GCM carve = prefix pin; multi-iteration), Finished both roles + role-separation, zero-length out, seed-order-flip negative
    sm4_xts_kat.rs          # v0.12 W2 — SM4-XTS byte-for-byte vs OpenSSL 3.x EVP `SM4-XTS` with xts_standard=GB (whole-block 16/32/48/64 + CTS 17/20/31); cfg-gated on `sm4-xts`
    sm4_xts_sectors.rs      # v0.15 W1 — multi-sector helper: encrypt_sectors/decrypt_sectors == looping the single-shot per sector across 36 shapes, + buf-untouched-on-None + the key/buf-overlap regression; cfg-gated on `sm4-xts`
    tlcp_record_kat.rs      # v1.7 — record-protection KATs cross-validated by an INDEPENDENT oracle (OpenSSL EVP SM4-CBC + GmSSL sm3hmac for CBC; GmSSL `sm4 -gcm -aad_hex` for GCM), the maintainer-chosen W3 posture; cfg-gated on `tlcp`
    x509_chain_kat.rs       # v1.8 — chain verification over the GmSSL 3-level fixtures (root -> intermediate -> leaf). Fixtures regenerate to FRESH keys, so every assertion is structural/relational, never specific key bytes; cfg-gated on `x509`
    tlcp_chain_kat.rs       # v1.8 — TLCP [sign, enc] certificate-PAIR verification over the same fixtures (one intermediate, one shared subject DN CN=gmtest.example — a real double-cert pair); cfg-gated on `tlcp,x509`
    rustcrypto_aead_traits.rs # v1.11 — aead 0.6 trait surface for Sm4Gcm/Sm4Ccm (14 tests). Its OWN [[test]] target with required-features=["aead-traits"] (Q11.10) — folding it into rustcrypto_traits.rs would widen THAT target's required-features and silently unwire its existing CI leg. A plain `cargo test --workspace` never builds it; see the Commands block.
    data/                   # v0.3 W2 binary KAT fixtures + regen recipe (Q7.9 decision); v0.8 W3 adds sm4_ccm_oracle.c (OpenSSL EVP harness)

crates/gmcrypto-c/          # v0.4 W4 — C ABI shim (cdylib + staticlib + rlib)
  src/lib.rs                # 104 FFI entry points (44 base + v0.9 W4's 6 single-shot AEAD + v0.10's 9 streaming AEAD + v0.13's 2 single-shot XTS + v0.16's 2 multi-sector XTS): opaque handles, ffi_guard catch_unwind, GMCRYPTO_ERR on every error. AEAD symbols (gmcrypto_sm4_gcm_* / gmcrypto_sm4_ccm_*) cfg-gated on a forwarding `sm4-aead` feature (= ["gmcrypto-core/sm4-aead"]). v0.10 W1-W2 adds 2 opaque types gmcrypto_sm4_gcm_{encryptor,decryptor}_t + 9 symbols (encryptor new/update/finalize/finalize_with_tag_len/free output-streaming; decryptor new/update/finalize_verify/free commit-on-verify); _finalize* consume+free. v0.13 adds gmcrypto_sm4_xts_encrypt/_decrypt (single-shot, no handles, no opaque struct) + always-on const GMCRYPTO_SM4_XTS_KEY_SIZE=32, cfg-gated on a forwarding `sm4-xts` feature (= ["gmcrypto-core/sm4-xts"]); regen-header need NOT imply sm4-xts (free fns + const emit from source regardless of cfg). v0.16 adds gmcrypto_sm4_xts_encrypt_sectors/_decrypt_sectors (in-place buf: *mut u8 + buf_len, start_sector: u64, tweak = LE-128(start_sector+i); NO out/out_capacity/out_actual_len — deliberate in-place divergence mirroring core's &mut [u8]; key copied into owned [u8;32] before &mut buf is built to avoid &/&mut aliasing UB on a caller key/buf overlap), same forwarding sm4-xts feature. **v0.23 W3: the AEAD (gcm/ccm) + XTS FFI symbols are now ALWAYS-ON** — the forwarding `sm4-aead`/`sm4-xts` cargo features on the C shim were DROPPED, so the default `cargo build -p gmcrypto-c` exports every symbol and the committed gmcrypto.h == the default build (resolves the header⟷build mismatch); the C shim's default build now transitively pulls gmcrypto-simd (gmcrypto-core keeps its own feature gates). The GCM-encrypt FFI already returned an error code, so making core's single-shot GCM encrypt fallible needs no ABI change. **v1.2 adds the 9 SM2-KX symbols + 2 opaque handles (gmcrypto_sm2_kx_{initiator,responder}_t) + GMCRYPTO_SM2_KX_CONFIRM_SIZE=32 (72 entry points total; always-on — sm2-key-exchange enabled unconditionally on the core dep): initiator born-waiting (_new writes R_A), _confirm/_finish consume+free, failed-_respond spends the handle / misuse second-_respond preserves Waiting; SysRng + _with_rng (CallbackRng); id_len==0 -> DEFAULT_SIGNER_ID; caller wipes key_out.** **v1.4 adds the 13 X.509 symbols + 1 opaque handle (gmcrypto_x509_certificate_t, immutable — accessors take const*, no consume-on-use) + 1 plain repr(C) struct (gmcrypto_x509_time_t) = 85 entry points total (always-on — x509 enabled unconditionally on the core dep): _from_der returns handle/NULL; 5 copy-out raw accessors via the shared x509_copy_out helper (closure MUST be `move` — by-ref capture of the generic getter fails ffi_guard's UnwindSafe bound); extensions_raw *out_actual_len==0 <=> absent; verify(_with_id) takes an issuer pubkey HANDLE and reuses signer_id_or_default (the v1.2 KX helper, renamed at v1.4 when a second domain began sharing it) for the id_len==0 default; is_self_issued = out-param + status (a bare 1/0 return would falsify the header banner's universal 0-on-success contract); _subject_public_key returns a NEWLY allocated gmcrypto_sm2_pubkey_t (caller frees).** **v1.9 adds the 19 TLCP toolkit symbols + 2 opaque ZeroizeOnDrop record-key handles (gmcrypto_tlcp_record_keys_{cbc,gcm}_t) + 7 consts = 85 → 104 entry points (always-on — tlcp added to the core-dep features): key schedule (derive_master_secret/derive_key_block/finished_verify_data, byte-in/byte-out no handle; tlcp_role maps int 0/1 → TlcpRole); no-confirm KX completers (initiator_derive_unconfirmed; responder_respond_unconfirmed[_with_rng]) consuming+freeing the v1.2 handles via Box::from_raw + a Fresh-variant match (the _finish precedent, NOT take-and-replace); record carriers _new(role,key_block)/_free + protect_cbc[_with_rng]/deprotect_cbc/protect_gcm/deprotect_gcm (copy-out via write_output Some-ONLY on the None path → no output touched; NO length-in param); verify_chain + tlcp_verify_pair (collect_cert_refs builds Vec<&Certificate> from the *const*const handle array, (NULL,0)=empty / NULL-elem=ERR; x509_time_from_c maps the C time struct — there is NO reverse From; out-param verdict + status) + key_usage/basic_constraints readers. CallbackRng reused verbatim for protect_cbc_with_rng + the no-confirm responder. Outputs STAGED (no R_B/key/IV write until the core Ok).**
  build.rs                  # cbindgen runs only under `regen-header` feature or GMCRYPTO_C_REGEN_HEADER=1
  cbindgen.toml             # cbindgen config (C language, include_guard = "GMCRYPTO_H_")
  include/gmcrypto.h        # committed header (CI gates drift via `git diff --exit-code`). cbindgen does NOT evaluate #[cfg(feature)] for free functions (single-shot AEAD prototypes appear unconditionally) BUT it DROPS cfg-gated opaque struct types (v0.10's gmcrypto_sm4_gcm_{encryptor,decryptor}_t) when the feature is inactive. So v0.10 makes `regen-header` IMPLY `sm4-aead` — regen is then deterministic + complete and the drift gate stays green with the documented `--features regen-header` command
  examples/sm2_sign.c       # end-to-end C example
  examples/sm4_gcm_streaming.c # v0.10 — chunked SM4-GCM streaming AEAD round-trip via the C ABI (doc-only; CI does not build C examples)
  examples/sm4_xts_sector.c # v0.13 — 512-byte SM4-XTS sector encrypt/decrypt round-trip via the C ABI (sector# as tweak; doc-only)
  examples/sm4_xts_multisector.c # v0.16 — in-place 8-sector ("disk region") SM4-XTS round-trip via the C ABI (start_sector: u64, auto-incrementing tweak; doc-only)
  examples/sm2_key_exchange.c # v1.2 — full two-party GM/T 0003.3 handshake via the C ABI (both tags verified, keys agree; doc-only, but compiled+run locally at dev time)
  examples/x509_verify.c    # v1.4 — leaf-vs-issuer certificate signature verification via the C ABI (argv DER paths; prints serial + validity, never checks a clock; doc-only, compiled+run locally at dev time)
  examples/tlcp_handshake.c # v1.9 — full TLCP handshake-to-record flow via the C ABI: no-confirm SM2-KX → derive_master_secret/derive_key_block → SM4-CBC record protect/deprotect round-trip → Finished verify_data (two embedded static keypairs; doc-only, compiled+run locally)
  examples/tlcp_verify_pair.c # v1.9 — TLCP [sign,enc] certificate-pair verification via the C ABI (argv DER paths → verify_pair; loudly NOT endpoint auth; a real gmssl pair verifies end-to-end; doc-only, compiled+run locally)
  tests/c_smoke.rs          # 97 Rust-equivalence tests via extern "C" interop (+13 v1.9 TLCP: key-schedule equivalence vs core + bad-role/null; no-confirm KX FFI handshake agreement + _with_rng + Waiting-handle single-ERR; record CBC protect/deprotect round-trip + cross-deprotect vs core + the bad-pad≡bad-MAC oracle test [valid-pad-bad-MAC via seq-mismatch; both single-ERR, out + out_actual_len untouched] + GCM round-trip/tamper + bad-role/null carriers; verify_chain==core + NULL semantics ((NULL,0)=empty, NULL-elem/(NULL,n)=ERR, over-depth=verdict) + verify_pair valid + role-swap reject + readers vs core) (35 default + 14 cfg-gated on sm4-aead: 6 v0.9 single-shot + 8 v0.10 streaming; + 16 cfg-gated on sm4-xts: 5 v0.13 single-shot whole-block/CTS equivalence + round-trip + short/weak-key/small-buffer errors, + 11 v0.16 multi-sector: equivalence-vs-core + round-trip + byte-boundary/high-LBA starts + bad sector_size/buf-multiple/weak-key/null-key/null-buf/empty + decrypt-side errors + key/buf-overlap regression; + 11 v1.2 SM2-KX: FFI<->FFI handshake, FFI<->Rust cross-handshakes both directions, the GM/T 0003.5 KAT byte-for-byte through the ABI via _with_rng fixed ephemerals, tampered-S_A/S_B, off-curve-R_A + spent-handle, double-respond state preservation, finish-before-respond, null/bad-klen/null-callback rejects; + 8 v1.4 X.509: accessor byte-equivalence vs core on BOTH gmssl fixtures incl. the CA serial pad-strip pin, extensions-absent via strip-the-[3]-block surgery, verify matrix (CA self-verify/leaf-vs-CA/wrong-key/wrong-ID/tampered-tbs), times+self-issued vs core, subject-key handle composition, copy-out too-small + NULL sweeps)
  README.md                 # C/C++/Python/Go/Zig integration docs

crates/gmcrypto-simd/       # v0.5 W4 phase 2 / v0.6 W6 / v0.8 W1 — SIMD backend crate (rlib-only, opt-in via gmcrypto-core's sm4-bitsliced-simd or sm4-aead feature)
  src/lib.rs                # `#![no_std]` + `#![allow(unsafe_code)]` (per-decl noise; Cargo.toml lint stays `warn` for intent); re-exports `has_avx2()`
  src/detect.rs             # `cpufeatures::new!(..., "avx2")` + `has_avx2()` wrapper (cached); x86_64-only
  src/sm4/scalar.rs         # local re-impl of v0.4 W3 Boyar-Peralta gate sequence (sbox_byte, const fn); fallback path for every SIMD entry
  src/sm4/avx2.rs           # x86_64-only — shared AVX2 byte-parallel primitives (gf_mul, gf_inv, affine_a, parity, sbox_round) on `__m256i`
  src/sm4/neon.rs           # aarch64-only — shared NEON byte-parallel primitives on `uint8x16_t`; compile-time baseline, no runtime detect
  src/sm4/sbox_x8.rs        # AVX2 path: 8 bytes packed in low lanes of __m256i (24 wasted); used by phase 2 `tau` per-byte dispatch
  src/sm4/sbox_x32.rs       # v0.6 W6 — AVX2 32-byte full-width packed S-box; used by phase 3 8-block CBC-decrypt batch
  src/sm4/sbox_x16.rs       # v0.6 W6 — NEON 16-byte packed S-box on aarch64; used by phase 3 4-block CBC-decrypt batch
  tests/lane_equivalence.rs # v0.5 W4 phase 2 — exhaustive cross-check of sbox_x8 vs inline GB/T 32907-2016 §6.2 S-box table
  tests/lane_position_x32.rs # v0.6 W6 — lane-position-shifted exhaustive sweep for sbox_x32 (256 × 32 = 8192 cases); codex's phase 3 flag #4
  tests/lane_position_x16.rs # v0.6 W6 — same for sbox_x16 (256 × 16 = 4096 cases)
  src/ghash/mod.rs          # v0.8 W1 — public dispatch `ghash_mul(h, x) -> [u8; 16]` selects CLMUL/PMULL/software at runtime
  src/ghash/software.rs     # v0.8 W1 — constant-time bit-serial GF(2^128) fallback (mask-XOR; no branches on H or X)
  src/ghash/clmul.rs        # v0.8 W1 — x86_64 PCLMULQDQ + SSE2 schoolbook 4-multiply + bit-serial descending-order reduction
  src/ghash/pmull.rs        # v0.8 W1 — aarch64 NEON `vmull_p64` schoolbook 4-multiply + same reduction shape as clmul
  tests/ghash_kat.rs        # v0.8 W1 — NIST-derived GHASH triple (H, X, Y) regression KAT across all three dispatch paths
  tests/ghash_lane_equivalence.rs # v0.8 W1 — software vs CLMUL vs PMULL byte-equivalence sweep over 75 inputs (random + structural edges)

fuzz/                       # v0.14 — cargo-fuzz (libFuzzer) harness. ITS OWN WORKSPACE (empty [workspace] table) + parent exclude=["fuzz"] → nightly-only libfuzzer-sys/arbitrary deps never enter the published 3-crate graph; unpublished, NOT MSRV-bound, NOT in cargo deny. fuzz/Cargo.lock IS committed (.gitignore anchors /Cargo.lock to root so it isn't swallowed). 33 targets (v0.14's 16 + v0.20's 2 streaming-decryptor differential + #98/#99's 7 post-1.0 hardening [SM3/HMAC-SM3/C-ABI/SM4-mode-encrypt] + v1.1's fuzz_sm2_kx + v1.3's fuzz_x509 + v1.7's fuzz_tlcp_{cbc,gcm}_deprotect + v1.8's fuzz_x509_chain + **v1.10's fuzz_sm4_xts_sectors + fuzz_sm4_gcm_tag_len_roundtrip** + **v1.11's fuzz_sm4_aead_traits**, the aead-0.6 trait-path-vs-inherent-path differential that guards the thin-wrapper premise behind v1.11's no-new-dudect-target decision); v0.14's prove the failure-mode invariant (no panic/OOM/hang), v0.20's prove streaming==single-shot; initial sweeps zero crashes (+ zero divergences for v0.20). **v1.10 also upgraded the 4 DER parser targets (fuzz_sig / fuzz_spki / fuzz_sm2_ciphertext_der / fuzz_sm2_raw_ciphertext) from no-panic to BYTE-IDEMPOTENCE — `encode(decode(x)) == x`, which needs no PartialEq on a published type (adding a derive to serve a fuzz target would be an api-baseline change) and catches a decoder admitting a second spelling of the same value; the raw target also gained an is_some()-parity differential vs decode_c1c2c3_legacy, whose validation prologue is a byte-for-byte duplicate.** The FUZZ_TARGETS list in fuzz-nightly.yml MUST name every [[bin]] — a target absent there builds (fuzz-build.yml) but is silently never fuzzed (the #98/#99 drift, fixed post-#101). **This is now ENFORCED**, not prose: fuzz-nightly.yml has a preflight step that parses the `[[bin]]` names out of fuzz/Cargo.toml and fails with `config drift, NOT a crash` naming any target missing from FUZZ_TARGETS (it sits beside the per-target seeds-dir preflight, which guards the other half of the same failure).
  Cargo.toml                # gmcrypto-core path dep w/ features=["sm4-aead","sm4-xts","sm2-key-exchange","x509","tlcp","aead-traits"] always on (no per-target feature juggling); 33 [[bin]] entries; empty [workspace]
  fuzz_targets/             # fuzz_pem, fuzz_pkcs8_{decode,decrypt}, fuzz_spki, fuzz_sec1, fuzz_sig, fuzz_asn1_reader, fuzz_sm2_{ciphertext_der,raw_ciphertext,pubkey_sec1,decrypt,verify}, fuzz_sm4_{cbc,gcm,ccm,xts}_decrypt + v0.20 fuzz_sm4_{cbc,gcm}_streaming_decrypt (DIFFERENTIAL: streaming Sm4{Cbc,Gcm}Decryptor fed in arbitrary chunks == single-shot mode_{cbc,gcm}::decrypt; layouts add a chunk_len byte) + #98/#99 fuzz_sm3 / fuzz_hmac_sm3 (one-shot==streaming differentials), fuzz_c_abi (raw-pointer extern "C" surface), fuzz_sm4_{cbc,gcm}_encrypt (encrypt differentials + round-trip), fuzz_sm4_{ccm,xts}_encrypt (encrypt→decrypt round-trips) + v1.1 fuzz_sm2_kx ([R_B:65][S_B:32] adversarial peer bytes; v1.6: THREE paths per input — confirm + derive_without_key_confirmation + respond_without_key_confirmation with the same 65 B as R_A; no dispatch byte, seed format unchanged) + v1.3 fuzz_x509 (certificate decode + verify; seeds = the gmssl KAT fixtures) + v1.7 fuzz_tlcp_{cbc,gcm}_deprotect (adversarial record bodies, layout [kb][seq:8][record]; the CBC one drives the Lucky13 deprotect; seeds = 2 each — `valid_record`/`valid_empty`, genuinely protected records, ADDED 2026-07-28: shipping these two with NO seeds dir made libFuzzer exit before running a single input, which fuzz-nightly mis-reported as `CRASH` for 44 consecutive nights while the Lucky13 path went entirely unfuzzed — the workflow now preflights a seeds dir per target) + v1.8 fuzz_x509_chain (BE-u16-length-prefixed DER blobs -> from_der each -> verify_chain + verify_pair over chain/anchor splittings; no-panic; seed = the 4 gmssl chain fixtures length-prefixed). SM4 targets carve key/iv/nonce/aad/tag via FRONT-consuming arbitrary::Unstructured (so seeds are plain concatenations; pinned to arbitrary 1.4.2 order). sm2_decrypt/verify use a fixed test key via OnceLock. v1.9 extended fuzz_c_abi with op 9 (verify_chain + verify_pair + readers over attacker cert-handle arrays, BE-u16-prefixed DER blobs; frees each handle once) + op 10 (deprotect_cbc/gcm over attacker record bytes vs fixed carriers); FUZZ_OP_COUNT 9 → 11, all seeds audited (op bytes 7/1/8 still select 7/1/8 under %11), new seed tlcp_verify_chain_op; census stays 30.
  seeds/<target>/           # committed curated valid seeds (from a one-time generator using gmcrypto-core's encode/sign/encrypt). corpus/, target/, artifacts/ are gitignored.
  README.md                 # build/run/repro runbook + seed-regen recipe

.github/workflows/
  ci.yml                    # 7 jobs (v0.17+). FIVE on GitHub-hosted macos-14 (aarch64): build/test (stable, full) + msrv (1.85, build-only) + cabi + cargo-deny + wasm32 matrix. TWO on Linux/x86_64: simd-x86 (ubuntu-latest, F17 — the AVX2/PCLMULQDQ paths aarch64 can't reach) + interop-gmssl (ubuntu-24.04, F16 — v1.10; gmssl cross-validation against a PINNED from-source GmSSL build, non-gating via continue-on-error). Per-feature clippy passes (digest-traits, cipher-traits, sm4-bitsliced, sm4-bitsliced-simd, crypto-bigint-scalar). concurrency: cancel-in-progress. UNAFFECTED by fuzz/ (excluded).
  dudect-pr.yml             # 10K samples on ubuntu-24.04 (v0.18 pin), |tau| gate, matrix on features=[default, sm4-bitsliced, sm4-bitsliced-simd, "sm4-bitsliced-simd,sm4-aead,sm4-xts"] (4 legs; the 4th gates the AEAD/XTS CT targets), path-allowlisted (incl. gmcrypto-simd/src/**), concurrency: cancel-in-progress
  dudect-nightly.yml        # 100K samples on ubuntu-24.04 (v0.18 pin), same gate + matrix, 30-day artifact retention; concurrency: cancel-in-progress=false (a partial 100K run is wasted compute). PR #38 drops the push:main trigger in favour of cron-only (regression watch) + workflow_dispatch (manual reruns).
  fuzz-nightly.yml          # v0.14 — capped cargo-fuzz sweep over all 33 targets (v0.20: FUZZ_TARGETS env is the single source of truth — MUST name every fuzz/Cargo.toml [[bin]], see the fuzz/ entry above) on GitHub-hosted ubuntu-latest (v0.17+; cron 06:00 UTC + workflow_dispatch w/ max_total_time input; installs nightly + pinned cargo-fuzz 0.13.1 per run; -max_total_time/-rss_limit_mb/-timeout caps; crash-artifact upload 30d; concurrency cancel-in-progress=false). NOT a PR gate. v0.20 adds a SEPARATE non-gating `coverage` job: cargo +nightly fuzz coverage per target over committed seeds → llvm-cov TOTALS SUMMARY.txt artifact (report-as-deliverable, no %-gate).
  fuzz-build.yml            # F18 (post-1.0 hardening) — PR-time `cargo +nightly fuzz build` (BUILD ONLY, no run) on ubuntu-latest, so a fuzz target that stops COMPILING (a changed gmcrypto-core public type / renamed decode entry) fails at PR time instead of ~24h later in fuzz-nightly. Triggers pull_request + push:main (path-filtered: fuzz/**, crates/gmcrypto-{core,simd}/**, Cargo.toml, the workflow itself) + workflow_dispatch; permissions: contents:read; concurrency cancel-in-progress. Caches the pinned cargo-fuzz 0.13.1 binary (actions/cache, since taiki-e/install-action has no cargo-fuzz manifest) + the fuzz target dir (rust-cache, workspaces: fuzz). **NOT a required check** — do NOT add it to branch protection while it keeps the `paths:` filter (a docs-only PR would never trigger it → permanent "Expected" block, the #90/#91 trap; drop the filter first if it must be required). The fuzzing RUN stays nightly-only.
  api-stability.yml         # v0.21 — 4 legs on ubuntu-latest (PR + push:main + workflow_dispatch): (1) public-api drift-check ENFORCED — regenerate docs/api-baseline/*.txt with PINNED cargo-public-api 0.52.0 + nightly-2026-05-23 (--omit blanket/auto-trait/auto-derived) + git diff --exit-code (the cbindgen-header pattern; bumping a pin = a reviewed re-baseline); (2) cargo-semver-checks ENFORCED from 1.0 (no continue-on-error; check-release vs the latest crates.io release; the forward breaking-change gate, flipped in #86); (3) cargo doc -D warnings -A rustdoc::private_intra_doc_links (per-crate so gmcrypto-c regen-header isn't triggered); (4) feature matrix --no-default-features + --all-features. The C ABI's guard stays the cbindgen header drift-check in ci.yml. NOT a publish gate.

docs/
  v0.1.0-release-review.md      # pre-publish reviewer checklist (template)
  v0.2.0-release-review.md      # v0.2 pre-publish reviewer checklist
  v0.3-scope.md                 # v0.3 scope doc + Q7.1–Q7.10 sign-off decisions
  v0.4-scope.md                 # v0.4 scope doc + Q4.1–Q4.19 sign-off decisions
  v0.5-scope.md                 # v0.5 scope doc + Q5.x sign-off decisions (Q5.11 SIMD architectural reset)
  v0.5-dudect-recalibration.md  # 2026-05-12 GH runner-image noise-floor analysis + sentinel posture
  v0.6-scope.md                 # v0.6 scope doc + Q6.1–Q6.10 sign-off decisions (W4 phase 3 / W6)
  v0.7-aead-scope.md            # v0.7 W4 — design cycle scope doc for v0.8 SM4-GCM + SM4-CCM (Q8.1–Q8.8 + v0.9 candidate Q-list); Q8.4 backref to W0 resolution
  v0.8-ccm-kat-sourcing.md      # v0.8 W0 — sourcing decision for SM4-CCM KAT vectors (OpenSSL 3.x EVP `SM4-CCM`; gmssl 3.1.1 lacks `-ccm`); embedded C harness + parametric coverage matrix
  v0.14-scope.md                # v0.14 W0 — parser-fuzzing scope (Q14.1–Q14.12, codex-reviewed); 16 cargo-fuzz targets over the untrusted-input decode/decrypt surface; assurance-only (clean run ⇒ no crates.io release per Q14.11); §6 v0.15 candidate Q-list
  v0.21-scope.md                # v0.21 W0 — v1.0-readiness-audit scope (Q21.1–Q21.9, codex-reviewed); non-publishing; Option A finalization; the public-api/semver-checks/cargo-doc guard set
  v1.2-scope.md                 # v1.2 — C FFI for SM2 key exchange scope (Q2.1–Q2.10; maintainer-signed Q2.1–Q2.3); X.509-with-SM2 deferred to v1.3
  v1.5-scope.md                 # v1.5 — TLCP-decomposition cycle charter (Q5.1–Q5.5, maintainer-signed; non-publishing); records the O3-toolkit end-state + v1.6 = key schedule + no-confirm KX
  tlcp-decomposition.md         # v1.5 deliverable — GB/T 38636 TLCP mapped onto cycles: wire anatomy, gap analysis G1–G5, the derived chain/pair profile (§4 — NOT server authentication), record-CT API constraints (§6), cycle map v1.6→v1.9 (§7), D-1…D-12 verification items (§8); codex-reviewed (W2)
  v1.6-scope.md                 # v1.6 — TLCP key schedule + no-confirm KX scope (Q6.1–Q6.10; Q6.2/Q6.3 maintainer-signed; Codex consult folded — typed PMS, loud completer names, OpenSSL recipe pins)
  v1.6-kat-sourcing.md          # v1.6 — KAT sourcing: OpenSSL TLS1-PRF digest:SM3 recipe (label-in-seed, hexsecret/hexseed, default provider) + the GM/T 0003.5 reuse rationale (K precedes tags); A5: short vectors inline in test files, nothing under tests/data/
  v1.9-scope.md                 # v1.9 — TLCP toolkit C FFI scope (Q9.1–Q9.8; 4 forks maintainer-locked + Codex consult folded): one cycle / opaque record-key handles (a deliberate revision of Q7.10) / cert-handle-ptr array + out-param verdict / SysRng+_with_rng; the inherited Q6.9/Q7.10/Q8.15 FFI-shape constraints; always-on posture
  v1.9-tlcp-ffi-plan.md         # v1.9 — TDD plan (Tasks 0–10: core refs adapter + ~19 FFI symbols + handles + header regen + c_smoke + fuzz op bump + C examples) + the W2 executed-review outcome (GO-WITH-FIXES, 6 must-fixes + 5 should-fixes folded) + the 19-symbol census lock
  v0.22-scope.md                # v0.22 W0 — API-tightening scope (Q22.1–Q22.8, codex-reviewed); resolves §3.A via Option 2 (decouple crypto-bigint); three-group map (A doc-hidden / B reshaped to [u8;32] / C kept-public ProjectivePoint); non-publishing
  v1.0-readiness.md             # v0.21 W3 (updated v0.22) — the GO/NO-GO readiness report + the 1.0.0 publish runbook; §3.A = the crypto-bigint-exposure decision, now RESOLVED in v0.22 (status flipped to GO)
  api-baseline/                 # v0.21 — committed cargo-public-api baselines (gmcrypto-core.txt = full surface; gmcrypto-simd.txt = `pub mod gmcrypto_simd` only); the drift-check contract regenerated by api-stability.yml. v0.22 regenerated gmcrypto-core.txt: Group-A curve/scalar items removed, Group-B sig/ciphertext reshaped to [u8;32], only the gated from_scalar(U256) residual remains crypto-bigint-typed
  (scope docs for v0.9–v0.13 + v0.15–v0.20 live alongside; not all relisted here)
```

`getrandom` is a direct workspace dep (`0.4.2`, `sys_rng` feature) — added
alongside the `rand_core 0.10` upgrade in `a670ce3` because `rand_core` no
longer ships `getrandom` integration in the same crate.

`spin = "0.10"` (with `default-features = false, features = ["once"]`) is
a v0.3 W6 runtime dep — the only no_std-compatible, no-unsafe primitive
for the comb-table lazy init. Per Q7.8 it's the explicit alternative to
`std::sync::LazyLock` (forbidden in `no_std`) and `once_cell::race::OnceBox`.
Added to `deny.toml`'s allowlist with a comment pointing back to Q7.8.

## Workflow notes

- **GitHub-hosted CI (v0.17+).** Five of `ci.yml`'s seven jobs (build / msrv /
  cabi / deny / wasm32) run on GitHub-hosted **`macos-14`** (aarch64); the other
  two run on Linux/x86_64 — `simd-x86` on **`ubuntu-latest`** and (v1.10)
  `interop-gmssl` on **`ubuntu-24.04`**, OS-label-pinned because a from-source
  GmSSL build's reproducibility rides the runner's compiler (this is NOT the
  dudect calibration pin — no `|tau|` is at stake — but the same discipline).
  `fuzz-nightly.yml` runs on **`ubuntu-latest`**. The two dudect workflows
  are pinned to **`ubuntu-24.04`** (v0.18) — their `|tau|` gates were empirically
  calibrated against GitHub's `ubuntu-24.04` runner-image noise floor (v0.4
  release-prep PR #22); **don't move dudect** or you invalidate the
  calibration. Through v0.16 the build jobs ran on a self-hosted macOS
  runner (to dodge private-repo minute caps); it was **retired at the v0.17
  public flip** — a self-hosted runner on a public repo is remote code
  execution (any fork PR would run on the host).
- Branch model: branch + PR for all changes. Direct commits to `main` reserved
  for trivial-and-time-sensitive fixes only. CI fires on the PR (+ on the
  merge commit to `main`); dudect-pr.yml smoke is path-allowlisted so doc-only
  PRs skip the bench job. For WIP PRs that should skip CI, put `[skip ci]` /
  `[ci skip]` / `[no ci]` / `[skip actions]` in the PR title (the workflow
  `if:` checks PR title; GitHub's native skip on push events also honours
  these markers in commit messages — added in PR #38).
- Tags are SSH-signed (`gpg.format = ssh`). Verify locally with
  `git tag -v vX.Y.Z` after configuring `gpg.ssh.allowedSignersFile`.
- `cargo publish` is the irreversible step (the maintainer's authenticated call,
  not the agent's). Template: `docs/v1.0.0-release-review.md`; runbook:
  `docs/v1.0-readiness.md` §4. **Three crates ship, in this order:**
  `gmcrypto-simd` → `gmcrypto-core` → `gmcrypto-c`. The intra-workspace path-deps
  are pinned **exactly** (`=1.0.1`, the §3.D lockstep contract), so each crate must
  be live on crates.io before the next resolves (core's `=1.0.1` dep on simd won't
  resolve until simd is published; `c`'s on core likewise).

## Don't

- Don't add a `Cargo.toml` `authors` field (privacy — removed at `982a2fc`).
- **Don't add per-version scope sections or verbose history-table rows to
  README.md.** The pre-v1.4 accretion pattern (a new "## vX.Y scope" section
  + a multi-sentence roadmap row every release) grew the README to ~900
  lines with Quick-start buried at line 790; the v1.4 cycle restructured it
  reader-first (~330 lines: what-is/isn't → quick-start → crates & features
  → stability → short history-and-roadmap → build). Per-release narratives
  go to CHANGELOG.md + `docs/vX.Y-scope.md` ONLY. A release touches the
  README only where the user-facing surface changed: the intro feature
  list, the feature table, the "current release is X.Y.Z" line + the
  crates.io history chain, the quick-start, and (for FFI cycles) the entry-
  point count. The README is also the crates.io landing page for all three
  crates — keep it an evaluation/onboarding document, not a changelog.
- **Don't grow the per-cycle narrative back into CLAUDE.md.** The same
  accretion the README rule above prevents happened *here*, unchecked, at
  four times the scale: by v1.11 the version prose had reached **864 lines
  — 42% of the file, ~16K tokens loaded into every session** — and it sat
  above the constraints an agent actually needs, under no heading at all.
  It now lives in `docs/version-history.md` (newest-first, verbatim). A
  cycle prepends its paragraph **there**, and touches CLAUDE.md only where
  a *live* constraint moved: the `Release state` table, the current-cycle
  subsection (**replace** the previous cycle's — never append), the
  counts/commands/architecture map, and any new `Don't` or gotcha. If you
  find yourself writing "**Earlier — vX.Y —**" in this file, it belongs in
  `docs/version-history.md`. The test for keeping something here: *would
  an agent that never reads it break something?* If the answer is "no,
  they'd just lack context", it is history — file it.
- Don't reduce the SM2 retry-loop iteration count or short-circuit on first valid
  candidate. Fixed-K masked-select is the constant-time invariant.
- Don't reference any external "Java prototype" / `gm-crypto-lite-java` repo.
  The Rust repo is standalone; that prototype was personal scaffolding.
- Don't replace the default SM4 `subtle`-style linear-scan S-box with a
  direct LUT ("just for performance"). The throughput trade is
  documented as deliberate. v0.4 W3 added the opt-in bitsliced
  (table-less, gate-only) fast-path behind the `sm4-bitsliced` feature;
  default-features build is unchanged. **Don't widen `sm4-bitsliced`
  to a multi-block SIMD-packed bitsliced implementation in v0.4** —
  per Q4.11 that's deferred to v0.5+; the v0.4 path is single-block
  only and must stay byte-identical to the linear-scan path
  (exhaustive equivalence test in
  `sm4::sbox_bitsliced::tests::bitsliced_matches_table`).
- Don't expose the bitsliced helpers (`gf_mul`, `gf_inv`, `affine_a`)
  publicly. They're `pub(crate)` (or function-local) by design; the
  only public surface is the implicit S-box swap when
  `sm4-bitsliced` is enabled.
- Don't generate the SM4-CBC IV inside `mode_cbc::encrypt`. Per NIST SP 800-38A
  Appendix C, CBC IVs must be **unpredictable** and caller-supplied; smuggling
  an `OsRng` into the API hides the contract from callers and conflates
  primitive-level concerns with RNG selection.
- Don't make `mode_cbc::decrypt` distinguish between failure modes (length
  not multiple of 16, bad pad_len, inconsistent padding bytes). Single `None`
  per the failure-mode invariant — anything else is a padding-oracle vector.
- Don't add an iteration-count default to `pbkdf2_hmac_sm3`. Defaults age
  badly (the OWASP baseline shifts every 2-3 years); callers pick. The API
  takes `iterations: u32` for a reason.
- Don't make `pbkdf2_hmac_sm3` allocate the output buffer. The
  caller-supplied `&mut [u8]` is the API contract — it kills the
  allocation-failure question and matches RustCrypto's pbkdf2 discipline.
- Streaming `HmacSm3` lands in v0.3 W5 alongside the in-crate `Mac` trait.
  v0.3+ keeps the single-shot `hmac_sm3` function for backward compat; do
  not remove it.
- Don't ship `encode_c1c2c3_legacy` in any version. The legacy byte
  concatenation `C1||C2||C3` is **decrypt-only** in v0.3 W4
  (`decode_c1c2c3_legacy`); adding an emit path would propagate the
  legacy ordering forever.
- Don't change `mul_g`'s public signature when working on `comb_table.rs`.
  The W6 invariant is "comb-table walk under an unchanged
  `pub fn mul_g(k: &Fn) -> ProjectivePoint`".
- Don't drop the W6 `spin::Once` lazy-init primitive for "just unsafe and
  faster". `unsafe_code = forbid` is non-negotiable; the comb-table init
  needs thread-safe one-time init, and `spin::Once` is the smallest crate
  that provides it. `std::sync::LazyLock` and `std::sync::OnceLock` are
  both `std` — forbidden in `no_std`. Hand-rolled init requires `unsafe`
  (raw pointer deref of `static mut` or `AtomicPtr`).
- Don't make `sm2::decrypt` distinguish failure modes (malformed DER,
  off-curve C1, all-zero KDF, MAC mismatch). Single `Failed` variant.
  Distinguishing them is a padding-oracle / invalid-curve attack vector.
- Don't drop the `point_on_curve` check on `C1` in `sm2::decrypt`. The
  invalid-curve attack leaks `d_B` bits via a small-order rogue subgroup;
  the check is the standard ECC defense.
- Don't expose the SM2 `kdf` (in `sm2::encrypt`) or `point_on_curve`
  helpers in the public API. `kdf` is `pub(super)` for `sm2::decrypt`'s
  use only; `point_on_curve` and `projective_from_affine` are
  `pub(crate)` (widened by W2 so `spki`/`sec1`/`raw_ciphertext` can
  reuse them at the import boundary). The top-level `kdf.rs` is reserved
  for PBKDF2.
- Don't make `pkcs8::decrypt` distinguish wrong-password from malformed-
  PEM from valid-PEM-but-bad-inner-ECPrivateKey. Single `Failed`
  variant per the failure-mode invariant — anything else is a
  password-oracle / inner-ASN.1 distinguishing-attack vector.
- `Sm2PrivateKey::to_bytes_be` (v0.5 W5; was `#[doc(hidden)] pub fn
  to_sec1_be` in v0.3-0.4) returns the secret scalar as plaintext
  bytes. **Callers must zeroize the returned `[u8; 32]` themselves**
  — the SDK can't enforce zeroization on a stack-owned array. v0.5
  promotes the method to SemVer-stable; the contract is documented
  on the method.
- `gmcrypto-c`'s FFI symbol `gmcrypto_sm2_privkey_to_sec1_be` keeps
  the `sec1` suffix for v0.4→v0.5 C-ABI backcompat even though the
  Rust method renamed to `to_bytes_be`. Don't rename the FFI symbol
  — C/Go/Zig callers can't follow a Rust-side type-alias trick.
- Don't widen `unsafe_code` in `gmcrypto-c` from `warn` to `allow`,
  and don't remove the `// SAFETY:` comment on any FFI `unsafe`
  block. Per Q4.7 in `docs/v0.4-scope.md`: warn surfaces each
  `unsafe` site in clippy without forbidding the unavoidable
  `Box::from_raw` / slice-reconstruct primitives. `gmcrypto-core`
  itself stays `unsafe_code = "forbid"` — don't relax that.
- Don't add SIMD intrinsics directly to `gmcrypto-core`. Route via
  the v0.5 W4 phase 2 sibling crate `gmcrypto-simd`
  (`unsafe_code = "warn"`). The `forbid` lint on `gmcrypto-core` is
  non-negotiable; `core::arch::x86_64::*` intrinsics are all
  `unsafe fn` and `#[target_feature(enable = "avx2")] unsafe fn` is
  the only stable-Rust path on MSRV 1.85 that combines runtime AVX2
  dispatch with intrinsic calls — neither composes with `forbid`
  in the same crate. The `gmcrypto-simd` ↔ `gmcrypto-c` precedent
  is the model: unavoidable-unsafe primitives quarantined to a
  named sibling, every block carrying a `// SAFETY:` comment.
- Don't promote `gmcrypto-simd` from rlib to cdylib/staticlib.
  `gmcrypto-c` is the single C ABI surface for the workspace.
  Adding a public SIMD dylib creates ABI / support surface without
  benefit — downstream non-Rust callers get the SIMD path
  transparently when they enable the C-ABI library's
  `sm4-bitsliced-simd` feature.
- Don't widen the `gmcrypto-simd` public API beyond Rust-internal
  use. No raw pointers across the crate boundary, no extern "C"
  shapes. The public API is `sbox_x8(&[u8; 8]) -> [u8; 8]` plus
  `has_avx2()`; phase 3 adds equivalents for NEON. Anything else
  invites the same "fixed-shape FFI primitives" problems the C-ABI
  shim already has — keep them in `gmcrypto-c`.
- Don't add a `cpufeatures` check inside an inner SM4 loop in
  `gmcrypto-core`. The detection is cached in `gmcrypto-simd`'s
  `detect.rs` already; the single per-call cost is acceptable for
  phase 2's per-`tau` shape. Phase 3's `Sm4CbcDecryptor` fanout
  amortizes the call over an 8-block batch — that's the right
  level. Don't pull `cpufeatures` into `gmcrypto-core` directly to
  "skip the indirection."
- Don't make any C ABI entry point distinguish failure modes. Every
  error path returns `GMCRYPTO_FAILED` (single failure code).
  Distinguishing wrong-password from malformed-PEM from MAC-mismatch
  through the C surface re-introduces the oracle attacks the
  Rust-side failure-mode invariant defends against.
- Don't add an RNG callback to the C ABI in v0.4. Per Q4.18, RNG is
  sourced via `getrandom::SysRng` internally; adding a callback
  shape is a v0.5+ candidate when the trade-off can be designed
  alongside multi-block bitslicing.
- Don't pull `getrandom`'s `wasm_js` backend into `gmcrypto-core`'s
  default dep graph. Per Q4.2, wasm callers wire their own
  `rand_core::Rng` impl by enabling `getrandom`'s `wasm_js` feature
  in *their own* `Cargo.toml`. Adding it to ours hides the contract
  from callers and bloats the no-wasm target.
- Don't implement SM4-XTS (`sm4::mode_xts`) per **IEEE 1619**. v0.12
  targets **GB/T 17964-2021** (`xts_standard=GB`, OpenSSL's default for
  SM4-XTS, the SM4 national standard). The two differ in the GF(2¹²⁸)
  tweak doubling: GB is **bit-reflected** (`mul_alpha` = right-shift,
  reduce `0xE1` into byte 0); IEEE is `<<1` / `0x87`. They produce
  identical block-0 output but diverge from block 1 onward. The KAT
  oracle pins `xts_standard=GB`; an IEEE impl fails it.
- Don't branch on the XTS tweak in `mul_alpha` — `T = SM4_E(Key2, ·)` is
  secret-derived. The carry reduction must stay a masked XOR
  (`t[0] ^= 0xE1 & carry.wrapping_neg()`), never an `if`.
- Don't add `gmcrypto-simd` (or any dep) to the `sm4-xts` feature. The
  XTS α-doubling is a trivial multiply-by-x, **not** GHASH's full
  carryless multiply — it lives in `gmcrypto-core`. `sm4-xts = []`.
- Don't relax `Key1 == Key2 → None` in `mode_xts`. It's a GB/T 17964 /
  FIPS weak-key guard (stricter than OpenSSL's default provider, which
  permits equal halves). The compare is constant-time (`subtle`); only
  the equal/not-equal *outcome* gates the reject.
- Don't let the XTS API generate or reuse tweaks. Per-data-unit
  tweak-uniqueness under a key is the caller's contract (the tweak is
  the sector number); reuse leaks equality structure. And XTS is
  **confidentiality only** — never imply it authenticates.
- Don't forget `MATRIX_FEATURES` must be re-declared on the dudect
  "Parse and gate" step (`env` is step-scoped). Without it the
  feature-conditional `|tau|` gates silently never fire (the v0.12 W3
  latent-bug fix).
- Don't bump the dudect `dtolnay/rust-toolchain@1.95.0` pin or the
  `runs-on: ubuntu-24.04` casually (v0.18). A deliberate toolchain/image
  bump is a **reviewed re-baseline**: bump → dispatch the nightly several
  times (`gh workflow run dudect-nightly.yml --ref <branch>`) → confirm the
  per-target medians are stable → record the new floor (with the run's
  `ImageVersion` + kernel) in `docs/v0.5-dudect-recalibration.md`. The pin is
  the load-bearing drift fix; the median is the residual-noise absorber.
- Don't move the dudect multi-run median into `timing_leaks.rs` (v0.18). The
  harness has no multi-run logic and stays **byte-unchanged**; the bench loop
  (`DUDECT_RUNS`) + the per-target median/min live entirely in the workflow
  YAML + the inline Python. `required_low` + the nightly sentinel gate the
  **median**; `negative_control` gates the **min**; any required target
  measured `< N` runs FAILs (completeness).
- Don't re-promote `ct_fn_invert`/`ct_fp_invert` to a `|tau|<0.20` gate just
  because a calibration shows them quiet (v0.18 kept them on telemetry/sentinel
  despite medians ~0.01). The noise is image-sensitive + intermittent; a tight
  gate — even a 5-run median — re-flakes if it returns. They stay on telemetry
  (PR) / gross-regression sentinel @0.55 (nightly).
- **The v0.19 fix-vs-fix relative gate was FALSIFIED — don't re-add it.** v0.19
  tried gating these two against a same-input probe
  (`noise_floor_f{n,p}_invert`) on the theory that image noise would lift probe
  and target together. The 100K calibration disproved it: the probes stay
  uniformly quiet (~0.005) while the targets spike to [0.26–0.32] (`ct_fp_invert`
  median 0.2606, ratio 50). **The runner noise is in the two-input class-split
  difference (`z_small` vs `z_large` timed against each other), not the operation
  duration a fix-vs-fix probe can see**, so the probe cannot track it. The probes
  are kept as telemetry (evidence), the relative gate is non-blocking
  `REL-TELEMETRY`, and a future self-calibrating reference must be a
  **class-split-aware "noise-twin"** (two *different* inputs through a
  known-CT op), not a same-input probe — a v0.21+ revisit-door candidate
  (v0.20 codified the current posture as the settled v1.0 baseline). See
  `docs/v0.5-dudect-recalibration.md` (v0.19 resolution).
- The dudect `rust-cache` `shared-key` is keyed on `strategy.job-index`, NOT
  `${{ matrix.features }}` (v0.18 / PR #76): the multi-feature leg's comma
  breaks `Swatinem/rust-cache` (`Key ... cannot contain commas`). Keep it
  comma-free.

## Agent gotchas

- **A new opt-in feature must be added to SEVEN places, and two of them fail
  late.** The obvious five are `Cargo.toml` (dep + feature), `deny.toml`
  (allowlist), and ci.yml's test / clippy / MSRV / wasm32 legs. The two that
  bite: (1) **`api-stability.yml`'s `cargo doc` leg enumerates every opt-in
  feature by name** — a feature missing there is simply never doc-checked, and
  worse, any **intra-doc link to a cfg-gated item** (`` [`sm4::Sm4Gcm`] ``)
  written in an always-compiled doc comment becomes an unresolved link in that
  configuration, which `-D warnings` turns into a CI failure (v1.11 hit exactly
  this). Add the feature to the list AND use plain code spans, not intra-doc
  links, when referring to cfg-gated items from always-compiled docs. (2) A new
  `[[test]]` with `required-features` is **never built by `cargo test
  --workspace`** — without its own ci.yml leg the suite silently does not run.
- **MSRV 1.85** — don't use `Integer::is_multiple_of` (stable in 1.87).
  Use `n % m == 0` / `% m != 0`. Clippy catches it at PR time, but
  the detour wastes a fmt+clippy cycle.
- **Fuzz crate (`fuzz/`) is a SEPARATE workspace.** `cargo fmt --all` /
  `cargo clippy --workspace` / `cargo test --workspace` do **NOT** touch
  it (parent `exclude=["fuzz"]` + its own empty `[workspace]`). To
  fmt/lint it, target it explicitly:
  `cargo fmt --manifest-path fuzz/Cargo.toml --all` and (nightly)
  `cargo +nightly fuzz build`. Don't expect workspace-wide commands to
  cover it.
- **`cargo fuzz run <target> <dir>` WRITES new corpus units into the
  FIRST dir.** Never pass `fuzz/seeds/<target>` as the first (write)
  dir — it pollutes the committed curated seeds with machine-generated
  files (happened in v0.14 W1; had to amend). Always
  `cargo +nightly fuzz run <t> fuzz/corpus/<t> fuzz/seeds/<t>` —
  corpus (gitignored) first, seeds (read-only) second.
- **`.gitignore` `Cargo.lock` must stay anchored as `/Cargo.lock`** (root
  only), NOT a bare `Cargo.lock` — a bare pattern also ignores
  `fuzz/Cargo.lock`, which the cargo-fuzz binary workspace pins and
  commits. (W0 codex finding.)
- **SM4 fuzz-target seed layouts are pinned to `arbitrary 1.4.2`'s
  front-consuming read order** (key/iv/nonce/aad/tag carved with
  `arbitrary::<[u8;N]>()` / `arbitrary::<u8>()` / `bytes(n)` / `take_rest`
  — all front; only `int_in_range` / collection-length read from the
  tail, which these targets avoid). Bumping `arbitrary` ⇒ re-verify the
  order and regenerate the four `fuzz_sm4_*` seeds. Pin is held by
  `fuzz/Cargo.lock`.
- **A new minor cycle does NOT always mean a crates.io release.** v0.14
  was an *assurance* cycle (parser fuzzing): clean fuzz run ⇒ published
  crates byte-unchanged ⇒ **no version bump, no publish** (per
  `docs/v0.14-scope.md` Q14.11). Don't reflexively bump
  `[workspace.package].version` or run `cargo publish` for a cycle that
  doesn't change a published crate. **v0.15.0 was that next code change**
  (the SM4-XTS sector helper), so workspace `version` went `0.13.0 →
  0.15.0` — **crates.io skips `0.14.0`** entirely (the unpublished fuzzing
  cycle named v0.14 in the docs is never a release; SemVer permits the gap).
  Don't try to publish a `0.14.0`.
- **SM4-XTS sector tweak is LE-128 of the sector number, not raw bytes.**
  `mode_xts::{encrypt_sectors,decrypt_sectors}` (v0.15) take a
  `start_sector: u128` and derive sector `i`'s 16-byte tweak as
  `(start_sector + i).to_le_bytes()` — the disk-XTS convention (matches the
  shipped `sm4_xts_sector.c` LE example). The single-shot `encrypt`/`decrypt`
  still take a **raw** `&[u8; 16]` tweak (caller-encoded). Don't conflate the
  two. The helper is **in-place** (`&mut [u8] -> Option<()>`); all validation
  is pre-flighted before the loop so `buf` is untouched on `None` — don't move
  a `checked_add(...)?` into the per-sector loop (it'd partially mutate `buf`
  before failing). No new dudect target (the per-sector path rides
  `ct_sm4_xts_decrypt`; sector numbers are public). **The v0.16 C FFI**
  (`gmcrypto_sm4_xts_{encrypt,decrypt}_sectors`) takes `start_sector` as a
  **`uint64_t`** (not raw bytes, not u128 — C has no portable u128; widened to
  u128 internally; a consequence is the overflow `None` is unreachable from the
  FFI) and is **in-place** (`buf: *mut u8 + buf_len`, NO
  `out`/`out_capacity`/`out_actual_len` — the only XTS FFI that diverges from
  the out-of-place convention). **Copy the 32-byte key into an owned `[u8;32]`
  before reconstructing `&mut buf`** — the in-place path holds a `&mut` over
  caller memory alongside the `&` key borrow, so a caller `key`/`buf` overlap
  would be `&`/`&mut` aliasing UB without the copy (regression-tested by
  `sm4_xts_sectors_key_buf_overlap_ok`). Don't "simplify" by reborrowing the
  key slice across the `&mut buf`.
- **`gmssl sm2keygen -out priv.pem`** writes the encrypted PKCS#8 to
  the file **and** prints the SPKI public key to stdout by default.
  Use `-pubout pub.pem` to capture it separately.
- **`gmssl sm2encrypt`** emits GM/T 0009 DER only. No `-binary` flag
  in 3.1.1 — a raw byte-concat W4 fixture cannot be sourced directly
  from gmssl.
- **Integration-test scratch dir** — use `env!("CARGO_TARGET_TMPDIR")`
  (cargo-managed; no `tempfile` dev-dep needed). v0.3 W3 interop
  tests use it.
- **Workspace version** lives at `[workspace.package].version` in the
  root `Cargo.toml`; all crates inherit via `version.workspace = true`.
  `cargo metadata --format-version 1` verifies the resolved version.
- **`cargo fmt --all` invalidates the Edit tool's file-state cache.**
  Re-Read any file you'll edit after running fmt, or Edit errors with
  "file has been modified since read".
- **Codex review prompts must stay short** (~500 words). Longer prompts
  silently hang for 25+ min with empty `--output-last-message` files
  and need `pkill -f "codex exec"`. Stack-rank focus questions; don't
  paste full file contents.
- **Stacked PRs**: `gh pr create --base <unmerged-branch>` targets an
  open PR's head. After the parent merges, GitHub auto-retargets the
  stacked PR to `main`. Used by v0.3 W2→W3 and the release-prep chain.
- **`pub(crate) const` inside a `pub(crate) mod`** trips
  clippy::pub-in-priv. Use plain `pub` on the inner items — the outer
  module's `pub(crate)` already gates visibility.
- **`dtolnay/rust-toolchain@master` with `targets:`** is known-flaky
  for non-default toolchains on GitHub-hosted Ubuntu (E0463: can't
  find crate for `core`). Always pair it with an explicit
  `rustup target add wasm32-unknown-unknown --toolchain ${MSRV}`
  step. See ci.yml's wasm32 job.
- **RustCrypto trait method resolution** (digest 0.11 / cipher 0.5 since
  v0.11): inherent methods like `HmacSm3::finalize` collide with
  `digest::Mac::finalize` when both are in scope. Use UFCS in tests:
  `<HmacSm3 as DigestMac>::finalize(chained).into_bytes()` and
  `<Sm4Cipher as CipherBlockEncrypt>::encrypt_block(&cipher, &mut block)`
  (the cipher trait is now `cipher::BlockCipherEncrypt`/`BlockCipherDecrypt`,
  not the old `BlockEncrypt`/`BlockDecrypt`). **HMAC construction** is via
  `<HmacSm3 as digest::KeyInit>::new_from_slice(key)` — `digest 0.11`'s `Mac`
  no longer carries `KeyInit`, so `Mac::new_from_slice` does not exist. Block
  values use `cipher::array::Array` (`hybrid-array`); prefer
  `KeyInit::new_from_slice` + `Array::from([u8; N])` over the deprecated
  `Array::from_slice`. See `crates/gmcrypto-core/tests/rustcrypto_traits.rs`.
- **cbindgen 0.27 doesn't recognize Rust 2024 `#[unsafe(no_mangle)]`**.
  Pin at `0.29` or later (see `gmcrypto-c/Cargo.toml`).
- **CI workflow only fires on PRs targeting `main`.** For stacked
  PRs whose base isn't `main`, fire manually via
  `gh workflow run ci.yml --ref <branch>` (workflow_dispatch added
  in `bdf4678`).
- **`cargo deny` in CI** uses the prebuilt `taiki-e/install-action@v2`
  with `tool: cargo-deny@0.19` — don't switch back to
  `cargo install --locked cargo-deny` (compiled from source, adds
  ~3 min per CI run; see `431df89`).
