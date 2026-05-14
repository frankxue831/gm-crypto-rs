# CLAUDE.md

Pure-Rust SM2/SM3/SM4 SDK. **v0.1.0–v0.5.0 published to crates.io
2026-05-10 → 2026-05-13**; **v0.5.1 tagged 2026-05-14** (W4 phase 2
— AVX2 8-way packed bitsliced SM4 S-box backend in new sibling
crate `gmcrypto-simd` with `unsafe_code = "warn"`; dudect
recalibration after the 2026-05-12 GH Actions `ubuntu-24.04`
runner-image change). **v0.6.0 prep on `main` 2026-05-14** — W4
phase 3 (THE THROUGHPUT-WIN RELEASE — milestone close-out):
`sbox_x32` (AVX2 32-byte full-width packed) + `sbox_x16` (NEON
4-way, compile-time baseline on aarch64) + `Sm4CbcDecryptor::
process_chunk` SIMD fanout (8-block batches on x86_64, 4-block
on aarch64) + new dudect target `ct_sm4_cbc_decrypt_fanout`.
No public API changes; no breaking changes — additive only.
Three-crate workspace:
`crates/gmcrypto-core/` (the no_std crypto core; default-member) +
`crates/gmcrypto-c/` (FFI shim; cdylib + staticlib + cbindgen header) +
`crates/gmcrypto-simd/` (SIMD backend; rlib-only, opt-in via
`gmcrypto-core`'s `sm4-bitsliced-simd` feature).

Read `README.md`, `SECURITY.md`, `CONTRIBUTING.md` for the user-facing posture.
This file lists the constraints a coding agent will violate by default.

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
# v0.4 W2 / W3 — opt-in features each get their own clippy pass.
cargo clippy -p gmcrypto-core --features digest-traits,cipher-traits --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features sm4-bitsliced --all-targets -- -D warnings

# Supply chain — note: --exclude-dev (dev-deps are exempt from the ban list).
cargo deny check --exclude-dev
# v0.4 W2 / W3 — second pass under the opt-in runtime feature flags
# (digest/cipher/inout/crypto-common allowlisted in deny.toml).
cargo deny --features gmcrypto-core/digest-traits,gmcrypto-core/cipher-traits,gmcrypto-core/sm4-bitsliced check --exclude-dev

# MSRV reproducibility.
cargo +1.85 build -p gmcrypto-core
cargo +1.85 build -p gmcrypto-core --features digest-traits,cipher-traits,sm4-bitsliced
cargo build -p gmcrypto-core --no-default-features  # confirms no_std posture

# v0.4 W1 — wasm32 build (caller-supplied RNG only).
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --no-default-features

# v0.4 W4 — C ABI shim build + header drift check.
cargo build -p gmcrypto-c --release
cargo build -p gmcrypto-c --features regen-header   # regenerates include/gmcrypto.h
git diff --exit-code crates/gmcrypto-c/include/gmcrypto.h
cargo test -p gmcrypto-c                            # c_smoke Rust-equivalence tests

# Dudect harness. Default 100K samples (~75s); CI smoke uses 10K.
# v0.5 W5 — the bench uses Sm2PrivateKey::from_scalar (renamed from
# `new`) which is gated on `crypto-bigint-scalar`. The [[bench]] entry
# in gmcrypto-core/Cargo.toml has required-features set, so cargo
# auto-enables it — but explicit is safer.
DUDECT_SAMPLES=10000  cargo bench --bench timing_leaks --features crypto-bigint-scalar  # PR-smoke budget
DUDECT_SAMPLES=100000 cargo bench --bench timing_leaks --features crypto-bigint-scalar  # nightly budget

# gmssl interop (gated; needs gmssl 3.1.1 installed).
GMCRYPTO_GMSSL=1 cargo test --test interop_gmssl
```

## Dudect harness gate

Located at `crates/gmcrypto-core/benches/timing_leaks.rs`. **Twelve
targets at the default / `sm4-bitsliced` budget; fourteen under
`sm4-bitsliced-simd`** (v0.3 added `ct_pkcs8_decrypt`; v0.5 W4 phase 1
added `ct_sm4_encrypt_block_bitsliced_simd` cfg-gated on
`sm4-bitsliced-simd`; v0.6 W6 added `ct_sm4_cbc_decrypt_fanout`
cfg-gated on the same feature per Q6.7 of `docs/v0.6-scope.md`). The PR-smoke and nightly workflows run the
harness under a matrix over
`features=[default, sm4-bitsliced, sm4-bitsliced-simd]` so the
`ct_sm4_key_schedule` and `ct_sm4_encrypt_block` targets are gated
under both the default linear-scan and W3 bitsliced S-box paths,
plus the v0.5 W4 SIMD-packed dispatch path:

| Target | Gate | Meaning |
|---|---|---|
| `negative_control` | `\|tau\| > 1.0` | MUST fire — proves harness wiring. |
| `ct_mul_g` | `\|tau\| < 0.20` | Fixed-base scalar mult. v0.3 W6 replaced the body with a comb-table walk; constant-time-designed lookup preserved. 10K-sample smoke after W6: `\|tau\| ≈ 0.04`. |
| `ct_mul_var` | `\|tau\| < 0.20` | Variable-base scalar mult. |
| `ct_sign` | `\|tau\| < 0.20` | `sign_raw_with_id`, class-split by private key `d` (NOT `sign_with_id` — DER is variable-time on public output). |
| `ct_sign_k_class` | nightly only: `\|tau\| < 0.25` | `sign_raw_with_id`, class-split by nonce `k` magnitude with `d` held fixed (W0; both retry nonces class-tied). v0.4 release-prep: **dropped from the PR-smoke (10K) allowlist** — observed values span [0.21–0.37] across seven runs on the GH Actions ubuntu-24.04 runner, with no structure tied to code changes. The 100K nightly gate at 0.25 is retained (signal-to-noise is meaningful there). The direct invert diagnostics (`ct_fn_invert` / `ct_fp_invert`) are the actual invert-leak regression guards at the PR budget; `ct_sign_k_class` is a composite that dilutes invert signal by ~50× per the v0.2 W0 analysis. The bench still runs (data lands in the artifact log) but doesn't gate at 10K. |
| `ct_fn_invert` | PR-smoke: **telemetry only**. Nightly: gross-regression sentinel at `\|tau\| ≥ 0.55`. | Direct `Fn::invert((1+d) mod n)` diagnostic (W0). Recalibrated 2026-05-13 — see `docs/v0.5-dudect-recalibration.md`. |
| `ct_fp_invert` | PR-smoke: **telemetry only**. Nightly: gross-regression sentinel at `\|tau\| ≥ 0.55`. | Direct `Fp::invert(Z)` diagnostic (W0). The 2026-05-12 GH Actions `ubuntu-24.04` runner-image update (image `20260413.86.1` → `20260512.134.1`, kernel `6.17.0-1010-azure` → `6.17.0-1013-azure`, Rust toolchain `1.94.1` → `1.95.0`) shifted the 100K noise floor on this target from ~0.006 (v0.2 baseline) to intermittent values in [0.29–0.40]. The 0.20 gate is no longer authoritative on the current shared runner; the gross-regression sentinel at 0.55 retains protection against a real cryptographic leak (the v0.1 `ConstMontyForm::invert` regression at `\|tau\| ≈ 0.70` would still fire). Authoritative fix (pinned / noise-isolated dudect runner) deferred to a future scope doc — see `docs/v0.5-dudect-recalibration.md`. |
| `ct_sm4_key_schedule` | `\|tau\| < 0.20` | SM4 key schedule, class-split by master key bytes (v0.2 W1). v0.4 CI also gates this under `features=sm4-bitsliced`. |
| `ct_sm4_encrypt_block` | `\|tau\| < 0.20` | SM4 "construct cipher + encrypt one block" timed under one window, class-split by master key bytes (v0.2 W1). v0.4 CI also gates this under `features=sm4-bitsliced`; 10K-sample smoke on the bitsliced path: `\|tau\| ≈ 0.025`. |
| `ct_hmac_sm3` | `\|tau\| < 0.20` | HMAC-SM3 keyed MAC, class-split by master key (v0.2 W3). Structurally covers PBKDF2-HMAC-SM3's (v0.2 W4) inner PRF, the v0.3 W5 streaming `HmacSm3` (Q7.6 deliberately skipped a separate target), and the PBKDF2 sub-path of v0.3 W2's encrypted PKCS#8 path. |
| `ct_sm2_decrypt` | `\|tau\| < 0.20` | SM2 decrypt, class-split by recipient `d_B`, fixed ciphertext encrypted to a third party so both classes fail at MAC via identical control flow (v0.2 Phase 3). |
| `ct_pkcs8_decrypt` | `\|tau\| < 0.20` | Encrypted-PKCS#8 decrypt + parse, class-split by password bytes; both classes' blobs are valid for their class's password so both succeed via identical control flow (v0.3 W2). 10K-sample smoke: `\|tau\| ≈ 0.04`. |
| `ct_sm4_encrypt_block_bitsliced_simd` | `\|tau\| < 0.20` (cfg-gated on `sm4-bitsliced-simd`) | SM4 "construct cipher + encrypt one block" timed under the SIMD-packed dispatch path (v0.5 W4). Phase 1 transparently delegates to the v0.4 single-block bitslice — byte-identical output, identical timing profile to `ct_sm4_encrypt_block` under `--features sm4-bitsliced`. Phase 2 swaps in AVX2 8-way intrinsics (runtime detect; silent fallback on non-AVX2 CPUs); phase 3 adds NEON 4-way. Same gate across all three phases. |
| `ct_sm4_cbc_decrypt_fanout` | `\|tau\| < 0.20` (cfg-gated on `sm4-bitsliced-simd`) | v0.6 W6 — Sm4CbcDecryptor's batched fanout path (`decrypt_batch`) timed under load. Class-split by master key; both classes' ciphertexts are valid encrypts under their own keys so both decrypt paths share identical control flow. Exercises `sbox_x32` (x86_64 AVX2; 8 blocks × 4 tau bytes per round = 32 bytes packed) or `sbox_x16` (aarch64 NEON; 4 blocks × 4 tau bytes per round = 16 bytes packed). Per Q6.7 of `docs/v0.6-scope.md`. |

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
CI noise floor is the moving piece.

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
    sm3.rs                  # single-file SM3 hash (impls v0.3 W5 in-crate Hash trait; v0.4 W2 impls digest::Digest under `digest-traits`)
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
      cipher.rs             # Sm4Cipher (block cipher) + subtle linear-scan S-box; v0.3 W5 impls in-crate BlockCipher trait; v0.4 W2 impls cipher::BlockEncrypt/BlockDecrypt under `cipher-traits`
      sbox_bitsliced.rs     # v0.4 W3 — bitsliced GF(2^8) Itoh-Tsujii inversion; opt-in via `sm4-bitsliced`; byte-identical to linear-scan
      sbox_bitsliced_simd.rs # v0.5 W4 phase 1 — SIMD-packed dispatch path (scaffolding); opt-in via `sm4-bitsliced-simd`; phase 1 transparently delegates to sbox_bitsliced. Phase 2 (AVX2) / phase 3 (NEON) swap in real intrinsics behind the same path.
      mode_cbc.rs           # encrypt/decrypt with PKCS#7 padding; caller-supplied unpredictable IV
      cbc_streaming.rs      # v0.3 W5 — Sm4CbcEncryptor / Sm4CbcDecryptor (buffer-back-by-one on decrypt)
    hmac.rs                 # v0.2 W3 — single-shot hmac_sm3; v0.3 W5 — streaming HmacSm3 (impls in-crate Mac trait); v0.4 W2 impls digest::Mac under `digest-traits`
    kdf.rs                  # v0.2 W4 — PBKDF2-HMAC-SM3 (caller-supplied output buffer)
    asn1/
      reader.rs             # v0.3 W1 — strict-canonical DER reader primitives
      writer.rs             # v0.3 W1 — DER writer primitives (16 MiB ceiling)
      oid.rs                # v0.3 W1 — const-fn OID encoder + 7 algorithm-identifier OIDs
      sig.rs                # SEQUENCE { r, s } — ports over W1 reader/writer in v0.3
      ciphertext.rs         # GM/T 0009 SM2 ciphertext SEQUENCE — ports over W1 in v0.3
    pem.rs                  # v0.3 W2 — RFC 7468 PEM + embedded base64 (hand-rolled, no_std)
    spki.rs                 # v0.3 W2 — RFC 5280 SubjectPublicKeyInfo for SM2
    sec1.rs                 # v0.3 W2 — RFC 5915 ECPrivateKey + SEC1 uncompressed point (04||X||Y)
    pkcs8.rs                # v0.3 W2 — RFC 5958 OneAsymmetricKey + RFC 8018 PBES2 (PBKDF2-HMAC-SM3 + SM4-CBC)
    traits.rs               # v0.3 W5 — in-crate Hash / Mac / BlockCipher traits (v0.4 W2 lands RustCrypto-trait fit alongside)
  benches/timing_leaks.rs   # dudect harness — 12 targets (v0.3 added ct_pkcs8_decrypt)
  tests/                    # integration tests
    interop_gmssl.rs        # v0.2 HMAC/PBKDF2 + v0.3 W3 bidirectional SM2 sign/verify, SM2 encrypt/decrypt, SM4-CBC
    v0_3_pkcs8_kat.rs       # v0.3 W2 — gmssl 3.1.1 PKCS#8/SPKI fixture round-trip
    rustcrypto_traits.rs    # v0.4 W2 — required-features-gated (digest-traits + cipher-traits); 9 trait integration tests using UFCS
    data/                   # v0.3 W2 binary KAT fixtures + regen recipe (Q7.9 decision)

crates/gmcrypto-c/          # v0.4 W4 — C ABI shim (cdylib + staticlib + rlib)
  src/lib.rs                # 31 FFI entry points: opaque handles, ffi_guard catch_unwind, GMCRYPTO_FAILED on every error
  build.rs                  # cbindgen runs only under `regen-header` feature or GMCRYPTO_C_REGEN_HEADER=1
  cbindgen.toml             # cbindgen config (C language, include_guard = "GMCRYPTO_H_")
  include/gmcrypto.h        # committed header (CI gates drift via `git diff --exit-code`)
  examples/sm2_sign.c       # end-to-end C example
  tests/c_smoke.rs          # 20 Rust-equivalence tests via extern "C" interop
  README.md                 # C/C++/Python/Go/Zig integration docs

crates/gmcrypto-simd/       # v0.5 W4 phase 2 / v0.6 W6 — SIMD backend crate (rlib-only, opt-in via gmcrypto-core's sm4-bitsliced-simd feature)
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

.github/workflows/
  ci.yml                    # build/test on stable (full) + 1.85 MSRV (build-only); cabi job; wasm32 matrix; cargo-deny via taiki-e/install-action
  dudect-pr.yml             # 10K samples, |tau| gate, matrix on features=[default, sm4-bitsliced], path-allowlisted
  dudect-nightly.yml        # 100K samples, same gate + matrix, 30-day artifact retention

docs/
  v0.1.0-release-review.md  # pre-publish reviewer checklist (template)
  v0.3-scope.md             # v0.3 scope doc + Q7.1–Q7.10 sign-off decisions
  v0.4-scope.md             # v0.4 scope doc + Q4.1–Q4.19 sign-off decisions
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

- **Self-hosted CI runner (v0.5+).** Private-repo Pro-plan minute caps
  drove a split: `ci.yml`'s five jobs (build / msrv / cabi / deny /
  wasm32) run on a **self-hosted macOS aarch64 runner labelled
  `gmcrypto`**; the two dudect workflows stay on `ubuntu-latest`
  because their `|tau|` gates were empirically calibrated against
  GitHub's `ubuntu-24.04` runner-image noise floor (v0.4 release-prep
  PR #22). Moving dudect would invalidate the calibration. See the
  `## Self-hosted CI runner setup` section below for the runbook.
- Branch model: direct commits to `main` for the maintainer; external PRs go
  through CI + dudect-pr.yml. The dudect smoke is path-allowlisted so doc-only
  PRs skip the bench job.
- Tags are SSH-signed (`gpg.format = ssh`). Verify locally with
  `git tag -v vX.Y.Z` after configuring `gpg.ssh.allowedSignersFile`.
- `cargo publish` is the irreversible step. Use `docs/v0.1.0-release-review.md`
  as the template before publishing v0.5. **Two crates ship**:
  `gmcrypto-core` first, then `gmcrypto-c` (path dep on core via
  `version = "0.5"` — core must be on crates.io before c can publish).

## Self-hosted CI runner setup

`ci.yml` runs on a self-hosted macOS aarch64 runner. One-time setup
per host machine:

```bash
# 1. Dedicated user — runner CANNOT read your daily-driver home dir.
#    `sysadminctl` is the modern macOS path (auto-assigns a free UID)
#    and avoids hand-rolled `dscl` boilerplate that can collide with
#    an existing UID 600. We intentionally do NOT set a login
#    password for ghrunner — it's a service account, no SSH/login
#    exposure, and `sudo -iu ghrunner` from the maintainer user
#    authenticates the maintainer, not ghrunner. Passwordless
#    service accounts are slightly more secure here.
sudo sysadminctl -addUser ghrunner -shell /bin/zsh \
  -home /Users/ghrunner -admin no
# Expect a "No clear text password ... will not allow user to use
# FDE" warning — benign for a service account. Note the assigned
# UID/GID in the output (typically 5xx / 20=staff).

# sysadminctl ASSIGNS but does NOT CREATE the home directory.
# Create it now or `sudo -iu ghrunner` will fail with
# "chdir to /Users/ghrunner: No such file or directory".
sudo mkdir /Users/ghrunner
sudo chown ghrunner:staff /Users/ghrunner
sudo chmod 700 /Users/ghrunner   # only ghrunner can read its own home

# Smoke-test before continuing:
sudo -iu ghrunner whoami   # should print: ghrunner
sudo -iu ghrunner pwd      # should print: /Users/ghrunner

# 2. Switch users + install rustup with the toolchains CI needs
sudo -iu ghrunner
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain stable
source $HOME/.cargo/env
rustup toolchain install 1.85
rustup target add wasm32-unknown-unknown --toolchain stable
rustup target add wasm32-unknown-unknown --toolchain 1.85
rustup component add clippy rustfmt --toolchain stable

# 2b. Pre-empt git's macOS keychain credential helper. The system
#     gitconfig that ships with Xcode CLT configures `credential.helper =
#     osxkeychain` globally. When git runs as a fresh user (ghrunner),
#     the first credential lookup triggers macOS Keychain Services
#     prompting "<user> wants to use the login keychain" — and ghrunner
#     has no login keychain, so the prompt is unsatisfiable and hangs
#     the runner. Override with an empty helper in ghrunner's user-
#     scoped gitconfig (written directly to sidestep `git config`'s
#     newer "no action specified" gotcha with empty-string values).
cat > ~/.gitconfig <<'INNER'
[credential]
	helper =
[safe]
	directory = *
INNER

# 3. Register the runner.
#
# 3a. Look up the latest runner version as your MAINTAINER user
#     (NOT as ghrunner — ghrunner has no `gh` auth). The
#     unauthenticated GitHub API has a 60-req/hour-per-IP cap; `gh
#     api` auto-uses your stored auth token and has a 5000/hour
#     limit. The first version of this runbook used raw `curl
#     https://api.github.com/...` and hit the rate limit on a fresh
#     setup attempt.
#
LATEST=$(gh api /repos/actions/runner/releases/latest \
  --jq '.tag_name | ltrimstr("v")')
echo "Use this version when prompted: ${LATEST}"
#
# 3b. Get TOKEN from
#     https://github.com/frankxue831/gm-crypto-rs/settings/actions/runners/new
#     (one-time-use, ~1 hour TTL).
#
# 3c. Switch to ghrunner and download + register. Substitute the
#     literal LATEST value from 3a above (ghrunner's shell does not
#     inherit it from sudo -iu).
sudo -iu ghrunner
mkdir -p ~/actions-runner && cd ~/actions-runner
LATEST=2.319.1   # <-- paste the literal version from 3a
curl -fsSL -o runner.tar.gz \
  "https://github.com/actions/runner/releases/download/v${LATEST}/actions-runner-osx-arm64-${LATEST}.tar.gz"
tar xzf runner.tar.gz
./config.sh --url https://github.com/frankxue831/gm-crypto-rs \
  --token <TOKEN> \
  --labels self-hosted,macos,arm64,gmcrypto \
  --work _work \
  --unattended

# 4. Test interactively first:
./run.sh   # Ctrl-C to stop

# 5. Once green, install as a launchd service. On macOS the runner's
#    `svc.sh` does NOT take a username argument (Linux semantics) and
#    must be invoked WITHOUT `sudo` — it installs under the current
#    user (which is `ghrunner` here per the `sudo -iu` in step 2).
./svc.sh install
./svc.sh start
./svc.sh status   # verify "active" / "Started"
```

Operational notes:

- The runner-side `_work/` directory holds checked-out repo + build
  artifacts. Persists between jobs (good for warm Cargo cache). Wipe
  with `rm -rf /Users/ghrunner/actions-runner/_work/*` (as
  `ghrunner`, no sudo) if state ever gets corrupted.
- The labels `[self-hosted, macos, arm64, gmcrypto]` are AND-ed in
  `ci.yml` (case-insensitive). Only runners matching ALL four labels
  pick up the job. The `gmcrypto` label is specific to this repo —
  important when you one day host multiple project runners on the
  same Mac.
- **Offline-runner behaviour: queued jobs sit pending until they hit
  GitHub's 24-hour timeout and then fail.** Not "indefinite". If you
  see a job stuck in `Queued`, check the runner is still healthy at
  https://github.com/frankxue831/gm-crypto-rs/settings/actions/runners
  (status should say `Idle`). Escape hatch: revert the self-hosted
  PR's `runs-on:` to `ubuntu-latest` and `git push`. Monitoring tip:
  GitHub emails the repo owner if a job fails for `no_self_hosted_
  runner_available` after the 24-hour timeout.
- The runner's CARGO_HOME (`/Users/ghrunner/.cargo/`) is pre-populated
  in step 2 with rustup + stable + 1.85 + clippy + rustfmt +
  wasm32-unknown-unknown targets. `Swatinem/rust-cache@v2` calls in
  `ci.yml` are configured with `cache-bin: "false"` so the action's
  restore step won't evict those pre-installed binaries (the
  default `cache-bin: "true"` has a known issue on long-lived
  self-hosted runners where the restore overwrites `~/.cargo/bin/`
  with whatever was in the cached snapshot).
- `Swatinem/rust-cache@v2`'s registry / target caches live under
  `/Users/ghrunner/actions-runner/_work/_cache/`. Native macOS
  filesystem makes incremental warm-cache builds significantly
  faster than the equivalent on `ubuntu-latest` (no Docker
  bind-mount).
- The dudect workflows STAY on `ubuntu-latest`. Don't move them —
  the `|tau|` gates were calibrated against GitHub's `ubuntu-24.04`
  image.

## Don't

- Don't add a `Cargo.toml` `authors` field (privacy — removed at `982a2fc`).
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

## Agent gotchas

- **MSRV 1.85** — don't use `Integer::is_multiple_of` (stable in 1.87).
  Use `n % m == 0` / `% m != 0`. Clippy catches it at PR time, but
  the detour wastes a fmt+clippy cycle.
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
- **RustCrypto trait method resolution**: inherent methods like
  `HmacSm3::finalize` collide with `digest::Mac::finalize` when both
  are in scope. Use UFCS in tests:
  `<HmacSm3 as DigestMac>::finalize(chained).into_bytes()` and
  `<Sm4Cipher as CipherBlockEncrypt>::encrypt_block(&cipher, &mut block)`.
  See `crates/gmcrypto-core/tests/rustcrypto_traits.rs`.
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
