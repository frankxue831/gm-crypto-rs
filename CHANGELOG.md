# Changelog

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased] — v0.5 development on `main`

### Changed — BREAKING (v0.5 W5)

- **Error-type unification (Q5.16).** All `Result`-returning public
  APIs in `gmcrypto-core` now use the new workspace-wide
  `gmcrypto_core::Error` enum (single `Failed` variant). The previous
  per-module enums (`sm2::SignError`, `sm2::EncryptError`,
  `sm2::DecryptError`) are **removed**; `pem::Error` and `pkcs8::Error`
  are now type aliases for the workspace-wide type. Module aliases
  `sm2::Error`, `pem::Error`, `pkcs8::Error` keep existing import
  paths working; callers matching on `SignError::Failed`,
  `EncryptError::Failed`, or `DecryptError::Failed` must migrate to
  `sm2::Error::Failed` (or `gmcrypto_core::Error::Failed`). The new
  type is `#[non_exhaustive]` so downstream **exhaustive** `match`
  arms must add a wildcard `_ => ...` (non-exhaustive's standard
  cross-crate behaviour); single-arm non-exhaustive matches and `if
  let pem::Error::Failed = _` callsites are unaffected. Failure
  semantics unchanged.
- **`Sm2PrivateKey::new(U256)` → `Sm2PrivateKey::from_scalar(U256)`
  under the new `crypto-bigint-scalar` feature flag (Q5.17).**
  Callers who don't want a transitive `crypto-bigint` dep should
  prefer the new always-on `Sm2PrivateKey::from_bytes_be(&[u8;
  32])` constructor. Migration recipe:
  ```text
  // Before v0.5:
  Sm2PrivateKey::new(d_u256)
  // After v0.5 (recommended — no crypto_bigint exposure):
  Sm2PrivateKey::from_bytes_be(&d_u256.to_be_bytes())
  // After v0.5 (with `crypto-bigint-scalar` enabled):
  Sm2PrivateKey::from_scalar(d_u256)
  ```
- **`Sm2PrivateKey::from_sec1_be` → `from_bytes_be`** (rename,
  always-on, SemVer-stable). Same `[1, n-2]` constant-time range
  check.
- **`Sm2PrivateKey::to_sec1_be` → `to_bytes_be`** (rename, always-on,
  **promoted from `#[doc(hidden)] pub` to SemVer-stable**). Caller
  is still responsible for zeroizing the returned `[u8; 32]`.
- **`std` Cargo feature flag removed (Q5.18).** It had been a no-op
  reservation since v0.3. Callers with `gmcrypto-core/std` in their
  feature list must remove the entry; no behavioural change. If a
  future v0.5.x ships a file-I/O helper, it will get a specific
  feature name like `std-file-io` rather than the generic `std`.

C ABI (`gmcrypto-c`) is unaffected — the failure path was already
`GMCRYPTO_FAILED` regardless of the Rust-side error type. FFI symbol
`gmcrypto_sm2_privkey_to_sec1_be` keeps its name for v0.4 → v0.5
C-side backcompat (the Rust implementation now calls the renamed
`to_bytes_be` internally).

### Added

- **`gmcrypto_core::Error`** — workspace-wide failure type with
  `Display` and `core::error::Error` impls. Single `Failed` variant
  (`#[non_exhaustive]`).
- **`Sm2PrivateKey::from_bytes_be(&[u8; 32]) -> CtOption<Self>`** —
  always-on, recommended public constructor. Same constant-time
  `[1, n-2]` range check as the renamed `from_scalar`.
- **`Sm2PrivateKey::to_bytes_be(&self) -> [u8; 32]`** — always-on,
  SemVer-stable promotion of v0.3's `#[doc(hidden)] pub fn
  to_sec1_be`.
- **`crypto-bigint-scalar` Cargo feature** — gates the public
  `Sm2PrivateKey::from_scalar(U256)`. Default-off.
- **v0.5 W4 phase 1** — `sm4-bitsliced-simd` opt-in feature flag
  scaffolding (Q5.10–Q5.15 in `docs/v0.5-scope.md`). Adds the new
  module `gmcrypto_core::sm4::sbox_bitsliced_simd` and wires it into
  `Sm4Cipher`'s `tau` dispatch under
  `cfg(feature = "sm4-bitsliced-simd")`. Phase 1 transparently
  delegates to the v0.4 single-block bitslice
  (`sm4::sbox_bitsliced::sbox`) — byte-identical output, identical
  timing profile. **No SIMD intrinsics in phase 1.** Phase 2 (W4
  phase-2 PR) replaces the inner body with AVX2 8-way bitsliced
  intrinsics on `x86_64` via the `safe_arch` crate (runtime CPU
  detection; silent fallback to single-block on non-AVX2 CPUs per
  Q5.13). Phase 3 adds NEON 4-way on `aarch64` and integrates the
  SIMD fast path into `Sm4CbcDecryptor` (Q5.10: CBC encryption
  stays single-block because of block-chain serialization).
  The feature-flag name is stable across all three phases; callers
  enabling `sm4-bitsliced-simd` in v0.5.0 transparently pick up the
  AVX2 / NEON fast paths as v0.5.x patch releases land. Default-off
  (Q5.15). Enabling `sm4-bitsliced-simd` also enables `sm4-bitsliced`.
- **dudect harness** — new target `ct_sm4_encrypt_block_bitsliced_simd`
  cfg-gated under `feature = "sm4-bitsliced-simd"`. Gates at
  `|tau| < 0.20` across all three phases of the W4 rollout (Q5.14).
  Both PR-smoke (10K samples) and nightly (100K samples) workflows
  add a third matrix entry under `features=sm4-bitsliced-simd`.
- **CI workflows** — `cargo test`, `cargo clippy`, MSRV build, and
  the dudect workflows all add `sm4-bitsliced-simd` to their feature
  matrices. The `cargo deny` opt-in-features pass extends to the new
  feature.

## [0.4.0] — 2026-05-12

### Added

- **v0.4 W1** — `wasm32-unknown-unknown` build target. CI gates both
  stable and MSRV (1.85) on the target via a dedicated matrix job in
  `.github/workflows/ci.yml`. The crate is `no_std + alloc` only and
  does NOT pull `getrandom`'s `wasm_js` backend or
  `wasm-bindgen` / `js-sys` into its default dep graph; wasm callers
  wire their own `rand_core::Rng` impl (typically by enabling
  `getrandom`'s `wasm_js` feature in their own `Cargo.toml`).
  Explicit `rustup target add wasm32-unknown-unknown --toolchain
  ${MSRV}` workaround for `dtolnay/rust-toolchain@master` not
  reliably installing the target for non-stable toolchains on
  GitHub-hosted Ubuntu runners. A `wasm-bindgen-test`-driven KAT
  runner is deferred to v0.5+.
- **v0.4 W2** — RustCrypto-trait fit behind opt-in feature flags
  (`digest-traits` and `cipher-traits`, per Q4.3 in
  `docs/v0.4-scope.md`). Implements `digest::Digest` for
  `gmcrypto_core::sm3::Sm3` (via `HashMarker`, `OutputSizeUser`,
  `Update`, `FixedOutput`, `Reset`, `FixedOutputReset`);
  `digest::Mac` for `gmcrypto_core::hmac::HmacSm3` (via
  `MacMarker`, `KeySizeUser` with `KeySize = U64`, `KeyInit` with a
  custom `new_from_slice` covering the variable-length-key path,
  `OutputSizeUser`, `Update`, `FixedOutput`); and `cipher::BlockCipher`
  + `BlockEncrypt` + `BlockDecrypt` + `BlockSizeUser` + `KeySizeUser`
  + `KeyInit` for `gmcrypto_core::sm4::Sm4Cipher` via the
  `BlockBackend` pattern. Default-features build is unchanged — no
  extra runtime deps. New required-features-gated integration test
  at `crates/gmcrypto-core/tests/rustcrypto_traits.rs` (nine tests
  using UFCS to disambiguate inherent vs. trait methods). New
  workspace-deny pass with the runtime opt-in features enabled gates
  the allowlist for `digest` / `cipher` / `crypto-common` / `inout`.
  Two separate flags so callers needing only one half don't pay for
  both. Pinned at major+minor (`digest = "0.10"`, `cipher = "0.4"`);
  future `digest 0.11` / `cipher 0.5` lines are a v0.5+ candidate.
- **v0.4 W3** — bitsliced (table-less, gate-only) SM4 S-box behind
  the opt-in `sm4-bitsliced` feature (Q4.9 / Q4.11 in
  `docs/v0.4-scope.md`). Boyar-Peralta-style Itoh-Tsujii inversion in
  GF(2^8) (`x^254` via additive chain in the algebraic structure
  `S(x) = A·INV(A·x ⊕ B) ⊕ B` with `A` circulant first row `0xD3`,
  `B = 0xD3`, polynomial `x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1`)
  plus two affine transformations. All `const`, all branch-free,
  zero table lookups. Byte-identical output to the default linear-
  scan S-box (exhaustive 256-input equivalence test in
  `sm4::sbox_bitsliced::tests::bitsliced_matches_table`). Constant-
  time by construction (no table lookups, no branches on secret
  bits). Single-block only in v0.4; multi-block SIMD-packed
  bitslicing deferred to v0.5+ per Q4.11. dudect harness matrix in
  `.github/workflows/dudect-{pr,nightly}.yml` adds a second entry
  (`features=sm4-bitsliced`) so the `ct_sm4_key_schedule` and
  `ct_sm4_encrypt_block` targets are gated under both feature
  configurations.
- **v0.4 W4** — `gmcrypto-c` workspace member: a thin C ABI over
  `gmcrypto-core` (cdylib + staticlib + rlib). 31 FFI entry points
  via the opaque-handle (`Box::into_raw`) pattern covering SM3 hash
  (single-shot + streaming), HMAC-SM3 (with constant-time `verify`),
  PBKDF2-HMAC-SM3, SM4 (block + CBC), and SM2 (key construction,
  sign / verify, encrypt / decrypt, PKCS#8 PEM). RNG is sourced via
  `getrandom::SysRng` internally per Q4.18; the C surface does not
  pass an RNG callback in v0.4. Every entry point follows the same
  null-check + slice-reconstruct + delegate + `write_output` pattern,
  with `ffi_guard()` wrapping `catch_unwind` so a Rust panic surfaces
  as `GMCRYPTO_FAILED` (never crosses the C ABI). Every error path
  collapses to a single `GMCRYPTO_FAILED` return code per the failure-
  mode invariant. Per Q4.7 in `docs/v0.4-scope.md`, the
  `unsafe_code = "forbid"` lint cannot apply to an FFI crate (slice
  reconstruction, `Box::from_raw`, `#[unsafe(no_mangle)]` all require
  `unsafe`); `gmcrypto-c` uses `unsafe_code = "warn"` with `// SAFETY:`
  comments on every `unsafe` block. `gmcrypto-core` itself stays
  `unsafe_code = "forbid"` workspace-wide. cbindgen 0.29 generates
  `crates/gmcrypto-c/include/gmcrypto.h`; the committed header is
  gated for drift via `git diff --exit-code` in CI (Q4.12). New
  `c_smoke` integration test exercises every entry point via Rust's
  own `extern "C"` interop and asserts Rust-equivalence. Per Q4.15,
  `gmcrypto-c` is a workspace member but NOT in `default-members`;
  most contributors work on `gmcrypto-core` and building the cdylib
  on every workspace `cargo build` would be surprising. CI explicitly
  `-p gmcrypto-c` for the FFI build / header-drift job.

### Changed

- **CI**: replaced `cargo install --locked cargo-deny` with
  `taiki-e/install-action@v2` (prebuilt-binary install). Split the
  old `[stable, "1.85"]` matrix into a stable `build` job (full
  test + clippy + fmt sweep, unchanged) and a separate `msrv` job
  (build-only — behaviour is rust-version-independent so test/clippy
  duplication was redundant per rust-lang/api-guidelines#231).
  Combined: ~33% reduction in total CI runner time per run
  (~2 min 11 sec saved). Added `workflow_dispatch` trigger to allow
  manual fire on stacked-PR branches.
- **dudect harness**: same 12 targets as v0.3; PR-smoke and nightly
  workflows now run the harness under a matrix over
  `features=[default, sm4-bitsliced]`. No new targets in v0.4.

### Posture (unchanged)

- `unsafe_code = "forbid"` on `gmcrypto-core` (workspace-wide for
  the no_std core crate; explicitly does not apply to the new
  `gmcrypto-c` FFI shim, which uses `unsafe_code = "warn"` with
  `// SAFETY:` comments on every `unsafe` block).
- `#![no_std]` + `alloc`-only inside `crates/gmcrypto-core/src/`;
  no `std::` paths.
- Constant-time discipline on all secret-touching paths. The W3
  bitsliced S-box is constant-time by construction (no table
  lookups, no branches on secret bits).
- Failure-mode invariant: every public surface that can fail returns
  `Option` or a single-`Failed` enum (`SignError::Failed`,
  `DecryptError::Failed`, `EncryptError::Failed`, `pem::Error::Failed`,
  `pkcs8::Error::Failed`). The C ABI collapses to a single
  `GMCRYPTO_FAILED` return code.
- MSRV 1.85, edition 2024.

## [0.3.0] — 2026-05-11

### Added

- **v0.3 W1** — reusable strict-canonical DER reader / writer subset
  (`gmcrypto_core::asn1::{reader, writer, oid}`). `asn1::sig` and
  `asn1::ciphertext` ported on top — byte-identical wire output and
  accept/reject behavior to v0.2. New OID constants for
  `id-ecPublicKey`, `sm2p256v1`, `sm2_sign_with_sm3`, `id-PBKDF2`,
  `id-PBES2`, `id-hmacWithSM3`, `sm4-cbc`. ~890 LOC net diff;
  unblocks W2/W4 and any future ASN.1 work.
- **v0.3 W2** — PEM / encrypted PKCS#8 / X.509 SPKI / SEC1 codecs
  (`gmcrypto_core::{pem, pkcs8, spki, sec1}`). Hand-rolled PEM
  (RFC 7468) with embedded base64 codec — strict-canonical encoder,
  liberal decoder. RFC 5958 OneAsymmetricKey + RFC 8018 PBES2 with
  PBKDF2-HMAC-SM3 + SM4-CBC for the encrypted variant. RFC 5280
  SubjectPublicKeyInfo with `id-ecPublicKey` + `sm2p256v1`. RFC 5915
  ECPrivateKey with SEC1 uncompressed point (`04 || X || Y`, 65
  bytes). New `Sm2PublicKey::{from_sec1_bytes, to_sec1_uncompressed,
  ConstantTimeEq}`. New `Sm2PrivateKey::{from_sec1_be, to_sec1_be}`
  — `to_sec1_be` ships `#[doc(hidden)]` and is **not SemVer-stable**
  (same posture as `sign_raw_with_id`). All failures collapse to a
  single `::Failed` variant per the failure-mode invariant. New
  dudect target `ct_pkcs8_decrypt`. gmssl 3.1.1 KAT fixtures
  committed as binary files under `crates/gmcrypto-core/tests/data/`
  with a regen recipe in `tests/data/README.md`.
- **v0.3 W3** — full bidirectional gmssl 3.1.1 interop in
  `tests/interop_gmssl.rs`. Six new tests cover SM2 sign / verify,
  SM2 encrypt / decrypt (GM/T 0009 DER), and SM4-CBC in both
  directions (gmssl → us and us → gmssl) using the W2 KAT fixtures.
  Gated on `GMCRYPTO_GMSSL=1`. Closes the v0.2 deferral; the
  headline interop bar finally clears.
- **v0.3 W4** — raw byte-concat SM2 ciphertext helpers
  (`gmcrypto_core::sm2::raw_ciphertext`). Modern `C1 || C3 || C2`
  emit + decode; legacy `C1 || C2 || C3` decrypt-only (deliberately
  **no** `encode_c1c2c3_legacy` — would propagate the legacy byte
  order forever). C1 is 65 bytes (`0x04 || X || Y`) per Q7.5. Same
  field-bound (`< p`) and on-curve checks as the GM/T 0009 DER
  decoder; same single-`None` failure-mode shape. Module placement
  pinned to `sm2::` (not `asn1::`) per Q7.4 — the helpers are
  explicitly not DER.
- **v0.3 W5** — streaming traits + streaming `HmacSm3` + streaming
  `Sm4CbcEncryptor` / `Sm4CbcDecryptor`. New `gmcrypto_core::traits`
  module with in-crate `Hash` / `Mac` / `BlockCipher` traits;
  RustCrypto trait fit (`digest::Digest`, `digest::Mac`,
  `cipher::BlockEncrypt`/`BlockDecrypt`) **deferred to v0.4** behind
  an opt-in feature flag per Q7.3 / Q7.10. Streaming `HmacSm3::new`
  / `update` / `finalize` produces byte-identical tags to single-
  shot `hmac_sm3` regardless of chunking; constant-time `verify`
  via `subtle::ConstantTimeEq`. Streaming `Sm4CbcDecryptor` uses
  **buffer-back-by-one** so the constant-time PKCS#7 strip applies
  uniformly at `finalize` time — no early-emit padding-oracle
  surface. No new dudect targets per Q7.6 (structural reuse of
  `ct_hmac_sm3` + `ct_sm4_*`).
- **v0.3 W6** — comb-table `mul_g` (~5× sign-side speedup).
  64 sub-tables × 16 entries each, lazily built once per process
  on first `mul_g` call. Constant-time linear scan over each sub-
  table preserved. `mul_g`'s public signature is unchanged. Per
  Q7.8: `spin::Once` is the new runtime-init primitive (no_std,
  ~4 KB lib, zero transitive deps, added to `deny.toml`
  allowlist); `std::sync::LazyLock` is forbidden because it
  violates `no_std`. 96 KB heap one-time-init; `w = 4` window
  width pinned per the table-size-vs-binary-bloat trade-off.
  100K-sample `ct_mul_g` measures `|tau| ≈ 0.04` — well under
  the 0.20 gate.

### Changed

- **dudect harness**: 11 → 12 targets (`ct_pkcs8_decrypt` added by
  W2; `ct_hmac_sm3_streaming` deliberately not added per Q7.6).
- **`mul_g`** is no longer a delegate to `mul_var` — it walks the
  W6 comb table directly. Output unchanged.
- **`asn1::sig`** and **`asn1::ciphertext`** internals now compose
  over the W1 reader / writer primitives. Wire output and
  accept / reject behavior unchanged.
- **Runtime dependencies**: `spin = "0.10"` (W6 lazy init). Added
  to `deny.toml` allowlist with a comment pointing back to Q7.8.

### Posture (unchanged)

- `unsafe_code = "forbid"` workspace-wide.
- `#![no_std]` + `alloc`-only inside `src/`; no `std::` paths.
- Constant-time discipline on all secret-touching paths.
- Failure-mode invariant: every public surface that can fail
  returns `Option` or a single-`Failed` enum.
- MSRV 1.85, edition 2024.

## [0.2.0] — 2026-05-10

### Added

- v0.2 W0 — dudect harness expansion, three new targets: `ct_sign_k_class`
  (nonce-magnitude class split with `d` held fixed; both retry nonces
  class-tied via a deterministic `ClassKRng`), `ct_fn_invert` (direct
  `Fn::invert((1+d) mod n)` diagnostic), `ct_fp_invert` (direct
  `Fp::invert(Z)` diagnostic). `dudect-pr.yml` and `dudect-nightly.yml`
  `required_low` allowlists extended to gate all three at `|tau| < 0.20`.
  Closes the v0.1 structural blind spot to nonce-only leaks (documented
  in published 0.1.0's SECURITY.md and CHANGELOG).
- v0.2 W1 — SM4 block cipher (`gmcrypto_core::sm4::Sm4Cipher`) per
  GB/T 32907-2016. Constant-time-designed: `subtle`-style linear-scan
  S-box (option b per the v0.2 scope plan). KAT vectors from
  GB/T 32907 Appendix A.1: single-block KAT and the 1,000,000-round KAT
  (the latter `#[ignore]`d by default; run with
  `cargo test --release -- --ignored` before release). Throughput
  trade documented in module-doc + this CHANGELOG: ~1-2M blocks/sec
  vs. ~150M for an LUT impl. Bitsliced S-box deferred to v0.4.
  `Sm4Cipher` zeroizes round-key buffer on drop via
  `#[derive(Zeroize, ZeroizeOnDrop)]`; key-schedule intermediates
  explicitly wiped before return.
- v0.2 W1 — SM4-CBC (`gmcrypto_core::sm4::mode_cbc::{encrypt, decrypt}`)
  with PKCS#7 padding (RFC 5652 §6.3). IV contract per NIST SP 800-38A
  Appendix C: caller-supplied, **unpredictable** (CSPRNG-derived),
  never reused under the same key. Padding-oracle caveat documented:
  raw CBC is unauthenticated; pair with HMAC-SM3 (W3, upcoming) in
  encrypt-then-MAC for integrity. PKCS#7 strip uses
  `subtle::ConditionallySelectable` constant-time scan over the final
  block; `decrypt` collapses every failure mode to a single `None`
  per the failure-mode invariant.
- v0.2 W1 — two new dudect harness targets: `ct_sm4_key_schedule`
  (class-split by master key bytes; key-schedule path) and
  `ct_sm4_encrypt_block` (class-split by master key bytes; "construct
  cipher + encrypt one block" timed under one window). Workflow
  allowlists extended to gate both at `|tau| < 0.20`. 100K baseline
  on `main`: `ct_sm4_key_schedule` `|tau| ≈ 0.011`,
  `ct_sm4_encrypt_block` `|tau| ≈ 0.009` — noise-level.
- v0.2 W3 — HMAC-SM3 (`gmcrypto_core::hmac::hmac_sm3`) per RFC 2104
  over GB/T 32905-2016 SM3. Single-shot
  `hmac_sm3(key, message) -> [u8; 32]` API; streaming
  `HmacSm3::new`/`update`/`finalize` deferred to v0.3 with the
  broader `Mac`-trait generalization. Hash-first long-key path per
  RFC 2104 §2 (key > 64 bytes → reduced via `SM3(K)` before pad).
  4 KAT vectors cross-validated against `gmssl sm3hmac` v3.1.1.
  Intermediate `K'`, `K' XOR ipad`, `K' XOR opad` buffers all
  zeroized before return.
- v0.2 W4 — PBKDF2-HMAC-SM3 (`gmcrypto_core::kdf::pbkdf2_hmac_sm3`)
  per RFC 8018 §5.2. Caller-supplied output buffer
  (`&mut [u8]` — output length implied by buffer length); avoids the
  allocation-failure question entirely and matches RustCrypto's
  pbkdf2 discipline. No iteration-count default (defaults age
  badly). Failure modes (`iterations == 0`, `output.is_empty()`,
  oversized output) all collapse to `None` per the failure-mode
  invariant. 5 KAT vectors cross-validated against `gmssl pbkdf2`
  v3.1.1. Intermediate `salt || INT(i)` scratch, `T_i` accumulator,
  and `U_j` chain all zeroized before return.
- v0.2 W3 — new dudect target `ct_hmac_sm3` (class-split by 32-byte
  master key bytes; fixed message). Covers W4's PBKDF2 inner PRF
  by structural reuse — no separate `ct_pbkdf2_hmac_sm3` target.
  100K baseline on `main`: `ct_hmac_sm3` `|tau| ≈ 0.008` —
  noise-level.
- v0.2 W3+W4 — `tests/interop_gmssl.rs` extended with two gmssl
  cross-validation tests (`hmac_sm3_matches_gmssl`,
  `pbkdf2_hmac_sm3_matches_gmssl`) gated on `GMCRYPTO_GMSSL=1`.
  Each runs against multiple input cases at commit time.
- v0.2 Phase 3 — GM/T 0009 SM2 ciphertext DER (`asn1::ciphertext`).
  `Sm2Ciphertext { x, y, hash, ciphertext }` with `encode`/`decode`
  per the SEQUENCE shape `{ XCoordinate INTEGER, YCoordinate INTEGER,
  HASH OCTET STRING, CipherText OCTET STRING }`. Strict X.690
  canonical INTEGER rules kept identical to `asn1::sig` (redundant
  `00`-pad rejected, sign-bit-set first byte rejected, empty INTEGER
  rejected) — prevents ciphertext malleability. Length encoding
  supports up to ~16 MB ciphertext (3-byte 0x83 length); larger
  payloads panic on encode (callers should chunk via SM4-CBC + an
  outer SM2 wrap). Raw byte concatenation (`C1||C3||C2` modern,
  `C1||C2||C3` legacy gmssl) is OUT OF SCOPE for v0.2 — DER only.
- v0.2 Phase 3 — SM2 public-key encryption
  (`gmcrypto_core::sm2::encrypt`) per GB/T 32918.4-2017 §6, returning
  GM/T 0009 DER. Single-shot `encrypt(public, plaintext, rng)` →
  `Result<Vec<u8>, EncryptError>` with single `Failed` variant.
  Includes the SM3 counter-mode KDF (§5.4.3) inline; `kdf.rs` is
  reserved for PBKDF2.
- v0.2 Phase 3 — SM2 public-key decryption
  (`gmcrypto_core::sm2::decrypt`) per GB/T 32918.4-2017 §7. Single-
  shot `decrypt(private, ciphertext_der)` →
  `Result<Vec<u8>, DecryptError>` with single `Failed` variant
  collapsing every failure mode (malformed DER, off-curve `C1`,
  identity `C1`, all-zero KDF, MAC mismatch). Defends against
  invalid-curve attacks via an explicit `point_on_curve` check on
  `C1`. MAC compare via `subtle::ConstantTimeEq`. Plaintext on the
  failure branch is zeroized before return.
- v0.2 Phase 3 — `ct_sm2_decrypt` dudect target. Class-split by
  recipient `d_B`; fixed ciphertext encrypted to a third party so
  both classes fail at the MAC check via identical control flow.
  Workflow allowlists extended; 100K baseline `|tau| ≈ 0.010` —
  noise-level.
- **SM2 encrypt/decrypt cross-validation against gmssl is OUT OF
  SCOPE for v0.2.** gmssl CLI requires PEM/PKCS#8/SPKI key wrapping,
  which is v0.3 work. v0.2 SM2 envelope encryption is KAT-validated
  via internal round-trip + a fixed-`k` smoke test only.

### Fixed

- SM2 ciphertext DER decoder now accepts the canonical encoding of
  zero (`02 01 00`) on `C1.x` / `C1.y` and rejects 32-byte coordinates
  `≥ p` (the SM2 field modulus). The v0.2 release-readiness review
  flagged that the previous decoder copied the signature INTEGER rule
  intended for `r, s ∈ [1, n-1]` — under those rules the canonical
  zero encoding was rejected (`(0, y)` is a valid C1) and 32-byte
  values above `p` slipped through to `Fp::new`, which silently
  reduced them, admitting two distinct DER blobs for the same field
  element (a malleability primitive on the ciphertext path). Decoder
  rules are now documented inline as the SM2-specific deltas vs.
  `asn1::sig`, and three regression tests pin the round-trip and
  rejection behavior. Asymmetrically affects the encode-then-decode
  round trip on `(0, _)` and `(_, 0)` C1 points: v0.1.0 did not ship
  SM2 envelope encryption at all (it lands in v0.2 Phase 3), so no
  *released* encrypt blob can be mis-decoded by the pre-fix
  decoder regardless. For v0.2's encrypt path, a uniform CSPRNG
  produces a coordinate whose top byte is zero with probability
  `≈ 2^-8`, the full coordinate is zero with probability `≈ 2^-256`
  (cryptographically negligible but **not** zero — the encrypt path
  rejects only the identity point, not zero coordinates per se), and
  the deterministic-`k` smoke test vectors used non-zero `k` so they
  do not exercise the boundary. The fix unblocks v0.3 callers who
  construct `Sm2Ciphertext` directly with `(0, _)` or `(_, 0)`
  coordinates without going through `encrypt`.
- HMAC-SM3 long-key path (`key.len() > 64`) now zeroizes the SM3
  digest stack buffer after copying it into `K'`. The codex review
  surfaced that for long keys `SM3(key)` is the *effective* RFC 2104
  HMAC key (per `HMAC(K, m) == HMAC(SM3(K), m)`), not merely a
  key-derived value, so leaving it unwiped weakened the documented
  zeroization guarantee.
- SM2 decrypt's KDF-zero rejection is now non-branching. The
  second-pass codex review flagged that an early-return on
  `all_zero(KDF) → Err(Failed)` exposed a chosen-ciphertext timing
  oracle: for short `C2` the per-attempt KDF-zero probability is
  `2^(-8·|C2|)` (e.g. `1/256` for a 1-byte `C2`), and the early-return
  branch skipped the XOR / SM3 / MAC work — observably faster than a
  normal MAC failure. Decrypt now folds the all-zero detection into a
  `subtle::Choice`, computes the SM3 MAC unconditionally, and combines
  `(mac_ok & !kdf_zero)` into one validity bit. Both failure classes
  collapse to identical control flow per the failure-mode invariant.
  Empty `C2` continues to suppress the KDF-zero check via a `nonempty`
  Choice mask. Two regression tests added: `rejects_forged_short_ciphertext`
  exercises the new branchless path on 1-byte ciphertexts; the
  existing `round_trip_boundary_lengths` covers the empty-suppression
  behaviour and a new `round_trip_empty_plaintext` pins it
  independently.
- SM2 encrypt's `ENCRYPT_RETRY_BUDGET` raised from `4` to `64`. The
  second-pass codex review noted that the per-iteration KDF-zero
  probability is length-dependent (`2^(-8·|M|)`, not the asymptotic
  `2^-256` figure the original budget assumed). At budget=4 a 1-byte
  plaintext fails ~`2^-32` of encryptions even with a uniform CSPRNG
  — observable in production. At budget=64 the cumulative-failure
  probability is `≤ 2^-512` for any plaintext length. GB/T 32918.4
  specifies the retry as indefinite; the 64-step bound is a
  defense-in-depth ceiling, never reached in practice.

### Changed

- `crypto-bigint` workspace dep raised from 0.6 to 0.7.3 (commits
  `a670ce3` / `89abfb9` / `22b77a2`). Edition raised from 2021 to 2024.
  MSRV raised from 1.74 (v0.1 initial) to 1.85 (`crypto-bigint 0.7`
  requirement). `subtle` 2.6.1, `zeroize` 1.8.2, `rand_core` 0.10.1,
  `dudect-bencher` 0.7.0, `hex-literal` 1.1.0; `getrandom` 0.4.2 added
  as a direct workspace dep with `sys_rng` feature (replacing the
  `rand_core` 0.6 `getrandom` integration that 0.10 dropped).

### Decided (v0.2 scope)

- **Fermat-invert workstream (W5) dropped.** The original v0.2 plan
  proposed replacing `Fn::invert` and `Fp::invert` at the two
  secret-touching call sites with a constant-time `pow_bounded_exp`.
  Direct measurement on the W0 harness against current `main`
  (`crypto-bigint 0.7.3`) at 100K samples lands `ct_fn_invert` at
  `|tau| ≈ 0.0071`, `ct_fp_invert` at `|tau| ≈ 0.0063`, `ct_sign_k_class`
  at `|tau| ≈ 0.0708`, and `ct_sign` at `|tau| ≈ 0.0044` — all under
  the 0.10 W5 Branch A threshold, two orders of magnitude below the
  v0.6-era 0.70. The 0.7 upgrade resolved the leak directly. The
  Fermat-invert option remains available as a fallback if a future
  `crypto-bigint` release regresses.

## [0.1.0] — 2026-05-10

### Added

- Initial release of `gmcrypto-core` (`#![no_std]` + `alloc`).
- SM3 hash function with KAT vectors from GB/T 32905-2016 (empty, "abc",
  16× "abcd", 63 zero bytes, plus a streaming-vs-one-shot equivalence test).
- `Fp` and `Fn` field arithmetic over `crypto-bigint = 0.7` `ConstMontyForm`,
  including `Fp::invert` / `Fn::invert` round-trip KATs.
- SM2 curve (GB/T 32918.5-2017) with Renes-Costello-Batina complete addition
  formulas (a=-3 specialized).
- `ProjectivePoint` with constant-time `ConstantTimeEq` via cross-multiplication.
- Fixed-base scalar multiplication (`mul_g`) and variable-base (`mul_var`),
  4-bit fixed window with constant-time-designed `subtle::ConditionallySelectable`
  linear-scan table lookup.
- `Sm2PrivateKey` with `[1, n-2]` range check (constant-time via
  `subtle::ConstantTimeLess`) and `ZeroizeOnDrop`.
- SM2 sign / verify with custom signer ID, default `1234567812345678` per
  GM/T 0009.
- Fixed-K masked-select signing retry (`SIGN_RETRY_BUDGET = 2`): the retry
  loop runs unconditionally regardless of which iteration produced a valid
  signature.
- `sign_raw_with_id` (`#[doc(hidden)] pub`): returns `(r, s)` without DER
  encoding. Provided for the dudect harness; not covered by SemVer stability.
- Minimal ASN.1 DER encoder/decoder for `SEQUENCE { r, s }`.
- `dudect-bencher` detectable-leak regression harness (`benches/timing_leaks.rs`)
  with deliberately-leaky negative control. Gates on `|tau|` (scale-free):
  `|tau| > 1.0` for the negative control, `|tau| < 0.20` for the real targets
  (`ct_mul_g`, `ct_mul_var`, `ct_sign`).
- PR-smoke workflow (`.github/workflows/dudect-pr.yml`) at 10⁴ samples.
- Nightly workflow (`.github/workflows/dudect-nightly.yml`) at 10⁵ samples;
  30-day raw-log artifact retention.
- `gmssl` CLI integration test gated on `GMCRYPTO_GMSSL=1`. v0.1 reduces the
  scope to binary reachability; full bidirectional signature interop ships in
  v0.3 (requires PKCS#8 + X.509 SPKI).
- KAT vectors:
  - GB/T 32905 (SM3): empty, "abc", 16× "abcd", 63 zeros.
  - GB/T 32918.2 Appendix A.2 (SM2): Z computation, fixed-k sign producing
    `r=0x88348A09…EA4C`, `s=0x0AD2CE55…D48D`, sample (D, P) pair, sign-verify
    round-trip.
  - 2G / 3G points cross-validated against an independent Python derivation.

### Hardening (pre-release)

The following issues were found and fixed during pre-release review;
listing them so the public history records why v0.1 ships with the
behavior it does. All of these were caught by external code review
across two review passes — the first five in the initial pass, the
last two in a follow-up pass.

- **Verify panicked on identity public key.** A caller could construct
  `Sm2PublicKey::from_point(ProjectivePoint::identity())` and then
  `verify_with_id` would panic inside `compute_z`'s `to_affine()`,
  contradicting the documented "returns false on any failure mode"
  contract. Fixed: `verify_with_id` rejects identity public keys at
  the API boundary. New regression test
  `verify::tests::identity_public_key_rejected_no_panic`.
- **DER decoder accepted non-canonical INTEGER encodings.** The
  previous `read_integer` stripped a leading `0x00` without checking
  the X.690 canonical-encoding rules and did not reject sign-bit-set
  first bytes (negative integers). This created a signature
  malleability surface — multiple distinct DER blobs mapping to the
  same `(r, s)`. Fixed: strict canonical check rejects redundant
  `00`-pad, sign-bit-set first byte, and zero-length INTEGER content.
  Three new regression tests in `asn1::sig::tests`.
- **Signer-ID length silently wrapped at 8192 bytes.** `compute_z`
  computed `ENTL_A` via `(id.len() as u16).wrapping_mul(8)`, so IDs
  above 8191 bytes produced non-spec `ENTL_A` values. Two SM2
  implementations both running this old code would agree (the wrap
  is identical on both sides), but interop with anything outside
  this crate would silently break. Fixed: `MAX_ID_LEN = 8191` const
  exposed; `sign_with_id` returns `SignError::Failed`,
  `verify_with_id` returns `false`. Two new regression tests.
- **README first-screen still advertised SM4.** v0.1 ships SM2 + SM3
  only; SM4 lands in v0.2. Fixed.
- **Honest disclosure of the dudect harness's coverage gap.** The
  harness can detect leaks on the secret `d` (currently diluted under
  the gate) but not on the secret nonce `k`. Specifically the
  `Fp::invert(Z)` inside `kg.to_affine()` after `mul_g(k)` is a
  nonce-dependent timing surface that the v0.1 class layout cannot
  see. Documented in `SECURITY.md`, the harness module docs, and
  the README. v0.2 will address both invert sites and add a
  `k`-class-split harness target.
- **`.gitignore` rule was not actually matching `Cargo.lock`.** A
  trailing inline comment after `Cargo.lock` was parsed as part of
  the pattern (gitignore does not support trailing comments on a
  pattern line), so the rule never matched the actual file. The
  workspace's "do not commit lockfile" library policy was therefore
  not being enforced. Fixed: split the comment to its own line.
- **`sample_nonzero_scalar` had a modulo bias.** The previous code
  called `Fn::new(&candidate)` — which reduces mod `n` — *before*
  the zero check, so candidates in `[n, 2^256)` were folded into
  `[0, 2^256 - n)` and added a slight upward bias on small scalars.
  The bias is small (~2^-32 per draw) but real, and a constant-time-
  designed crypto crate should not ship with it. Fixed: rejection-
  sample on `candidate != 0 && candidate < n` *before* reduction,
  matching NIST FIPS 186 Appendix B's standard ECDSA approach. New
  regression test
  `sm2::sign::tests::sample_nonzero_scalar_rejects_candidates_above_order`.

### Known limitations

- **`crypto-bigint::ConstMontyForm::invert` is not constant-time across
  inputs.** Three invert sites in v0.1's secret-touching code path:
  - `Fn::invert((1 + d) mod n)` — secret-dependent. Diluted to
    `|tau| ≈ 0.04-0.14` in `sign_raw_with_id`; under the harness's
    0.20 gate.
  - `Fp::invert(Z)` in `to_affine()` after `mul_g(k)` —
    **nonce-dependent**. Not caught by v0.1's class layout.
  - `Fp::invert(Z)` in `to_affine()` from `compute_z`'s public-key
    conversion — public input only.
  v0.2 will address these sites. Candidate fixes include upgrading
  to a `crypto-bigint` line whose `invert` measures empirically more
  constant-time on this harness, or replacing with a Fermat-invert
  via `pow_bounded_exp`. See `SECURITY.md`.
- **DER `encode_sig` is variable-time on `(r, s)` byte patterns.** `(r, s)`
  is public output, so this leak does not reveal secrets — but the harness
  target `ct_sign` deliberately goes through `sign_raw_with_id` (no DER) to
  avoid the false-positive signal.
- **`gmssl` interop test verifies binary reachability only.** Full bidirectional
  signature interop deferred to v0.3.
- **Fixed-base `mul_g` delegates to `mul_var(k, &generator())` in v0.1.**
  Comb-table optimization deferred to v0.2.
- **Variable-time-multiplier CPUs are out of scope.**
