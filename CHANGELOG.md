# Changelog

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
  round trip on `(0, _)` and `(_, 0)` C1 points, but the encrypt
  path never produced such ciphertexts (encrypt rejects the identity
  point and the deterministic-`k` test vectors used non-zero
  coordinates), so no released encrypt blob is mis-decoded.
- HMAC-SM3 long-key path (`key.len() > 64`) now zeroizes the SM3
  digest stack buffer after copying it into `K'`. The codex review
  surfaced that for long keys `SM3(key)` is the *effective* RFC 2104
  HMAC key (per `HMAC(K, m) == HMAC(SM3(K), m)`), not merely a
  key-derived value, so leaving it unwiped weakened the documented
  zeroization guarantee.

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
