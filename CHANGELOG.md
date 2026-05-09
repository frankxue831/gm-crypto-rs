# Changelog

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] — TBD

### Added

- Initial release of `gmcrypto-core` (`#![no_std]` + `alloc`).
- SM3 hash function with KAT vectors from GB/T 32905-2016 (empty, "abc",
  16× "abcd", 63 zero bytes, plus a streaming-vs-one-shot equivalence test).
- `Fp` and `Fn` field arithmetic over `crypto-bigint = 0.6` `ConstMontyForm`,
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

### Known limitations

- **`crypto-bigint::ConstMontyForm::invert` is not constant-time across inputs.**
  Direct measurement shows `|tau| ≈ 0.70` in isolation. Inside `sign_raw_with_id`
  the diluted signal is `|tau| ≈ 0.04-0.14`, under the 0.20 gate, so the
  harness still passes — but this is the dominant residual leak vector. v0.2
  replaces `(1+d).invert()` with a Fermat-invert via constant-time
  `pow_bounded_exp`, after first validating the `pow` path. See
  [`SECURITY.md`](SECURITY.md).
- **DER `encode_sig` is variable-time on `(r, s)` byte patterns.** `(r, s)`
  is public output, so this leak does not reveal secrets — but the harness
  target `ct_sign` deliberately goes through `sign_raw_with_id` (no DER) to
  avoid the false-positive signal.
- **`gmssl` interop test verifies binary reachability only.** Full bidirectional
  signature interop deferred to v0.3.
- **Fixed-base `mul_g` delegates to `mul_var(k, &generator())` in v0.1.**
  Comb-table optimization deferred to v0.2.
- **Variable-time-multiplier CPUs are out of scope.**
