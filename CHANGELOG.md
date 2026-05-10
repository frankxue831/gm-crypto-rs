# Changelog

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] — 2026-05-10

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
