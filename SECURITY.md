# Security Policy

## Reporting a vulnerability

Please report security issues privately via a **GitHub Security Advisory** on
this repository — open a draft advisory at
<https://github.com/frankxue831/gm-crypto-rs/security/advisories/new>.

We aim to acknowledge within 5 business days. There is no bug bounty.

## Supported versions

Only the latest released minor version receives security fixes. There is no
LTS branch.

## Threat model

Server-side use, dedicated host, operator-trusted. Network MITM is in scope;
side channels beyond what the in-CI `dudect-bencher` harness exercises are
NOT in scope.

## Constant-time posture (v0.1)

`gmcrypto-core` is **constant-time-designed** — every secret-dependent operation
is implemented through `subtle`-style masked selection rather than data-dependent
branches, and the SM2 sign retry loop runs a fixed number of iterations
regardless of which (if any) candidate is valid.

The in-CI [`dudect-bencher`](https://docs.rs/dudect-bencher/) harness
(`benches/timing_leaks.rs`) gates on `|tau| < 0.20` for the real targets:

- `ct_mul_g`   — fixed-base scalar multiplication `k·G`.
- `ct_mul_var` — variable-base scalar multiplication `k·P`.
- `ct_sign`    — full SM2 sign through `sign_raw_with_id`.

A deliberately-leaky `negative_control` target gates `|tau| > 1.0` to confirm
the harness wiring on every PR. **The harness detects leaks; it does not prove
constant-time.** Low `|tau|` values mean the test could not detect a leak with
the budget given, not that no leak exists. Language is from `dudect-bencher`'s
own docs.

### Known v0.1 limitation: `crypto-bigint::ConstMontyForm::invert`

Direct measurement on the harness shows `|tau| ≈ 0.70` for
`ConstMontyForm::invert` between two random non-degenerate inputs. This is
upstream behavior — `crypto-bigint = "0.6"`'s safegcd/Bernstein-Yang inversion
is documented as constant-time but is not constant-time across different inputs
in practice on the observed implementation.

In `sign_raw_with_id`, where the invert step (`(1+d).invert()`) is ~1-2% of
total sign time, the diluted signal is `|tau| ≈ 0.04-0.14`, comfortably under
the 0.20 gate. **The `ct_sign` target therefore passes the gate today.**

Two concrete consequences for v0.1 users:

1. The `Fp::invert(z)` step inside `to_affine()` (used to convert projective
   points to affine for hashing in `compute_z`) operates on **public** point
   coordinates. Timing variance there does not reveal secrets.

2. The `Fn::invert((1 + d) mod n)` step inside `sign_raw_with_id` operates on
   the secret `d`. The diluted signal is below the harness's detection
   threshold today, but a future change to the surrounding code (e.g. a
   different sign algorithm where invert is a larger fraction of total time,
   or a faster underlying scalar mult that makes invert relatively more
   significant) could push it above. v0.2 replaces this site with a
   Fermat-style invert via `pow_bounded_exp` after first validating that the
   `pow` path is itself constant-time.

This limitation is explicitly noted in `benches/timing_leaks.rs`'s module
docs and tracked for the v0.2 fix.

## Other known limitations (non-goals)

- **Variable-time multiplier CPUs.** Some older x86 / low-end embedded chips
  have data-dependent multiplication latencies (per `crypto-bigint`'s warnings);
  the constant-time contract degrades to "best-effort" on those targets.
- **DER encoding is not constant-time on `(r, s)`.** `encode_sig` strips
  leading zeros and conditionally pads on high-bit-set, so its runtime
  varies with the byte pattern of the signature. `(r, s)` is **public output**,
  so this leak does not reveal secrets — but `dudect` cannot tell the
  difference, which is why the harness target `ct_sign` gates against
  `sign_raw_with_id` (no DER) rather than `sign_with_id`.
- **Fault attacks.** No fault-injection countermeasures.
- **Hardware-backed keys (SDF/SKF/HSM).** Out of scope.
- **TLS / TLCP / GM-TLS profiles.** Out of scope.
- **Certificate-chain validation, CRL, OCSP, CSR, CMS.** Out of scope.

## Failure-mode invariant (defense-in-depth)

`gmcrypto-core` collapses error variants to single uninformative shapes
wherever a distinguishing failure could leak information. Specifically:

- `verify_with_id` returns `bool` (never an error type).
- DER decode failures return `None`, never specific error variants.
- `SignError::Failed` has exactly one variant.

PRs that distinguish failure modes — even "helpfully" — will be rejected.

## Compliance posture

This is a personal open-source project. It is not a certified cryptographic
module and makes no regulatory, procurement, or production-suitability claim.
