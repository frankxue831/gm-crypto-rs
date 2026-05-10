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
upstream behavior — `crypto-bigint = "0.7"`'s safegcd/Bernstein-Yang inversion
is documented as constant-time but is not constant-time across different inputs
in practice on the observed implementation.

There are **three** invert sites in v0.1's secret-touching code path:

1. **`Fn::invert((1 + d) mod n)`** in `sign_raw_with_id` — operates on the
   secret private key `d`.
2. **`Fp::invert(Z)`** in `ProjectivePoint::to_affine()`, called from
   `try_sign_once` *after* `mul_g(k)` — operates on `Z` derived from the
   secret nonce `k`.
3. **`Fp::invert(Z)`** in `to_affine()`, called from `compute_z`'s public-key
   conversion — operates on **public** input only and reveals nothing new.

Sites 1 and 2 are both **secret-dependent** timing surfaces in v0.1.

### Honest admission about the dudect harness's coverage

The in-CI `dudect-bencher` harness (`benches/timing_leaks.rs`) splits its
`ct_sign` test classes by **private key `d`** while letting **`k` be
fresh-random in every sample**. This design catches site (1) — the
`(1+d).invert()` leak — diluted to `|tau| ≈ 0.04–0.14` because invert
is ~1-2% of total sign time. The diluted signal is under the 0.20 gate,
so `ct_sign` passes today.

**The harness does not, however, detect site (2).** A nonce-dependent leak
distributes uniformly across both classes, so it cannot show up as a
between-class timing difference. dudect with this class assignment is
structurally blind to nonce-only leaks. The `mul_g`/`mul_var` targets are
class-split by scalar magnitude and so partially exercise the nonce path,
but their `to_affine` is never called inside the timed window — so they
also miss it.

A `ct_sign` pass is therefore **not** evidence that signing is leak-free
on the nonce path. It is evidence only that the `(1+d).invert()` leak is
diluted under threshold at current sign-step proportions.

### v0.2 plan

v0.2 replaces both `Fn::invert` and `Fp::invert` at sites (1) and (2)
with a constant-time Fermat-invert via `pow_bounded_exp` (after first
validating the `pow` path is itself constant-time on the same harness).
Once both sites are fixed, the harness will be reworked so that one of
its targets is class-split by `k` (with `d` held fixed) to specifically
exercise the nonce path that v0.1's class layout could not see.

This limitation is also noted in `benches/timing_leaks.rs`'s module
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
