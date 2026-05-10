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

- `ct_mul_g`         — fixed-base scalar multiplication `k·G`.
- `ct_mul_var`       — variable-base scalar multiplication `k·P`.
- `ct_sign`          — full SM2 sign through `sign_raw_with_id`, class-split by
  private key `d`.
- `ct_sign_k_class`  — same, class-split by nonce `k` magnitude with `d` held
  fixed (W0; closes the v0.1 structural blind spot to nonce-only leaks).
- `ct_fn_invert`     — direct `Fn::invert((1+d) mod n)` diagnostic (W0).
- `ct_fp_invert`     — direct `Fp::invert(Z)` diagnostic (W0).

A deliberately-leaky `negative_control` target gates `|tau| > 1.0` to confirm
the harness wiring on every PR. **The harness detects leaks; it does not prove
constant-time.** Low `|tau|` values mean the test could not detect a leak with
the budget given, not that no leak exists. Language is from `dudect-bencher`'s
own docs.

### `crypto-bigint::ConstMontyForm::invert` — v0.1 vs. main

**Published v0.1.0 (on `crypto-bigint = 0.6`).** Direct measurement on the
v0.1 harness showed `|tau| ≈ 0.70` for `ConstMontyForm::invert` between two
random non-degenerate inputs. Inside `ct_sign`, where invert is ~1-2% of
total sign time, the signal diluted to `|tau| ≈ 0.04–0.14` — under the
0.20 gate. The v0.1 harness was class-split by `d` only; nonce-only
leaks distributed uniformly across both classes, so the harness was
**structurally blind** to a leak in `Fp::invert(Z)` after `mul_g(k)`.

**Main (post-publish, on `crypto-bigint = 0.7.3`).** The dep upgrade
landed in commits `a670ce3` / `89abfb9` / `22b77a2`, and the v0.2 W0
harness expansion (`ct_sign_k_class`, `ct_fn_invert`, `ct_fp_invert`)
landed alongside. At 100K samples on the W0 harness:

| target (W0) | `\|tau\|` |
|---|---|
| `ct_fn_invert` (direct site 1 diagnostic) | 0.0071 |
| `ct_fp_invert` (direct site 2 diagnostic) | 0.0063 |
| `ct_sign_k_class` (nonce-class-split sign) | 0.0708 |
| `ct_sign` (private-key-class-split sign, retained) | 0.0044 |

All four are under the 0.10 Branch A threshold; both classes of direct
invert measurement land in the noise regime, two orders of magnitude
below the v0.6 measurement. The v0.2 Fermat-invert workstream (W5) is
**dropped**; `pow_bounded_exp` remains a fallback if a future
`crypto-bigint` release regresses on this gate.

The three secret-touching invert sites are documented for completeness:

1. `Fn::invert((1 + d) mod n)` in `sign_raw_with_id` — operates on the
   secret private key `d`. Direct diagnostic: `ct_fn_invert`.
2. `Fp::invert(Z)` in `ProjectivePoint::to_affine()`, called from
   `try_sign_once` *after* `mul_g(k)` — operates on `Z` derived from the
   secret nonce `k`. Direct diagnostic: `ct_fp_invert`. Sign-level
   diagnostic: `ct_sign_k_class`.
3. `Fp::invert(Z)` in `to_affine()`, called from `compute_z`'s public-key
   conversion — operates on **public** input only and reveals nothing new.

### `ct_sign_k_class` and the structural blind spot fix

v0.1's harness was class-split by `d` while letting `k` be fresh-random in
every sample, structurally blind to nonce-only leaks. `ct_sign_k_class`
(W0) inverts the class assignment: `d` held fixed; class-split by nonce
magnitude. **Both** retry nonces in the `SIGN_RETRY_BUDGET = 2` loop are
class-tied — a class label that only controls the first nonce and lets
the second be fresh-random would contaminate the signal (the second
nonce becomes a noise source distributing uniformly across both classes).

`ct_sign_k_class` measuring `|tau| = 0.0708` at 100K samples (vs. `ct_sign`'s
0.0044) suggests the nonce path has slight signal elevation that the
`d`-class harness could not see. Well under threshold; not a leak. Worth
noting the elevated signal exists.

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
