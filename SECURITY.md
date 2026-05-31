# Security Policy

## Reporting a vulnerability

Please report security issues privately via a **GitHub Security Advisory** on
this repository — open a draft advisory at
<https://github.com/frankxue831/gm-crypto-rs/security/advisories/new>.

We aim to acknowledge within 5 business days. There is no bug bounty.

## Supported versions

Only the latest released minor version receives security fixes. There is no
LTS branch.

## API stability & SemVer

The crate line is pre-1.0 (0.x); the **v1.0 readiness audit** (v0.21) froze and
CI-guarded the public surface ahead of a `1.0` commitment, and the **v0.22
API-tightening cycle** decoupled it from `crypto-bigint 0.7` (the audit's §3.A
finding — the always-on/default-features public API now names **zero**
`crypto-bigint` types; only the opt-in `crypto-bigint-scalar` `from_scalar(U256)`
retains one, a documented escape hatch). The SemVer contract covers the public Rust
API of `gmcrypto-core` (snapshotted in `docs/api-baseline/gmcrypto-core.txt`,
drift-checked in CI) and the `gmcrypto-c` **C ABI** (the committed
`crates/gmcrypto-c/include/gmcrypto.h`, drift-checked in CI). It does **not** cover
any `#[doc(hidden)]` item (`sm2::sign_raw_with_id`; the
`Sm4Cbc{Encryptor,Decryptor}::take_output` FFI-shim drains; and, since v0.22, the
low-level `sm2::curve` / `sm2::scalar_mul` / `ProjectivePoint::to_affine` curve
arithmetic) or the **`gmcrypto-simd`** crate (an internal acceleration backend with
no stable Rust API). See [`docs/v1.0-readiness.md`](docs/v1.0-readiness.md) for the
full posture, the guard tooling, and the (now-resolved) §3.A decision.

## Threat model

Server-side use, dedicated host, operator-trusted. Network MITM is in scope;
side channels beyond what the in-CI `dudect-bencher` harness exercises are
NOT in scope.

## Constant-time posture

`gmcrypto-core` is **constant-time-designed** — every secret-dependent operation
is implemented through `subtle`-style masked selection rather than data-dependent
branches, and the SM2 sign retry loop runs a fixed number of iterations
regardless of which (if any) candidate is valid.

The in-CI [`dudect-bencher`](https://docs.rs/dudect-bencher/) harness
(`benches/timing_leaks.rs`) ships **18 real `ct_*` targets** (12 always-on
+ 2 cfg-gated under `sm4-bitsliced-simd` + 3 cfg-gated under `sm4-aead`
+ 1 cfg-gated under `sm4-xts`)
plus a deliberately-leaky `negative_control`. Most real targets gate on
`|tau| < 0.20`;
`negative_control` gates the opposite direction (`|tau| > 1.0` **must**
fire to prove harness wiring); `ct_sign_k_class` and the direct
`ct_fn_invert` / `ct_fp_invert` invert diagnostics have target-specific
gate policy after the 2026-05-12 GH Actions runner-image shift — see
the recalibration note below and `docs/v0.5-dudect-recalibration.md`.
CLAUDE.md carries the canonical per-target gate table.

**Real `ct_*` always-on (12):**

- `ct_mul_g`         — fixed-base scalar multiplication `k·G`.
- `ct_mul_var`       — variable-base scalar multiplication `k·P`.
- `ct_sign`          — full SM2 sign through `sign_raw_with_id`, class-split by
  private key `d`.
- `ct_sign_k_class`  — same, class-split by nonce `k` magnitude with `d` held
  fixed (W0; closes the v0.1 structural blind spot to nonce-only leaks).
  Nightly-only gate at `|tau| < 0.25`; dropped from the PR-smoke 10K
  allowlist (telemetry-only there).
- `ct_fn_invert`     — direct `Fn::invert((1+d) mod n)` diagnostic (W0).
  PR-smoke telemetry-only; nightly gross-regression sentinel at
  `|tau| ≥ 0.55`.
- `ct_fp_invert`     — direct `Fp::invert(Z)` diagnostic (W0). Same
  policy as `ct_fn_invert`.
- `ct_sm4_key_schedule` — SM4 key schedule class-split by master key bytes
  (v0.2 W1; the key-schedule pipeline runs the S-box on secret-derived state).
- `ct_sm4_encrypt_block` — SM4 "construct cipher + encrypt one block" timed
  under one window, class-split by master key bytes (v0.2 W1).
- `ct_sm4_ctr_encrypt` — SM4-CTR encrypt over a fixed 256-byte plaintext
  (16 blocks), class-split by master key bytes (v0.7 W3). Dispatches through
  `Sm4Cipher::encrypt_blocks` so the gate covers every cipher path: linear-scan
  default, gate-only `sm4-bitsliced`, SIMD-packed batches under
  `sm4-bitsliced-simd`.
- `ct_hmac_sm3` — HMAC-SM3 keyed MAC, class-split by master key (v0.2 W3).
  Structurally covers PBKDF2-HMAC-SM3's (v0.2 W4) inner PRF and the v0.3 W2
  PBKDF2 sub-path of encrypted-PKCS#8 decrypt.
- `ct_sm2_decrypt` — SM2 decrypt, class-split by recipient `d_B`,
  fixed ciphertext encrypted to a third party so both classes fail
  at the MAC check via identical control flow (v0.2 Phase 3).
- `ct_pkcs8_decrypt` — encrypted-PKCS#8 decrypt + parse, class-split by
  password bytes (v0.3 W2). Both classes' blobs are valid for their class's
  password so both succeed via identical control flow.

**Cfg-gated on `sm4-bitsliced-simd` (2):**

- `ct_sm4_encrypt_block_bitsliced_simd` — SM4 single-block encrypt under the
  SIMD-packed dispatch path (v0.5 W4 phase 2). Same `|tau| < 0.20` gate.
- `ct_sm4_cbc_decrypt_fanout` — `Sm4CbcDecryptor`'s batched fanout
  (`decrypt_batch`) timed under load, class-split by master key (v0.6 W6).
  Exercises `sbox_x32` on `x86_64` AVX2 (8 blocks × 4 tau bytes = 32 bytes
  packed) and `sbox_x16` on `aarch64` NEON (4 blocks × 4 = 16 bytes).

**Cfg-gated on `sm4-aead` (3):**

- `ct_sm4_gcm_decrypt` — single-shot SM4-GCM decrypt over a fixed
  256-byte plaintext + 16-byte AAD + 12-byte nonce, class-split by master
  key (v0.8 W4). Both classes' `(ct, tag)` verify under their own key so
  both reach the constant-time tag compare via identical control flow.
  Exercises `H = SM4_E(key, 0^128)`, the GHASH chain (rides CLMUL on
  `x86_64` / PMULL on `aarch64` / software Karatsuba elsewhere), GCTR,
  and `subtle::ConstantTimeEq`.
- `ct_sm4_ccm_decrypt` — single-shot SM4-CCM decrypt, same shape, fixed
  `tag_len = 16` (v0.8 W4). Exercises the sequential CBC-MAC chain + CTR
  stream + constant-time tag compare.
- `ct_sm4_gcm_decrypt_buffered` — incremental-input buffered SM4-GCM
  decrypt via `Sm4GcmDecryptor`, fed in two chunks to straddle block
  boundaries (v0.9 W3). Exercises the running-GHASH accumulator + the
  commit-on-verify path (plaintext released only after the tag verifies).

**Cfg-gated on `sm4-xts` (1):**

- `ct_sm4_xts_decrypt` — single-shot SM4-XTS decrypt via `mode_xts::decrypt`
  over a fixed CTS (non-block-multiple) data unit (100 B = 6 blocks + 4) so
  the ciphertext-stealing tail — the riskiest tweak arithmetic — gates, not
  just whole-block (v0.12 W3). Class-split by master key; both classes' data
  units are valid encrypts under their own 32-byte key so both decrypt via
  identical control flow. Exercises the key schedule, `T_0 = SM4_E(Key2,
  tweak)`, the constant-time bit-reflected α-doubling chain (right-shift +
  masked `0xE1`), the `decrypt_blocks` batch path (rides SIMD fanout under
  `sm4-bitsliced-simd`), and the CTS tail.

**The harness detects leaks; it does not prove constant-time.** Low
`|tau|` values mean the test could not detect a leak with the budget
given, not that no leak exists. Language is from `dudect-bencher`'s own
docs.

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

**Recalibration note (2026-05-12).** The 100K-sample baseline above
was measured against the GH Actions `ubuntu-24.04` image
`20260413.86.1` (kernel `6.17.0-1010-azure`, Rust toolchain `1.94.1`).
After the 2026-05-12 image update to `20260512.134.1` (kernel
`6.17.0-1013-azure`, Rust toolchain `1.95.0`), `ct_fn_invert` and
`ct_fp_invert` began producing intermittent `|tau|` values in
[0.29–0.40] on identical source code, with same-commit pass/fail
across consecutive nightly runs. Both targets were moved to PR-smoke
telemetry + a nightly gross-regression sentinel at `|tau| ≥ 0.55` —
preserving protection against a real cryptographic leak (the v0.1
`ConstMontyForm::invert` regression at `|tau| ≈ 0.70` would still
fire) while acknowledging that the 0.20 gate is no longer authoritative
on the current shared runner. The code is unchanged from the v0.2
baseline. See [`docs/v0.5-dudect-recalibration.md`](docs/v0.5-dudect-recalibration.md).

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

### v1.0 constant-time baseline (settled — v0.18 / v0.19 / v0.20)

This is the **settled constant-time gate posture for v1.0**, with narrow,
explicitly-named revisit criteria (not "permanent/final", not "still an open
hardening gap"):

- **Composite dudect targets remain release-gated at `|tau| < 0.20`.** These are
  the full-operation targets (sign, scalar-mult, SM4 key-schedule / encrypt /
  CTR / CBC-fanout / GCM / CCM / XTS decrypt, HMAC, SM2 decrypt, PKCS#8 decrypt);
  they measure quietly and gate authoritatively.
- **The two single-field-inversion micro-diagnostics (`ct_fn_invert`,
  `ct_fp_invert`) are retained as telemetry (PR) + a nightly gross-regression
  sentinel at `|tau| ≥ 0.55`** — *not* the 0.20 gate. Shared GitHub-runner
  measurements show an empirically unstable **two-input class-split** floor for
  these short targets after the 2026-05-12 image refresh (intermittent
  [0.26–0.40]), while every composite target stays < 0.01.
- **Why not a tighter gate.** v0.18 pinned the toolchain/image + added a CI-level
  multi-run median; v0.19 then built two **fix-vs-fix noise probes**
  (`noise_floor_f{n,p}_invert`) and a self-calibrating relative gate to re-promote
  these two — and **falsified it**: the same-input probes stay quiet (~0.005)
  while the class-split targets spike (median 0.26, ratio ~50), i.e. the noise
  lives in the *two-input class-split difference*, which a same-input probe is
  structurally blind to. The probes are kept as permanent telemetry — they are
  the *evidence* for this baseline. (Full data: `docs/v0.5-dudect-recalibration.md`,
  v0.18 + v0.19 resolutions.)
- **Revisit criteria (narrow).** Re-promotion will be reconsidered **only** if a
  *materially different measurement design* exists: a **class-split-twin**
  diagnostic that reproduces the dudect two-input split geometry *without* the
  inversion operation (so it measures the runner's two-input noise floor a
  fix-vs-fix probe cannot), **or** an **offline / dedicated / manual-hardware**
  measurement. It will **not** be revisited by re-tuning shared-CI thresholds, and
  **not** via PR-executing public self-hosted CI (remote-code-execution risk,
  rejected at v0.17). This baseline does not block v1.0 — the constant-time
  *design* is unchanged and complete; only the *measurability* of two short
  diagnostics on noisy shared CI is bounded.

### SM4 (W1) — S-box and CBC contract

**S-box.** SM4's 32-round Feistel-like structure runs four S-box lookups
per round on secret-derived state. v0.2 ships SM4 with a `subtle`-style
linear-scan S-box: each lookup runs a fixed 256-iteration loop over
`subtle::ConstantTimeEq` + `subtle::ConditionallySelectable::conditional_assign`,
mirroring the existing scalar-mult fixed-window table-lookup pattern.
Throughput drops from an LUT impl's ~150M blocks/sec to ~1-2M; the
trade keeps the cryptographic side-channel posture consistent with the
rest of the crate. Bitsliced S-box (faster, still constant-time) is
deferred to v0.4 alongside the C-ABI / wasm work. 100K dudect baseline
on `main`: `ct_sm4_key_schedule` `|tau| ≈ 0.011`, `ct_sm4_encrypt_block`
`|tau| ≈ 0.009` — noise-level.

**CBC IV contract.** Per NIST SP 800-38A Appendix C, CBC IVs must be
**unpredictable** — generated by an FIPS-approved RBG or equivalent
CSPRNG, never reused under the same key. "Unique per key" is the
**CTR**-mode rule and is **insufficient** for CBC (predictable IVs
leak via chosen-plaintext attacks; see e.g. BEAST). Caller-supplied
in this crate; `gmcrypto_core::sm4::mode_cbc::encrypt` does not
generate IVs internally — pull from `OsRng` or equivalent at the
call site.

**CBC authenticity caveat.** Raw CBC is unauthenticated. A
network-attached attacker who can distinguish "decrypt succeeded"
from "decrypt failed" via timing or side channels can mount a
padding-oracle attack on the plaintext. v0.2 `mode_cbc::decrypt`
implements PKCS#7 strip via a `subtle::ConditionallySelectable`
constant-time scan (the amount of work is independent of `pad_len`),
but the final `Option<Vec<u8>>` signals validity — one bit. Callers
needing integrity **MUST** pair CBC with HMAC-SM3 (`gmcrypto_core::hmac`)
in encrypt-then-MAC: serialize `(IV || ciphertext)`, compute the MAC
over that, send `IV || ciphertext || tag`, verify the MAC before
invoking `decrypt`.

### SM2 envelope encryption (Phase 3)

**Invalid-curve attack defense.** `sm2::decrypt` validates the
received `C1 = (x, y)` lies on the SM2 curve before computing
`d_B * C1`. Without this check, an attacker submitting `C1` on a
twist or other curve sharing the same `x` coordinate could leak
bits of `d_B` via the small-order subgroup of the rogue curve.

**Failure-mode invariant.** `decrypt` returns
`Result<Vec<u8>, gmcrypto_core::Error>` (alias `sm2::Error`) with a
single `Failed` variant collapsing every failure mode (malformed
DER, off-curve `C1`, identity `C1`, all-zero KDF, MAC mismatch). MAC compare uses
`subtle::ConstantTimeEq` on the 32-byte digest; on failure the
already-XOR'd plaintext buffer is zeroized before return.

**Wire format.** GM/T 0009-2012 §6 DER is the primary wire format and
the only emit format until v0.3. v0.3 W4 added raw-byte concatenation
helpers: `sm2::raw_ciphertext::encode_c1c3c2` / `decode_c1c3c2` for
the modern `C1||C3||C2` ordering, and `decode_c1c2c3_legacy`
(decrypt-only) for the legacy `C1||C2||C3` gmssl ordering. v0.3 W3
added bidirectional gmssl `sm2encrypt`/`sm2decrypt` cross-validation
(gated on `GMCRYPTO_GMSSL=1`); v0.2's KAT-validation via internal
round-trip + fixed-`k` smoke test remains.

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
- The workspace-wide `gmcrypto_core::Error` (with module-level
  aliases `sm2::Error`, `pem::Error`, `pkcs8::Error`) has exactly
  one variant: `Failed`. Marked `#[non_exhaustive]` to preserve
  flexibility, but no second variant is anticipated — adding one
  would itself be the kind of failure-mode distinction this
  invariant exists to forbid.

PRs that distinguish failure modes — even "helpfully" — will be rejected.

## Parser fuzzing (v0.14)

The failure-mode invariant above is enforced not only by the type system and
KAT/interop tests over curated inputs, but by **coverage-guided fuzzing over
adversarial inputs**. v0.14 adds a `cargo-fuzz` (libFuzzer) harness
(`fuzz/`, a workspace-excluded nightly-only crate — never in the published
dependency graph) with **16 targets covering the entire untrusted-input
decode/decrypt boundary**:

- **Wire formats:** PEM, PKCS#8 (`decode` + PBES2 `decrypt`), SPKI, SEC1, the
  ASN.1 `SEQUENCE { r, s }` signature, the low-level strict-canonical DER reader
  primitives, the GM/T 0009 SM2 DER ciphertext, and the raw SM2 ciphertext
  (`C1‖C3‖C2` + legacy `C1‖C2‖C3`).
- **Public-key / composite paths:** `Sm2PublicKey::from_sec1_bytes`,
  `sm2::decrypt` (DER parse + KDF + MAC) and `verify_with_id` (DER signature
  parse + verify), both under a fixed test key.
- **Symmetric decrypts:** SM4-CBC, SM4-GCM (incl. truncated-tag
  `decrypt_with_tag_len`), SM4-CCM, SM4-XTS.

The property under test is exactly the failure-mode invariant on hostile bytes:
**every malformed input collapses to the single safe `None` / `Error::Failed`
(or `false`) — no panic, no unbounded allocation, no hang.** This is *negative-
input* fuzzing, not a correctness oracle (correctness is KAT/interop's job) and
not a constant-time check (that is `dudect`'s job — see above).

A capped nightly job (`.github/workflows/fuzz-nightly.yml`) runs the targets on
a schedule; a crash uploads a minimized reproducer, which becomes a committed
regression seed under `fuzz/seeds/`. The **initial v0.14 sweep found zero
crashes** across all 16 targets. Reproduce locally per
[`fuzz/README.md`](fuzz/README.md).

**v0.20 — streaming-decryptor differential fuzzing + coverage.** Two targets are
added (**18 total**): `fuzz_sm4_cbc_streaming_decrypt` and
`fuzz_sm4_gcm_streaming_decrypt`. These are **differential** harnesses, a stronger
property than negative-input: each feeds the ciphertext to the *streaming*
decryptor (`Sm4CbcDecryptor` / `Sm4GcmDecryptor`) in **arbitrary chunk
boundaries** and asserts the result is **byte-identical** to the *single-shot*
`mode_{cbc,gcm}::decrypt` oracle fed all-at-once (`Some==Some` plaintext, or
`None==None`) — so any chunking-dependent divergence (e.g. the CBC
buffer-back-by-one PKCS#7 boundary, or the GCM commit-on-verify GHASH
accumulator) is caught, on top of the no-panic/OOM/hang invariant. The initial
v0.20 sweep found **zero crashes and zero divergences**. The nightly workflow
also gained a non-gating **`cargo fuzz coverage`** job that renders per-target
`llvm-cov` region/line totals over the committed seed corpus and uploads them as
an artifact (the report is the deliverable, not a coverage-% gate). v0.20 is an
infra-assurance cycle — no published-crate change; workspace stays `0.16.0`.

## Compliance posture

This is a personal open-source project. It is not a certified cryptographic
module and makes no regulatory, procurement, or production-suitability claim.
