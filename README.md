# gm-crypto-rs

Constant-time-designed pure-Rust SM2 / SM3 / SM4 SDK for Chinese national
cryptography (GB/T 32905 / 32918 / 32907 / GM/T 0009). Sign / verify,
public-key encrypt / decrypt, SM4-CBC, SM4-CTR (single-shot + streaming),
length-flexible batched SM4 block encryption, HMAC-SM3, PBKDF2-HMAC-SM3 —
all secret-touching paths guarded by an in-CI `dudect-bencher`
detectable-leak regression harness.

[![Crates.io](https://img.shields.io/crates/v/gmcrypto-core.svg)](https://crates.io/crates/gmcrypto-core)
[![Documentation](https://docs.rs/gmcrypto-core/badge.svg)](https://docs.rs/gmcrypto-core)
[![License](https://img.shields.io/crates/l/gmcrypto-core.svg)](https://crates.io/crates/gmcrypto-core)

**Personal project notice:** not affiliated with, endorsed by, sponsored by, or
certified by any upstream cryptography project, payment gateway, standards body,
or vendor.

> ⚠️ **Not independently audited.** No third-party / external security audit has
> been performed. Assurance is internal: a multi-model adversarial pre-publish
> re-audit (see [`docs/v1.0-reaudit.md`](docs/v1.0-reaudit.md)), in-CI KAT vectors,
> maintainer-run gmssl 3.1.1 interop (11/11, gated on `GMCRYPTO_GMSSL` — not run in
> CI), an in-CI `dudect` timing-leak harness, and an 18-target `cargo-fuzz` suite. This is a solo-maintained, best-effort open-source
> project with no support SLA. Review the code and **use at your own risk.** See
> [`SECURITY.md`](SECURITY.md) for the threat model and disclosure process.

## What this is

A small, auditable, pure-Rust SM2 / SM3 / SM4 SDK whose central
differentiating commitment is that secret-touching code paths are
**constant-time-designed and guarded by an in-CI [`dudect-bencher`](https://docs.rs/dudect-bencher/)
detectable-leak regression harness**: 18 real `ct_*` targets (12
always-on + 2 cfg-gated under `sm4-bitsliced-simd` + 3 cfg-gated under
`sm4-aead` + 1 cfg-gated under `sm4-xts`) plus a deliberately-leaky
`negative_control` that proves
the harness can detect leaks. Most real targets gate at `|tau| < 0.20`;
`ct_sign_k_class` and the direct `ct_fn_invert` / `ct_fp_invert` invert
diagnostics carry target-specific gate policy after the 2026-05-12
recalibration — see [`SECURITY.md`](SECURITY.md) and
[`docs/v0.5-dudect-recalibration.md`](docs/v0.5-dudect-recalibration.md).

The harness reports timing-leak detection events. **It does not prove
constant-time.** Low `|tau|` values mean the test could not detect a leak with
the budget given, not that no leak exists. Language taken directly from
`dudect-bencher`'s own docs.

The harness covers: SM2 sign (split by both private key `d` and nonce
`k` magnitude, with both retry nonces class-tied), SM2 decrypt (split
by recipient `d_B`), SM4 key schedule + single-block encrypt (split by
master key, under default linear-scan and `sm4-bitsliced` paths), the
v0.5 SIMD-packed dispatch (`ct_sm4_encrypt_block_bitsliced_simd`,
cfg-gated), v0.6's batched CBC-decrypt fanout
(`ct_sm4_cbc_decrypt_fanout`, cfg-gated), v0.7's SM4-CTR encrypt
(`ct_sm4_ctr_encrypt`, exercising the public batch path on every
cipher matrix entry), v0.8's SM4-GCM + SM4-CCM decrypt
(`ct_sm4_gcm_decrypt` and `ct_sm4_ccm_decrypt`, cfg-gated on
`sm4-aead`), v0.9's incremental-input buffered SM4-GCM decrypt
(`ct_sm4_gcm_decrypt_buffered`, cfg-gated on `sm4-aead`), HMAC-SM3
(split by key), encrypted-PKCS#8
decrypt (split by password bytes — both classes' blobs valid for their
class's password so both succeed via identical control flow), plus
direct `Fn::invert` and `Fp::invert` diagnostics. The `ct_sign_k_class`
target closes v0.1's structural blind spot to nonce-only leaks.

The `crypto-bigint 0.6 → 0.7.3` upgrade resolved the v0.1-era
`ConstMontyForm::invert` leak directly: on the v0.2 W0 harness both
direct invert diagnostics measured under `|tau| ≈ 0.01`, two orders of
magnitude below the gate. Subsequent GH Actions runner-image drift on
2026-05-12 raised the empirical noise floor on `ct_fn_invert` /
`ct_fp_invert` — both targets moved to PR-smoke telemetry + a nightly
gross-regression sentinel at `|tau| ≥ 0.55`. See
[`docs/v0.5-dudect-recalibration.md`](docs/v0.5-dudect-recalibration.md)
for the data and posture. See [`SECURITY.md`](SECURITY.md) for the full
constant-time discipline.

The differentiator vs. existing Rust SM2 crates (notably
[`RustCrypto/sm2`](https://docs.rs/sm2/), which already aims for constant-time
secret-dependent operations in its design) is **the in-CI regression gate**, not
the design intent in isolation.

## What this isn't

- Not a TLS/TLCP implementation.
- Not SM9, ZUC, post-quantum.
- Not an HSM/SDF/SKF integration.
- Not a certified cryptographic module.
- Not constant-time on CPUs with data-dependent multiply latencies (some older
  x86, some embedded).
- Not a comprehensive SM-crypto library yet — see the milestone roadmap.

## Stability & SemVer

The line graduates to **1.0 (stable)** with this release. crates.io history goes
**0.16.0 → 1.0.0**, skipping 0.17.0–0.23.0 (those were non-publishing assurance +
API-finalization milestones; their changes all ship together in the first stable
`1.0.0`). The only migration is 0.16 → 1.0, a single major bump — no published 0.x
consumer ever saw an intermediate break. The public API had been stable in
practice since v0.5; the **v1.0 readiness audit** (v0.21) froze and tooling-guarded
it, the **v0.22 API-tightening cycle** decoupled it from `crypto-bigint 0.7`, and
the **v0.23 pre-1.0 re-audit remediation cycle** applied the API/ABI-finality +
hardening fixes from a multi-model adversarial re-audit
([`docs/v1.0-reaudit.md`](docs/v1.0-reaudit.md)) —
see [`docs/v1.0-readiness.md`](docs/v1.0-readiness.md).

**From 1.0, SemVer is enforced**: breaking changes to the covered surface require a
major bump, and `cargo-semver-checks` runs as the forward breaking-change gate in
CI (the three crates always release together at one lockstep version, with
intra-workspace deps pinned exactly — `=1.0.0`). The runtime wire output (SM2
signatures / ciphertexts, SM4 mode bytes) is byte-identical to 0.16.0.

- **What's covered by SemVer:** the public Rust API of `gmcrypto-core` (the
  surface snapshotted in [`docs/api-baseline/gmcrypto-core.txt`](docs/api-baseline/gmcrypto-core.txt),
  drift-checked in CI) and the `gmcrypto-c` **C ABI** (the committed
  `crates/gmcrypto-c/include/gmcrypto.h`, drift-checked in CI).
- **What's NOT covered:** anything `#[doc(hidden)]` — `sm2::sign_raw_with_id` (the
  dudect harness hook), `Sm4Cbc{Encryptor,Decryptor}::take_output` (FFI-shim drains),
  (v0.22) the low-level SM2 curve arithmetic `sm2::curve` / `sm2::scalar_mul` /
  `ProjectivePoint::to_affine`, and (v0.23) the raw EC point surface
  `sm2::point` / `ProjectivePoint` (the type + module + re-export) +
  `Sm2PublicKey::{from_point, point}`, the low-level `asn1::{reader, writer, oid}`
  modules, and the in-crate `traits::{Hash, Mac, BlockCipher}` module (all kept
  `pub` only for in-repo dev crates); and the entire **`gmcrypto-simd`** crate, which
  is an internal acceleration backend with **no stable Rust API** (use `gmcrypto-core`
  from Rust, `gmcrypto-c` from C). These may change or be removed in any release.
- **High-level key path speaks keys, not points (v0.23).**
  `Sm2PrivateKey::public_key()` returns `Sm2PublicKey` (not the now-internal
  `ProjectivePoint`); `Sm2PublicKey::from_sec1_bytes` is the on-curve-checked public
  point constructor. `spki::{encode, decode}` and `sec1::EcPrivateKey.public` speak
  `Sm2PublicKey`.
- **RNG bound (v0.23).** `sm2::{sign_with_id, encrypt}` name the **fallible**
  `rand_core::TryCryptoRng` bound — a deliberate, documented ecosystem coupling
  (`rand_core` is the RNG interop point, the RustCrypto-wide convention; unlike the
  v0.22 `crypto-bigint` decoupling, replacing it would hurt interop). An RNG failure
  collapses to the single `Failed`, never a panic.
- **Single-shot SM4-GCM `encrypt` is fallible (v0.23).**
  `mode_gcm::{encrypt, encrypt_with_tag_len}` return `Option<…>`, rejecting plaintext
  past the `2^36 − 32`-byte GCM counter ceiling (matching the streaming path and
  `decrypt`).
- **Features are additive** (`default = []`; all 7 are opt-in) and the build is
  `no_std` + `alloc`-only with `unsafe_code = "forbid"` on the core.
- **MSRV is 1.85** (edition 2024); an MSRV bump is treated as a minor, not a patch.
- **`crypto-bigint` decoupling (v0.22):** the **always-on** (default-features) public
  API names **no** `crypto-bigint` types — the byte-adjacent types
  (`asn1::{encode,decode}_sig`, `Sm2Ciphertext::{x,y}`) take/return `[u8; 32]`, and
  the curve/scalar arithmetic is `#[doc(hidden)]` (above). The **only** place a
  `crypto-bigint 0.7` type appears in the public API is the **opt-in**
  `crypto-bigint-scalar` feature's `Sm2PrivateKey::from_scalar(U256)` — enabling that
  feature is an explicit opt-in to the `crypto-bigint 0.7` type contract (a
  `crypto-bigint` major bump would be breaking for that feature). The recommended
  always-on path (`Sm2PrivateKey::from_bytes_be`) avoids it entirely. See
  [`docs/v1.0-readiness.md`](docs/v1.0-readiness.md) §3.A.

## v0.16 scope (shipped)

**C FFI for the SM4-XTS multi-sector helper.** v0.16 exposes the v0.15
`sm4::mode_xts::{encrypt_sectors, decrypt_sectors}` through the `gmcrypto-c` C
ABI (behind the existing forwarding `sm4-xts` feature): two new symbols
`gmcrypto_sm4_xts_encrypt_sectors` / `gmcrypto_sm4_xts_decrypt_sectors` that
transform a contiguous run of equal-size sectors **in place** (`buf: *mut u8` +
`buf_len`), deriving sector `i`'s tweak as little-endian-128(`start_sector + i`)
— `start_sector` is a `uint64_t` LBA. Unlike the single-shot XTS FFI (uniformly
out-of-place), these are **in-place** — mirroring the core's `&mut [u8]` API so
disk callers never double-allocate. Byte-identical to the core helper; single
`GMCRYPTO_ERR` with `buf` untouched on error; confidentiality only (no auth).
The deferred FFI half of v0.15, on the established core-in-vN / FFI-in-vN+1
cadence — every cipher mode is now FFI-complete. **No new dependency, no new
feature flag, no new `gmcrypto-core` API, no new dudect target.** Design
rationale: [`docs/v0.16-scope.md`](docs/v0.16-scope.md) (Q16.1–Q16.12).

## v0.20 scope (infra-assurance, not a crates.io release) — streaming-decryptor differential fuzzing + coverage

**Two new differential fuzz targets + `cargo fuzz coverage` + a codified v1.0
constant-time baseline.** `fuzz_sm4_cbc_streaming_decrypt` and
`fuzz_sm4_gcm_streaming_decrypt` feed the ciphertext to the **streaming**
decryptors (`Sm4CbcDecryptor` / `Sm4GcmDecryptor`) in **arbitrary chunk
boundaries** and assert the result is **byte-identical** to the single-shot
`mode_{cbc,gcm}::decrypt` oracle — a *differential* invariant (catches the CBC
buffer-back-by-one PKCS#7 boundary and the GCM commit-on-verify GHASH
accumulator), stronger than v0.14's no-panic property. The nightly fuzz sweep
grows to **18 targets** (initial sweep: zero crashes, zero divergences) and gains
a **non-gating `cargo fuzz coverage`** job that renders per-target `llvm-cov`
TOTALS over the committed seed corpus and uploads them (the report is the
deliverable, not a coverage-% gate). v0.20 also **codifies the settled v1.0
constant-time baseline** in [`SECURITY.md`](SECURITY.md): composite dudect
targets stay gated `|tau| < 0.20`; the two single-inversion micro-diagnostics
remain telemetry + a `|tau| ≥ 0.55` sentinel (the v0.19 falsification is the
evidence), with a *narrow* revisit door (a class-split-twin without the inversion
op, or offline/dedicated hardware — never PR-executing public self-hosted CI).
The theme was chosen after a Codex + Grok strategy discussion (one more assurance
cycle that feeds v1.0 readiness, over a third dudect cycle or new features). A
*repository / infra-assurance* milestone — only the workspace-excluded `fuzz/`
crate + `fuzz-nightly.yml` + docs change (workspace stays `0.16.0`; crates.io
skips `0.20.0` per the v0.14/v0.17/v0.18/v0.19 precedent). Design + result:
[`docs/v0.20-scope.md`](docs/v0.20-scope.md) (Q20.1–Q20.5). **Next: v0.21 = the
v1.0 readiness audit**, with v0.20's harnesses + coverage as input evidence.

## v0.19 scope (infra-assurance, not a crates.io release) — relative gate tested and falsified

**Self-calibrating relative dudect gate — TESTED and FALSIFIED → honest fallback.**
v0.19 set out to re-promote the two direct-invert diagnostics
(`ct_fn_invert` / `ct_fp_invert`) off the v0.18 telemetry/sentinel posture by
adding two **fix-vs-fix noise-floor probes** (`noise_floor_fn_invert` /
`noise_floor_fp_invert` — each runs the same `Fn`/`Fp` inversion as its suspect
but feeds both dudect classes one identical input, so its `|tau|` is pure
measurement noise) and gating each target *relatively*:
`median(target) ≤ max(0.20, 4·median(probe))` — a threshold that adapts to the
runner's own noise floor.

The 100K calibration on `main` **falsified the matched-sensitivity premise**: the
probes stay uniformly quiet (~0.005) while the real class-split targets spike
intermittently into [0.26–0.32] (`ct_fp_invert` reached a **median of 0.2606** on
the `sm4-bitsliced-simd` leg, ratio 50). The runner noise lives in the **two-input
class-split difference** (`z_small` vs `z_large`), *not* the operation duration a
same-input probe can observe — so the probe cannot track it and the relative
threshold just pins at the `0.20` the noise already breaks. Per the pre-committed
honest-fallback path, the relative gate is demoted to non-blocking telemetry, the
two targets revert to telemetry (PR) / gross-regression **sentinel @0.55**
(nightly), and the probes are **kept as telemetry** — they are the evidence that
the noise is class-split-specific, the input to a v0.20 **class-split-aware
"noise-twin"** reference. A **repository / infra-assurance** milestone — the only
crate change is the dev-only bench harness (published library byte-unchanged;
workspace stays `0.16.0`; crates.io skips `0.19.0` per the v0.14 / v0.17 / v0.18
precedent). Design + result:
[`docs/v0.19-scope.md`](docs/v0.19-scope.md) (Q19.1–Q19.7) +
[`docs/v0.5-dudect-recalibration.md`](docs/v0.5-dudect-recalibration.md) (v0.19
resolution).

**Deferred to v0.20+**: a class-split-aware "noise-twin" dudect reference (the
v0.19 successor that could finally re-promote the invert diagnostics);
round-trip / differential + streaming-decryptor parser fuzzing; RustCrypto `aead`
trait fit (still `0.6.0-rc.10`); `cargo fuzz coverage`; AVX-512 `sbox_x64`; CCM
buffered input; a v1.0 readiness pass.

## v0.18 scope (shipped — infra-assurance, not a crates.io release)

**dudect-gate hardening.** v0.18 pins the dudect CI workflows' drift axes
(`ubuntu-24.04` OS-label + exact `dtolnay/rust-toolchain@1.95.0`) and gates on a
**CI-level multi-run median** `|tau|` (PR 3 runs / nightly 5 runs; the
`required_low` gates + the nightly gross-regression sentinel use the **median**,
`negative_control` uses the **min**, and any required target not measured on
every run fails). The bench harness `timing_leaks.rs` is **byte-unchanged** — the
loop and median live entirely in CI. A 100K×5 calibration measured the
`ct_fn_invert`/`ct_fp_invert` diagnostics back near their ~0.006 baseline, but
they were **kept on the telemetry / sentinel posture (not re-promoted)**: the
noise that demoted them is runner-image-sensitive and would re-flake a tight gate
if it returns — robustness over a tighter gate. A **repository / infra-assurance**
milestone — no crate code change (workspace stays `0.16.0`; crates.io skips
`0.18.0` per the v0.14 / v0.17 precedent). Design rationale:
[`docs/v0.18-scope.md`](docs/v0.18-scope.md) (Q18.1–Q18.7) +
[`docs/v0.5-dudect-recalibration.md`](docs/v0.5-dudect-recalibration.md) (v0.18
resolution).

**Deferred to v0.19+** (per [`docs/v0.18-scope.md`](docs/v0.18-scope.md) §5/§6):
a self-calibrating relative dudect gate (the change that could safely re-promote
the invert diagnostics); round-trip / differential + streaming-decryptor parser
fuzzing; RustCrypto `aead` trait fit (still `0.6.0-rc.10`); `cargo fuzz coverage`;
AVX-512 `sbox_x64`; CCM buffered input; a v1.0 readiness pass.

## v0.15 scope (shipped)

**SM4-XTS multi-sector (disk) helper.** v0.15 adds
`sm4::mode_xts::{encrypt_sectors, decrypt_sectors}` (opt-in `sm4-xts` feature):
encrypt/decrypt a contiguous run of equal-size disk sectors **in place**
(`&mut [u8] -> Option<()>`), deriving sector `i`'s tweak as the **little-endian
128-bit** encoding of `start_sector + i` (the standard disk-XTS data-unit
convention). It owns the sector-number → tweak encoding the single-shot v0.12 API
left to the caller, and is byte-identical to looping that API per sector. Single
`None` failure mode (`buf` untouched on validation failure); confidentiality
only (no authentication). **Pure-core: no new dependency, no new feature flag, no
new SIMD, no new dudect target.** Design rationale:
[`docs/v0.15-scope.md`](docs/v0.15-scope.md) (Q15.1–Q15.12). The C FFI for the
sector helper **shipped in v0.16** (above), on the established core-in-vN /
FFI-in-vN+1 cadence.

crates.io goes **0.13.0 → 0.15.0**: `0.14.0` names the unpublished
parser-fuzzing assurance cycle (below) and is intentionally never published.

## v0.14 — parser fuzzing (assurance; not a crates.io release)

**Pre-v1.0 hardening.** v0.14 adds a `cargo-fuzz` (libFuzzer) harness over the
**entire untrusted-input decode/decrypt surface** of `gmcrypto-core` — 16
targets covering PEM, PKCS#8 (incl. PBES2 decrypt), SPKI, SEC1, the DER reader
primitives, SM2 DER + raw ciphertext, SM2 decrypt + signature-verify, and the
SM4-CBC/GCM/CCM/XTS decrypts — proving the failure-mode invariant on adversarial
bytes: **no panic, no unbounded allocation, no hang.** A capped nightly job
(`.github/workflows/fuzz-nightly.yml`) runs them on a schedule.

The initial sweep found **zero crashes** across all 16 targets, so v0.14 makes
**no code change to the published crates** and is **not cut as a crates.io
release** (publishing byte-identical crypto is release noise) — it lands as an
assurance/infra change. The fuzz crate lives in a workspace-excluded `fuzz/`
(nightly-only; never enters the published dependency graph). Design rationale:
[`docs/v0.14-scope.md`](docs/v0.14-scope.md). Run it yourself:
[`fuzz/README.md`](fuzz/README.md).

**Deferred to v0.15+** (per [`docs/v0.14-scope.md`](docs/v0.14-scope.md) §5/§6):
the SM4-XTS per-sector helper (**shipped in v0.15**, above); round-trip /
differential parser fuzzing, streaming-decryptor fuzzing, RustCrypto `aead`
trait fit (still `0.6.0-rc.10`), pinned dudect runner, `cargo fuzz coverage` in
CI, AVX-512 `sbox_x64`, a v1.0 readiness pass (now v0.16+).

## v0.13 scope (shipped)

**C ABI for SM4-XTS.** v0.13 exposes the v0.12 `sm4::mode_xts` core through the
`gmcrypto-c` C ABI (`gmcrypto_sm4_xts_encrypt` / `_decrypt`) behind a new
forwarding `sm4-xts` feature — the deferred FFI half of v0.12, on the
established core-then-FFI cadence (SM4-GCM/CCM core in v0.8 → FFI in v0.10).
Design rationale: [`docs/v0.13-scope.md`](docs/v0.13-scope.md).

- **Additive only — no public API breakage, no new dependency.** The default
  build of both crates is byte-unchanged; `sm4-xts` forwards to the pure-core
  `gmcrypto-core/sm4-xts`.
- Single-shot, mirroring the single-shot SM4-GCM FFI shape minus nonce/AAD/tag:
  32-byte key (`Key1 ‖ Key2`), 16-byte tweak, length-preserving output via the
  `(out, out_capacity, out_actual_len)` convention. Byte-identical to
  `gmcrypto_core::sm4::mode_xts`. New `GMCRYPTO_SM4_XTS_KEY_SIZE` header
  constant; single `GMCRYPTO_ERR` failure mode. **Confidentiality only.**
- Doc-only C example `crates/gmcrypto-c/examples/sm4_xts_sector.c`; 5 new
  `c_smoke` Rust-equivalence tests. No new `gmcrypto-core` API, no new dudect
  target (the FFI is a thin shim over the v0.12 core path).

**Followed by v0.14** (per [`docs/v0.13-scope.md`](docs/v0.13-scope.md) §5/§6):
parser fuzzing — the recommended pre-v1.0 assurance gate — landed as the v0.14
assurance cycle above. RustCrypto `aead` trait fit (still `0.6.0-rc.10`),
pinned/noise-isolated dudect runner, and AVX-512 `sbox_x64` remain deferred.

## v0.12 scope (shipped)

**SM4-XTS — tweakable mode for disk/sector encryption.** v0.12 adds
`sm4::mode_xts` behind the new opt-in `sm4-xts` feature: single-shot, full
ciphertext stealing, GB/T 17964-2021 (GM-T OID `1.2.156.10197.1.104.10`),
byte-identical to OpenSSL 3.x EVP `SM4-XTS` (`xts_standard=GB`). Design
rationale: [`docs/v0.12-scope.md`](docs/v0.12-scope.md); KAT sourcing:
[`docs/v0.12-xts-kat-sourcing.md`](docs/v0.12-xts-kat-sourcing.md).

- **Default-features users are unaffected** — additive, opt-in, **no new
  dependency** (the XTS tweak doubling is a trivial bit-reflected
  multiply-by-x, not GHASH, so no `gmcrypto-simd` dep).
- **GB/T 17964, not IEEE 1619** — the two standards differ in the GF(2¹²⁸)
  tweak-doubling convention (GB is the bit-reflected / GHASH-style one), so
  they produce different ciphertext for multi-block / non-aligned data. v0.12
  targets GB (the SM4 national standard + OpenSSL's default for SM4-XTS).
- **Confidentiality only — no authentication.** XTS has no tag; callers needing
  integrity use an AEAD mode (GCM/CCM). The per-data-unit tweak-uniqueness
  contract is the caller's responsibility.
- 32-byte key (`Key1 ‖ Key2`) + raw 16-byte tweak; lengths `[16 B, 16 MiB]`;
  single `None` failure mode. New dudect target `ct_sm4_xts_decrypt`. The whole-
  block bulk rides the `Sm4Cipher::encrypt_blocks` batch API (picks up the SIMD
  fanout under `sm4-bitsliced-simd`).

**Deferred to v0.13** (per [`docs/v0.12-scope.md`](docs/v0.12-scope.md) §5/§6):
C FFI for SM4-XTS, RustCrypto `aead` trait fit, pinned/noise-isolated dudect
runner, AVX-512 `sbox_x64`, CCM incremental input.

## v0.11 scope (shipped)

**RustCrypto trait-fit modernization.** v0.11 migrates the opt-in
`digest-traits` / `cipher-traits` impls from `digest 0.10` / `cipher 0.4` to
`digest 0.11` / `cipher 0.5` (the `crypto-common 0.2` / `hybrid-array`
generation), in-place. Design rationale:
[`docs/v0.11-scope.md`](docs/v0.11-scope.md).

- **Default-features users are unaffected** — the trait fit is opt-in;
  `generic-array` / `hybrid-array` never enter the default dep graph, and every
  SM2 / SM3 / SM4 / HMAC / AEAD output is byte-identical (validated against the
  full KAT suite + gmssl 3.1.1 interop).
- **BREAKING for trait-fit consumers only:** code enabling
  `digest-traits` / `cipher-traits` must bump its own `digest` / `cipher` deps
  to `0.11` / `0.5`. HMAC construction via the `Mac` trait moves to
  `digest::KeyInit::new_from_slice` (`digest 0.11`'s `Mac` dropped `KeyInit`);
  the `cipher` block traits renamed `BlockEncrypt` / `BlockDecrypt` →
  `BlockCipherEncrypt` / `BlockCipherDecrypt`.
- **MSRV stays 1.85.** The RustCrypto `aead 0.6` trait fit remains deferred
  (still `0.6.0-rc.10`); v0.11 lands the `crypto-common 0.2` line it will need.

**Deferred to v0.12** (per [`docs/v0.11-scope.md`](docs/v0.11-scope.md) §5/§6):
RustCrypto `aead` trait fit, pinned/noise-isolated dudect runner, AVX-512
`sbox_x64`, SM4-XTS, CCM incremental input, Argon2-with-SM3.

## v0.10 scope (shipped)

**Streaming AEAD FFI.** v0.10 exposes the v0.9 incremental-input buffered
SM4-GCM encryptor/decryptor through the `gmcrypto-c` C ABI — the item
v0.9 deferred (Q9.6) now that the Rust streaming API is proven. Additive
behind the existing `sm4-aead` feature. Design rationale:
[`docs/v0.10-scope.md`](docs/v0.10-scope.md).

- **9 streaming AEAD C FFI symbols + 2 opaque handle types** —
  `gmcrypto_sm4_gcm_encryptor_t` (output-streaming: `new` / `update` →
  ciphertext per chunk / `finalize` + `finalize_with_tag_len` → tag /
  `free`) and `gmcrypto_sm4_gcm_decryptor_t` (commit-on-verify: `new` /
  `update` buffers and emits **nothing** / `finalize_verify` releases
  plaintext only after the constant-time tag check / `free`).
  `_finalize*` consume+free the handle; single `GMCRYPTO_ERR` on every
  failure (no tag-/length-oracle across the boundary). Mirrors the v0.5
  CBC-streaming lifecycle. C example:
  [`examples/sm4_gcm_streaming.c`](crates/gmcrypto-c/examples/sm4_gcm_streaming.c).

**No public API breakage — purely additive.** v0.9.0 callers can
`cargo update` to v0.10.0 without migration. No new `gmcrypto-core` API;
no new dudect target (the FFI is a thin wrapper over the v0.9
`ct_sm4_gcm_decrypt_buffered`-gated path).

**Deferred to v0.11** (per [`docs/v0.10-scope.md`](docs/v0.10-scope.md)
§5/§6): streaming/incremental CCM, RustCrypto `aead` trait fit (upstream
still `0.6.0-rc.10`), pinned dudect runner, AVX-512 `sbox_x64`, SM4-XTS,
Argon2-with-SM3.

## v0.9 scope (shipped)

**AEAD ergonomics.** v0.9 extends the v0.8 AEAD core with the three
items v0.8 deferred: GCM tag-length parameterization, incremental-input
buffered SM4-GCM, and single-shot AEAD C FFI. All additive behind the
existing `sm4-aead` flag. Design rationale: [`docs/v0.9-scope.md`](docs/v0.9-scope.md).

- **`sm4::GcmTagLen` + `mode_gcm::encrypt_with_tag_len` /
  `decrypt_with_tag_len`** — W1. Caller-chosen GCM tag length per NIST
  SP 800-38D §5.2.1.2 (`{4, 8, 12, 13, 14, 15, 16}` bytes; truncated
  tag = `MSB_t(full_tag)`). `GcmTagLen::new(usize) -> Option<Self>`
  centralizes the valid-length policy. The fixed-16-byte `encrypt` /
  `decrypt` are unchanged.
- **`sm4::Sm4GcmEncryptor` / `Sm4GcmDecryptor`** — W2. Incremental-
  input buffered SM4-GCM (deliberately NOT "streaming"). The
  **encryptor** is output-streaming: `update(chunk) -> Option<Vec<u8>>`
  emits each chunk's ciphertext (`None` once the cumulative plaintext
  would exceed the NIST §5.2.1.1 ceiling `2^36 − 32` bytes);
  `finalize()` / `finalize_with_tag_len()` emit the tag. The
  **decryptor** is input-incremental but output-BUFFERED:
  `update(chunk)` buffers ciphertext + folds GHASH, and
  `finalize_verify(tag) -> Option<Vec<u8>>` releases the plaintext only
  after the constant-time tag check (commit-on-verify — never leaks
  pre-verify bytes). AAD is supplied at construction. Driven with any
  chunking, both reproduce the single-shot path byte-for-byte.
- **6 single-shot AEAD C FFI entry points** — W4. `gmcrypto_sm4_gcm_
  encrypt` / `_decrypt` / `_encrypt_with_tag_len` / `_decrypt_with_tag_
  len` + `gmcrypto_sm4_ccm_encrypt` / `_decrypt`, behind a new
  forwarding `sm4-aead` feature on `gmcrypto-c`. Every error path
  returns `GMCRYPTO_ERR` (single failure code). Streaming AEAD FFI is
  deferred to v0.10.
- **New dudect target `ct_sm4_gcm_decrypt_buffered`** — W3. Class-split
  by master key, drives `Sm4GcmDecryptor`; `|tau| < 0.20` (5K-sample
  smoke `|τ| ≈ 0.029`). No new CI matrix slot — rides the existing
  `sm4-aead` entries.

**No public API breakage — purely additive.** v0.8.0 callers can
`cargo update` to v0.9.0 without migration; `sm4-aead` is opt-in.

**Deferred to v0.10** (per [`docs/v0.9-scope.md`](docs/v0.9-scope.md)
§5/§6): CCM incremental input, streaming AEAD FFI, RustCrypto `aead`
trait fit (upstream still on `0.6.0-rc`), pinned dudect runner,
AVX-512 `sbox_x64`, SM4-XTS, Argon2-with-SM3.

## v0.8 scope (shipped)

The **AEAD core**. v0.8 cashed in the cipher-mode surface that v0.7
opened up: SM4-GCM and SM4-CCM single-shot, plus a constant-time
GHASH primitive in `gmcrypto-simd`.

- **`sm4::mode_gcm::encrypt` / `decrypt`** — W2. Single-shot SM4-GCM
  per NIST SP 800-38D / GM/T 0009 / RFC 8998. `encrypt(key, nonce,
  aad, pt) -> (Vec<u8>, [u8; 16])` returns `(ciphertext, tag)`.
  `decrypt(key, nonce, aad, ct, tag) -> Option<Vec<u8>>` —
  `Some(plaintext)` only when the tag verifies (constant-time
  compare via `subtle::ConstantTimeEq`). Both 12-byte canonical
  and arbitrary-length nonce paths supported. Tag length fixed at
  128 bits in v0.8 (parameterized in v0.9 via `GcmTagLen`).
  **Byte-identical to gmssl 3.1.1 `sm4 -gcm`** — bidirectional
  interop validated.
- **`sm4::mode_ccm::encrypt` / `decrypt`** — W3. Single-shot SM4-CCM
  per NIST SP 800-38C / RFC 3610 / GM/T 0009 (OID
  `1.2.156.10197.1.104.9`). `encrypt(key, nonce, aad, pt, tag_len)
  -> Option<Vec<u8>>` (output: `ciphertext ‖ tag`). `tag_len ∈
  {4, 6, 8, 10, 12, 14, 16}` per spec, validated at API entry.
  `nonce.len() ∈ [7, 13]`. Pure-Rust CBC-MAC + CTR over the
  existing `Sm4Cipher` path — no GHASH. **Byte-identical to OpenSSL
  3.x EVP `SM4-CCM`** across 8 KAT scenarios (gmssl 3.1.1 doesn't
  ship `sm4 -ccm` so the CCM reference oracle comes from OpenSSL;
  see [`docs/v0.8-ccm-kat-sourcing.md`](docs/v0.8-ccm-kat-sourcing.md)).
- **`gmcrypto_simd::ghash::ghash_mul(h, x) -> [u8; 16]`** — W1.
  Constant-time GHASH multiplication over `GF(2^128) /
  (x^128 + x^7 + x^2 + x + 1)`. Single dispatch entry point:
  - `ghash_mul_clmul` on `x86_64` (PCLMULQDQ + SSE2; runtime
    cpufeatures detect; Intel Westmere+ / AMD Bulldozer+).
  - `ghash_mul_pmull` on `aarch64` (ARMv8.0 AES extension
    `vmull_p64`; runtime cpufeatures detect; Apple Silicon /
    most modern ARM chips).
  - `ghash_mul_software` (bit-serial mask-XOR; constant-time over
    both inputs; available everywhere as fallback).
- **New `sm4-aead` feature flag** — default-off; opt-in.
  `sm4-aead = ["dep:gmcrypto-simd"]` activates `mode_gcm` and
  `mode_ccm`. Additive on the default-features build.
- **New dudect targets `ct_sm4_gcm_decrypt` + `ct_sm4_ccm_decrypt`**
  — W4. Class-split by master key over a fixed 256-byte
  plaintext + 16-byte AAD. Both classes' `(ct, tag)` pairs are
  valid encrypts under their **own** keys, so both decrypt paths
  reach the tag-compare via identical control flow. Same
  `|tau| < 0.20` gate as the rest of the SM4 surface; new CI
  matrix slot `sm4-bitsliced-simd,sm4-aead` exercises the
  most-demanding cipher-stack combination.

**No public API breakage — purely additive.** v0.7.0 callers can
`cargo update` to v0.8.0 without migration; `sm4-aead` is opt-in.

Everything v0.4 shipped (`wasm32-unknown-unknown` build, RustCrypto
trait fit behind `digest-traits` / `cipher-traits`, bitsliced SM4
S-box behind `sm4-bitsliced`, `gmcrypto-c` C ABI crate) is unchanged
— see the Roadmap row for the compact reference and `CHANGELOG.md`
`[0.4.0]` for detail.

Everything v0.3 shipped is unchanged:

- Reusable strict-canonical DER reader / writer subset
  (`gmcrypto_core::asn1::{reader, writer, oid}`).
- PEM + encrypted PKCS#8 + X.509 SPKI + SEC1 codecs
  (`gmcrypto_core::{pem, pkcs8, spki, sec1}`).
- Full bidirectional gmssl 3.1.1 interop (SM2 sign / verify, SM2
  encrypt / decrypt, SM4-CBC). Gated on `GMCRYPTO_GMSSL=1`.
- Raw byte-concat SM2 ciphertext helpers
  (`gmcrypto_core::sm2::raw_ciphertext`): `C1 || C3 || C2`
  emit + decode; legacy `C1 || C2 || C3` decrypt-only.
- Streaming `HmacSm3` + `Sm4Cbc{En,De}cryptor`. In-crate
  `Hash` / `Mac` / `BlockCipher` traits (`gmcrypto_core::traits`).
- Comb-table `mul_g` (~5× sign-side speedup). 64 sub-tables of 16
  entries each, lazily built once per process via `spin::Once`.

Everything v0.2 shipped is unchanged:

- SM3 hash function (`#![no_std]` + `alloc`).
- SM2 sign / verify with custom signer ID (default `1234567812345678` per GM/T 0009).
- SM2 public-key encrypt / decrypt with GM/T 0009-2012 ciphertext DER
  (`SEQUENCE { x, y, hash, ciphertext }`). Invalid-curve attack defense
  via on-curve check on `C1` before scalar mult; non-branching
  KDF-zero detection so a chosen-ciphertext attacker cannot distinguish
  it from a normal MAC failure.
- SM4 block cipher (GB/T 32907-2016) and SM4-CBC (PKCS#7 padding,
  caller-supplied unpredictable IV per NIST SP 800-38A Appendix C).
  Constant-time-designed `subtle` linear-scan S-box (~1-2M blocks/s);
  opt-in bitsliced (table-less, gate-only) S-box via the
  `sm4-bitsliced` feature (v0.4 W3). PKCS#7 strip uses a
  constant-time scan over the final block; `decrypt` collapses every
  failure mode to a single `None` against padding-oracle attacks.
- HMAC-SM3 per RFC 2104, gmssl-cross-validated KAT vectors. Hash-first
  long-key path. v0.3 adds the streaming `HmacSm3` shape alongside
  single-shot `hmac_sm3`.
- PBKDF2-HMAC-SM3 per RFC 8018 §5.2. Caller-supplied output buffer
  (no internal allocation, no iteration-count default).
- Constant-time-designed `Fp` and `Fn` field arithmetic via
  `crypto-bigint = 0.7.3`.
- Renes-Costello-Batina complete addition formulas for the SM2 curve (a=-3 specialized).
- Fixed-base (v0.3 comb-table) and variable-base scalar multiplication,
  both constant-time-designed with `subtle::ConditionallySelectable`
  linear-scan table lookup.
- Fixed-K masked-select signing retry: the retry loop runs `K=2` iterations
  unconditionally, regardless of which iteration produced a valid signature.
  The constant-time contract holds for any RNG that respects `CryptoRng`;
  pathological RNGs cannot leak the secret via observable retry count.
- Strict canonical ASN.1 DER for `SEQUENCE { r, s }` (signatures), the
  GM/T 0009 SM2 ciphertext SEQUENCE, and all v0.3 PEM / PKCS#8 / SPKI
  / SEC1 wire formats. Rejects non-canonical leading-zero padding,
  sign-bit-set first bytes, empty content, and (for ciphertext
  coordinates) values `≥ p`.
- KAT vectors from GB/T 32905-2016 (SM3), GB/T 32918.2-2017 / .5-2017
  (SM2), GB/T 32907-2016 Appendix A.1 (SM4 single-block + 1M-round),
  GM/T 0042-2015 (HMAC-SM3), GM/T 0091-2020 (PBKDF2-HMAC-SM3).
- `gmssl` CLI cross-validation for HMAC-SM3, PBKDF2-HMAC-SM3, and
  (new in v0.3) SM2 sign/verify, SM2 encrypt/decrypt, and SM4-CBC
  in both directions. Gated on `GMCRYPTO_GMSSL=1`.
- `dudect-bencher` harness — 18 real `ct_*` targets (12 always-on + 2
  cfg-gated under `sm4-bitsliced-simd` + 3 cfg-gated under `sm4-aead` + 1
  cfg-gated under `sm4-xts`) plus a deliberately-leaky `negative_control`
  that proves the harness can detect leaks. Matrix-run under
  `features=default`, `sm4-bitsliced`, `sm4-bitsliced-simd`, and
  `sm4-bitsliced-simd,sm4-aead,sm4-xts`
  — PR-smoke 10⁴ samples; nightly 10⁵ samples (more samples = tighter
  empirical confidence at the same threshold). Most real targets gate
  at `|tau| < 0.20`; per-target policy in [`SECURITY.md`](SECURITY.md).
- Failure-mode invariant: every `Result`-returning public API uses
  the workspace-wide `gmcrypto_core::Error` (single `Failed` variant,
  `#[non_exhaustive]`); per-module aliases `sm2::Error`, `pem::Error`,
  `pkcs8::Error` all point at the same type. `verify_with_id` returns
  `bool`; DER decode returns `Option`. Defense against padding-oracle,
  malleability, and invalid-curve attacks.
- Zeroization on private keys, SM4 round keys, HMAC `K'` /
  `K' XOR ipad` / `K' XOR opad`, PBKDF2 intermediates, SM2 KDF
  buffers, and PKCS#8 inner-key scratch.

## Roadmap

| Version | Scope |
|---|---|
| v0.2 (shipped) | SM4 + SM4-CBC, HMAC-SM3, PBKDF2-HMAC-SM3, SM2 encrypt/decrypt + GM/T 0009 ciphertext DER, dudect harness expansion to 11 targets. See [`CHANGELOG.md`](CHANGELOG.md) `[0.2.0]`. |
| v0.3 (shipped) | Reusable ASN.1 reader/writer subset; PEM, encrypted PKCS#8, X.509 SPKI, SEC1; full bidirectional gmssl interop (incl. SM2 sign/verify + SM2 encrypt/decrypt with PEM-wrapped keys + SM4-CBC); raw byte-concat ciphertext helpers (`C1\|\|C3\|\|C2` modern + legacy `C1\|\|C2\|\|C3` decrypt); streaming `HmacSm3` / `Sm4CbcEncryptor` / `Sm4CbcDecryptor` + in-crate `Hash`/`Mac`/`BlockCipher` traits; comb-table `mul_g` (~5× sign-side speedup); dudect harness expanded to 12 targets. See [`CHANGELOG.md`](CHANGELOG.md) `[0.3.0]`. |
| v0.4 (shipped) | `wasm32-unknown-unknown` build target; RustCrypto-trait fit (`digest::Digest` / `digest::Mac` / `cipher::BlockEncrypt`/`BlockDecrypt`) behind opt-in `digest-traits` / `cipher-traits` feature flags; bitsliced (table-less, gate-only) SM4 S-box behind the opt-in `sm4-bitsliced` feature; new `gmcrypto-c` workspace member exposing the SM2/SM3/SM4/HMAC/PBKDF2 surface as a C ABI (cdylib + staticlib + cbindgen-generated header). See [`CHANGELOG.md`](CHANGELOG.md) `[0.4.0]`. |
| v0.5.0 (shipped) | C-ABI completeness (streaming CBC + raw-byte SM2 ciphertext + caller-supplied RNG callback); `sm4-bitsliced-simd` feature-flag scaffolding — v0.5.0 ships no SIMD fast path (the feature transparently delegates to the v0.4 single-block bitslice); BREAKING ergonomic cleanup — workspace-wide `gmcrypto_core::Error`, `Sm2PrivateKey::new(U256)` → `from_scalar(U256)` (gated behind `crypto-bigint-scalar`) + always-on `from_bytes_be(&[u8; 32])` constructor, `std` feature removed. See [`CHANGELOG.md`](CHANGELOG.md) `[0.5.0]`. |
| v0.5.1 (shipped) | W4 phase 2 — new sibling crate `gmcrypto-simd` carrying an **AVX2 8-way packed bitsliced SM4 S-box** behind opt-in `sm4-bitsliced-simd`, with runtime CPU detection (`cpufeatures`) and silent scalar fallback on non-AVX2 hosts. v0.5.1's `tau` dispatch fed the AVX2 path with 7 wasted lanes; production throughput matched v0.4 single-block bitslice. Dudect calibration update — `ct_fn_invert` / `ct_fp_invert` moved to PR-smoke telemetry + 100K nightly gross-regression sentinel after a GH Actions `ubuntu-24.04` runner-image shift on 2026-05-12 raised the empirical noise floor; see `docs/v0.5-dudect-recalibration.md`. See [`CHANGELOG.md`](CHANGELOG.md) `[0.5.1]`. |
| v0.6.0 (shipped) | **W4 milestone close-out — the throughput-win release.** W4 phase 3: NEON 4-way bitsliced SM4 on `aarch64` (compile-time baseline) + AVX2 32-byte full-width packed S-box (`sbox_x32`) + `Sm4CbcDecryptor::process_chunk` SIMD fanout. Per round of the SM4 decrypt, batched blocks' `tau` inputs pack into one SIMD register (32 bytes on x86_64 / 8-block batch, 16 bytes on aarch64 / 4-block batch) — 32× fewer SIMD dispatches per 8-block batch than v0.5.1. CBC encryption stays single-block (chain-of-blocks defeats SIMD packing). New dudect target `ct_sm4_cbc_decrypt_fanout` (Q6.7) gates the fanout path at `\|tau\| < 0.20`. Exhaustive lane-position-shifted SIMD tests (8192 + 4096 cases) per Q6.8. **No public API changes; no breaking changes — additive only.** See [`CHANGELOG.md`](CHANGELOG.md) `[0.6.0]` and `docs/v0.6-scope.md`. |
| v0.7.0 (shipped) | **Cipher-mode surface expansion.** First version where v0.6's SIMD machinery is callable from user code outside the CBC-decrypt internal path. New: public length-flexible `Sm4Cipher::encrypt_blocks` / `decrypt_blocks` (W1; Q7.7); single-shot `sm4::mode_ctr::encrypt` / `decrypt` (W2; GM/T 0002-2012 §5.4); streaming `sm4::ctr_streaming::Sm4CtrCipher` (W3); new dudect target `ct_sm4_ctr_encrypt` (gates `\|tau\| < 0.20` on every cipher path). Plus the v0.8 AEAD scope doc (`docs/v0.7-aead-scope.md`, Q8.1–Q8.8 sign-off + v0.9 candidate Q-list). **No public API breakage — additive only.** See [`CHANGELOG.md`](CHANGELOG.md) `[0.7.0]`. |
| v0.8.0 (shipped) | **AEAD core — SM4-GCM + SM4-CCM.** Per `docs/v0.7-aead-scope.md` Q8.1–Q8.8. New: `gmcrypto_simd::ghash::ghash_mul` constant-time GHASH primitive (CLMUL on `x86_64` / PMULL on `aarch64` / software Karatsuba fallback; W1); `sm4::mode_gcm::encrypt` / `decrypt` byte-identical to gmssl 3.1.1 `sm4 -gcm` with bidirectional interop (W2); `sm4::mode_ccm::encrypt` / `decrypt` byte-identical to OpenSSL 3.x EVP `SM4-CCM` across 8 KAT scenarios (W3; gmssl 3.1.1 lacks `sm4 -ccm` so OpenSSL is the oracle — see `docs/v0.8-ccm-kat-sourcing.md`); new dudect targets `ct_sm4_gcm_decrypt` + `ct_sm4_ccm_decrypt` + new CI matrix slot `sm4-bitsliced-simd,sm4-aead` (W4). Behind opt-in `sm4-aead` feature flag (additive; default-off). **No public API breakage — additive only.** See [`CHANGELOG.md`](CHANGELOG.md) `[0.8.0]`. |
| v0.9.0 (shipped) | **AEAD ergonomics.** Per `docs/v0.9-scope.md` Q9.1–Q9.10. New: `sm4::GcmTagLen` + `mode_gcm::encrypt_with_tag_len` / `decrypt_with_tag_len` (NIST SP 800-38D §5.2.1.2 truncated tags; W1); incremental-input buffered `sm4::Sm4GcmEncryptor` (output-streaming) / `Sm4GcmDecryptor` (output-buffered, commit-on-verify) — differential-KAT-equal to single-shot across arbitrary chunking (W2); new dudect target `ct_sm4_gcm_decrypt_buffered` (W3); 6 single-shot AEAD C FFI symbols (`gmcrypto_sm4_gcm_*` / `gmcrypto_sm4_ccm_*`) behind a forwarding `sm4-aead` feature on `gmcrypto-c` (W4). Behind the existing `sm4-aead` flag. **No public API breakage — additive only.** See [`CHANGELOG.md`](CHANGELOG.md) `[0.9.0]`. |
| v0.10.0 (shipped) | **Streaming AEAD FFI — SM4-GCM.** Per `docs/v0.10-scope.md` Q10.1–Q10.11. New: 9 `gmcrypto-c` FFI symbols + 2 opaque handle types exposing the v0.9 incremental-input buffered SM4-GCM encryptor (output-streaming) / decryptor (commit-on-verify) to C/C++/Go/Zig/Python — `gmcrypto_sm4_gcm_encryptor_{new,update,finalize,finalize_with_tag_len,free}` + `gmcrypto_sm4_gcm_decryptor_{new,update,finalize_verify,free}`, behind the existing `sm4-aead` feature on `gmcrypto-c`; `_finalize*` consume+free, single `GMCRYPTO_ERR`; C example `examples/sm4_gcm_streaming.c`. `regen-header` now implies `sm4-aead` (cbindgen drops cfg-gated opaque structs otherwise). No new `gmcrypto-core` API; no new dudect target. **No public API breakage — additive only.** See [`CHANGELOG.md`](CHANGELOG.md) `[0.10.0]`. |
| v0.11.0 (shipped) | **RustCrypto trait-fit modernization.** Per `docs/v0.11-scope.md` Q11.1–Q11.11. Migrates the opt-in `digest-traits` / `cipher-traits` impls from `digest 0.10` / `cipher 0.4` to `digest 0.11` / `cipher 0.5` (the `crypto-common 0.2` / `hybrid-array` generation), in-place: `cipher` block backend reshaped to cipher 0.5's separate `BlockCipherEncBackend` / `BlockCipherDecBackend`; HMAC construction via `digest::KeyInit::new_from_slice` (`digest 0.11` `Mac` dropped `KeyInit`). **BREAKING for trait-fit consumers only** (bump your own `digest`/`cipher`); default-features users unaffected, output byte-identical (full KAT + gmssl interop). MSRV stays 1.85; no new dudect target. See [`CHANGELOG.md`](CHANGELOG.md) `[0.11.0]`. |
| v0.12.0 (shipped) | **SM4-XTS — tweakable disk/sector mode.** Per `docs/v0.12-scope.md` Q12.1–Q12.13. New: `sm4::mode_xts::{encrypt, decrypt}` + `XTS_KEY_SIZE` behind the opt-in `sm4-xts` feature — GB/T 17964-2021 (GM-T OID `1.2.156.10197.1.104.10`), full ciphertext stealing, byte-identical to OpenSSL 3.x EVP `SM4-XTS` (`xts_standard=GB`; **not** IEEE 1619 — they differ in the GF(2¹²⁸) tweak doubling). 32-byte key (`Key1 ‖ Key2`) + raw 16-byte tweak, lengths `[16 B, 16 MiB]`, single `None` failure mode, confidentiality-only (no auth). Pure-core (**no new dependency**); rides the `Sm4Cipher::encrypt_blocks` batch API + SIMD fanout. New dudect target `ct_sm4_xts_decrypt`. Also fixes a latent CI bug where the feature-conditional dudect gates never fired. C FFI deferred to v0.13. **Additive — no public API breakage.** See [`CHANGELOG.md`](CHANGELOG.md) `[0.12.0]`. |
| v0.13.0 (shipped) | **C ABI for SM4-XTS.** Per `docs/v0.13-scope.md` Q13.1–Q13.12. New: `gmcrypto_sm4_xts_encrypt` / `_decrypt` + `GMCRYPTO_SM4_XTS_KEY_SIZE` in `gmcrypto-c`, behind a forwarding `sm4-xts` feature — single-shot, mirroring the single-shot SM4-GCM FFI shape minus nonce/AAD/tag (32-byte key, 16-byte tweak, length-preserving `(out, out_capacity, out_actual_len)` output), byte-identical to `gmcrypto_core::sm4::mode_xts`, single `GMCRYPTO_ERR`, confidentiality-only. The deferred FFI half of v0.12 (the v0.8-core → v0.10-FFI cadence). 5 new `c_smoke` tests + doc-only C example `examples/sm4_xts_sector.c`; regenerated header (no `regen-header` change needed — free fns + always-on const). No new `gmcrypto-core` API, no new dudect target, **no new dependency**. **Additive — no public API breakage.** See [`CHANGELOG.md`](CHANGELOG.md) `[0.13.0]`. |
| v0.14 (assurance; not published) | **Parser fuzzing.** Per `docs/v0.14-scope.md` Q14.1–Q14.12. A `cargo-fuzz` (libFuzzer) harness over the full untrusted-input decode/decrypt surface of `gmcrypto-core` (16 targets: PEM, PKCS#8 decode/decrypt, SPKI, SEC1, DER reader primitives, SM2 DER + raw ciphertext, SM2 decrypt + verify, SM4-CBC/GCM/CCM/XTS decrypt) proving the failure-mode invariant on adversarial bytes — no panic / no OOM / no hang. Workspace-excluded `fuzz/` crate (nightly-only; never in the published dep graph) + a capped nightly CI job (`.github/workflows/fuzz-nightly.yml`). Initial sweep: **zero crashes** → no published-crate change, **not a crates.io release** (assurance/infra only). See [`fuzz/README.md`](fuzz/README.md). |
| v0.15.0 (shipped) | **SM4-XTS multi-sector (disk) helper.** Per `docs/v0.15-scope.md` Q15.1–Q15.12. New: `sm4::mode_xts::{encrypt_sectors, decrypt_sectors}` (opt-in `sm4-xts`) — encrypt/decrypt a contiguous run of equal-size disk sectors **in place** (`&mut [u8] -> Option<()>`), sector `i` under tweak = little-endian-128(`start_sector + i`) (the standard disk-XTS data-unit convention; owns the encoding the single-shot v0.12 API left to the caller). Byte-identical to looping the single-shot per sector (transitively OpenSSL `xts_standard=GB`-pinned); whole-block sectors (no ciphertext stealing); ciphers built once + reused scratch (no per-sector allocation); single `None` for all validation with `buf` untouched; confidentiality-only. **Pure-core: no new dependency, no new feature flag, no new SIMD, no new dudect target** (the existing `ct_sm4_xts_decrypt` covers it). C FFI deferred to v0.16. crates.io skips `0.14.0` (the unpublished fuzzing cycle). **Additive — no public API breakage.** See [`CHANGELOG.md`](CHANGELOG.md) `[0.15.0]`. |
| v0.16.0 (shipped) | **C ABI for the SM4-XTS multi-sector helper.** Per `docs/v0.16-scope.md` Q16.1–Q16.12. New: `gmcrypto_sm4_xts_encrypt_sectors` / `_decrypt_sectors` in `gmcrypto-c`, behind the existing forwarding `sm4-xts` feature — **in-place** over a contiguous run of equal-size sectors (`buf: *mut u8` + `buf_len`; no `out`/`out_capacity`/`out_actual_len`, mirroring the core's `&mut [u8]` so disk callers never double-allocate), `start_sector: uint64_t`, tweak = LE-128(`start_sector + i`). Byte-identical to `gmcrypto_core::sm4::mode_xts::{encrypt,decrypt}_sectors`; single `GMCRYPTO_ERR` with `buf` untouched on error; confidentiality-only. The deferred FFI half of v0.15 — every cipher mode is now FFI-complete. 11 new `c_smoke` tests + doc-only C example `examples/sm4_xts_multisector.c`; regenerated header (no `regen-header` change — free fns, no new opaque structs). No new `gmcrypto-core` API, no new dudect target, **no new dependency**. **Additive — no public API breakage.** See [`CHANGELOG.md`](CHANGELOG.md) `[0.16.0]`. |
| v0.17 (public release; not a crates.io release) | **Open-sourced the repository.** Flipped the GitHub repo private → public on the 0.x line; CI migrated off the self-hosted macOS runner to GitHub-hosted (`ci.yml` → `macos-14`, `fuzz-nightly.yml` → `ubuntu-latest`). A *repository* milestone — no crate code changes (workspace stays `0.16.0`; crates.io skips `0.17.0` per the v0.14 precedent); v1.0 reserved. Per [`docs/v0.17-scope.md`](docs/v0.17-scope.md). |
| v0.18 (infra-assurance; not a crates.io release) | **dudect-gate hardening.** Per `docs/v0.18-scope.md` Q18.1–Q18.7. Pinned the dudect CI workflows' drift axes (`ubuntu-24.04` OS-label + exact `dtolnay/rust-toolchain@1.95.0`) and gate on a CI-level multi-run median `\|tau\|` (PR 3 runs / nightly 5 runs; `required_low` + the nightly sentinel on the median, `negative_control` on the min, completeness gate on `< N` runs). `timing_leaks.rs` byte-unchanged — the loop + median live in CI. A 100K×5 calibration showed `ct_fn_invert`/`ct_fp_invert` back near baseline (medians 0.006–0.028) but **kept on telemetry / sentinel — not re-promoted** (the noise is runner-image-sensitive; a tight gate would re-flake if it returns). Also a comma-free `rust-cache` `shared-key`. A *repository / infra-assurance* milestone — no crate code change (workspace stays `0.16.0`; crates.io skips `0.18.0` per the v0.14 / v0.17 precedent). See [`docs/v0.5-dudect-recalibration.md`](docs/v0.5-dudect-recalibration.md) (v0.18 resolution). |
| v0.19 (infra-assurance; not a crates.io release) | **Self-calibrating relative dudect gate — TESTED and FALSIFIED → honest fallback.** Per `docs/v0.19-scope.md` Q19.1–Q19.7. Added two fix-vs-fix noise-floor probes (`noise_floor_f{n,p}_invert`) + a relative gate `median(target) ≤ max(0.20, 4·median(probe))` to re-promote `ct_fn_invert`/`ct_fp_invert`. The 100K calibration disproved the matched-sensitivity premise: the probes stay quiet (~0.005) while the targets spike to [0.26–0.32] (`ct_fp_invert` median 0.2606, ratio 50) — the noise is in the two-input class split, not the operation, so a same-input probe can't track it. Reverted to telemetry / sentinel @0.55; probes kept as telemetry (evidence for a v0.21+ class-split-aware "noise-twin"). Only the dev-only bench harness changed (workspace stays `0.16.0`; crates.io skips `0.19.0`). See [`docs/v0.5-dudect-recalibration.md`](docs/v0.5-dudect-recalibration.md) (v0.19 resolution). |
| v0.20 (infra-assurance; not a crates.io release) | **Streaming-decryptor differential fuzzing + `cargo fuzz coverage` + codified v1.0 CT baseline.** Per `docs/v0.20-scope.md` Q20.1–Q20.5. Two new differential targets (`fuzz_sm4_{cbc,gcm}_streaming_decrypt`) assert the streaming decryptors fed in arbitrary chunks equal the single-shot oracle; fuzz sweep → 18 targets (zero crashes, zero divergences); a non-gating `cargo fuzz coverage` nightly job (llvm-cov TOTALS artifact). Codified the settled v1.0 CT baseline in `SECURITY.md` (composite targets gated <0.20; the two single-inversion diagnostics on telemetry/sentinel @0.55, narrow revisit door). Theme chosen after a Codex+Grok discussion. Only `fuzz/` + `fuzz-nightly.yml` + docs changed (workspace stays `0.16.0`; crates.io skips `0.20.0`). |
| v0.21 (infra-assurance; not a crates.io release) | **v1.0 readiness audit.** Per `docs/v0.21-scope.md` Q21.1–Q21.9. Froze + tooling-guarded the public API ahead of 1.0: committed `cargo-public-api` baselines + an enforced drift-check, `cargo-semver-checks` (informational pre-1.0), a `cargo doc -D warnings` gate, and a `--no-default-features`/`--all-features` matrix (new `.github/workflows/api-stability.yml`); finalized the `#[doc(hidden)]` surface (3 core items + the whole `gmcrypto-simd` internal backend) with "not public / not SemVer" notes + existence tests; froze the docs. Non-publishing (doc-attributes + tests only, no behavior change; workspace stays `0.16.0`, crates.io skips `0.21.0`). **Headline finding:** the always-on public API names `crypto-bigint 0.7` types — a decision to resolve before 1.0 ([`docs/v1.0-readiness.md`](docs/v1.0-readiness.md) §3.A). Deferred to post-1.0: class-split-aware "noise-twin" dudect reference; round-trip/differential parser fuzzing; `aead 0.6` (upstream `0.6.0-rc.10`); AVX-512 `sbox_x64`; CCM buffered input; the `dudect-nightly` leg-cancellation fix. |
| v0.22 (infra-assurance; not a crates.io release) | **API-tightening — decouple `crypto-bigint 0.7` from the 1.0 contract.** Per `docs/v0.22-scope.md` Q22.1–Q22.8 (resolves the v0.21 §3.A finding via Option 2). Group A: `#[doc(hidden)]` (kept `pub`) the low-level `sm2::curve` / `sm2::scalar_mul` / `ProjectivePoint::to_affine` surface. Group B: reshape `asn1::{encode,decode}_sig` + `Sm2Ciphertext::{x,y}` from `U256` to `[u8; 32]`, **byte-output-identical** (KAT + gmssl interop 11/11). Group C: `ProjectivePoint` stays public + unchanged. The always-on (default-features) public API now names **zero** `crypto-bigint` types; only the opt-in `crypto-bigint-scalar` `from_scalar(U256)` retains it (documented escape hatch). **BREAKING** for consumers that named `Fn`/`Fp`/`encode_sig`/`Sm2Ciphertext::x`; ships with 1.0 (non-publishing — workspace stays `0.16.0`, crates.io skips `0.22.0`). |
| v0.23 (infra-assurance; not a crates.io release) | **Pre-1.0 re-audit remediation.** Per `docs/v0.23-scope.md` Q23.1–Q23.9 + `docs/v1.0-reaudit.md`. A multi-model adversarial pre-publish re-audit (Codex `gpt-5.5` + Grok, source-verified) returned NO-GO as-is — core primitives sound, but 2 API/ABI BLOCKERs + API-finality / zeroize-on-failure / spec-ceiling / doc should-fixes. Remediated: **W1 (API)** `Sm2PrivateKey::public_key() -> Sm2PublicKey`, the raw `ProjectivePoint` surface + `asn1::{reader,writer,oid}` + `traits::*` made `#[doc(hidden)]`; **W2 (crypto)** single-shot SM4-GCM `encrypt` made fallible (`2^36−32` ceiling), the fallible `rand_core::TryCryptoRng` bound on SM2 sign/encrypt (no-panic RNG-failure path), a fixed-budget constant-time SM2 nonce sampler, sign-nonce / CCM-tentative-plaintext / `Sm3`-on-drop zeroization, SM2 KDF wrap guard; **W3 (C ABI)** the SM4-GCM/CCM/XTS FFI symbols made always-on so `gmcrypto.h` == the default build. **Runtime output byte-identical** (gmssl interop 11/11) except the deliberately-changed signatures; the breaking API/ABI changes ship with 1.0 (non-publishing — workspace stays `0.16.0`, crates.io skips `0.23.0`). |
| v1.0 | **API stabilization + crates.io publish** (the deliberate cut after the audit + tightening + re-audit: the `crypto-bigint`-exposure decision is **resolved** [v0.22] and the pre-publish re-audit findings **remediated** [v0.23], bump `0.16.0 → 1.0.0` with exact sibling pins, publish `gmcrypto-simd → core → c`, flip `cargo-semver-checks` to enforced — see the runbook in [`docs/v1.0-readiness.md`](docs/v1.0-readiness.md) §4). |

## Quick-start

```rust
use gmcrypto_core::sm2::{
    sign_with_id, verify_with_id, Sm2PrivateKey, DEFAULT_SIGNER_ID,
};
use getrandom::SysRng;
use hex_literal::hex;

// v0.5 W5 — `from_bytes_be` is the recommended public constructor
// (always-on, doesn't expose `crypto_bigint::U256` to callers).
let d_be: [u8; 32] = hex!(
    "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
);
let key = Sm2PrivateKey::from_bytes_be(&d_be).expect("d in [1, n-2]");
// `public_key()` returns an `Sm2PublicKey` directly (v0.23).
let public = key.public_key();

// SM2 sign/encrypt take a fallible `rand_core::TryCryptoRng` (v0.23), so
// `getrandom::SysRng` is passed directly — no `UnwrapErr` wrapper.
let mut rng = SysRng;
let sig = sign_with_id(&key, DEFAULT_SIGNER_ID, b"hello", &mut rng).unwrap();
assert!(verify_with_id(&public, DEFAULT_SIGNER_ID, b"hello", &sig));
```

## Threat model

See [`SECURITY.md`](SECURITY.md). Briefly: server-side use, dedicated host,
operator-trusted, network MITM in scope, side-channel attacks beyond what the
dudect harness covers are NOT in scope.

## Build & test

```bash
cargo test --workspace                                                          # unit + integration
cargo bench --bench timing_leaks --features crypto-bigint-scalar                # local timing harness (~75s)
DUDECT_SAMPLES=10000 cargo bench --bench timing_leaks --features crypto-bigint-scalar  # match CI smoke budget
```

`gmssl` interop test (gated; install [`gmssl`](https://github.com/guanzhi/GmSSL)
v3.1.1 to enable):

```bash
GMCRYPTO_GMSSL=1 cargo test --test interop_gmssl
```

## wasm32 support

`gmcrypto-core` builds on `wasm32-unknown-unknown` as of v0.4. CI gates
both stable and MSRV (1.85) builds on the target.

```bash
rustup target add wasm32-unknown-unknown
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --no-default-features
```

The crate is `no_std + alloc` only and does NOT pull `getrandom`'s
`wasm_js` backend or `wasm-bindgen` / `js-sys` into its default dep
graph. Wasm callers wire their own `rand_core::Rng` impl — typically
by enabling `getrandom`'s `wasm_js` feature in *their* `Cargo.toml`:

```toml
[dependencies]
gmcrypto-core = "1.0"
rand_core = { version = "0.10", default-features = false }
getrandom = { version = "0.4", default-features = false, features = ["wasm_js"] }
```

```rust
use gmcrypto_core::sm2::{sign_with_id, Sm2PrivateKey, DEFAULT_SIGNER_ID};
use getrandom::SysRng;

let mut rng = SysRng; // wasm_js-backed when targeting wasm32
let sig = sign_with_id(&priv_key, DEFAULT_SIGNER_ID, b"msg", &mut rng).unwrap();
```

A `wasm-bindgen-test`-driven test runner (running KAT vectors under
Node or a headless browser) is post-v0.4 — v0.4 ships the build-target
gate only.

## License

Apache-2.0. See [`LICENSE`](LICENSE).

Some reference outputs use the upstream [`gmssl`](https://github.com/guanzhi/GmSSL)
tool. This project is independent of that project.
