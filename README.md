# gm-crypto-rs

Constant-time-designed pure-Rust SM2 / SM3 / SM4 SDK for Chinese national
cryptography (GB/T 32905 / 32918 / 32907 / GM/T 0009). SM2 sign / verify,
public-key encrypt / decrypt, key exchange (GM/T 0003.3), X.509-with-SM2
leaf certificate parse + signature verify, the TLCP (GB/T 38636) key
schedule; SM4-CBC / CTR / GCM / CCM / XTS (single-shot and streaming);
HMAC-SM3, PBKDF2-HMAC-SM3; plus a complete C ABI (`gmcrypto-c`, 104 entry
points) — all secret-touching paths guarded by an in-CI `dudect-bencher`
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
> CI), an in-CI `dudect` timing-leak harness, and a 27-target `cargo-fuzz` suite. This is a solo-maintained, best-effort open-source
> project with no support SLA. Review the code and **use at your own risk.** See
> [`SECURITY.md`](SECURITY.md) for the threat model and disclosure process.

## What this is

A small, auditable, pure-Rust SM2 / SM3 / SM4 SDK whose central
differentiating commitment is that secret-touching code paths are
**constant-time-designed and guarded by an in-CI [`dudect-bencher`](https://docs.rs/dudect-bencher/)
detectable-leak regression harness**: 19 real `ct_*` targets (12
always-on + 2 cfg-gated under `sm4-bitsliced-simd` + 3 cfg-gated under
`sm4-aead` + 1 cfg-gated under `sm4-xts` + 1 cfg-gated under
`sm2-key-exchange`) plus a deliberately-leaky
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
(`ct_sm4_gcm_decrypt_buffered`, cfg-gated on `sm4-aead`), v1.1's full
SM2 key-exchange initiator flow (`ct_sm2_key_exchange`, cfg-gated on
`sm2-key-exchange` — split by static `d_A` with per-class valid
responder transcripts), HMAC-SM3
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

- Not a TLS/TLCP protocol implementation (the `tlcp` feature ships crypto
  building blocks only — no handshake, no records, no I/O).
- Not SM9, ZUC, post-quantum.
- Not an HSM/SDF/SKF integration.
- Not a certified cryptographic module.
- Not constant-time on CPUs with data-dependent multiply latencies (some older
  x86, some embedded).
- Not a comprehensive SM-crypto library yet — see the roadmap below.

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

**SM2 key exchange** (v1.1, opt-in `sm2-key-exchange`): an authenticated
two-party key agreement with mandatory key confirmation. Each step consumes
the state machine, so an ephemeral cannot be reused and neither side sees
the key before the peer's confirmation tag verifies:

```rust
use gmcrypto_core::sm2::key_exchange::{Sm2KxInitiator, Sm2KxResponder};

// A (initiator) and B (responder) hold each other's static public keys.
let init = Sm2KxInitiator::new(&key_a, &pub_b, b"A-id", b"B-id", 32)?;
let (r_a, init_waiting) = init.produce_ephemeral(&mut rng)?; // R_A -> B

let resp = Sm2KxResponder::new(&key_b, &pub_a, b"A-id", b"B-id", 32)?;
let (r_b, s_b, resp_waiting) = resp.respond(&r_a, &mut rng)?; // (R_B, S_B) -> A

let (k_a, s_a) = init_waiting.confirm(&r_b, &s_b)?; // verifies S_B; S_A -> B
let k_b = resp_waiting.finish(&s_a)?;               // verifies S_A
assert_eq!(k_a.as_bytes(), k_b.as_bytes());         // 32-byte agreed key
```

**X.509-with-SM2** (v1.3, opt-in `x509`): parse a DER v3 leaf certificate
and verify its SM2-with-SM3 signature against an issuer public key. **This
makes no trust decisions** — no chains, no clock, no extension
interpretation, no revocation; `true` means exactly "this issuer key signed
these exact wire `tbsCertificate` bytes":

```rust
use gmcrypto_core::x509::Certificate;

let cert = Certificate::from_der(&leaf_der).ok_or("not a GM/T 0015 cert")?;
assert!(cert.verify_signature(&issuer_public_key));
let _validity = (cert.not_before(), cert.not_after()); // exposed; no clock
```

v1.8 adds a deliberately narrow chain layer: `x509::verify_chain` walks a
caller-ordered chain to a trusted anchor (per-edge signature, keyUsage /
basicConstraints, optional comparison time), and `tlcp::chain::verify_pair`
(with `tlcp` + `x509`) verifies a TLCP [sign, enc] double-cert pair. Both
return a single `bool` and make **structural** trust decisions only —
**endpoint identity binding stays the caller's, permanently** (a `true` is
never "this is the peer I dialed").

The same surfaces are reachable from C / C++ / Python / Go / Zig through
`gmcrypto-c` — see [`crates/gmcrypto-c/README.md`](crates/gmcrypto-c/README.md)
and the doc-only examples under
[`crates/gmcrypto-c/examples/`](crates/gmcrypto-c/examples/)
(`sm2_sign.c`, `sm4_gcm_streaming.c`, `sm4_xts_sector.c`,
`sm4_xts_multisector.c`, `sm2_key_exchange.c`, `x509_verify.c`).

## Crates & features

Three crates, released together at one lockstep version:

| Crate | Role |
|---|---|
| [`gmcrypto-core`](https://crates.io/crates/gmcrypto-core) | The `no_std + alloc` crypto core (`unsafe_code = "forbid"`). The Rust API. |
| [`gmcrypto-c`](https://crates.io/crates/gmcrypto-c) | C ABI shim (cdylib + staticlib): 104 entry points, committed [`gmcrypto.h`](crates/gmcrypto-c/include/gmcrypto.h) drift-checked in CI. **Always-on**: a default build exports the full surface. |
| [`gmcrypto-simd`](https://crates.io/crates/gmcrypto-simd) | Internal AVX2/NEON/CLMUL/PMULL acceleration backend. **No stable Rust API** — use `gmcrypto-core`. |

`gmcrypto-core` features (`default = []`; all additive, all opt-in):

| Feature | Adds |
|---|---|
| `sm4-aead` | SM4-GCM + SM4-CCM single-shot AEAD, incremental-input buffered GCM (pulls `gmcrypto-simd` for GHASH). |
| `sm4-xts` | SM4-XTS (GB/T 17964-2021, **not** IEEE 1619): single-shot + in-place multi-sector disk helpers. Confidentiality only. |
| `sm2-key-exchange` | GM/T 0003.3 key agreement (typestate role state-machines): confirmed flow by default + the standard-permitted no-confirmation completers (v1.6). |
| `x509` | X.509-with-SM2 leaf parse + signature verify; v1.8 adds linear `verify_chain` + keyUsage/basicConstraints readers. **Structural trust only — NOT endpoint authentication.** |
| `tlcp` | TLCP (GB/T 38636-2020) crypto toolkit: key schedule (P_SM3 PRF, master secret, key block, Finished) + **record protection** (SM4-CBC Lucky13-hardened deprotect; SM4-GCM record with `sm4-aead`) + **certificate-pair verification** (`tlcp::chain::verify_pair`, with `x509`). **Not a protocol implementation.** |
| `sm4-bitsliced` | Table-less, gate-only SM4 S-box (constant-time by construction; byte-identical output). |
| `sm4-bitsliced-simd` | AVX2 (x86_64) / NEON (aarch64) packed bitsliced SM4 batches; runtime detection, scalar fallback. |
| `digest-traits` / `cipher-traits` | RustCrypto trait fit (`digest 0.11` / `cipher 0.5`) for `Sm3` / `HmacSm3` / `Sm4Cipher`. |
| `crypto-bigint-scalar` | `Sm2PrivateKey::from_scalar(U256)` — the documented `crypto-bigint 0.7` escape hatch. |

## Stability & SemVer

The line graduated to **1.0 (stable)** with the **1.0.0** release; the current release is
**1.9.0** (TLCP toolkit C FFI — the cadence cycle closing the TLCP arc). crates.io history
goes **0.16.0 → 1.0.0 → 1.0.1 → 1.1.0 → 1.2.0 → 1.3.0 → 1.4.0 → 1.6.0 → 1.7.0 → 1.8.0 → 1.9.0**, skipping 0.17.0–0.23.0
and 1.5.0 (those were non-publishing milestones — the 0.x run was the assurance +
API-finalization arc that shipped together in `1.0.0`; 1.5 was the TLCP-decomposition
design cycle, [`docs/tlcp-decomposition.md`](docs/tlcp-decomposition.md)). Every post-1.0 release has been additive (SemVer-checked);
the only migration ever required is 0.16 → 1.0, a single major bump — no published 0.x
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
intra-workspace deps pinned exactly — `=1.9.0`). The runtime wire output (SM2
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
- **Features are additive** (`default = []`; all 9 are opt-in) and the build is
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

## Release history & roadmap

Per-release narratives live in [`CHANGELOG.md`](CHANGELOG.md) (every
published version, Keep-a-Changelog format) and in the per-cycle scope
documents under [`docs/`](docs/) (`vX.Y-scope.md` — including the
non-publishing assurance milestones v0.14 and v0.17–v0.23: parser fuzzing,
the open-source flip, dudect-gate hardening, the v1.0 readiness audit and
remediation).

The arc so far: v0.1–v0.16 built the primitive surface (SM2/SM3/SM4, all
SM4 cipher modes incl. AEAD + XTS, the C ABI, SIMD acceleration); v0.17–v0.23
were the assurance + API-finalization run-up to **1.0.0**; the 1.x line has
been strictly additive — SM2 key exchange (1.1) + its C FFI (1.2),
X.509-with-SM2 leaf parse/verify (1.3) + its C FFI (1.4).

**Direction:** TLCP (GB/T 38636) is the headline candidate — its
cryptographic prerequisites (SM2-KX, X.509-with-SM2) are now shipped; X.509
chain validation is the remaining building block and a deliberate
non-feature so far ("no trust decisions"). Smaller parked items (RustCrypto
`aead` trait fit, AVX-512, CCM buffered input, a class-split-aware dudect
noise-twin) are tracked in the scope docs.

**How it was built:** for the human+agent development method behind this
library — pre-registered scope, multi-model adversarial review,
executable-evidence gates, and the failures kept as receipts — see
[`CASE-STUDY.md`](CASE-STUDY.md).

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
gmcrypto-core = "1.4"
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
