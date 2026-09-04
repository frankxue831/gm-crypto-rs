# gm-crypto-rs

Pure-Rust SM2 / SM3 / SM4 — the Chinese national cryptographic algorithms —
with constant-time discipline that is **measured in CI**, not just intended.

[![Crates.io](https://img.shields.io/crates/v/gmcrypto-core.svg)](https://crates.io/crates/gmcrypto-core)
[![Documentation](https://docs.rs/gmcrypto-core/badge.svg)](https://docs.rs/gmcrypto-core)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](https://github.com/frankxue831/gm-crypto-rs#stability--semver)
[![License](https://img.shields.io/crates/l/gmcrypto-core.svg)](https://crates.io/crates/gmcrypto-core)

For Rust services that must speak GB/T 32918 / 32905 / 32907 and want a
`no_std` core with no C dependency — and for C, C++, Python, Go and Zig
callers through a complete, always-on C ABI. Every secret-touching path is
written against `subtle`'s constant-time primitives and guarded by a
`dudect` timing-leak harness that blocks merges.

```rust
use gmcrypto_core::sm2::{DEFAULT_SIGNER_ID, Sm2PrivateKey, sign_with_id, verify_with_id};
use gmcrypto_core::sm3;
use getrandom::SysRng; // any `rand_core::TryCryptoRng`; this crate ships no RNG

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let digest = sm3::hash(b"hello");                     // SM3: 32 bytes

    let key = Sm2PrivateKey::from_bytes_be(&secret_32)    // your scalar, big-endian
        .into_option().ok_or("scalar out of range")?;
    let sig = sign_with_id(&key, DEFAULT_SIGNER_ID, b"hello", &mut SysRng)?;
    assert!(verify_with_id(&key.public_key(), DEFAULT_SIGNER_ID, b"hello", &sig));
    Ok(())
}
```

> ⚠️ **Not independently audited.** No third-party / external security audit has
> been performed. Assurance is internal: a multi-model adversarial pre-publish
> re-audit (see [`docs/v1.0-reaudit.md`](docs/v1.0-reaudit.md)), in-CI KAT vectors,
> in-CI gmssl 3.2.0 interop (13/13, cross-validated against a pinned from-source
> build of the reference implementation; currently non-gating), an in-CI `dudect`
> timing-leak harness, and a 35-target `cargo-fuzz` suite. This is a solo-maintained, best-effort open-source
> project with no support SLA. Review the code and **use at your own risk.** See
> [`SECURITY.md`](SECURITY.md) for the threat model and disclosure process.

## Installation

```bash
cargo add gmcrypto-core
```

```toml
[dependencies]
gmcrypto-core = "1.11"
getrandom = { version = "0.4", default-features = false, features = ["sys_rng"] }
```

`default = []`. The base build is SM2, SM3, SM4-ECB/CBC/CTR, HMAC-SM3,
PBKDF2-HMAC-SM3 and the DER / PEM / PKCS#8 codecs, with no optional
dependency. Everything else below is behind a feature flag. The crate
deliberately pulls no RNG; SM2 signing and encryption take any
`rand_core::TryCryptoRng`, and `getrandom`'s `SysRng` is the usual choice.

C / C++ / Python / Go / Zig callers want [`gmcrypto-c`](crates/gmcrypto-c/README.md)
instead. `gmcrypto-simd` is an internal backend — do not depend on it directly.

## What's in the box

| | Standard | Feature |
|---|---|---|
| SM2 sign / verify, encrypt / decrypt | GB/T 32918, GM/T 0009 DER | default |
| SM3 hash, HMAC-SM3, PBKDF2-HMAC-SM3 | GB/T 32905, RFC 2104 / 8018 | default |
| SM4-ECB / CBC / CTR, single-shot and streaming | GB/T 32907 | default |
| DER / PEM / SPKI / SEC1 / PKCS#8 (incl. PBES2-encrypted) | RFC 5280 / 5915 / 5958 / 7468 | default |
| SM4-GCM / SM4-CCM AEAD, incremental-input GCM, length-committed streaming CCM | — | `sm4-aead` |
| SM4-XTS sector mode (confidentiality only) | GB/T 17964-2021 | `sm4-xts` |
| SM2 key exchange with key confirmation | GM/T 0003.3 | `sm2-key-exchange` |
| X.509-with-SM2 leaf parse + verify, linear chain verify | GM/T 0015 | `x509` |
| TLCP key schedule, record protection, `[sign, enc]` pair verify | GB/T 38636-2020 | `tlcp` |
| RustCrypto `digest` / `cipher` / `aead` trait fits | — | `*-traits` |
| Table-less bitsliced SM4 S-box; AVX2 / NEON packed batches | — | `sm4-bitsliced[-simd]` |

Three crates, released together at one lockstep version:

| Crate | Role |
|---|---|
| [`gmcrypto-core`](https://crates.io/crates/gmcrypto-core) | The `no_std + alloc` crypto core, `unsafe_code = "forbid"`. The Rust API. |
| [`gmcrypto-c`](https://crates.io/crates/gmcrypto-c) | C ABI, cdylib + staticlib: 104 entry points, committed [`gmcrypto.h`](crates/gmcrypto-c/include/gmcrypto.h) drift-checked in CI. A default build exports the whole surface. |
| [`gmcrypto-simd`](https://crates.io/crates/gmcrypto-simd) | Internal AVX2 / NEON / CLMUL / PMULL backend. No stable Rust API. |

## Why this rather than the alternatives

| | gm-crypto-rs | `libsm` | RustCrypto `sm2` / `sm4` |
|---|---|---|---|
| SM2 + SM3 + SM4 in one crate | ✅ | ✅ | separate crates |
| Timing-leak harness in CI | ✅ 20 `dudect` targets, 16 blocking | — | — |
| Fuzzing | ✅ 35 targets, nightly | — | — |
| C ABI | ✅ 104 entry points | — | — |
| TLCP (GB/T 38636) toolkit | ✅ | — | — |
| `no_std` | ✅ | not advertised | ✅ |
| Enforced SemVer (`cargo-semver-checks`) | ✅ | — | — |
| **External security audit** | **none** | none | none |
| **Production track record** | **thin — first published 2026** | years | years |

A dash means "not offered as a documented feature", checked against each
project's crates.io metadata and repository in July 2026 — not a claim that
the work is absent from someone's tree, and worth re-checking before you rely
on it.

The last two rows are the honest counterweight and are meant to stay. If your
priority is the longest field exposure, `libsm` has years of it and this does
not. If your priority is verifiable constant-time discipline, a C ABI, or TLCP
building blocks, none of the alternatives offer them.

## How "constant-time" is checked

The differentiator is not the design intent — [`RustCrypto/sm2`](https://docs.rs/sm2/)
aims for constant-time too — it is the **in-CI regression gate**. Every PR
and every night, a [`dudect-bencher`](https://docs.rs/dudect-bencher/) harness
times each secret-touching operation under two input classes and gates the
per-target `|tau|` statistic. A deliberately leaky `negative_control` must
fire on every run, proving the harness can still see a leak.

| Target | Secret it splits on | Gate |
|---|---|---|
| `ct_sign` | private key `d` and nonce `k` magnitude | 0.20 |
| `ct_sign_k_class` | nonce only, fixed `d` — the leak `ct_sign` cannot see | sentinel 0.55 |
| `ct_mul_g`, `ct_mul_var` | scalar | 0.20 |
| `ct_sm2_decrypt` | recipient `d_B` | 0.20 |
| `ct_sm2_key_exchange` (`sm2-key-exchange`) | initiator's static `d_A` | 0.20 |
| `ct_sm4_key_schedule`, `ct_sm4_encrypt_block`, `ct_sm4_ctr_encrypt` | master key | 0.20 |
| `ct_sm4_encrypt_block_bitsliced_simd`, `ct_sm4_cbc_decrypt_fanout` (`sm4-bitsliced-simd`) | master key, through the SIMD batch path | 0.20 |
| `ct_sm4_gcm_decrypt`, `ct_sm4_gcm_decrypt_buffered`, `ct_sm4_ccm_decrypt` (`sm4-aead`) | master key, valid `(ct, tag)` for both classes | 0.20 |
| `ct_sm4_xts_decrypt` (`sm4-xts`) | master key, over a ciphertext-stealing tail | 0.20 |
| `ct_tlcp_cbc_deprotect` (`tlcp`) | recovered-fragment length, fixed key — the Lucky13 residual | 0.20 |
| `ct_hmac_sm3` | key | sentinel 0.55 |
| `ct_pkcs8_decrypt` | password bytes, both blobs valid | 0.20 |
| `ct_fn_invert`, `ct_fp_invert` | field element, direct inversion diagnostics | sentinel 0.55 |
| `negative_control` | deliberately leaky | must fire, `> 1.0` |

Sixteen of the twenty block a merge at `|tau| <= 0.20`. Four sit on a `0.55`
gross-regression sentinel: they measure a composite window whose class split
reads as noise on some hosted-runner CPUs, so they report as telemetry and
only an egregious value fails. The harness reports detection events — **it
does not prove constant-time.** A low `|tau|` means no leak was detected with
the budget given, not that none exists. The full discipline, the hosted-runner
noise history, and every demotion with its data are in [`SECURITY.md`](SECURITY.md)
and [`docs/v0.5-dudect-recalibration.md`](docs/v0.5-dudect-recalibration.md).

Beyond timing: KAT vectors in CI, 35 `cargo-fuzz` targets run nightly, and an
interop suite against a pinned from-source [GmSSL](https://github.com/guanzhi/GmSSL)
3.2.0 — the reference implementation — cross-validating signatures,
ciphertexts and AEAD output byte-for-byte.

## What this isn't

- Not a TLS/TLCP protocol implementation. The `tlcp` feature ships the
  cryptographic building blocks — key schedule, record protection,
  certificate-pair verification — but no handshake state machine, record
  framing, session orchestration or transport I/O.
- Not SM9, ZUC, or post-quantum.
- Not an HSM / SDF / SKF integration, and not a certified cryptographic module.
- Not constant-time on CPUs with data-dependent multiply latencies (some older
  x86, some embedded).
- `verify_chain` / `verify_pair` make **structural** trust decisions only. A
  `true` means the chain links to an anchor you supplied — never "this is the
  peer I dialed". Binding an identity to an endpoint is the caller's, permanently.

## More examples

**SM2 key exchange** (`sm2-key-exchange`) — authenticated two-party agreement
with mandatory key confirmation. Each step consumes the state machine, so an
ephemeral cannot be reused and neither side sees the key before the peer's
confirmation tag verifies:

```rust
use gmcrypto_core::sm2::key_exchange::{Sm2KxInitiator, Sm2KxResponder};

let init = Sm2KxInitiator::new(&key_a, &pub_b, b"A-id", b"B-id", 32)?;
let (r_a, init_waiting) = init.produce_ephemeral(&mut rng)?;      // R_A -> B

let resp = Sm2KxResponder::new(&key_b, &pub_a, b"A-id", b"B-id", 32)?;
let (r_b, s_b, resp_waiting) = resp.respond(&r_a, &mut rng)?;      // (R_B, S_B) -> A

let (k_a, s_a) = init_waiting.confirm(&r_b, &s_b)?;               // verifies S_B; S_A -> B
let k_b = resp_waiting.finish(&s_a)?;                             // verifies S_A
assert_eq!(k_a.as_bytes(), k_b.as_bytes());
```

**X.509-with-SM2** (`x509`) — parse a DER v3 leaf and verify its SM2-with-SM3
signature against an issuer key. `true` means exactly "this issuer key signed
these wire `tbsCertificate` bytes"; no clock, no extension interpretation, no
revocation:

```rust
use gmcrypto_core::x509::Certificate;

let cert = Certificate::from_der(&leaf_der).ok_or("not a GM/T 0015 cert")?;
assert!(cert.verify_signature(&issuer_public_key));
let _validity = (cert.not_before(), cert.not_after());  // exposed, never compared
```

The same surfaces are reachable from C through `gmcrypto-c`; ten shipped
[examples](crates/gmcrypto-c/examples/) — SM2 signing, streaming GCM, single-shot and length-committed streaming CCM, XTS
sectors, key exchange, X.509, a TLCP handshake and pair verification — are
compiled in CI against the committed header with `-Wall -Wextra -Werror`.

## Stability & SemVer

- **1.x is stable.** Every release since 1.0.0 has been additive;
  `cargo-semver-checks` gates breaking changes in CI. The only migration ever
  required was 0.16 → 1.0.
- **Covered:** the public Rust API of `gmcrypto-core` (snapshotted in
  [`docs/api-baseline/`](docs/api-baseline/), drift-checked in CI) and the
  `gmcrypto-c` C ABI (the committed header, drift-checked in CI).
- **Not covered:** anything `#[doc(hidden)]` — the low-level curve and point
  arithmetic, the raw DER reader / writer, the in-crate traits — and the whole
  of `gmcrypto-simd`. These exist for in-repo dev crates and may change in any
  release.
- **Wire output is byte-identical to 0.16.0:** SM2 signatures and ciphertexts,
  every SM4 mode.
- **MSRV is 1.85** (edition 2024). An MSRV bump is a minor, not a patch.
- **Features are additive**, `default = []`, all eleven opt-in.
- **No `crypto-bigint` type in the always-on API.** Byte-adjacent types take
  and return `[u8; 32]`. The one exception is the opt-in `crypto-bigint-scalar`
  feature's `Sm2PrivateKey::from_scalar(U256)`, and enabling it opts you into
  that crate's major-version contract.
- **Failures are opaque by design.** `verify_with_id` returns `bool`; every
  other fallible operation returns one `Error::Failed` or `None`, never a
  reason. PRs that distinguish failure modes are rejected — see
  [`SECURITY.md`](SECURITY.md).

Release notes: [`CHANGELOG.md`](CHANGELOG.md), every published version. The
per-cycle design records are under [`docs/`](docs/); the verification-first
method behind them — pre-registered scope, adversarial review, executable
evidence gates, failures kept as receipts — is in [`CASE-STUDY.md`](CASE-STUDY.md).
The TLCP toolkit is complete as a toolkit; a sans-I/O protocol engine would be
a separate crate and has not been committed to.

## Threat model

See [`SECURITY.md`](SECURITY.md). Briefly: server-side use, dedicated host,
operator-trusted, network MITM in scope; side-channel attacks beyond what the
dudect harness covers are not.

## Build & test

```bash
cargo test --workspace                                                          # unit + integration
cargo bench --bench timing_leaks --features crypto-bigint-scalar                # local timing harness (~75s)
DUDECT_SAMPLES=10000 cargo bench --bench timing_leaks --features crypto-bigint-scalar  # match CI smoke budget
```

`gmssl` interop test (gated; install [`gmssl`](https://github.com/guanzhi/GmSSL)
**v3.2.0** to enable — this is what Homebrew currently ships):

```bash
GMCRYPTO_GMSSL=1 cargo test --test interop_gmssl                    # 11 tests
GMCRYPTO_GMSSL=1 cargo test --test interop_gmssl --features sm4-aead  # 13 tests
```

The suite **pins its oracle version** and fails with an `ORACLE DRIFT` message
on any other build. GmSSL renames subcommands and narrows accepted input
ranges between releases, so an unpinned oracle quietly changes what "interop
passes" means. To cross-validate against a different release deliberately,
set `GMCRYPTO_GMSSL_VERSION` (e.g. `"GmSSL 3.1.1"`).

## wasm32 support

`gmcrypto-core` builds on `wasm32-unknown-unknown`; CI gates both stable and
MSRV builds on the target.

```bash
rustup target add wasm32-unknown-unknown
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --no-default-features
```

The crate does not pull `getrandom`'s `wasm_js` backend or `wasm-bindgen` into
its default graph. Wasm callers enable it in *their* `Cargo.toml`:

```toml
[dependencies]
gmcrypto-core = "1.11"
getrandom = { version = "0.4", default-features = false, features = ["wasm_js"] }
```

There is no `wasm-bindgen-test` runner executing KAT vectors under Node or a
headless browser; adding one has not been committed to.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([`LICENSE-MIT`](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option. Both texts ship inside every published crate from 1.11.0;
archives up to 1.9.0 on crates.io do not contain them — the licence that
governs those releases is unchanged, only the packaging was wrong.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project by you, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms or
conditions.

**Personal project notice:** not affiliated with, endorsed by, sponsored by, or
certified by any upstream cryptography project, payment gateway, standards body,
or vendor. Some reference outputs use the upstream
[`gmssl`](https://github.com/guanzhi/GmSSL) tool; this project is independent of
it. Official ecosystem membership, layering, versioning and compatibility gates
are defined in the [gmcrypto Rust ecosystem charter](docs/ECOSYSTEM.md).
