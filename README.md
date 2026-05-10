# gm-crypto-rs

Constant-time-designed pure-Rust SM2 / SM3 SDK for Chinese national
cryptography. v0.2 will add SM4 and SM2 encrypt/decrypt — see the
roadmap below.

[![CI](https://github.com/frankxue831/gm-crypto-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/frankxue831/gm-crypto-rs/actions/workflows/ci.yml)
[![dudect smoke](https://github.com/frankxue831/gm-crypto-rs/actions/workflows/dudect-pr.yml/badge.svg)](https://github.com/frankxue831/gm-crypto-rs/actions/workflows/dudect-pr.yml)
[![dudect nightly](https://github.com/frankxue831/gm-crypto-rs/actions/workflows/dudect-nightly.yml/badge.svg)](https://github.com/frankxue831/gm-crypto-rs/actions/workflows/dudect-nightly.yml)

**Personal project notice:** not affiliated with, endorsed by, sponsored by, or
certified by any upstream cryptography project, payment gateway, standards body,
or vendor.

## What this is

A small, auditable, pure-Rust SM2 + SM3 SDK whose central differentiating
commitment is that the SM2 private-key path uses **constant-time-designed code
paths guarded by an in-CI [`dudect-bencher`](https://docs.rs/dudect-bencher/)
detectable-leak regression harness**. SM4 lands in v0.2.

The harness reports timing-leak detection events. **It does not prove
constant-time.** Low `|tau|` values mean the test could not detect a leak with
the budget given, not that no leak exists. Language taken directly from
`dudect-bencher`'s own docs.

v0.1 has a known limitation worth surfacing here, not just in `SECURITY.md`:
the harness's `ct_sign` target splits classes by the private key `d`, so it
catches `(1+d).invert()` leaks (currently diluted under the gate) but is
**structurally blind** to leaks on the per-sample nonce `k` — including
the `Fp::invert(Z)` inside `kg.to_affine()` after `mul_g(k)`. v0.2 fixes
both invert sites and reworks the harness to specifically exercise the
nonce path. See [`SECURITY.md`](SECURITY.md) for the full posture.

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

## v0.1 scope

- SM3 hash function (`#![no_std]` + `alloc`).
- SM2 sign / verify with custom signer ID (default `1234567812345678` per GM/T 0009).
- Constant-time-designed `Fp` and `Fn` field arithmetic via `crypto-bigint = 0.6`.
- Renes-Costello-Batina complete addition formulas for the SM2 curve (a=-3 specialized).
- Fixed-base and variable-base scalar multiplication, both constant-time-designed
  with `subtle::ConditionallySelectable` linear-scan table lookup.
- Fixed-K masked-select signing retry: the retry loop runs `K=2` iterations
  unconditionally, regardless of which (if any) iteration produced a valid
  signature. The constant-time contract holds for any RNG that respects
  `CryptoRng`; pathological RNGs cannot leak the secret via observable retry
  count.
- Minimal ASN.1 DER for `SEQUENCE { r, s }`.
- KAT vectors from GB/T 32905-2016 (SM3) and GB/T 32918.2-2017 (SM2).
- `gmssl` CLI reachability check (full bidirectional interop deferred to v0.3
  when PKCS#8 + X.509 SPKI ship).
- `dudect-bencher` harness with PR-smoke (10⁴ samples, `|tau|<0.20`) and nightly
  (10⁵ samples, same `|tau|<0.20` gate, more samples = tighter empirical
  confidence) modes, plus a deliberately-leaky negative control that proves the
  harness can detect leaks.

See [`SECURITY.md`](SECURITY.md) for v0.1's known constant-time limitations,
notably the dependency on `crypto-bigint::ConstMontyForm::invert`.

## Roadmap

| Version | Scope |
|---|---|
| v0.2 | Fermat-invert via `pow_bounded_exp` (replaces non-CT `crypto-bigint::invert`); SM2 encrypt/decrypt; GM/T 0009 ciphertext DER; SM4, SM4-CBC; HMAC-SM3; PBKDF2-HMAC-SM3 |
| v0.3 | Full ASN.1, PEM, encrypted PKCS#8, X.509 SPKI extractor; full bidirectional gmssl interop |
| v0.4 | `gmcrypto-partner` crate (gateway-side merchant payment SDK) |
| v0.5 | C ABI (`gmcrypto-c`), `wasm32-unknown-unknown` build target |
| v1.0 | API stabilization, crates.io publish |

## Quick-start

```rust
use gmcrypto_core::sm2::{
    sign_with_id, verify_with_id, Sm2PrivateKey, Sm2PublicKey, DEFAULT_SIGNER_ID,
};
use crypto_bigint::U256;
use rand_core::OsRng;

let d = U256::from_be_hex(
    "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
);
let key = Sm2PrivateKey::new(d).expect("d in [1, n-2]");
let public = Sm2PublicKey::from_point(key.public_key());

let sig = sign_with_id(&key, DEFAULT_SIGNER_ID, b"hello", &mut OsRng).unwrap();
assert!(verify_with_id(&public, DEFAULT_SIGNER_ID, b"hello", &sig));
```

## Threat model

See [`SECURITY.md`](SECURITY.md). Briefly: server-side use, dedicated host,
operator-trusted, network MITM in scope, side-channel attacks beyond what the
dudect harness covers are NOT in scope.

## Build & test

```bash
cargo test --workspace                                # unit + integration
cargo bench --bench timing_leaks                      # local timing harness (~75s)
DUDECT_SAMPLES=10000 cargo bench --bench timing_leaks # match CI smoke budget
```

`gmssl` interop test (gated; install [`gmssl`](https://github.com/guanzhi/GmSSL)
v3.1.1 to enable):

```bash
GMCRYPTO_GMSSL=1 cargo test --test interop_gmssl
```

## License

Apache-2.0. See [`LICENSE`](LICENSE).

Some reference outputs use the upstream [`gmssl`](https://github.com/guanzhi/GmSSL)
tool. This project is independent of that project.
