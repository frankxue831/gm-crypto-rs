# gm-crypto-rs

Constant-time-designed pure-Rust SM2 / SM3 / SM4 SDK for Chinese national
cryptography (GB/T 32905 / 32918 / 32907 / GM/T 0009). Sign / verify,
public-key encrypt / decrypt, SM4-CBC, HMAC-SM3, PBKDF2-HMAC-SM3 — all
secret-touching paths guarded by an in-CI `dudect-bencher`
detectable-leak regression harness.

[![Crates.io](https://img.shields.io/crates/v/gmcrypto-core.svg)](https://crates.io/crates/gmcrypto-core)
[![Documentation](https://docs.rs/gmcrypto-core/badge.svg)](https://docs.rs/gmcrypto-core)
[![License](https://img.shields.io/crates/l/gmcrypto-core.svg)](https://crates.io/crates/gmcrypto-core)

**Personal project notice:** not affiliated with, endorsed by, sponsored by, or
certified by any upstream cryptography project, payment gateway, standards body,
or vendor.

## What this is

A small, auditable, pure-Rust SM2 / SM3 / SM4 SDK whose central
differentiating commitment is that secret-touching code paths are
**constant-time-designed and guarded by an in-CI [`dudect-bencher`](https://docs.rs/dudect-bencher/)
detectable-leak regression harness** with 12 gates at `|tau| < 0.20`.

The harness reports timing-leak detection events. **It does not prove
constant-time.** Low `|tau|` values mean the test could not detect a leak with
the budget given, not that no leak exists. Language taken directly from
`dudect-bencher`'s own docs.

v0.3's harness covers 12 secret-touching code paths: SM2 sign (split by
both private key `d` and nonce `k` magnitude, with both retry nonces
class-tied), SM2 decrypt (split by recipient `d_B`), SM4 key schedule
and encrypt (split by master key), HMAC-SM3 (split by key), the new
v0.3 `ct_pkcs8_decrypt` (split by password bytes — both classes' blobs
valid for their class's password so both succeed via identical control
flow), plus direct `Fn::invert` and `Fp::invert` diagnostics. The
`ct_sign_k_class` target closes v0.1's structural blind spot to
nonce-only leaks. The `crypto-bigint 0.6 → 0.7.3` upgrade resolved the
v0.6-era `ConstMontyForm::invert` leak directly: at 100K samples on
0.7.3 both direct invert diagnostics measure under `|tau| ≈ 0.01`, two
orders of magnitude below the gate. See [`SECURITY.md`](SECURITY.md)
for the full posture.

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

## v0.3 scope (shipped)

Builds on v0.2 (SM4 + SM4-CBC + HMAC-SM3 + PBKDF2-HMAC-SM3 + SM2
encrypt/decrypt + dudect harness expansion to 11 targets). v0.3 adds
the wire-format / interop / streaming / performance work that v0.2
deliberately deferred:

- **Reusable strict-canonical DER reader / writer** subset
  (`gmcrypto_core::asn1::{reader, writer, oid}`) — W1. `asn1::sig` and
  `asn1::ciphertext` ported on top; wire output and accept/reject
  behavior byte-identical to v0.2.
- **PEM + encrypted PKCS#8 + X.509 SPKI + SEC1** codecs
  (`gmcrypto_core::{pem, pkcs8, spki, sec1}`) — W2. Hand-rolled,
  no_std, zero-runtime-deps. PBES2 with PBKDF2-HMAC-SM3 + SM4-CBC
  for encrypted PKCS#8.
- **Full bidirectional gmssl interop** — W3. SM2 sign / verify, SM2
  encrypt / decrypt (GM/T 0009 DER), and SM4-CBC all cross-validated
  in both directions against gmssl 3.1.1 (gated on
  `GMCRYPTO_GMSSL=1`).
- **Raw byte-concat SM2 ciphertext helpers**
  (`gmcrypto_core::sm2::raw_ciphertext`) — W4. Modern
  `C1 || C3 || C2` emit + decode; legacy `C1 || C2 || C3`
  decrypt-only.
- **Streaming `HmacSm3` + `Sm4Cbc{En,De}cryptor`** — W5. In-crate
  `Hash` / `Mac` / `BlockCipher` trait surface
  (`gmcrypto_core::traits`). RustCrypto trait fit deferred to v0.4
  behind an opt-in feature flag.
- **Comb-table `mul_g` optimization** (~5× sign-side speedup) — W6.
  64 sub-tables of 16 entries each, lazily built once per process
  via `spin::Once`. `mul_g`'s public signature is unchanged;
  constant-time-designed lookup preserved. Adds one runtime dep
  (`spin = "0.10"`, no_std, ~4 KB lib).

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
  bitsliced fast-path deferred to v0.4. PKCS#7 strip uses a
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
- `dudect-bencher` harness with **12 targets** at `|tau| < 0.20` —
  PR-smoke 10⁴ samples; nightly 10⁵ samples (more samples = tighter
  empirical confidence at the same threshold). Plus a deliberately-
  leaky negative control that proves the harness can detect leaks.
- Failure-mode invariant: error types collapse to single uninformative
  variants (`SignError::Failed`, `DecryptError::Failed`,
  `EncryptError::Failed`, `pem::Error::Failed`, `pkcs8::Error::Failed`);
  `verify_with_id` returns `bool`; DER decode returns `Option`.
  Defense against padding-oracle, malleability, and invalid-curve
  attacks.
- Zeroization on private keys, SM4 round keys, HMAC `K'` /
  `K' XOR ipad` / `K' XOR opad`, PBKDF2 intermediates, SM2 KDF
  buffers, and PKCS#8 inner-key scratch.

## Roadmap

| Version | Scope |
|---|---|
| v0.2 (shipped) | SM4 + SM4-CBC, HMAC-SM3, PBKDF2-HMAC-SM3, SM2 encrypt/decrypt + GM/T 0009 ciphertext DER, dudect harness expansion to 11 targets. See [`CHANGELOG.md`](CHANGELOG.md) `[0.2.0]`. |
| v0.3 (shipped) | Reusable ASN.1 reader/writer subset; PEM, encrypted PKCS#8, X.509 SPKI, SEC1; full bidirectional gmssl interop (incl. SM2 sign/verify + SM2 encrypt/decrypt with PEM-wrapped keys + SM4-CBC); raw byte-concat ciphertext helpers (`C1\|\|C3\|\|C2` modern + legacy `C1\|\|C2\|\|C3` decrypt); streaming `HmacSm3` / `Sm4CbcEncryptor` / `Sm4CbcDecryptor` + in-crate `Hash`/`Mac`/`BlockCipher` traits; comb-table `mul_g` (~5× sign-side speedup); dudect harness expanded to 12 targets. See [`CHANGELOG.md`](CHANGELOG.md) `[0.3.0]`. |
| v0.4 | C ABI (`gmcrypto-c`), `wasm32-unknown-unknown` build target, bitsliced SM4 S-box (faster constant-time fast-path), RustCrypto-trait fit (`digest::Digest` / `digest::Mac` / `cipher::BlockMode`) behind opt-in feature flags. |
| v1.0 | API stabilization |

## Quick-start

```rust
use gmcrypto_core::sm2::{
    sign_with_id, verify_with_id, Sm2PrivateKey, Sm2PublicKey, DEFAULT_SIGNER_ID,
};
use crypto_bigint::U256;
use getrandom::SysRng;
use rand_core::UnwrapErr;

let d = U256::from_be_hex(
    "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
);
let key = Sm2PrivateKey::new(d).expect("d in [1, n-2]");
let public = Sm2PublicKey::from_point(key.public_key());

let mut rng = UnwrapErr(SysRng);
let sig = sign_with_id(&key, DEFAULT_SIGNER_ID, b"hello", &mut rng).unwrap();
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
