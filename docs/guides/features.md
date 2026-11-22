# Choosing Cargo features

`gmcrypto-core` uses `default = []`. The default build gives you the `no_std + alloc` core with zero optional dependencies:

- **SM2:** sign/verify (`GB/T 32918.2`), encrypt/decrypt (`GB/T 32918.4`, `GM/T 0009` DER and raw `C1‖C3‖C2`)
- **SM3:** hash (`GB/T 32905`), HMAC-SM3 (`RFC 2104`), PBKDF2-HMAC-SM3 (`RFC 8018`)
- **SM4:** ECB, CBC, CTR (single-shot and streaming, `GB/T 32907`)
- **Codecs:** DER signatures/ciphertexts, PEM (`RFC 7468`), SEC1 (`RFC 5915`), PKCS#8 + PBES2 (`RFC 5958` / `8018`), SPKI (`RFC 5280`)

Everything else is additive and opt-in.

## Feature matrix

| Feature | What it adds | Extra dependency | Typical use |
|---|---|---|---|
| `sm4-aead` | SM4-GCM, SM4-CCM (single-shot + incremental GCM + length-committed streaming CCM) | `gmcrypto-simd` (GHASH) | Authenticated symmetric encryption (recommended default for new designs) |
| `sm4-xts` | SM4-XTS single-shot and multi-sector (`GB/T 17964-2021`) | None | Disk / block-device sector encryption |
| `sm2-key-exchange` | SM2 key agreement (`GB/T 32918.3-2016`), confirmed and no-confirmation flows | None | Ephemeral key agreement, TLCP ECDHE suites |
| `x509` | X.509-with-SM2 leaf parse/verify and linear structural chain check (`GM/T 0015`) | None | Parsing SM2 certificates and checking signatures/chains |
| `tlcp` | TLCP (`GB/T 38636-2020`) key schedule and CBC record protection (+ GCM with `sm4-aead`; `[sign, enc]` pair check with `x509`) | None | Building blocks for a TLCP engine |
| `sm4-bitsliced` | Table-less gate-only SM4 S-box (single-block) | None | Faster constant-time-designed SM4 without SIMD |
| `sm4-bitsliced-simd` | Packed AVX2 / NEON bitsliced SM4 S-box (+ GFNI on supported `x86_64` with rustc ≥ 1.89) | `gmcrypto-simd` | Highest SM4 throughput on x86_64 / aarch64 |
| `digest-traits` | RustCrypto `digest::Digest` (`Sm3`) and `digest::Mac` (`HmacSm3`) | `digest 0.11` | Interop with generic `digest` crates |
| `cipher-traits` | RustCrypto `cipher::{BlockCipherEncrypt, BlockCipherDecrypt, KeyInit}` (`Sm4Cipher`) | `cipher 0.5` | Interop with generic `cipher` crates |
| `aead-traits` | RustCrypto `aead::{AeadCore, AeadInOut, KeyInit}` (`Sm4Gcm`, `Sm4Ccm`; implies `sm4-aead`) | `aead 0.6`, `gmcrypto-simd` | Interop with generic `aead` crates |
| `crypto-bigint-scalar` | `Sm2PrivateKey::from_scalar(crypto_bigint::U256)` | None (exposes internal dep) | Callers who already hold a `U256` scalar |

## Common combinations

- **General service (signing + authenticated encryption):**
  ```toml
  gmcrypto-core = { version = "1.18", features = ["sm4-aead", "sm4-bitsliced-simd"] }
  ```
- **TLCP toolkit (all four SM2-family suites + cert pair verification + ECDHE):**
  ```toml
  gmcrypto-core = { version = "1.18", features = ["tlcp", "x509", "sm4-aead", "sm2-key-exchange"] }
  ```
- **`wasm32-unknown-unknown`:**
  Enable any pure-core / `no_std` feature set (`sm4-aead`, `sm4-bitsliced-simd`, `sm4-xts`, `sm2-key-exchange`, `x509`, `tlcp`, `*-traits`) and add `getrandom` with its `wasm_js` feature in your own `Cargo.toml` to pass `SysRng` to SM2 operations.
- **Non-Rust callers (C, C++, Python, Go, Zig):**
  Use [`gmcrypto-c`](../../crates/gmcrypto-c/README.md) instead; its default build exports the full C ABI with no Cargo feature flags required. Do not depend on `gmcrypto-simd` directly (it is an internal backend with no SemVer guarantee).

## SemVer note on `*-traits` and `crypto-bigint-scalar`

The core Rust API is 1.x SemVer-stable and names zero `crypto-bigint` types by default. Enabling `digest-traits`, `cipher-traits`, `aead-traits`, or `crypto-bigint-scalar` exposes types from those pre-1.0 crates, so a breaking upstream release of that crate is outside `gmcrypto-core`'s 1.x guarantee.
