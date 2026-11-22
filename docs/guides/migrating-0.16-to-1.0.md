# Migrating from 0.16 to 1.0

`1.0.0` is the first SemVer-stable release. Crates.io skipped `0.17.0`–`0.23.0` (internal assurance and API-finalization cycles), so **0.16 → 1.0 is the only breaking migration** in the crate's history. All subsequent `1.x` releases (`1.0.1` through `1.17.0`) are strictly additive.

Runtime wire output (SM2 signatures and ciphertexts, SM3/HMAC/PBKDF2, and every SM4 mode) is unchanged from `0.16.0` — the breaking changes are API and ABI shape only.

## Breaking changes and how to update

### 1. `Sm2PublicKey` replaces raw `ProjectivePoint`
- **Before (0.16):** `Sm2PrivateKey::public_key()` returned `ProjectivePoint`; `sec1::EcPrivateKey.public` and `spki::{encode, decode}` took/returned `ProjectivePoint`.
- **After (1.x):** All high-level APIs speak `Sm2PublicKey`. Construct public keys via `Sm2PublicKey::from_sec1_bytes` or `spki::decode`, and serialize via `Sm2PublicKey::to_sec1_uncompressed` or `spki::encode`.
- Raw curve and point arithmetic (`sm2::point`, `ProjectivePoint`, `sm2::curve`, `sm2::scalar_mul`) is `#[doc(hidden)]` and not SemVer-covered.

### 2. Zero `crypto-bigint` types in the always-on public API
- **Before (0.16):** `asn1::{encode_sig, decode_sig}` and `Sm2Ciphertext::{x, y}` used `crypto_bigint::U256`.
- **After (1.x):** They use fixed `[u8; 32]` big-endian byte arrays. For private keys, prefer `Sm2PrivateKey::from_bytes_be(&[u8; 32])`; `Sm2PrivateKey::from_scalar(U256)` remains available only behind the opt-in `crypto-bigint-scalar` feature.

### 3. Fallible `rand_core::TryCryptoRng` bound on SM2 sign / encrypt
- **Before (0.16):** `sm2::{sign_with_id, encrypt}` required infallible `CryptoRng + Rng`.
- **After (1.x):** They accept `rand_core::TryCryptoRng` (`rand_core 0.10.x`), collapsing any RNG failure into `Error::Failed` instead of panicking. Pass `&mut getrandom::SysRng` directly (drop any `UnwrapErr` adapter).

### 4. Single-shot `sm4::mode_gcm::encrypt` is now fallible (`Option`)
- **Before (0.16):** `mode_gcm::encrypt` and `mode_gcm::encrypt_with_tag_len` returned `(Vec<u8>, Tag)` directly.
- **After (1.x):** Both return `Option<…>`, returning `None` if `plaintext.len() > 2^36 − 32` bytes (the GCM 32-bit counter ceiling). Handle the `Option` at the call site.

### 5. `#[doc(hidden)]` low-level modules
- `asn1::{reader, writer, oid}` and `traits::{Hash, Mac, BlockCipher}` are `#[doc(hidden)]` and outside the 1.x SemVer contract. Use the high-level modules (`asn1::{encode_sig, decode_sig}`, `Sm2Ciphertext`, `sm3`, `hmac`, `sm4`) or the opt-in `digest-traits` / `cipher-traits` / `aead-traits` RustCrypto fits.

### 6. C ABI (`gmcrypto-c`): always-on AEAD and XTS
- **Before (0.16):** `gmcrypto-c` exposed `sm4-aead` and `sm4-xts` forwarding features.
- **After (1.x):** Those features were removed; a default `cargo build -p gmcrypto-c` always exports the complete C ABI matching `crates/gmcrypto-c/include/gmcrypto.h`.

## Reference

See the full [`[1.0.0]` entry in `CHANGELOG.md`](../../CHANGELOG.md#100---2026-06-01) and [`docs/v1.0-readiness.md`](../v1.0-readiness.md) for the complete readiness audit behind these changes.
