---
paths:
  - "crates/gmcrypto-core/src/sm2/**"
  - "crates/gmcrypto-core/src/sm3.rs"
  - "crates/gmcrypto-core/src/hmac.rs"
  - "crates/gmcrypto-core/src/kdf.rs"
  - "crates/gmcrypto-core/src/pkcs8.rs"
  - "crates/gmcrypto-core/src/pem.rs"
  - "crates/gmcrypto-core/src/sec1.rs"
  - "crates/gmcrypto-core/src/spki.rs"
  - "crates/gmcrypto-core/src/asn1/**"
---

# SM2 / SM3 / KDF / key formats

## SM2

- Sign retry is fixed `K=2`, masked-select. Don't reduce the iteration count
  or short-circuit on the first valid candidate.
- `sign_raw_with_id` is `#[doc(hidden)] pub` for dudect only — **not SemVer**.
  Don't expand or publicly expose it.
- Don't change `mul_g`'s public signature
  (`pub fn mul_g(k: &Fn) -> ProjectivePoint`).
- Comb-table lazy init is `spin::Once` — the `no_std` choice. Don't swap it
  for `LazyLock`/`OnceLock` (both `std`) or "just unsafe and faster".
- `sm2::decrypt`: single `Failed`; don't drop the `point_on_curve` check on
  `C1`. Don't expose SM2 `kdf` or `point_on_curve` publicly (top-level
  `kdf.rs` is PBKDF2 / HKDF).
- Don't ship `encode_c1c2c3_legacy` — legacy `C1||C2||C3` is decrypt-only.
- `Sm2PrivateKey::to_bytes_be` returns plaintext secret bytes — **callers
  zeroize** the `[u8; 32]`. The FFI name stays `gmcrypto_sm2_privkey_to_sec1_be`.
- Don't invent a second RNG-callback shape; `CallbackRng` already covers key
  exchange and TLCP records. `getrandom` is a direct workspace dep (`sys_rng`).
- `Sm2PublicKey::{to_sec1_compressed, from_sec1_compressed}` are additive
  bare-point helpers (SEC1 §2.3.3–2.3.4). Keep `Sm2PublicKey::from_sec1_bytes`,
  `spki::decode`, `sec1::decode`, and `gmcrypto-c`'s `gmcrypto_sm2_pubkey_new`
  strictly uncompressed (`65` bytes); keep field/sqrt helpers in `sec1.rs`
  `pub(crate)` or private.

## SM3 / HMAC / KDF

- Don't remove single-shot `hmac_sm3` (streaming `HmacSm3` exists alongside).
- Don't add an iteration-count default to `pbkdf2_hmac_sm3`, and don't make it
  allocate the output buffer (caller `&mut [u8]`).
- `hkdf_sm3` and `hkdf_sm3_expand` take caller `&mut [u8]` (zero heap
  allocation), return `None` without modifying `output` when `output.is_empty()`
  or `output.len() > 255 * 32` (`8160`), and unconditionally zeroize rolling
  `T(i)` (plus intermediate `prk` in `hkdf_sm3`) before return.

## Key formats

- `pkcs8::decrypt` returns a single `Failed` for wrong-password /
  malformed-PEM / bad-inner — don't distinguish. DER decode returns `Option`.
