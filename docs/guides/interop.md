# Interoperability notes

## GmSSL 3.2.0 (CI-verified)

CI runs [`crates/gmcrypto-core/tests/interop_gmssl.rs`](../../crates/gmcrypto-core/tests/interop_gmssl.rs) against a pinned from-source build of **GmSSL v3.2.0** (a required status check on `main`: any cryptographic mismatch blocks merging; infrastructure failures only skip).

### What the 13 tests cover

| Surface | Direction | Check |
|---|---|---|
| Oracle version | — | Asserts exact GmSSL 3.2.0 binary (`ORACLE DRIFT` on mismatch) |
| SM2 sign / verify | `gmcrypto-core` ↔ GmSSL | Cross-verify DER signatures using `DEFAULT_SIGNER_ID` (`"1234567812345678"`) |
| SM2 encrypt / decrypt | `gmcrypto-core` ↔ GmSSL | Cross-decrypt GM/T 0009 DER `C1‖C3‖C2` ciphertexts |
| SM4-CBC / SM4-CTR | `gmcrypto-core` ↔ GmSSL | Cross-decrypt ciphertexts (PKCS#7 padding for CBC) |
| SM4-GCM (`--features sm4-aead`) | `gmcrypto-core` ↔ GmSSL | Cross-decrypt authenticated ciphertexts + tags |
| HMAC-SM3, PBKDF2-HMAC-SM3 | `gmcrypto-core` vs GmSSL | Byte-for-byte equal digests / derived keys |

### What is *not* in the GmSSL interop suite

SM4-CCM, SM4-XTS, SM2 key exchange, X.509, and TLCP are **not** exercised by `interop_gmssl.rs`. Those surfaces are cross-validated by committed known-answer tests sourced from OpenSSL 3.x EVP, GB/T 32918.5 worked examples, and GmSSL certificate fixtures (see the [KAT sourcing records](../README.md#kat-sourcing)).

### Running locally

```bash
GMCRYPTO_GMSSL=1 cargo test --test interop_gmssl --features sm4-aead
```

## Common wire-format pitfalls when interoperating

1. **SM2 ciphertext ordering (`C1‖C3‖C2` vs `C1‖C2‖C3`):** `gmcrypto-core` implements the current standard `C1‖C3‖C2` order (GB/T 32918.4 / GM/T 0009 DER by default, or raw bytes via `sm2::raw_ciphertext`). Very old implementations using the pre-2012 `C1‖C2‖C3` order are not compatible without reordering `C2` and `C3`.
2. **SM2 ciphertext ASN.1 DER vs raw bytes:** `sm2::encrypt` and `sm2::decrypt` speak GM/T 0009 ASN.1 DER `SEQUENCE { x, y, hash, cipherText }`. If a peer sends bare `04 ‖ X ‖ Y ‖ C3 ‖ C2` (or `X ‖ Y ‖ C3 ‖ C2` without the `04` prefix), use `sm2::raw_ciphertext` to convert between raw and DER forms.
3. **SM2 signature DER vs raw `r ‖ s`:** `sm2::sign_with_id` / `verify_with_id` use ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }`. Use `asn1::{encode_sig, decode_sig}` when bridging to a peer that expects fixed 64-byte `r(32) ‖ s(32)`.
4. **SM2 signer ID:** Confirm both sides use the same `id` (normally `"1234567812345678"`).
5. **SM4-XTS standard:** `sm4::mode_xts` implements `GB/T 17964-2021` (equivalent to OpenSSL `xts_standard=GB`), where the tweak uses the bit-reflected GF(2^128) convention.

## Browser / WebAssembly (`gm-crypto-web`)

[gm-crypto-web](https://www.frankxue.dev/gm-crypto-web/) compiles `gmcrypto-core` directly to `wasm32-unknown-unknown` and runs SM2 / SM3 / SM4 locally in the browser (unaudited demo; do not use production keys). When compiling your own wasm32 consumer, enable `getrandom` with the `wasm_js` feature in your application's `Cargo.toml` and pass `getrandom::SysRng` into SM2 operations.
