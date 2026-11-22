# Choosing an SM4 mode

Start with **authenticated encryption** (`SM4-GCM` or `SM4-CCM`, behind the `sm4-aead` feature) unless an existing protocol or storage format forces another mode. Unauthenticated modes (CBC, CTR, XTS, ECB) do **not** detect tampering.

## Mode comparison

| Mode | Feature | Confidentiality | Authenticity | Nonce / IV rule | Typical use |
|---|---|---|---|---|---|
| **SM4-GCM** (`sm4::mode_gcm`, `sm4::gcm_streaming`) | `sm4-aead` | Yes | Yes (AEAD, 128-bit default tag) | **Never reuse `(key, nonce)`**; 12-byte (96-bit) nonce strongly recommended | General messages, RPCs, files, TLCP GCM records |
| **SM4-CCM** (`sm4::mode_ccm`, `sm4::ccm_streaming`) | `sm4-aead` | Yes | Yes (AEAD, RFC 3610 / RFC 8998) | **Never reuse `(key, nonce)`**; nonce 7–13 bytes, tag 4–16 even bytes | Protocols requiring CCM; streaming encryptor commits to `plaintext_len` upfront |
| **SM4-CBC** (`sm4::mode_cbc`, `sm4::cbc_streaming`) | default | Yes | **No** (pair with HMAC-SM3) | Fresh unpredictable 16-byte CSPRNG IV per message | Legacy wire formats; must use Encrypt-then-MAC with a separate MAC key |
| **SM4-CTR** (`sm4::mode_ctr`, `sm4::ctr_streaming`) | default | Yes | **No** (pair with HMAC-SM3) | **Never reuse `(key, counter)`** across messages | Legacy stream formats; must use Encrypt-then-MAC |
| **SM4-XTS** (`sm4::mode_xts`) | `sm4-xts` | Yes | **No** | Unique sector tweak per data unit; 32-byte key (`K1 ‖ K2`, `K1 != K2` recommended) | Fixed-size disk / storage sectors (`GB/T 17964-2021`) |
| **SM4-ECB** (`sm4::Sm4Cipher`) | default | Single-block primitive only | **No** | N/A | Building block only — **never** use raw ECB for multi-block data |

## Critical rules and ceilings

1. **Nonce reuse breaks GCM and CCM completely.** Reusing `(key, nonce)` in GCM exposes the XOR of plaintexts *and* leaks the GHASH authentication key `H`, allowing arbitrary tag forgeries. Use a fresh 96-bit random nonce only for bounded message counts per key, or a monotonic counter / deterministic nonce construction.
2. **CBC requires Encrypt-then-MAC.** If a protocol mandates SM4-CBC, derive two independent keys (encryption key + HMAC-SM3 key), compute `HMAC-SM3(mac_key, iv || ciphertext)`, and **verify the MAC before decrypting**. Note also that `Sm4CbcDecryptor` emits unauthenticated plaintext incrementally as chunks arrive — do not act on decrypted chunks until authentication succeeds.
3. **GCM length ceiling.** `mode_gcm::encrypt` and `mode_gcm::encrypt_with_tag_len` return `None` if `plaintext.len() > 2^36 − 32` bytes (NIST SP 800-38D §5.2.1.1 32-bit GCTR counter limit).
4. **Streaming AEAD buffering.**
   - `Sm4GcmDecryptor` buffers input incrementally and decrypts only after verifying the tag in `finalize_verify`, so unverified plaintext is never exposed.
   - `Sm4CcmEncryptor` requires `plaintext_len` at construction (CCM encodes the length in `B0`) and streams ciphertext with `O(chunk)` memory; `Sm4CcmDecryptor` buffers until `finalize_verify` so failed tags never release plaintext.
5. **Performance.** The default build uses a 256-entry constant-time linear-scan S-box (portable, no secret-dependent table lookup, slower). Enable `sm4-bitsliced` or `sm4-bitsliced-simd` for faster constant-time-designed SM4 with byte-identical wire output.
