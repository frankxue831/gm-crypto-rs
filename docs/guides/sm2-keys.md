# SM2 key formats and the default signer ID

`gmcrypto-core` separates raw key operations from wire codecs so you can load and save SM2 keys in whichever format your peers use.

## Generating a fresh key pair

`gmcrypto-core` pulls no RNG into its dependency graph. Pass any `rand_core::TryCryptoRng` (for example `getrandom::SysRng`) to `Sm2PrivateKey::generate`, which samples `d ∈ [1, n-2]` in constant time with a fixed 4-draw budget and wipes its temporary buffers internally:

```rust
use getrandom::SysRng;
use gmcrypto_core::sm2::Sm2PrivateKey;

let key = Sm2PrivateKey::generate(&mut SysRng)?;
let public = key.public_key();
```

If you already hold a raw 32-byte big-endian scalar, import it with `Sm2PrivateKey::from_bytes_be(&raw)` (constant-time `[1, n-2]` check returning `subtle::CtOption`) and wipe your `[u8; 32]` buffer afterwards. `Sm2PrivateKey` zeroizes its scalar on drop; if you export the raw scalar with `Sm2PrivateKey::to_bytes_be()`, you own zeroizing the returned `[u8; 32]`.

## Key and point encodings

| Format | Module | Private / Public | Wire form | PEM label (`pem::encode` / `pem::decode`) |
|---|---|---|---|---|
| Raw scalar | `sm2::Sm2PrivateKey` | Private | 32-byte big-endian `d ∈ [1, n-2]` (`from_bytes_be` / `to_bytes_be`) | N/A |
| SEC1 point (uncompressed) | `sm2::Sm2PublicKey` | Public | 65-byte uncompressed `04 ‖ X(32) ‖ Y(32)` (`from_sec1_bytes` / `to_sec1_uncompressed`) | N/A |
| SEC1 point (compressed, bare public key) | `sm2::Sm2PublicKey` | Public | 33-byte compressed `02`/`03 ‖ X(32)` (`from_sec1_compressed` / `to_sec1_compressed`); identity `00` and hybrid `06`/`07` rejected | N/A |
| SEC1 `ECPrivateKey` (RFC 5915) | `sec1` | Private (+ optional public) | DER `SEQUENCE` with `sm2p256v1` OID (`1.2.156.10197.1.301`) | `"EC PRIVATE KEY"` |
| PKCS#8 `OneAsymmetricKey` (RFC 5958) | `pkcs8::{encode, decode}` | Private | DER `SEQUENCE` wrapping SEC1 `ECPrivateKey` | `"PRIVATE KEY"` |
| Encrypted PKCS#8 (PBES2, RFC 8018) | `pkcs8::{encrypt, decrypt}` | Private (password-protected) | DER `EncryptedPrivateKeyInfo` using PBKDF2-HMAC-SM3 + SM4-CBC | `"ENCRYPTED PRIVATE KEY"` |
| SPKI `SubjectPublicKeyInfo` (RFC 5280) | `spki::{encode, decode}` | Public | DER `SEQUENCE` with `id-ecPublicKey` + `sm2p256v1` + uncompressed point `BIT STRING` | `"PUBLIC KEY"` |

All decoders follow the crate's **failure-mode invariant**: malformed DER, wrong PEM label, off-curve points, and wrong PBES2 passwords collapse to a single opaque `Error::Failed` (or `None`).

### Choosing a format

- **Store private keys on disk:** prefer password-encrypted PKCS#8 (`pkcs8::encrypt` + `pem::encode("ENCRYPTED PRIVATE KEY", ...)` with a random 16-byte salt, random 16-byte IV, and a strong PBKDF2 iteration count such as `>= 100_000`), or unencrypted PKCS#8 (`"PRIVATE KEY"`) when an external secret manager handles encryption at rest.
- **Exchange public keys:** use SPKI (`spki::encode` + `pem::encode("PUBLIC KEY", ...)`) for PEM/ASN.1 ecosystems (GmSSL, OpenSSL), raw 65-byte SEC1 (`to_sec1_uncompressed`) for fixed-size uncompressed protocols and `gmcrypto-c`, or 33-byte compressed SEC1 (`to_sec1_compressed` / `from_sec1_compressed`) when storing or exchanging compact bare SM2 public keys (`from_sec1_bytes`, `spki::decode`, and `sec1::decode` continue to require the 65-byte uncompressed form).

## The signer ID (`Z_A`) and `DEFAULT_SIGNER_ID`

Unlike ECDSA, SM2 signatures (GB/T 32918.2) and SM2 key exchange (GB/T 32918.3) bind a **user identity string `id`** into the hash via `Z = SM3(ENTL ‖ ID ‖ a ‖ b ‖ x_G ‖ y_G ‖ x_A ‖ y_A)` and sign `SM3(Z ‖ message)`.

- Signing and verifying **must** use the exact same `id` bytes, or `verify_with_id` returns `false`.
- `sm2::DEFAULT_SIGNER_ID` is `b"1234567812345678"` (GB/T 32918.2 §10), which is the default used by GmSSL, OpenSSL SM2, X.509-with-SM2 (`GM/T 0015`), and TLCP handshake signatures (`GB/T 38636`).
- Treat `id` as part of your protocol contract: do not start with `DEFAULT_SIGNER_ID` intending to change it later, because changing `id` invalidates all previously issued signatures.
