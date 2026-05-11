//! PKCS#8 `OneAsymmetricKey` codec (RFC 5958) + PBES2 encryption (RFC 8018).
//!
//! Wire shapes:
//!
//! ```text
//! OneAsymmetricKey ::= SEQUENCE {
//!     version              INTEGER (0),
//!     privateKeyAlgorithm  AlgorithmIdentifier,
//!     privateKey           OCTET STRING -- DER-encoded ECPrivateKey
//! }
//!
//! EncryptedPrivateKeyInfo ::= SEQUENCE {
//!     encryptionAlgorithm  AlgorithmIdentifier,
//!     encryptedData        OCTET STRING
//! }
//! ```
//!
//! For SM2 the `privateKeyAlgorithm` is `id-ecPublicKey` with
//! `namedCurve = sm2p256v1`; `privateKey` wraps a DER-encoded RFC 5915
//! [`crate::sec1::EcPrivateKey`].
//!
//! For the encrypted variant, `encryptionAlgorithm` is `id-PBES2`
//! with `keyDerivationFunc = id-PBKDF2` (PRF = id-hmacWithSM3) and
//! `encryptionScheme = sm4-cbc` (IV in the parameters OCTET STRING).
//! `encryptedData` is the SM4-CBC ciphertext of the inner
//! `OneAsymmetricKey`.
//!
//! # Failure-mode invariant (API)
//!
//! All decoders return `Result<_, Error>` with a single
//! [`Error::Failed`] variant. The return type carries no distinction
//! between "wrong password", "malformed PEM", and "valid PEM but
//! bad inner `ECPrivateKey`" — the caller sees one uninformative
//! shape on any failure.
//!
//! # Timing-side-channel posture
//!
//! Code paths over **secret material** are constant-time-designed:
//! PBKDF2-HMAC-SM3 (covered by [`crate::hmac`]'s constant-time
//! discipline), SM4-CBC decrypt + PKCS#7 strip
//! ([`crate::sm4::mode_cbc::decrypt`]), and the inner
//! [`Sm2PrivateKey::new`] range gate. The W2 dudect target
//! `ct_pkcs8_decrypt` class-splits by **password bytes** (both
//! classes ship valid blobs so both succeed via identical control
//! flow); local 10K-sample run measures `|tau| ≈ 0.02`.
//!
//! Code paths over **public attacker-supplied wire bytes** (the
//! PBES2 structural parse) early-return on malformed input. A
//! structurally invalid blob fails in microseconds; a structurally
//! valid blob with a wrong password runs full PBKDF2 + SM4-CBC + an
//! inner parse before failing. **This wall-clock distinction is
//! observable but not secret-dependent** — the attacker built the
//! blob and already knows its structural validity. The dudect
//! gate above covers the only secret-dependent timing class
//! (password vs password under a valid blob).
//!
//! # KDF parameter validation
//!
//! [`decrypt`] rejects `iterations == 0` (RFC 8018 §5.2 requires
//! `c ≥ 1`) and `iterations > 10_000_000` (denial-of-service
//! bound; the upper limit is per the W2 risk-trap in
//! `docs/v0.3-scope.md`). Any other malformed PBES2 parameter
//! folds into [`Error::Failed`] identically.

use crate::asn1::oid::{ID_EC_PUBLIC_KEY, ID_HMAC_WITH_SM3, ID_PBKDF2, PBES2, SM2P256V1, SM4_CBC};
use crate::asn1::{reader, writer};
use crate::kdf::pbkdf2_hmac_sm3;
use crate::sec1;
use crate::sm2::Sm2PrivateKey;
use crate::sm4::mode_cbc;
use alloc::vec::Vec;
use crypto_bigint::U256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// PKCS#8 codec failure. Single uninformative variant per the
/// project's failure-mode invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Decoding, decryption, or inner-key reconstruction failed for
    /// any reason — wrong password, malformed PBES2 parameters,
    /// off-curve public key, out-of-range scalar, etc. Single
    /// uninformative outcome.
    Failed,
}

/// PKCS#8 version field (`v1 = 0`). RFC 5958 also defines `v2 = 1`
/// when the optional `publicKey` BIT STRING is present; v0.3 emits
/// `v1` and accepts both `v1` and `v2`.
const PKCS8_V1: u8 = 0;
const PKCS8_V2: u8 = 1;

/// Default SM4-CBC key length (always 16 bytes for SM4).
const SM4_KEY_LEN: usize = 16;
/// SM4 block size = CBC IV size.
const SM4_IV_LEN: usize = 16;

/// PBKDF2 iteration count upper bound for [`decrypt`].
///
/// Rejects adversarial blobs that would burn unbounded CPU. v0.3
/// picks `10_000_000` as the denial-of-service ceiling — well
/// above any realistic production iteration count and still
/// bounded.
pub const PBKDF2_MAX_ITERATIONS: u32 = 10_000_000;

/// Encode an SM2 private key as a DER-encoded **unencrypted**
/// PKCS#8 `OneAsymmetricKey`.
///
/// The inner `ECPrivateKey` carries the scalar plus the optional
/// `publicKey` field (uncompressed `04 || X || Y`); the outer
/// privateKeyAlgorithm is `id-ecPublicKey` with `sm2p256v1`.
///
/// The intermediate `ECPrivateKey` body is zeroized before return.
/// **The returned `Vec<u8>` contains the raw scalar bytes** —
/// caller is responsible for wiping it before letting it leave
/// their stack frame.
#[must_use]
pub fn encode(key: &Sm2PrivateKey) -> Vec<u8> {
    let mut scalar_be = key.to_sec1_be();
    let pub_uncompressed = {
        let pub_key = crate::sm2::Sm2PublicKey::from_point(key.public_key());
        pub_key.to_sec1_uncompressed()
    };
    let mut inner = sec1::encode(&scalar_be, Some(&pub_uncompressed));
    scalar_be.zeroize();

    // privateKeyAlgorithm SEQUENCE { id-ecPublicKey, namedCurve }
    let mut alg_inner = Vec::with_capacity(ID_EC_PUBLIC_KEY.len() + SM2P256V1.len() + 4);
    writer::write_oid(&mut alg_inner, ID_EC_PUBLIC_KEY);
    writer::write_oid(&mut alg_inner, SM2P256V1);
    let mut alg_seq = Vec::with_capacity(alg_inner.len() + 4);
    writer::write_sequence(&mut alg_seq, &alg_inner);

    let mut body = Vec::with_capacity(inner.len() + alg_seq.len() + 8);
    writer::write_integer(&mut body, &[PKCS8_V1]);
    body.extend_from_slice(&alg_seq);
    writer::write_octet_string(&mut body, &inner);

    let mut out = Vec::with_capacity(body.len() + 4);
    writer::write_sequence(&mut out, &body);

    // Wipe the secret-bearing intermediates. (Zeroize is a side-
    // effecting write the optimizer must preserve via the
    // `volatile_write` in `zeroize::Zeroize`; the buffer is read by
    // SM4-CBC during the encrypt path's previous use.)
    inner.zeroize();
    body.zeroize();
    out
}

/// Decode an unencrypted PKCS#8 `OneAsymmetricKey` blob into an
/// [`Sm2PrivateKey`].
///
/// Validates the version (0 or 1), the privateKeyAlgorithm
/// (id-ecPublicKey + sm2p256v1), the inner `ECPrivateKey` scalar
/// (`d ∈ [1, n-2]`), and any optional public key (must match
/// `d·G`).
///
/// # Errors
///
/// Returns [`Error::Failed`] for any malformed input or
/// out-of-range scalar.
pub fn decode(input: &[u8]) -> Result<Sm2PrivateKey, Error> {
    let (body, rest) = reader::read_sequence(input).ok_or(Error::Failed)?;
    if !rest.is_empty() {
        return Err(Error::Failed);
    }

    // version INTEGER
    let (version, body) = reader::read_integer(body).ok_or(Error::Failed)?;
    if version != [PKCS8_V1] && version != [PKCS8_V2] {
        return Err(Error::Failed);
    }

    // privateKeyAlgorithm SEQUENCE
    let (alg_inner, body) = reader::read_sequence(body).ok_or(Error::Failed)?;
    let (alg_oid, alg_inner) = reader::read_oid(alg_inner).ok_or(Error::Failed)?;
    if alg_oid != ID_EC_PUBLIC_KEY {
        return Err(Error::Failed);
    }
    let (curve_oid, alg_inner) = reader::read_oid(alg_inner).ok_or(Error::Failed)?;
    if curve_oid != SM2P256V1 || !alg_inner.is_empty() {
        return Err(Error::Failed);
    }

    // privateKey OCTET STRING { ECPrivateKey }
    let (inner_bytes, body) = reader::read_octet_string(body).ok_or(Error::Failed)?;
    let mut inner = sec1::decode(inner_bytes).ok_or(Error::Failed)?;

    // Trailing PKCS#8 v2 attributes/publicKey are tolerated but not
    // required; we reject any unrecognized tag to stay strict.
    // (gmssl 3.1.1 emits PKCS#8 v1 by default, which has no trailing
    // fields.)
    if !body.is_empty() {
        // PKCS#8 v2 may carry [0] Attributes and [1] BIT STRING
        // publicKey. Skip them tolerantly: we don't need either,
        // since the inner ECPrivateKey already carries the public
        // point and the scalar is authoritative.
        let mut tail = body;
        while !tail.is_empty() {
            // Try [0] attributes EXPLICIT.
            if let Some((_, after)) = reader::read_context_tagged_explicit(tail, 0) {
                tail = after;
                continue;
            }
            // Try [1] publicKey EXPLICIT BIT STRING.
            if let Some((_, after)) = reader::read_context_tagged_explicit(tail, 1) {
                tail = after;
                continue;
            }
            // Unknown tag — fold into Failed.
            inner.scalar_be.zeroize();
            return Err(Error::Failed);
        }
    }

    let d = U256::from_be_slice(&inner.scalar_be);
    inner.scalar_be.zeroize();
    let key = Sm2PrivateKey::new(d);
    let key: Option<Sm2PrivateKey> = key.into();
    let key = key.ok_or(Error::Failed)?;

    // If the inner ECPrivateKey carried a publicKey, cross-check it
    // matches d·G — defends against stripped-public-key + stripped-
    // scalar swaps that escape unencrypted PKCS#8 detection.
    if let Some(stored_pub) = inner.public {
        let derived = key.public_key();
        if !bool::from(stored_pub.ct_eq(&derived)) {
            return Err(Error::Failed);
        }
    }

    Ok(key)
}

/// Encrypt an SM2 private key as a DER-encoded RFC 5958
/// `EncryptedPrivateKeyInfo` blob using PBES2 (PBKDF2-HMAC-SM3 +
/// SM4-CBC).
///
/// `salt` and `iv` must be **caller-supplied unpredictable
/// CSPRNG output** — see `CLAUDE.md` and
/// [`crate::sm4::mode_cbc::encrypt`]'s IV contract. Re-using the
/// same `(salt, iv)` under the same password under two different
/// keys is a key-recovery attack.
///
/// `iterations` should be at least 600,000 (OWASP 2024 PBKDF2
/// baseline); v0.3 does not enforce a minimum to keep test
/// vectors reproducible cheaply, but production callers must
/// pick.
///
/// # Errors
///
/// Returns [`Error::Failed`] only if `iterations == 0` (RFC 8018
/// `c ≥ 1`).
pub fn encrypt(
    key: &Sm2PrivateKey,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    iv: &[u8; SM4_IV_LEN],
) -> Result<Vec<u8>, Error> {
    if iterations == 0 {
        return Err(Error::Failed);
    }

    // 1. Encode the inner OneAsymmetricKey.
    let mut inner = encode(key);

    // 2. Derive an SM4-CBC key: PBKDF2-HMAC-SM3(password, salt, iter, 16).
    let mut sm4_key = [0u8; SM4_KEY_LEN];
    pbkdf2_hmac_sm3(password, salt, iterations, &mut sm4_key).ok_or(Error::Failed)?;

    // 3. Encrypt under SM4-CBC + PKCS#7 padding.
    let ciphertext = mode_cbc::encrypt(&sm4_key, iv, &inner);

    // Wipe sensitive intermediates.
    inner.zeroize();
    sm4_key.zeroize();

    // 4. Build the EncryptedPrivateKeyInfo wrapper.
    let pbes2_params = build_pbes2_params(salt, iterations, iv);
    let mut alg_inner = Vec::with_capacity(PBES2.len() + pbes2_params.len() + 4);
    writer::write_oid(&mut alg_inner, PBES2);
    alg_inner.extend_from_slice(&pbes2_params);
    let mut alg_seq = Vec::with_capacity(alg_inner.len() + 4);
    writer::write_sequence(&mut alg_seq, &alg_inner);

    let mut body = Vec::with_capacity(alg_seq.len() + ciphertext.len() + 8);
    body.extend_from_slice(&alg_seq);
    writer::write_octet_string(&mut body, &ciphertext);

    let mut out = Vec::with_capacity(body.len() + 4);
    writer::write_sequence(&mut out, &body);
    Ok(out)
}

/// Build the PBES2 `parameters` SEQUENCE for [`encrypt`].
///
/// ```text
/// PBES2-params ::= SEQUENCE {
///     keyDerivationFunc  AlgorithmIdentifier { id-PBKDF2,  PBKDF2-params },
///     encryptionScheme   AlgorithmIdentifier { sm4-cbc,    OCTET STRING (IV) }
/// }
///
/// PBKDF2-params ::= SEQUENCE {
///     salt            OCTET STRING,
///     iterationCount  INTEGER,
///     keyLength       INTEGER OPTIONAL,
///     prf             AlgorithmIdentifier { id-hmacWithSM3, NULL }
/// }
/// ```
fn build_pbes2_params(salt: &[u8], iterations: u32, iv: &[u8; SM4_IV_LEN]) -> Vec<u8> {
    // PBKDF2-params.
    let mut pbkdf2_inner = Vec::with_capacity(salt.len() + 32);
    writer::write_octet_string(&mut pbkdf2_inner, salt);
    writer::write_integer(&mut pbkdf2_inner, &iterations.to_be_bytes());
    // PRF AlgorithmIdentifier { id-hmacWithSM3, NULL }
    let mut prf_inner = Vec::with_capacity(ID_HMAC_WITH_SM3.len() + 4);
    writer::write_oid(&mut prf_inner, ID_HMAC_WITH_SM3);
    writer::write_null(&mut prf_inner);
    let mut prf_seq = Vec::with_capacity(prf_inner.len() + 4);
    writer::write_sequence(&mut prf_seq, &prf_inner);
    pbkdf2_inner.extend_from_slice(&prf_seq);

    let mut pbkdf2_seq = Vec::with_capacity(pbkdf2_inner.len() + 4);
    writer::write_sequence(&mut pbkdf2_seq, &pbkdf2_inner);

    // keyDerivationFunc AlgorithmIdentifier { id-PBKDF2, PBKDF2-params }.
    let mut kdf_inner = Vec::with_capacity(ID_PBKDF2.len() + pbkdf2_seq.len() + 4);
    writer::write_oid(&mut kdf_inner, ID_PBKDF2);
    kdf_inner.extend_from_slice(&pbkdf2_seq);
    let mut kdf_seq = Vec::with_capacity(kdf_inner.len() + 4);
    writer::write_sequence(&mut kdf_seq, &kdf_inner);

    // encryptionScheme AlgorithmIdentifier { sm4-cbc, OCTET STRING (IV) }.
    let mut es_inner = Vec::with_capacity(SM4_CBC.len() + iv.len() + 4);
    writer::write_oid(&mut es_inner, SM4_CBC);
    writer::write_octet_string(&mut es_inner, iv);
    let mut es_seq = Vec::with_capacity(es_inner.len() + 4);
    writer::write_sequence(&mut es_seq, &es_inner);

    let mut params_inner = Vec::with_capacity(kdf_seq.len() + es_seq.len());
    params_inner.extend_from_slice(&kdf_seq);
    params_inner.extend_from_slice(&es_seq);

    let mut out = Vec::with_capacity(params_inner.len() + 4);
    writer::write_sequence(&mut out, &params_inner);
    out
}

/// Decrypt a DER-encoded RFC 5958 `EncryptedPrivateKeyInfo` blob.
///
/// Parses the PBES2 parameters, derives the SM4-CBC key from
/// `password`, decrypts, and reconstructs the inner SM2 private
/// key. Single uninformative outcome — no path to distinguish
/// "wrong password" from "malformed PBES2 parameters" from
/// "decrypt succeeded but inner key was malformed".
///
/// # Errors
///
/// Returns [`Error::Failed`] for any malformed input. Same shape
/// regardless of where the failure occurred.
pub fn decrypt(input: &[u8], password: &[u8]) -> Result<Sm2PrivateKey, Error> {
    let parsed = parse_encrypted_blob(input).ok_or(Error::Failed)?;

    // Derive the SM4-CBC key from password + salt + iterations.
    let mut sm4_key = [0u8; SM4_KEY_LEN];
    let derive_ok =
        pbkdf2_hmac_sm3(password, parsed.salt, parsed.iterations, &mut sm4_key).is_some();
    // Even if derive failed (iterations == 0 caught above by the
    // 1..=PBKDF2_MAX_ITERATIONS gate, so this is unreachable in
    // practice), continue through decrypt with a zero key to keep
    // failure-mode shapes uniform.
    let _ = derive_ok;

    // SM4-CBC decrypt + PKCS#7 strip. Folds into Failed on any
    // failure (length not multiple of 16, bad pad, etc.).
    let plaintext = mode_cbc::decrypt(&sm4_key, &parsed.iv, parsed.ciphertext);
    sm4_key.zeroize();

    let mut plaintext = plaintext.ok_or(Error::Failed)?;

    // Parse the inner unencrypted OneAsymmetricKey. Failure folds
    // into the same Failed.
    let result = decode(&plaintext);
    plaintext.zeroize();
    result
}

/// Internal: parsed PBES2 parameters + ciphertext.
struct ParsedEncrypted<'a> {
    salt: &'a [u8],
    iterations: u32,
    iv: [u8; SM4_IV_LEN],
    ciphertext: &'a [u8],
}

/// Parse an `EncryptedPrivateKeyInfo` blob into validated PBES2
/// parameters + the ciphertext slice. Returns `None` for any
/// malformed input or unsupported algorithm.
fn parse_encrypted_blob(input: &[u8]) -> Option<ParsedEncrypted<'_>> {
    let (body, rest) = reader::read_sequence(input)?;
    if !rest.is_empty() {
        return None;
    }
    // encryptionAlgorithm SEQUENCE { id-PBES2, PBES2-params }.
    let (alg_inner, body) = reader::read_sequence(body)?;
    let (alg_oid, alg_inner) = reader::read_oid(alg_inner)?;
    if alg_oid != PBES2 {
        return None;
    }
    let (params_inner, alg_inner_rest) = reader::read_sequence(alg_inner)?;
    if !alg_inner_rest.is_empty() {
        return None;
    }

    // keyDerivationFunc SEQUENCE { id-PBKDF2, PBKDF2-params }.
    let (kdf_seq, params_rest) = reader::read_sequence(params_inner)?;
    let (kdf_oid, kdf_after) = reader::read_oid(kdf_seq)?;
    if kdf_oid != ID_PBKDF2 {
        return None;
    }
    let (pbkdf2_inner, kdf_seq_rest) = reader::read_sequence(kdf_after)?;
    if !kdf_seq_rest.is_empty() {
        return None;
    }

    // PBKDF2-params: salt, iterations, [keyLength], [PRF].
    let (salt, pbkdf2_inner) = reader::read_octet_string(pbkdf2_inner)?;
    let (iter_bytes, mut pbkdf2_inner) = reader::read_integer(pbkdf2_inner)?;
    if iter_bytes.len() > 4 {
        return None;
    }
    let mut iter_buf = [0u8; 4];
    iter_buf[4 - iter_bytes.len()..].copy_from_slice(iter_bytes);
    let iterations = u32::from_be_bytes(iter_buf);
    if iterations == 0 || iterations > PBKDF2_MAX_ITERATIONS {
        return None;
    }
    // Optional keyLength. SM4-CBC fixes 16 bytes; if present, must equal 16.
    if let Some((kl_bytes, after)) = reader::read_integer(pbkdf2_inner) {
        if kl_bytes.len() > 4 {
            return None;
        }
        let mut kl_buf = [0u8; 4];
        kl_buf[4 - kl_bytes.len()..].copy_from_slice(kl_bytes);
        let key_length = u32::from_be_bytes(kl_buf) as usize;
        if key_length != SM4_KEY_LEN {
            return None;
        }
        pbkdf2_inner = after;
    }
    // Optional PRF. Default is HMAC-SHA-1 per RFC 8018; we accept
    // only id-hmacWithSM3 (gmssl convention; required for SM2 PKCS#8).
    // No PRF specified would default to HMAC-SHA1, which is invalid
    // for SM2 PKCS#8 — reject.
    if pbkdf2_inner.is_empty() {
        return None;
    }
    let (prf_seq, prf_rest) = reader::read_sequence(pbkdf2_inner)?;
    if !prf_rest.is_empty() {
        return None;
    }
    let (prf_oid, prf_seq_rest) = reader::read_oid(prf_seq)?;
    if prf_oid != ID_HMAC_WITH_SM3 {
        return None;
    }
    // The PRF parameters MAY be NULL or absent.
    if !prf_seq_rest.is_empty()
        && (reader::read_null(prf_seq_rest).is_none() || prf_seq_rest.len() != 2)
    {
        return None;
    }

    // encryptionScheme SEQUENCE { sm4-cbc, OCTET STRING (IV) }.
    let (es_seq, params_outer_rest) = reader::read_sequence(params_rest)?;
    if !params_outer_rest.is_empty() {
        return None;
    }
    let (es_oid, es_after) = reader::read_oid(es_seq)?;
    if es_oid != SM4_CBC {
        return None;
    }
    let (iv_bytes, es_seq_rest) = reader::read_octet_string(es_after)?;
    if !es_seq_rest.is_empty() || iv_bytes.len() != SM4_IV_LEN {
        return None;
    }
    let mut iv = [0u8; SM4_IV_LEN];
    iv.copy_from_slice(iv_bytes);

    // encryptedData OCTET STRING.
    let (ciphertext, body_rest) = reader::read_octet_string(body)?;
    if !body_rest.is_empty() {
        return None;
    }

    Some(ParsedEncrypted {
        salt,
        iterations,
        iv,
        ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::U256;

    fn sample_key() -> Sm2PrivateKey {
        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        Sm2PrivateKey::new(d).expect("valid d")
    }

    /// Unencrypted PKCS#8 round-trip.
    #[test]
    fn round_trip_unencrypted() {
        let key = sample_key();
        let der = encode(&key);
        let recovered = decode(&der).expect("decode");
        // Same scalar → same public key.
        assert!(bool::from(recovered.public_key().ct_eq(&key.public_key())));
    }

    /// Unencrypted decode rejects trailing junk.
    #[test]
    fn unencrypted_rejects_trailing_bytes() {
        let key = sample_key();
        let mut der = encode(&key);
        der.push(0x00);
        assert!(matches!(decode(&der), Err(Error::Failed)));
    }

    /// Unencrypted decode rejects mismatched optional public key.
    #[test]
    fn unencrypted_rejects_public_key_mismatch() {
        // Build a PKCS#8 by hand whose inner ECPrivateKey has the
        // SAMPLE-1 scalar but the SAMPLE-2 public key — must fail.
        let d1 =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let d2 =
            U256::from_be_hex("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");
        let key1 = Sm2PrivateKey::new(d1).expect("d1");
        let key2 = Sm2PrivateKey::new(d2).expect("d2");
        let scalar1 = key1.to_sec1_be();
        let pk2 = crate::sm2::Sm2PublicKey::from_point(key2.public_key()).to_sec1_uncompressed();
        let inner_bad = sec1::encode(&scalar1, Some(&pk2));

        // Wrap in unencrypted PKCS#8 manually (re-using what encode does).
        let mut alg_inner = Vec::new();
        writer::write_oid(&mut alg_inner, ID_EC_PUBLIC_KEY);
        writer::write_oid(&mut alg_inner, SM2P256V1);
        let mut alg_seq = Vec::new();
        writer::write_sequence(&mut alg_seq, &alg_inner);
        let mut body = Vec::new();
        writer::write_integer(&mut body, &[PKCS8_V1]);
        body.extend_from_slice(&alg_seq);
        writer::write_octet_string(&mut body, &inner_bad);
        let mut out = Vec::new();
        writer::write_sequence(&mut out, &body);

        assert!(matches!(decode(&out), Err(Error::Failed)));
    }

    /// Encrypted PKCS#8 round-trip with low iteration count.
    #[test]
    fn round_trip_encrypted() {
        let key = sample_key();
        let salt = [0xAB; 16];
        let iv = [0xCD; SM4_IV_LEN];
        let blob =
            encrypt(&key, b"correct horse battery staple", &salt, 1024, &iv).expect("encrypt");
        let recovered =
            decrypt(&blob, b"correct horse battery staple").expect("decrypt with right password");
        assert!(bool::from(recovered.public_key().ct_eq(&key.public_key())));
    }

    /// Encrypted decrypt with the wrong password fails into Failed.
    #[test]
    fn encrypted_wrong_password_fails() {
        let key = sample_key();
        let salt = [0xAB; 16];
        let iv = [0xCD; SM4_IV_LEN];
        let blob = encrypt(&key, b"right", &salt, 1024, &iv).expect("encrypt");
        assert!(matches!(decrypt(&blob, b"wrong"), Err(Error::Failed)));
    }

    #[test]
    fn encrypted_zero_iterations_rejected() {
        let key = sample_key();
        let salt = [0xAB; 16];
        let iv = [0xCD; SM4_IV_LEN];
        assert!(matches!(
            encrypt(&key, b"pw", &salt, 0, &iv),
            Err(Error::Failed)
        ));
    }

    #[test]
    fn decrypt_rejects_truncated_blob() {
        assert!(matches!(decrypt(&[], b"pw"), Err(Error::Failed)));
        assert!(matches!(decrypt(&[0x30, 0x00], b"pw"), Err(Error::Failed)));
    }

    #[test]
    fn decrypt_rejects_excessive_iterations() {
        // Build a malformed blob with iterations > PBKDF2_MAX_ITERATIONS.
        let key = sample_key();
        let salt = [0xAB; 16];
        let iv = [0xCD; SM4_IV_LEN];
        let blob = encrypt(&key, b"pw", &salt, 1024, &iv).expect("encrypt");
        // Patch the iteration-count INTEGER. The structure is
        // SEQ { SEQ { id-PBES2, SEQ { kdf, encScheme } }, OCTETSTRING }.
        // Easier: round-trip parse to confirm the gate, by wrapping
        // a hand-built blob with a forbidden iteration count.

        let bad_iter: u32 = PBKDF2_MAX_ITERATIONS + 1;
        let pbes2_params = build_pbes2_params(&salt, bad_iter, &iv);
        let mut alg_inner = Vec::new();
        writer::write_oid(&mut alg_inner, PBES2);
        alg_inner.extend_from_slice(&pbes2_params);
        let mut alg_seq = Vec::new();
        writer::write_sequence(&mut alg_seq, &alg_inner);
        // Borrow ciphertext bytes from the valid blob's tail.
        // Simplest: parse the valid blob to recover ciphertext slice.
        let parsed = parse_encrypted_blob(&blob).expect("baseline parse");
        let mut body = Vec::new();
        body.extend_from_slice(&alg_seq);
        writer::write_octet_string(&mut body, parsed.ciphertext);
        let mut bad_blob = Vec::new();
        writer::write_sequence(&mut bad_blob, &body);
        assert!(matches!(decrypt(&bad_blob, b"pw"), Err(Error::Failed)));
    }
}
