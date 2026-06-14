//! Compile-time DER-encoded ASN.1 OBJECT IDENTIFIER constants.
//!
//! Each constant exposes the **sub-identifier bytes** (per X.690
//! §8.19), without the outer `06 LEN` TLV framing. Use
//! [`super::writer::write_oid`] to wrap with framing, or compare
//! directly against the bytes returned by [`super::reader::read_oid`].
//!
//! Encoding is computed at compile time via [`encoded_len`] +
//! [`encode`] — `const fn` with `while` loops, no `unsafe`, no
//! proc macros, no build script (matches the `sm4::cipher::CK`
//! pattern). MSRV 1.85 + edition 2024 supports this.
//!
//! All seven OIDs cross-validated against the DER bytes published
//! in their authoritative specs (RFC 5912 §6 for PKCS-related,
//! RFC 5480 §2 for `id-ecPublicKey`, GM/T 0006-2012 §3 and
//! GM/T 0010-2012 §6 for the SM-flavored `1.2.156.10197.…` arcs).

/// Compute the encoded length of an OID's sub-identifier bytes.
///
/// No outer `06 LEN` framing. The first two arcs combine into a
/// single byte (`40·a + b`); each subsequent arc is encoded in
/// base-128 with the high bit of each non-final byte set.
///
/// # Panics
/// At const-eval if `arcs.len() < 2`, `arcs[0] > 2`, or
/// `arcs[0] < 2 && arcs[1] >= 40`.
pub const fn encoded_len(arcs: &[u32]) -> usize {
    assert!(arcs.len() >= 2, "OID must have at least 2 arcs");
    assert!(arcs[0] <= 2, "OID first arc must be 0, 1, or 2");
    if arcs[0] < 2 {
        assert!(
            arcs[1] < 40,
            "OID second arc must be < 40 when first arc < 2"
        );
    }
    let mut len = 1; // first byte = 40*arcs[0] + arcs[1]
    let mut i = 2;
    while i < arcs.len() {
        let mut bytes = 1u32;
        let mut x = arcs[i] >> 7;
        while x > 0 {
            bytes += 1;
            x >>= 7;
        }
        len += bytes as usize;
        i += 1;
    }
    len
}

/// Encode dotted-decimal `arcs` into the DER OBJECT IDENTIFIER
/// sub-identifier bytes. Output length is `LEN`; callers compute
/// `LEN` via [`encoded_len`] and pass it as the const-generic
/// argument.
///
/// # Panics (at const-eval)
/// Panics if `LEN != encoded_len(arcs)` (out-of-bounds writes).
#[allow(clippy::cast_possible_truncation)]
pub const fn encode<const LEN: usize>(arcs: &[u32]) -> [u8; LEN] {
    let mut out = [0u8; LEN];
    out[0] = (40 * arcs[0] + arcs[1]) as u8;
    let mut pos = 1usize;
    let mut i = 2;
    while i < arcs.len() {
        let arc = arcs[i];
        // Count bytes needed.
        let mut bytes_needed = 1u32;
        let mut tmp = arc >> 7;
        while tmp > 0 {
            bytes_needed += 1;
            tmp >>= 7;
        }
        // Emit big-endian with continuation bits on all but the last byte.
        let mut j = bytes_needed;
        while j > 0 {
            j -= 1;
            let shift = j * 7;
            let chunk = ((arc >> shift) & 0x7F) as u8;
            let cont = if j == 0 { 0u8 } else { 0x80u8 };
            out[pos] = chunk | cont;
            pos += 1;
        }
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------
// Per-OID const wiring. Each OID gets:
//   const ARCS_X: &[u32] = &[…];
//   const LEN_X: usize = encoded_len(ARCS_X);
//   const ENCODED_X: [u8; LEN_X] = encode::<LEN_X>(ARCS_X);
//   pub const X: &[u8] = &ENCODED_X;
// ---------------------------------------------------------------------

/// `id-ecPublicKey`: 1.2.840.10045.2.1 — SPKI algorithm OID for ECDSA-
/// shaped keys. RFC 5480 §2.1.1.
const ARCS_ID_EC_PUBLIC_KEY: &[u32] = &[1, 2, 840, 10045, 2, 1];
const LEN_ID_EC_PUBLIC_KEY: usize = encoded_len(ARCS_ID_EC_PUBLIC_KEY);
const ENCODED_ID_EC_PUBLIC_KEY: [u8; LEN_ID_EC_PUBLIC_KEY] =
    encode::<LEN_ID_EC_PUBLIC_KEY>(ARCS_ID_EC_PUBLIC_KEY);
/// `id-ecPublicKey` sub-identifier bytes.
pub const ID_EC_PUBLIC_KEY: &[u8] = &ENCODED_ID_EC_PUBLIC_KEY;

/// `sm2p256v1`: 1.2.156.10197.1.301 — SPKI namedCurve parameter for
/// the SM2 256-bit prime curve. GM/T 0006-2012.
const ARCS_SM2P256V1: &[u32] = &[1, 2, 156, 10197, 1, 301];
const LEN_SM2P256V1: usize = encoded_len(ARCS_SM2P256V1);
const ENCODED_SM2P256V1: [u8; LEN_SM2P256V1] = encode::<LEN_SM2P256V1>(ARCS_SM2P256V1);
/// `sm2p256v1` sub-identifier bytes.
pub const SM2P256V1: &[u8] = &ENCODED_SM2P256V1;

/// `sm2-sign-with-sm3`: 1.2.156.10197.1.501.
///
/// `SignatureAlgorithm` OID for SM2 signing with SM3 digest.
/// Reserved for future use; not used internally in v0.3, but
/// encoded so W2 callers can refer to it. GM/T 0006-2012.
const ARCS_SM2_SIGN_WITH_SM3: &[u32] = &[1, 2, 156, 10197, 1, 501];
const LEN_SM2_SIGN_WITH_SM3: usize = encoded_len(ARCS_SM2_SIGN_WITH_SM3);
const ENCODED_SM2_SIGN_WITH_SM3: [u8; LEN_SM2_SIGN_WITH_SM3] =
    encode::<LEN_SM2_SIGN_WITH_SM3>(ARCS_SM2_SIGN_WITH_SM3);
/// `sm2-sign-with-sm3` sub-identifier bytes.
pub const SM2_SIGN_WITH_SM3: &[u8] = &ENCODED_SM2_SIGN_WITH_SM3;

/// `id-PBKDF2`: 1.2.840.113549.1.5.12 — PKCS#5 PBES2 KDF function.
/// RFC 8018 §A.2.
const ARCS_ID_PBKDF2: &[u32] = &[1, 2, 840, 113_549, 1, 5, 12];
const LEN_ID_PBKDF2: usize = encoded_len(ARCS_ID_PBKDF2);
const ENCODED_ID_PBKDF2: [u8; LEN_ID_PBKDF2] = encode::<LEN_ID_PBKDF2>(ARCS_ID_PBKDF2);
/// `id-PBKDF2` sub-identifier bytes.
pub const ID_PBKDF2: &[u8] = &ENCODED_ID_PBKDF2;

/// `pbes2`: 1.2.840.113549.1.5.13 — PKCS#5 PBES2 outer encryption
/// scheme OID. RFC 8018 §A.4.
const ARCS_PBES2: &[u32] = &[1, 2, 840, 113_549, 1, 5, 13];
const LEN_PBES2: usize = encoded_len(ARCS_PBES2);
const ENCODED_PBES2: [u8; LEN_PBES2] = encode::<LEN_PBES2>(ARCS_PBES2);
/// `pbes2` sub-identifier bytes.
pub const PBES2: &[u8] = &ENCODED_PBES2;

/// `id-hmacWithSM3`: 1.2.156.10197.1.401.2 — HMAC-SM3 OID, used as
/// the PBKDF2 PRF identifier in PBES2 wrappings. GM/T 0006-2012.
const ARCS_ID_HMAC_WITH_SM3: &[u32] = &[1, 2, 156, 10197, 1, 401, 2];
const LEN_ID_HMAC_WITH_SM3: usize = encoded_len(ARCS_ID_HMAC_WITH_SM3);
const ENCODED_ID_HMAC_WITH_SM3: [u8; LEN_ID_HMAC_WITH_SM3] =
    encode::<LEN_ID_HMAC_WITH_SM3>(ARCS_ID_HMAC_WITH_SM3);
/// `id-hmacWithSM3` sub-identifier bytes.
pub const ID_HMAC_WITH_SM3: &[u8] = &ENCODED_ID_HMAC_WITH_SM3;

/// `sm4-cbc`: 1.2.156.10197.1.104.2.
///
/// `SM4-CBC` `EncryptionScheme` OID for PBES2 `EncryptionScheme`.
/// GM/T 0006-2012.
const ARCS_SM4_CBC: &[u32] = &[1, 2, 156, 10197, 1, 104, 2];
const LEN_SM4_CBC: usize = encoded_len(ARCS_SM4_CBC);
const ENCODED_SM4_CBC: [u8; LEN_SM4_CBC] = encode::<LEN_SM4_CBC>(ARCS_SM4_CBC);
/// `sm4-cbc` sub-identifier bytes.
pub const SM4_CBC: &[u8] = &ENCODED_SM4_CBC;

/// `id-ce-keyUsage`: 2.5.29.15 (RFC 5280 §4.2.1.3). Used by the v1.8 X.509
/// chain-verification keyUsage reader.
const ARCS_KEY_USAGE: &[u32] = &[2, 5, 29, 15];
const LEN_KEY_USAGE: usize = encoded_len(ARCS_KEY_USAGE);
const ENCODED_KEY_USAGE: [u8; LEN_KEY_USAGE] = encode::<LEN_KEY_USAGE>(ARCS_KEY_USAGE);
/// `keyUsage` sub-identifier bytes.
pub const KEY_USAGE: &[u8] = &ENCODED_KEY_USAGE;

/// `id-ce-basicConstraints`: 2.5.29.19 (RFC 5280 §4.2.1.9). Used by the v1.8
/// X.509 chain-verification basicConstraints reader.
const ARCS_BASIC_CONSTRAINTS: &[u32] = &[2, 5, 29, 19];
const LEN_BASIC_CONSTRAINTS: usize = encoded_len(ARCS_BASIC_CONSTRAINTS);
const ENCODED_BASIC_CONSTRAINTS: [u8; LEN_BASIC_CONSTRAINTS] =
    encode::<LEN_BASIC_CONSTRAINTS>(ARCS_BASIC_CONSTRAINTS);
/// `basicConstraints` sub-identifier bytes.
pub const BASIC_CONSTRAINTS: &[u8] = &ENCODED_BASIC_CONSTRAINTS;

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode at runtime via a non-const reference implementation,
    /// then compare against the const-evaluated bytes. This protects
    /// us from a subtle const-fn bug going undetected if the const
    /// values themselves were ever wrong.
    fn runtime_encode(arcs: &[u32]) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::new();
        #[allow(clippy::cast_possible_truncation)]
        out.push((40 * arcs[0] + arcs[1]) as u8);
        for &arc in &arcs[2..] {
            let mut bytes_needed = 1u32;
            let mut tmp = arc >> 7;
            while tmp > 0 {
                bytes_needed += 1;
                tmp >>= 7;
            }
            for j in (0..bytes_needed).rev() {
                let shift = j * 7;
                #[allow(clippy::cast_possible_truncation)]
                let chunk = ((arc >> shift) & 0x7F) as u8;
                let cont = if j == 0 { 0u8 } else { 0x80u8 };
                out.push(chunk | cont);
            }
        }
        out
    }

    #[test]
    fn const_matches_runtime_id_ec_public_key() {
        assert_eq!(
            ID_EC_PUBLIC_KEY,
            runtime_encode(ARCS_ID_EC_PUBLIC_KEY).as_slice()
        );
    }

    #[test]
    fn const_matches_runtime_sm2p256v1() {
        assert_eq!(SM2P256V1, runtime_encode(ARCS_SM2P256V1).as_slice());
    }

    #[test]
    fn const_matches_runtime_sm2_sign_with_sm3() {
        assert_eq!(
            SM2_SIGN_WITH_SM3,
            runtime_encode(ARCS_SM2_SIGN_WITH_SM3).as_slice()
        );
    }

    #[test]
    fn const_matches_runtime_id_pbkdf2() {
        assert_eq!(ID_PBKDF2, runtime_encode(ARCS_ID_PBKDF2).as_slice());
    }

    #[test]
    fn const_matches_runtime_pbes2() {
        assert_eq!(PBES2, runtime_encode(ARCS_PBES2).as_slice());
    }

    #[test]
    fn const_matches_runtime_id_hmac_with_sm3() {
        assert_eq!(
            ID_HMAC_WITH_SM3,
            runtime_encode(ARCS_ID_HMAC_WITH_SM3).as_slice()
        );
    }

    #[test]
    fn const_matches_runtime_sm4_cbc() {
        assert_eq!(SM4_CBC, runtime_encode(ARCS_SM4_CBC).as_slice());
    }

    /// Spot-check against published bytes for `id-PBKDF2`
    /// (RFC 5912 §6 and RFC 8018 Appendix A.2 reference).
    #[test]
    fn id_pbkdf2_matches_published_bytes() {
        // 1.2.840.113549.1.5.12 → 2A 86 48 86 F7 0D 01 05 0C
        assert_eq!(
            ID_PBKDF2,
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C]
        );
    }

    /// Spot-check against published bytes for `id-ecPublicKey`
    /// (RFC 5480 §2.1.1).
    #[test]
    fn id_ec_public_key_matches_published_bytes() {
        // 1.2.840.10045.2.1 → 2A 86 48 CE 3D 02 01
        assert_eq!(
            ID_EC_PUBLIC_KEY,
            &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
        );
    }

    /// Spot-check `sm2p256v1` (1.2.156.10197.1.301) against a
    /// hand-computed encoding.
    #[test]
    fn sm2p256v1_matches_published_bytes() {
        // 1.2 → 0x2A
        // 156 → 0x81 0x1C
        // 10197 → 0xCF 0x55
        // 1 → 0x01
        // 301 → 0x82 0x2D
        assert_eq!(SM2P256V1, &[0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D]);
    }

    /// All seven OIDs round-trip through the writer + reader.
    #[test]
    fn all_oids_round_trip_through_writer_reader() {
        use crate::asn1::{reader, writer};
        let oids: &[&[u8]] = &[
            ID_EC_PUBLIC_KEY,
            SM2P256V1,
            SM2_SIGN_WITH_SM3,
            ID_PBKDF2,
            PBES2,
            ID_HMAC_WITH_SM3,
            SM4_CBC,
        ];
        for oid in oids {
            let mut buf = alloc::vec::Vec::new();
            writer::write_oid(&mut buf, oid);
            let (parsed, rest) = reader::read_oid(&buf).unwrap();
            assert_eq!(parsed, *oid);
            assert!(rest.is_empty());
        }
    }
}
