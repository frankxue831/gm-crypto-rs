//! X.509 `SubjectPublicKeyInfo` codec (RFC 5280 §4.1.2.7) for SM2 keys.
//!
//! Wire shape:
//!
//! ```text
//! SubjectPublicKeyInfo ::= SEQUENCE {
//!     algorithm        AlgorithmIdentifier,
//!     subjectPublicKey BIT STRING
//! }
//!
//! AlgorithmIdentifier ::= SEQUENCE {
//!     algorithm   OBJECT IDENTIFIER,
//!     parameters  ANY DEFINED BY algorithm OPTIONAL
//! }
//! ```
//!
//! For SM2 the algorithm OID is `id-ecPublicKey`
//! (`1.2.840.10045.2.1`) and `parameters` carries the
//! `namedCurve` OID `sm2p256v1` (`1.2.156.10197.1.301`).
//! `subjectPublicKey` is a BIT STRING wrapping the SEC1
//! uncompressed point `04 || X || Y`.
//!
//! # Failure-mode invariant
//!
//! Decoders return `Option`; no distinguishing variants per
//! `CLAUDE.md`.

use crate::asn1::oid::{ID_EC_PUBLIC_KEY, SM2P256V1};
use crate::asn1::{reader, writer};
use crate::sec1::{SEC1_UNCOMPRESSED_LEN, decode_uncompressed_point, encode_uncompressed_point};
use alloc::vec::Vec;

/// Encode an SM2 public key as a DER `SubjectPublicKeyInfo` blob.
///
/// Caller pre-validates that the key's point is on-curve and not at
/// infinity. (The standard accessor
/// [`crate::sm2::Sm2PublicKey::to_sec1_uncompressed`] feeds this
/// helper after extracting the affine `(x, y)`.)
///
/// # Panics
///
/// Panics if the underlying point is at infinity (callers must reject the
/// identity point at the boundary).
#[must_use]
#[allow(clippy::missing_panics_doc)]
pub fn encode(key: &crate::sm2::Sm2PublicKey) -> Vec<u8> {
    let (x, y) = key.point().to_affine().expect("SPKI: point at infinity");
    let pk = encode_uncompressed_point(&x, &y);
    encode_uncompressed(&pk)
}

/// Encode the pre-formatted SEC1 uncompressed `04 || X || Y` bytes
/// directly into a `SubjectPublicKeyInfo` blob. Avoids the affine
/// extraction when the caller already has the bytes.
#[must_use]
pub fn encode_uncompressed(uncompressed: &[u8; SEC1_UNCOMPRESSED_LEN]) -> Vec<u8> {
    // AlgorithmIdentifier { algorithm = id-ecPublicKey, parameters = sm2p256v1 OID }
    let mut alg_inner = Vec::with_capacity(ID_EC_PUBLIC_KEY.len() + SM2P256V1.len() + 4);
    writer::write_oid(&mut alg_inner, ID_EC_PUBLIC_KEY);
    writer::write_oid(&mut alg_inner, SM2P256V1);

    let mut alg_seq = Vec::with_capacity(alg_inner.len() + 4);
    writer::write_sequence(&mut alg_seq, &alg_inner);

    // subjectPublicKey BIT STRING { uncompressed }
    let mut bitstr = Vec::with_capacity(uncompressed.len() + 4);
    writer::write_bit_string(&mut bitstr, 0, uncompressed);

    let mut body = Vec::with_capacity(alg_seq.len() + bitstr.len());
    body.extend_from_slice(&alg_seq);
    body.extend_from_slice(&bitstr);

    let mut out = Vec::with_capacity(body.len() + 4);
    writer::write_sequence(&mut out, &body);
    out
}

/// Decode a DER `SubjectPublicKeyInfo` blob into a validated
/// [`crate::sm2::Sm2PublicKey`].
///
/// Validates:
///
/// - outer SEQUENCE with no trailing bytes;
/// - `algorithm == id-ecPublicKey` and `parameters == sm2p256v1`;
/// - `subjectPublicKey` BIT STRING with `unused_bits == 0` wrapping
///   exactly 65 bytes;
/// - the wrapped 65 bytes decode as an on-curve, non-identity SEC1
///   uncompressed point.
///
/// Returns `None` for any malformed input.
#[must_use]
pub fn decode(input: &[u8]) -> Option<crate::sm2::Sm2PublicKey> {
    let (body, rest) = reader::read_sequence(input)?;
    if !rest.is_empty() {
        return None;
    }

    // AlgorithmIdentifier SEQUENCE
    let (alg_inner, body) = reader::read_sequence(body)?;
    let (alg_oid, alg_inner) = reader::read_oid(alg_inner)?;
    if alg_oid != ID_EC_PUBLIC_KEY {
        return None;
    }
    // parameters = namedCurve OID = sm2p256v1
    let (curve_oid, alg_inner) = reader::read_oid(alg_inner)?;
    if curve_oid != SM2P256V1 || !alg_inner.is_empty() {
        return None;
    }

    // subjectPublicKey BIT STRING
    let (unused, pk_bytes, body) = reader::read_bit_string(body)?;
    if unused != 0 || !body.is_empty() {
        return None;
    }
    Some(crate::sm2::Sm2PublicKey::from_point(
        decode_uncompressed_point(pk_bytes)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::point::ProjectivePoint;

    /// SPKI round-trip for the SM2 generator.
    #[test]
    fn round_trip_generator() {
        let g = ProjectivePoint::generator();
        let der = encode(&crate::sm2::Sm2PublicKey::from_point(g));
        let recovered = decode(&der).expect("decode");
        let (gx, gy) = g.to_affine().expect("G finite");
        let (rx, ry) = recovered.point().to_affine().expect("recovered finite");
        assert_eq!(rx.retrieve(), gx.retrieve());
        assert_eq!(ry.retrieve(), gy.retrieve());
    }

    /// Encoded SPKI starts with the expected SEQUENCE tag and has
    /// the right length.
    #[test]
    fn encoded_form_shape() {
        let g = ProjectivePoint::generator();
        let der = encode(&crate::sm2::Sm2PublicKey::from_point(g));
        assert_eq!(der[0], 0x30, "outer tag must be SEQUENCE");
        // SubjectPublicKeyInfo for SM2 is always 91 bytes: 2-byte SEQUENCE
        // header + 18-byte AlgorithmIdentifier + 71-byte BIT STRING wrapping 65-byte key
        // = 2 + 16 + 73 = 91 bytes.
        assert_eq!(der.len(), 91, "SM2 SPKI is 91 bytes");
    }

    #[test]
    fn rejects_wrong_algorithm_oid() {
        // AlgorithmIdentifier with id-rsaEncryption (1.2.840.113549.1.1.1):
        // 2A 86 48 86 F7 0D 01 01 01.
        let mut alg_inner = Vec::new();
        writer::write_oid(
            &mut alg_inner,
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01],
        );
        writer::write_null(&mut alg_inner);
        let mut alg_seq = Vec::new();
        writer::write_sequence(&mut alg_seq, &alg_inner);
        let mut bitstr = Vec::new();
        writer::write_bit_string(&mut bitstr, 0, &[0u8; 65]);
        let mut body = Vec::new();
        body.extend_from_slice(&alg_seq);
        body.extend_from_slice(&bitstr);
        let mut der = Vec::new();
        writer::write_sequence(&mut der, &body);
        assert!(decode(&der).is_none());
    }

    #[test]
    fn rejects_wrong_curve_oid() {
        // P-256 OID 1.2.840.10045.3.1.7 — same algorithm but wrong curve.
        let mut alg_inner = Vec::new();
        writer::write_oid(&mut alg_inner, ID_EC_PUBLIC_KEY);
        writer::write_oid(
            &mut alg_inner,
            &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
        );
        let mut alg_seq = Vec::new();
        writer::write_sequence(&mut alg_seq, &alg_inner);
        let mut bitstr = Vec::new();
        writer::write_bit_string(&mut bitstr, 0, &[0u8; 65]);
        let mut body = Vec::new();
        body.extend_from_slice(&alg_seq);
        body.extend_from_slice(&bitstr);
        let mut der = Vec::new();
        writer::write_sequence(&mut der, &body);
        assert!(decode(&der).is_none());
    }

    #[test]
    fn rejects_off_curve_point() {
        let mut alg_inner = Vec::new();
        writer::write_oid(&mut alg_inner, ID_EC_PUBLIC_KEY);
        writer::write_oid(&mut alg_inner, SM2P256V1);
        let mut alg_seq = Vec::new();
        writer::write_sequence(&mut alg_seq, &alg_inner);
        let mut pt = [0u8; 65];
        pt[0] = 0x04;
        pt[1] = 1;
        pt[33] = 1; // (1, 1) — off the curve.
        let mut bitstr = Vec::new();
        writer::write_bit_string(&mut bitstr, 0, &pt);
        let mut body = Vec::new();
        body.extend_from_slice(&alg_seq);
        body.extend_from_slice(&bitstr);
        let mut der = Vec::new();
        writer::write_sequence(&mut der, &body);
        assert!(decode(&der).is_none());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let g = ProjectivePoint::generator();
        let mut der = encode(&crate::sm2::Sm2PublicKey::from_point(g));
        der.push(0x00);
        assert!(decode(&der).is_none());
    }
}
