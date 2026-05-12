//! SEC1 `ECPrivateKey` codec (RFC 5915) for SM2 keys.
//!
//! Wire shape (RFC 5915 §3):
//!
//! ```text
//! ECPrivateKey ::= SEQUENCE {
//!     version        INTEGER { ecPrivkeyVer1(1) },
//!     privateKey     OCTET STRING,
//!     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
//!     publicKey  [1] BIT STRING OPTIONAL
//! }
//! ```
//!
//! `parameters` is a CHOICE; this module emits and accepts the
//! `namedCurve` arm only, with the `sm2p256v1` OID
//! (`1.2.156.10197.1.301`). `privateKey` carries the 32-byte
//! big-endian scalar `d`. `publicKey`, when present, carries the
//! 65-byte uncompressed point `04 || X || Y`.
//!
//! # SEC1 point encoding
//!
//! [`encode_uncompressed_point`] / [`decode_uncompressed_point`]
//! handle the 65-byte `04 || X || Y` form (SEC1 §2.3.3). The
//! decoder rejects the identity point `00`, the compressed
//! forms `02`/`03 || X` (deferred to v0.4), and any off-curve
//! `(X, Y)`.
//!
//! # Failure-mode invariant
//!
//! Decoders return `Option`; no distinguishing variants. The
//! free-form encoder helpers panic only on programmer error
//! (32-byte slices guaranteed by callers).

use crate::asn1::oid::SM2P256V1;
use crate::asn1::{reader, writer};
use crate::sm2::curve::{Fn, Fp};
use crate::sm2::encrypt::{point_on_curve, projective_from_affine};
use crate::sm2::point::ProjectivePoint;
use alloc::vec::Vec;
use crypto_bigint::U256;
use subtle::ConstantTimeLess;
use zeroize::Zeroize;

/// SEC1 uncompressed-point tag byte (`04 || X || Y`).
pub(crate) const SEC1_TAG_UNCOMPRESSED: u8 = 0x04;
/// SEC1 uncompressed-point total byte length (`1 + 32 + 32`).
pub(crate) const SEC1_UNCOMPRESSED_LEN: usize = 65;
/// RFC 5915 `ECPrivateKey` version number (always `ecPrivkeyVer1 = 1`).
const ECPRIVKEY_VER1: u8 = 1;

/// Encode `(x, y)` field elements as a 65-byte SEC1 uncompressed point.
///
/// Output is `04 || X(32 bytes BE) || Y(32 bytes BE)`. Caller
/// pre-validates that the point is on-curve and not at infinity.
#[must_use]
pub(crate) fn encode_uncompressed_point(x: &Fp, y: &Fp) -> [u8; SEC1_UNCOMPRESSED_LEN] {
    let mut out = [0u8; SEC1_UNCOMPRESSED_LEN];
    out[0] = SEC1_TAG_UNCOMPRESSED;
    out[1..33].copy_from_slice(&x.retrieve().to_be_bytes());
    out[33..65].copy_from_slice(&y.retrieve().to_be_bytes());
    out
}

/// Decode a 65-byte SEC1 uncompressed point into a validated
/// [`ProjectivePoint`]. Returns `None` for any malformed input,
/// including:
///
/// - wrong length (not 65 bytes);
/// - leading byte not `0x04`;
/// - identity point (a single `0x00`);
/// - `X >= p` or `Y >= p` (field-element bounds);
/// - `(X, Y)` not on the SM2 curve.
///
/// Compressed forms (`0x02` / `0x03`) are rejected — decompression
/// requires a modular square root that v0.3 does not implement.
#[must_use]
pub(crate) fn decode_uncompressed_point(input: &[u8]) -> Option<ProjectivePoint> {
    if input.len() != SEC1_UNCOMPRESSED_LEN {
        return None;
    }
    if input[0] != SEC1_TAG_UNCOMPRESSED {
        return None;
    }
    let x_be = &input[1..33];
    let y_be = &input[33..65];
    let x_u = U256::from_be_slice(x_be);
    let y_u = U256::from_be_slice(y_be);
    let p = *Fp::MODULUS.as_ref();
    if !bool::from(x_u.ct_lt(&p)) || !bool::from(y_u.ct_lt(&p)) {
        return None;
    }
    let x = Fp::new(&x_u);
    let y = Fp::new(&y_u);
    if !point_on_curve(&x, &y) {
        return None;
    }
    Some(projective_from_affine(x, y))
}

/// Encode an SM2 `ECPrivateKey` (RFC 5915) into DER bytes.
///
/// `scalar_be` is the 32-byte big-endian private scalar. The
/// `parameters` field is emitted with `namedCurve = sm2p256v1`;
/// the optional `publicKey` BIT STRING is emitted as the
/// 65-byte uncompressed point when `Some`.
///
/// The intermediate body buffer is zeroized before return — the
/// caller-supplied `scalar_be` slice is **not** zeroized (caller
/// owns it).
#[must_use]
pub fn encode(
    scalar_be: &[u8; 32],
    public_uncompressed: Option<&[u8; SEC1_UNCOMPRESSED_LEN]>,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(120);
    // version INTEGER 1
    writer::write_integer(&mut body, &[ECPRIVKEY_VER1]);
    // privateKey OCTET STRING (raw 32-byte scalar; SEC1 OCTET STRING
    // is unsigned, no DER INTEGER discipline).
    writer::write_octet_string(&mut body, scalar_be);
    // [0] EXPLICIT ECParameters: namedCurve OID = sm2p256v1.
    let mut params_inner = Vec::with_capacity(SM2P256V1.len() + 2);
    writer::write_oid(&mut params_inner, SM2P256V1);
    writer::write_context_tagged_explicit(&mut body, 0, &params_inner);
    // [1] EXPLICIT BIT STRING { uncompressed point } if present.
    if let Some(pk) = public_uncompressed {
        let mut pk_inner = Vec::with_capacity(SEC1_UNCOMPRESSED_LEN + 4);
        writer::write_bit_string(&mut pk_inner, 0, pk);
        writer::write_context_tagged_explicit(&mut body, 1, &pk_inner);
    }
    let mut out = Vec::with_capacity(body.len() + 4);
    writer::write_sequence(&mut out, &body);
    body.zeroize();
    out
}

/// Decoded SEC1 `ECPrivateKey` contents.
///
/// Returned by [`decode`]; consumers translate the validated scalar
/// into an [`crate::sm2::Sm2PrivateKey`] via the constructor on that
/// type. Holds public bytes only — no Mont-form scalars.
#[derive(Debug, Clone)]
pub struct EcPrivateKey {
    /// 32-byte big-endian scalar `d`. Not validated against the
    /// curve order here — the caller must reject `d == 0` and
    /// `d == n-1` via [`crate::sm2::Sm2PrivateKey::from_bytes_be`].
    pub scalar_be: [u8; 32],
    /// Decoded uncompressed public point, if the optional
    /// `publicKey` field was present and well-formed.
    pub public: Option<ProjectivePoint>,
}

impl Drop for EcPrivateKey {
    fn drop(&mut self) {
        self.scalar_be.zeroize();
    }
}

/// Decode a DER `ECPrivateKey` blob.
///
/// Validates:
///
/// - outer SEQUENCE with no trailing bytes;
/// - `version == 1`;
/// - `privateKey` is a 32-byte OCTET STRING (SM2's curve has 256-bit
///   scalars; oversize/undersize is malformed);
/// - if present, `[0] parameters` is `namedCurve = sm2p256v1` only;
/// - if present, `[1] publicKey` is a 65-byte uncompressed point
///   that decodes successfully (on-curve, not identity).
///
/// Returns `None` for any malformed input.
#[must_use]
pub fn decode(input: &[u8]) -> Option<EcPrivateKey> {
    let (body, rest) = reader::read_sequence(input)?;
    if !rest.is_empty() {
        return None;
    }

    // version INTEGER 1.
    let (version, body) = reader::read_integer(body)?;
    if version != [ECPRIVKEY_VER1] {
        return None;
    }
    // privateKey OCTET STRING — exactly 32 bytes for SM2.
    let (scalar_bytes, mut body) = reader::read_octet_string(body)?;
    if scalar_bytes.len() != 32 {
        return None;
    }
    let mut scalar_be = [0u8; 32];
    scalar_be.copy_from_slice(scalar_bytes);

    let mut public: Option<ProjectivePoint> = None;

    // [0] EXPLICIT parameters (OPTIONAL).
    if let Some((params_inner, after)) = reader::read_context_tagged_explicit(body, 0) {
        let (oid, params_rest) = reader::read_oid(params_inner)?;
        if !params_rest.is_empty() || oid != SM2P256V1 {
            scalar_be.zeroize();
            return None;
        }
        body = after;
    }

    // [1] EXPLICIT publicKey BIT STRING (OPTIONAL).
    if let Some((pk_inner, after)) = reader::read_context_tagged_explicit(body, 1) {
        let (unused, pk_bytes, pk_rest) = reader::read_bit_string(pk_inner)?;
        if unused != 0 || !pk_rest.is_empty() {
            scalar_be.zeroize();
            return None;
        }
        if let Some(p) = decode_uncompressed_point(pk_bytes) {
            public = Some(p);
        } else {
            scalar_be.zeroize();
            return None;
        }
        body = after;
    }

    if !body.is_empty() {
        scalar_be.zeroize();
        return None;
    }

    Some(EcPrivateKey { scalar_be, public })
}

/// Bound the scalar `d` to `[1, n-1]` in the SEC1 sense — i.e. it
/// must be a representative of a non-zero scalar field element.
/// Returns the validated scalar in Mont form. **Caller is
/// responsible for the tighter `[1, n-2]` range required by
/// SM2 sign/encrypt — that lives in `Sm2PrivateKey::from_bytes_be`.**
#[must_use]
#[allow(dead_code)]
pub(crate) fn validate_scalar(scalar_be: &[u8; 32]) -> Option<Fn> {
    let d = U256::from_be_slice(scalar_be);
    let n = *Fn::MODULUS.as_ref();
    if d == U256::ZERO {
        return None;
    }
    if !bool::from(d.ct_lt(&n)) {
        return None;
    }
    Some(Fn::new(&d))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::point::ProjectivePoint;

    /// SEC1 uncompressed encoding of the SM2 generator round-trips.
    #[test]
    fn uncompressed_point_round_trip_generator() {
        let g = ProjectivePoint::generator();
        let (x, y) = g.to_affine().expect("G finite");
        let bytes = encode_uncompressed_point(&x, &y);
        assert_eq!(bytes[0], 0x04);
        let recovered = decode_uncompressed_point(&bytes).expect("decode");
        let (rx, ry) = recovered.to_affine().expect("recovered finite");
        assert_eq!(rx.retrieve(), x.retrieve());
        assert_eq!(ry.retrieve(), y.retrieve());
    }

    #[test]
    fn uncompressed_point_rejects_wrong_length() {
        assert!(decode_uncompressed_point(&[0x04]).is_none());
        assert!(decode_uncompressed_point(&[0x04; 64]).is_none());
        assert!(decode_uncompressed_point(&[0x04; 66]).is_none());
    }

    #[test]
    fn uncompressed_point_rejects_compressed_tag() {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x02;
        assert!(decode_uncompressed_point(&bytes).is_none());
        bytes[0] = 0x03;
        assert!(decode_uncompressed_point(&bytes).is_none());
    }

    #[test]
    fn uncompressed_point_rejects_off_curve() {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x04;
        bytes[1] = 1;
        bytes[33] = 1;
        // (1, 1) is not on the SM2 curve.
        assert!(decode_uncompressed_point(&bytes).is_none());
    }

    #[test]
    fn uncompressed_point_rejects_x_at_or_above_p() {
        let g = ProjectivePoint::generator();
        let (_x, y) = g.to_affine().expect("G finite");
        let p = *Fp::MODULUS.as_ref();
        let mut bytes = [0u8; SEC1_UNCOMPRESSED_LEN];
        bytes[0] = 0x04;
        // X = p (the modulus, not a valid field element).
        bytes[1..33].copy_from_slice(&p.to_be_bytes());
        bytes[33..65].copy_from_slice(&y.retrieve().to_be_bytes());
        assert!(
            decode_uncompressed_point(&bytes).is_none(),
            "X = p must be rejected"
        );
    }

    /// `ECPrivateKey` round-trip with public-key field present.
    #[test]
    fn ecprivatekey_round_trip_with_public() {
        let scalar_be: [u8; 32] = [
            0x39, 0x45, 0x20, 0x8F, 0x7B, 0x21, 0x44, 0xB1, 0x3F, 0x36, 0xE3, 0x8A, 0xC6, 0xD3,
            0x9F, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xB5, 0x1A, 0x42, 0xFB, 0x81, 0xEF,
            0x4D, 0xF7, 0xC5, 0xB8,
        ];
        // Use the GB/T 32918.2 sample — its public point is on-curve.
        let d = U256::from_be_slice(&scalar_be);
        let key = crate::sm2::Sm2PrivateKey::from_scalar_inner(d).expect("valid d");
        let (x, y) = key.public_key().to_affine().expect("finite");
        let pk = encode_uncompressed_point(&x, &y);
        let der = encode(&scalar_be, Some(&pk));

        let recovered = decode(&der).expect("decode");
        assert_eq!(recovered.scalar_be, scalar_be);
        assert!(recovered.public.is_some());
        let (rx, ry) = recovered.public.unwrap().to_affine().expect("finite");
        assert_eq!(rx.retrieve(), x.retrieve());
        assert_eq!(ry.retrieve(), y.retrieve());
    }

    /// `ECPrivateKey` round-trip without optional fields.
    #[test]
    fn ecprivatekey_round_trip_minimal() {
        let scalar_be: [u8; 32] = [0x42; 32];
        let der = encode(&scalar_be, None);
        let recovered = decode(&der).expect("decode");
        assert_eq!(recovered.scalar_be, scalar_be);
        assert!(recovered.public.is_none());
    }

    /// Round-trip with parameters present (sm2p256v1) and public absent.
    #[test]
    fn ecprivatekey_round_trip_params_only() {
        let scalar_be: [u8; 32] = [0x11; 32];
        let der = encode(&scalar_be, None);
        // The encoder always writes parameters. Decode and re-encode.
        let recovered = decode(&der).expect("decode");
        let der2 = encode(
            &recovered.scalar_be,
            recovered
                .public
                .as_ref()
                .map(|p| {
                    let (x, y) = p.to_affine().expect("finite");
                    encode_uncompressed_point(&x, &y)
                })
                .as_ref(),
        );
        assert_eq!(der, der2);
    }

    #[test]
    fn ecprivatekey_rejects_wrong_version() {
        let bad = [
            0x30, 0x05, // SEQ len=5
            0x02, 0x01, 0x02, // INTEGER 2 (wrong version)
            0x04, 0x00, // OCTET STRING empty
        ];
        assert!(decode(&bad).is_none());
    }

    #[test]
    fn ecprivatekey_rejects_short_scalar() {
        let bad = [
            0x30, 0x06, // SEQ
            0x02, 0x01, 0x01, // INTEGER 1
            0x04, 0x01, 0xAB, // OCTET STRING 1 byte (wrong length)
        ];
        assert!(decode(&bad).is_none());
    }

    #[test]
    fn ecprivatekey_rejects_wrong_curve_oid() {
        // Build a SEC1 ECPrivateKey with a fake namedCurve (P-256 OID).
        let mut body = Vec::new();
        writer::write_integer(&mut body, &[1]);
        let scalar = [0u8; 32];
        writer::write_octet_string(&mut body, &scalar);
        // P-256 OID 1.2.840.10045.3.1.7 → DER content bytes
        // 2A 86 48 CE 3D 03 01 07
        let p256_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        let mut params = Vec::new();
        writer::write_oid(&mut params, p256_oid);
        writer::write_context_tagged_explicit(&mut body, 0, &params);
        let mut der = Vec::new();
        writer::write_sequence(&mut der, &body);
        assert!(
            decode(&der).is_none(),
            "non-SM2 namedCurve must be rejected"
        );
    }

    #[test]
    fn ecprivatekey_rejects_trailing_bytes() {
        let scalar_be: [u8; 32] = [0x42; 32];
        let mut der = encode(&scalar_be, None);
        der.push(0x00);
        assert!(decode(&der).is_none(), "trailing byte must be rejected");
    }

    #[test]
    fn validate_scalar_rejects_zero() {
        let zero = [0u8; 32];
        assert!(validate_scalar(&zero).is_none());
    }

    #[test]
    fn validate_scalar_rejects_n() {
        let n = *Fn::MODULUS.as_ref();
        let n_bytes = n.to_be_bytes();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&n_bytes);
        assert!(validate_scalar(&buf).is_none());
    }
}
