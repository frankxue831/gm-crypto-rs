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
//! `encode_uncompressed_point` / `decode_uncompressed_point`
//! handle the 65-byte `04 || X || Y` form (SEC1 §2.3.3), which
//! [`encode`], [`decode`], [`crate::spki`], and [`crate::sm2::Sm2PublicKey::from_sec1_bytes`]
//! require. `encode_compressed_point` / `decode_compressed_point` handle
//! the 33-byte `02/03 || X` form (SEC1 §§2.3.3–2.3.4) used exclusively by
//! [`crate::sm2::Sm2PublicKey::to_sec1_compressed`] and
//! [`crate::sm2::Sm2PublicKey::from_sec1_compressed`].
//!
//! # Failure-mode invariant
//!
//! Decoders return `Option`; no distinguishing variants. The
//! free-form encoder helpers panic only on programmer error
//! (32-byte slices guaranteed by callers).

use crate::asn1::oid::SM2P256V1;
use crate::asn1::{reader, writer};
use crate::sm2::curve::{Fn, Fp, b};
use crate::sm2::encrypt::{point_on_curve, projective_from_affine};
use crate::sm2::point::ProjectivePoint;
use alloc::vec::Vec;
use crypto_bigint::U256;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use zeroize::Zeroize;

/// SEC1 compressed-point even-Y tag byte (`02 || X`).
const SEC1_TAG_COMPRESSED_EVEN: u8 = 0x02;
/// SEC1 compressed-point odd-Y tag byte (`03 || X`).
const SEC1_TAG_COMPRESSED_ODD: u8 = 0x03;
/// SEC1 compressed-point total byte length (`1 + 32`).
pub(crate) const SEC1_COMPRESSED_LEN: usize = 33;
/// SEC1 uncompressed-point tag byte (`04 || X || Y`).
pub(crate) const SEC1_TAG_UNCOMPRESSED: u8 = 0x04;
/// SEC1 uncompressed-point total byte length (`1 + 32 + 32`).
pub(crate) const SEC1_UNCOMPRESSED_LEN: usize = 65;
/// RFC 5915 `ECPrivateKey` version number (always `ecPrivkeyVer1 = 1`).
const ECPRIVKEY_VER1: u8 = 1;
/// Modular square-root exponent `(p + 1) / 4` since SM2 `p ≡ 3 (mod 4)`.
const FP_SQRT_EXP: U256 = (*Fp::MODULUS.as_ref())
    .wrapping_add(&U256::ONE)
    .shr_vartime(2);

/// Encode `(x, y)` field elements as a 33-byte SEC1 compressed point
/// (`02 || X` for even `y`, `03 || X` for odd `y`).
#[must_use]
pub(crate) fn encode_compressed_point(x: &Fp, y: &Fp) -> [u8; SEC1_COMPRESSED_LEN] {
    let y_be = y.retrieve().to_be_bytes();
    let mut out = [0u8; SEC1_COMPRESSED_LEN];
    out[0] = SEC1_TAG_COMPRESSED_EVEN | (y_be[31] & 1);
    out[1..33].copy_from_slice(&x.retrieve().to_be_bytes());
    out
}

/// Decode a 33-byte SEC1 compressed point (`02/03 || X`) into a validated
/// [`ProjectivePoint`], rejecting wrong lengths, invalid tags (`00`, `04`,
/// hybrid `06`/`07`, etc.), `X >= p`, quadratic non-residues, and any parity or
/// curve mismatch.
#[must_use]
pub(crate) fn decode_compressed_point(input: &[u8]) -> Option<ProjectivePoint> {
    if input.len() != SEC1_COMPRESSED_LEN {
        return None;
    }
    let want_odd: u8 = match input[0] {
        SEC1_TAG_COMPRESSED_EVEN => 0,
        SEC1_TAG_COMPRESSED_ODD => 1,
        _ => return None,
    };
    let x_u = U256::from_be_slice(&input[1..33]);
    let p = *Fp::MODULUS.as_ref();
    if !bool::from(x_u.ct_lt(&p)) {
        return None;
    }
    let x = Fp::new(&x_u);
    let three = Fp::new(&U256::from_u64(3));
    let rhs = x * x * x - three * x + b();
    let y0 = rhs.pow(&FP_SQRT_EXP);
    if !bool::from((y0 * y0).retrieve().ct_eq(&rhs.retrieve())) {
        return None;
    }
    let y0_odd = y0.retrieve().to_be_bytes()[31] & 1;
    let y = Fp::conditional_select(&y0, &(-y0), Choice::from(y0_odd ^ want_odd));
    if (y.retrieve().to_be_bytes()[31] & 1) != want_odd || !point_on_curve(&x, &y) {
        return None;
    }
    Some(projective_from_affine(x, y))
}

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
/// type. `scalar_be` holds the raw 32-byte secret scalar (zeroized on
/// drop and redacted in [`core::fmt::Debug`]).
#[derive(Clone)]
pub struct EcPrivateKey {
    /// 32-byte big-endian scalar `d`. Not validated against the
    /// curve order here — the caller must reject `d == 0` and
    /// `d == n-1` via [`crate::sm2::Sm2PrivateKey::from_bytes_be`].
    pub scalar_be: [u8; 32],
    /// Decoded uncompressed public key, if the optional
    /// `publicKey` field was present and well-formed.
    pub public: Option<crate::sm2::Sm2PublicKey>,
}

impl core::fmt::Debug for EcPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EcPrivateKey")
            .field("scalar_be", &"<redacted>")
            .field("public", &self.public)
            .finish()
    }
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

    let mut public: Option<crate::sm2::Sm2PublicKey> = None;

    // [0] EXPLICIT parameters (OPTIONAL).
    if let Some((params_inner, after)) = reader::read_context_tagged_explicit(body, 0) {
        let Some((oid, params_rest)) = reader::read_oid(params_inner) else {
            scalar_be.zeroize();
            return None;
        };
        if !params_rest.is_empty() || oid != SM2P256V1 {
            scalar_be.zeroize();
            return None;
        }
        body = after;
    }

    // [1] EXPLICIT publicKey BIT STRING (OPTIONAL).
    if let Some((pk_inner, after)) = reader::read_context_tagged_explicit(body, 1) {
        let Some((unused, pk_bytes, pk_rest)) = reader::read_bit_string(pk_inner) else {
            scalar_be.zeroize();
            return None;
        };
        if unused != 0 || !pk_rest.is_empty() {
            scalar_be.zeroize();
            return None;
        }
        if let Some(p) = decode_uncompressed_point(pk_bytes) {
            public = Some(crate::sm2::Sm2PublicKey::from_point(p));
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
        let (x, y) = key.public_key().point().to_affine().expect("finite");
        let pk = encode_uncompressed_point(&x, &y);
        let der = encode(&scalar_be, Some(&pk));

        let recovered = decode(&der).expect("decode");
        assert_eq!(recovered.scalar_be, scalar_be);
        assert!(recovered.public.is_some());
        let (rx, ry) = recovered
            .public
            .unwrap()
            .point()
            .to_affine()
            .expect("finite");
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
                    let (x, y) = p.point().to_affine().expect("finite");
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

    #[test]
    fn compressed_point_round_trip_and_exponent_identity() {
        let p = *Fp::MODULUS.as_ref();
        let four_exp = FP_SQRT_EXP.shl_vartime(2);
        assert_eq!(four_exp.wrapping_sub(&U256::ONE), p);

        let g = ProjectivePoint::generator();
        let (gx, gy) = g.to_affine().expect("G finite");
        let g_comp = encode_compressed_point(&gx, &gy);
        let expected_g: [u8; 33] = [
            0x02, 0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A,
            0x39, 0xC9, 0x94, 0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45,
            0x89, 0x33, 0x4C, 0x74, 0xC7,
        ];
        assert_eq!(g_comp, expected_g);
        let rec_g = decode_compressed_point(&g_comp).expect("decode G");
        assert!(bool::from(rec_g.ct_eq(&g)));

        let neg_gy = -gy;
        let neg_g_comp = encode_compressed_point(&gx, &neg_gy);
        let mut expected_neg_g = expected_g;
        expected_neg_g[0] = 0x03;
        assert_eq!(neg_g_comp, expected_neg_g);
        let rec_neg_g = decode_compressed_point(&neg_g_comp).expect("decode -G");
        let (rx, ry) = rec_neg_g.to_affine().expect("-G finite");
        assert_eq!(rx.retrieve(), gx.retrieve());
        assert_eq!(ry.retrieve(), neg_gy.retrieve());
    }

    #[test]
    fn compressed_point_rejections_and_ecprivatekey_isolation() {
        assert!(decode_compressed_point(&[]).is_none());
        assert!(decode_compressed_point(&[0x00]).is_none());
        assert!(decode_compressed_point(&[0x02; 32]).is_none());
        assert!(decode_compressed_point(&[0x02; 34]).is_none());
        assert!(decode_compressed_point(&[0x04; 65]).is_none());

        let g = ProjectivePoint::generator();
        let (gx, gy) = g.to_affine().expect("G finite");
        let g_comp = encode_compressed_point(&gx, &gy);
        for bad_tag in [0x00u8, 0x01, 0x04, 0x05, 0x06, 0x07, 0xFF] {
            let mut bad = g_comp;
            bad[0] = bad_tag;
            assert!(decode_compressed_point(&bad).is_none());
        }

        let p = *Fp::MODULUS.as_ref();
        for x_bad in [p, p.wrapping_add(&U256::ONE), U256::MAX] {
            let mut bad = [0u8; 33];
            bad[0] = 0x02;
            bad[1..33].copy_from_slice(&x_bad.to_be_bytes());
            assert!(decode_compressed_point(&bad).is_none());
        }

        // X = 2 is a quadratic non-residue on the SM2 curve.
        let mut non_res = [0u8; 33];
        non_res[32] = 0x02;
        non_res[0] = 0x02;
        assert!(decode_compressed_point(&non_res).is_none());
        non_res[0] = 0x03;
        assert!(decode_compressed_point(&non_res).is_none());

        // RFC 5915 ECPrivateKey decoder still rejects 33-byte compressed publicKey.
        let mut body = Vec::new();
        writer::write_integer(&mut body, &[ECPRIVKEY_VER1]);
        writer::write_octet_string(&mut body, &[0x42u8; 32]);
        let mut params = Vec::new();
        writer::write_oid(&mut params, SM2P256V1);
        writer::write_context_tagged_explicit(&mut body, 0, &params);
        let mut pk_bitstr = Vec::new();
        writer::write_bit_string(&mut pk_bitstr, 0, &g_comp);
        writer::write_context_tagged_explicit(&mut body, 1, &pk_bitstr);
        let mut der = Vec::new();
        writer::write_sequence(&mut der, &body);
        assert!(decode(&der).is_none());
    }

    #[test]
    fn ecprivatekey_debug_redacts_scalar() {
        let key = EcPrivateKey {
            scalar_be: [0xAB; 32],
            public: None,
        };
        let formatted = alloc::format!("{key:?}");
        assert!(formatted.contains("<redacted>"));
        assert!(!formatted.contains("171"));
    }

    #[test]
    fn ecprivatekey_decode_rejects_malformed_optional_tags() {
        // Valid prefix: version = 1, privateKey = 32-byte scalar.
        let mut base = Vec::new();
        writer::write_integer(&mut base, &[ECPRIVKEY_VER1]);
        writer::write_octet_string(&mut base, &[0x42u8; 32]);

        // [0] containing NULL (not an OID).
        let mut bad_params_body = base.clone();
        let mut null_tlv = Vec::new();
        writer::write_null(&mut null_tlv);
        writer::write_context_tagged_explicit(&mut bad_params_body, 0, &null_tlv);
        let mut bad_params_der = Vec::new();
        writer::write_sequence(&mut bad_params_der, &bad_params_body);
        assert!(decode(&bad_params_der).is_none());

        // [1] containing NULL (not a BIT STRING).
        let mut bad_pk_body = base;
        writer::write_context_tagged_explicit(&mut bad_pk_body, 1, &null_tlv);
        let mut bad_pk_der = Vec::new();
        writer::write_sequence(&mut bad_pk_der, &bad_pk_body);
        assert!(decode(&bad_pk_der).is_none());
    }
}
