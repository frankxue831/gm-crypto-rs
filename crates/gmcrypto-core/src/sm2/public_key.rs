//! SM2 public keys.

use crate::sec1::{
    SEC1_COMPRESSED_LEN, SEC1_UNCOMPRESSED_LEN, decode_compressed_point, decode_uncompressed_point,
    encode_compressed_point, encode_uncompressed_point,
};
use crate::sm2::point::ProjectivePoint;
use subtle::ConstantTimeEq;

/// SM2 public key: a curve point `P = d·G`.
#[derive(Clone, Copy, Debug)]
pub struct Sm2PublicKey {
    point: ProjectivePoint,
}

impl Sm2PublicKey {
    /// Not part of the public API / not covered by SemVer; may change or be removed in any release. Internal/low-level — Rust users construct via [`Sm2PublicKey::from_sec1_bytes`] or [`crate::sm2::Sm2PrivateKey::public_key`].
    ///
    /// Wrap a curve point as a public key. Caller is responsible for
    /// having checked the point is on-curve and not at infinity. API entry
    /// points that need stronger failure guarantees perform their own
    /// boundary checks.
    #[doc(hidden)]
    #[must_use]
    pub const fn from_point(point: ProjectivePoint) -> Self {
        Self { point }
    }

    /// Not part of the public API / not covered by SemVer; may change or be removed in any release. Internal/low-level — Rust users construct via [`Sm2PublicKey::from_sec1_bytes`] or [`crate::sm2::Sm2PrivateKey::public_key`].
    ///
    /// Underlying point.
    #[doc(hidden)]
    #[must_use]
    pub const fn point(&self) -> ProjectivePoint {
        self.point
    }

    /// Decode a SEC1 uncompressed public key (`04 || X || Y`, 65 bytes)
    /// into an `Sm2PublicKey`. Rejects the identity point and any
    /// off-curve `(X, Y)`. Returns `None` for any malformed input.
    #[must_use]
    pub fn from_sec1_bytes(bytes: &[u8]) -> Option<Self> {
        let point = decode_uncompressed_point(bytes)?;
        // decode_uncompressed_point already enforces on-curve and
        // length=65. The identity point cannot be encoded as `04 || X
        // || Y` (the identity has no affine form), so the on-curve
        // check on (X, Y) implicitly excludes it. Be explicit anyway.
        if bool::from(point.is_identity()) {
            return None;
        }
        Some(Self { point })
    }

    /// Encode this public key as 65 bytes of SEC1 uncompressed
    /// `04 || X || Y`. Panics only if the underlying point is at
    /// infinity, which `from_sec1_bytes` and the [`crate::sm2::Sm2PrivateKey`]
    /// constructor both rule out at the boundary.
    ///
    /// # Panics
    ///
    /// Panics if the underlying point is at infinity.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn to_sec1_uncompressed(&self) -> [u8; SEC1_UNCOMPRESSED_LEN] {
        let (x, y) = self
            .point
            .to_affine()
            .expect("Sm2PublicKey at infinity violates the invariant");
        encode_uncompressed_point(&x, &y)
    }

    /// Decode a SEC1 compressed public key (`02 || X` or `03 || X`, 33 bytes)
    /// into an `Sm2PublicKey`. Rejects wrong lengths, invalid tags, `X >= p`,
    /// non-residues, the identity point, and every other malformed input with
    /// `None`. Note [`Self::from_sec1_bytes`] continues to accept only 65-byte
    /// uncompressed points.
    #[must_use]
    pub fn from_sec1_compressed(bytes: &[u8]) -> Option<Self> {
        let point = decode_compressed_point(bytes)?;
        if bool::from(point.is_identity()) {
            return None;
        }
        Some(Self { point })
    }

    /// Encode this public key as 33 bytes of SEC1 compressed
    /// `02 || X` (even affine `Y`) or `03 || X` (odd affine `Y`).
    ///
    /// # Panics
    ///
    /// Panics if the underlying point is at infinity (only constructible via
    /// the hidden low-level [`Self::from_point`] constructor).
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn to_sec1_compressed(&self) -> [u8; SEC1_COMPRESSED_LEN] {
        let (x, y) = self
            .point
            .to_affine()
            .expect("Sm2PublicKey at infinity violates the invariant");
        encode_compressed_point(&x, &y)
    }
}

/// Not part of the public API / not covered by SemVer; may change or be removed in any release. Internal/low-level — Rust users construct via [`Sm2PublicKey::from_sec1_bytes`] or [`crate::sm2::Sm2PrivateKey::public_key`].
#[doc(hidden)]
impl From<ProjectivePoint> for Sm2PublicKey {
    fn from(p: ProjectivePoint) -> Self {
        Self::from_point(p)
    }
}

impl ConstantTimeEq for Sm2PublicKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.point.ct_eq(&other.point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::Sm2PrivateKey;
    use crypto_bigint::U256;

    /// Round-trip the SM2 generator's public-point uncompressed encoding.
    #[test]
    fn sec1_round_trip_generator() {
        let g = Sm2PublicKey::from_point(ProjectivePoint::generator());
        let bytes = g.to_sec1_uncompressed();
        let recovered = Sm2PublicKey::from_sec1_bytes(&bytes).expect("decode");
        assert_eq!(bytes, recovered.to_sec1_uncompressed());
    }

    /// Round-trip the GB/T 32918.2 sample public key derived from D.
    #[test]
    fn sec1_round_trip_gbt_sample() {
        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let priv_key = Sm2PrivateKey::from_scalar_inner(d).expect("valid d");
        let pub_key = priv_key.public_key();
        let bytes = pub_key.to_sec1_uncompressed();
        assert_eq!(bytes[0], 0x04);
        let recovered = Sm2PublicKey::from_sec1_bytes(&bytes).expect("decode");
        assert!(bool::from(pub_key.ct_eq(&recovered)));
    }

    /// `from_sec1_bytes` rejects wrong length / wrong tag / off-curve.
    #[test]
    fn sec1_rejects_malformed() {
        assert!(Sm2PublicKey::from_sec1_bytes(&[0x04]).is_none());
        let mut bad = [0u8; 65];
        bad[0] = 0x04;
        bad[1] = 1;
        bad[33] = 1;
        assert!(Sm2PublicKey::from_sec1_bytes(&bad).is_none());
        // Compressed form rejected.
        bad[0] = 0x02;
        assert!(Sm2PublicKey::from_sec1_bytes(&bad).is_none());
    }

    #[test]
    fn sec1_compressed_pinned_g_neg_g_and_round_trips() {
        let g = Sm2PublicKey::from_point(ProjectivePoint::generator());
        let g_comp = g.to_sec1_compressed();
        let expected_g: [u8; 33] = [
            0x02, 0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A,
            0x39, 0xC9, 0x94, 0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45,
            0x89, 0x33, 0x4C, 0x74, 0xC7,
        ];
        assert_eq!(g_comp, expected_g);

        // Negating G flips parity without changing X.
        let mut expected_neg_g = expected_g;
        expected_neg_g[0] = 0x03;
        let neg_g = Sm2PublicKey::from_sec1_compressed(&expected_neg_g).expect("-G");
        assert_eq!(neg_g.to_sec1_compressed(), expected_neg_g);
        let neg_uncomp = neg_g.to_sec1_uncompressed();
        let g_uncomp = g.to_sec1_uncompressed();
        assert_eq!(neg_uncomp[1..33], g_uncomp[1..33]);
        assert_ne!(neg_uncomp[33..65], g_uncomp[33..65]);

        // Uncompressed parser must still reject valid 33-byte keys.
        assert!(Sm2PublicKey::from_sec1_bytes(&g_comp).is_none());
        assert!(Sm2PublicKey::from_sec1_bytes(&expected_neg_g).is_none());

        // Exercise both parities across scalar multiples and verify a signature.
        for scalar_byte in [1u8, 2, 3, 4, 5, 7, 11] {
            let mut raw = [0u8; 32];
            raw[31] = scalar_byte;
            let sk = Sm2PrivateKey::from_bytes_be(&raw).expect("valid scalar");
            let pk = sk.public_key();
            let comp = pk.to_sec1_compressed();
            let rec = Sm2PublicKey::from_sec1_compressed(&comp).expect("decompress");
            assert!(bool::from(rec.ct_eq(&pk)));
            assert_eq!(rec.to_sec1_uncompressed(), pk.to_sec1_uncompressed());

            let msg = b"compressed SEC1 verify check";
            let mut rng = getrandom::SysRng;
            let sig = crate::sm2::sign_with_id(&sk, crate::sm2::DEFAULT_SIGNER_ID, msg, &mut rng)
                .expect("sign");
            assert!(crate::sm2::verify_with_id(
                &rec,
                crate::sm2::DEFAULT_SIGNER_ID,
                msg,
                &sig,
            ));
        }
    }

    #[test]
    fn sec1_compressed_rejects_malformed_x_ge_p_and_non_residue() {
        assert!(Sm2PublicKey::from_sec1_compressed(&[]).is_none());
        assert!(Sm2PublicKey::from_sec1_compressed(&[0x00]).is_none());
        assert!(Sm2PublicKey::from_sec1_compressed(&[0x02; 32]).is_none());
        assert!(Sm2PublicKey::from_sec1_compressed(&[0x02; 34]).is_none());
        let g_uncomp =
            Sm2PublicKey::from_point(ProjectivePoint::generator()).to_sec1_uncompressed();
        assert!(Sm2PublicKey::from_sec1_compressed(&g_uncomp).is_none());

        let mut g_bad_tag =
            Sm2PublicKey::from_point(ProjectivePoint::generator()).to_sec1_compressed();
        for tag in [0x00u8, 0x01, 0x04, 0x05, 0x06, 0x07, 0xFF] {
            g_bad_tag[0] = tag;
            assert!(Sm2PublicKey::from_sec1_compressed(&g_bad_tag).is_none());
        }

        let mut x_eq_p = [0u8; 33];
        x_eq_p[0] = 0x02;
        x_eq_p[1..33].copy_from_slice(&crate::sm2::curve::Fp::MODULUS.as_ref().to_be_bytes());
        assert!(Sm2PublicKey::from_sec1_compressed(&x_eq_p).is_none());

        let mut non_res = [0u8; 33];
        non_res[32] = 0x02;
        non_res[0] = 0x02;
        assert!(Sm2PublicKey::from_sec1_compressed(&non_res).is_none());
        non_res[0] = 0x03;
        assert!(Sm2PublicKey::from_sec1_compressed(&non_res).is_none());
    }

    #[test]
    #[should_panic(expected = "Sm2PublicKey at infinity violates the invariant")]
    fn sec1_compressed_panics_on_identity() {
        let id = Sm2PublicKey::from_point(ProjectivePoint::identity());
        let _ = id.to_sec1_compressed();
    }
}
