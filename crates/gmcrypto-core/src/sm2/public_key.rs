//! SM2 public keys.

use crate::sec1::{SEC1_UNCOMPRESSED_LEN, decode_uncompressed_point, encode_uncompressed_point};
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
}
