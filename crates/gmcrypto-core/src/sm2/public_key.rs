//! SM2 public keys (compressed/uncompressed encoding lands in v0.3).

use crate::sm2::point::ProjectivePoint;

/// SM2 public key: a curve point `P = d·G`.
#[derive(Clone, Copy, Debug)]
pub struct Sm2PublicKey {
    point: ProjectivePoint,
}

impl Sm2PublicKey {
    /// Wrap a curve point as a public key. Caller is responsible for
    /// having checked the point is on-curve and not at infinity (Task 18
    /// adds those checks where they matter — Z-component verification).
    #[must_use]
    pub const fn from_point(point: ProjectivePoint) -> Self {
        Self { point }
    }

    /// Underlying point.
    #[must_use]
    pub const fn point(&self) -> ProjectivePoint {
        self.point
    }
}

impl From<ProjectivePoint> for Sm2PublicKey {
    fn from(p: ProjectivePoint) -> Self {
        Self::from_point(p)
    }
}
