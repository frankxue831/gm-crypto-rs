//! SM2 curve points in projective (X:Y:Z) coordinates with
//! Renes-Costello-Batina complete addition formulas (eprint 2015/1060).
//!
//! See `add` and `double` for the algorithms transcribed from the paper.
//! No early-out branches; the point at infinity is represented as `Z = 0`
//! and is folded into the formulas via projective representation.

use crate::sm2::curve::{b, Fp, GX_HEX, GY_HEX};
use crypto_bigint::{Invert, U256};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// A point on the SM2 curve in projective coordinates (X:Y:Z).
///
/// The point at infinity is represented as (0:1:0).
#[derive(Clone, Copy, Debug)]
pub struct ProjectivePoint {
    pub(crate) x: Fp,
    pub(crate) y: Fp,
    pub(crate) z: Fp,
}

impl ConstantTimeEq for ProjectivePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        let lhs_x = self.x * other.z;
        let rhs_x = other.x * self.z;
        let lhs_y = self.y * other.z;
        let rhs_y = other.y * self.z;
        lhs_x.retrieve().ct_eq(&rhs_x.retrieve()) & lhs_y.retrieve().ct_eq(&rhs_y.retrieve())
    }
}

impl ConditionallySelectable for ProjectivePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: Fp::conditional_select(&a.x, &b.x, choice),
            y: Fp::conditional_select(&a.y, &b.y, choice),
            z: Fp::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl ProjectivePoint {
    /// The point at infinity (0 : 1 : 0).
    #[must_use]
    pub const fn identity() -> Self {
        Self {
            x: Fp::new(&U256::ZERO),
            y: Fp::new(&U256::ONE),
            z: Fp::new(&U256::ZERO),
        }
    }

    /// The curve generator G.
    #[must_use]
    pub const fn generator() -> Self {
        Self {
            x: Fp::new(&U256::from_be_hex(GX_HEX)),
            y: Fp::new(&U256::from_be_hex(GY_HEX)),
            z: Fp::new(&U256::ONE),
        }
    }

    /// Whether this is the point at infinity (Z = 0). Constant-time.
    #[must_use]
    pub fn is_identity(&self) -> Choice {
        self.z.retrieve().ct_eq(&U256::ZERO)
    }

    /// Add two points using RCB Algorithm 4 (a=-3 specialized, complete).
    ///
    /// Transcribed from eprint 2015/1060 Algorithm 4.
    #[must_use]
    #[allow(clippy::similar_names)]
    pub fn add(&self, other: &Self) -> Self {
        let b = b();
        let (x1, y1, z1) = (self.x, self.y, self.z);
        let (x2, y2, z2) = (other.x, other.y, other.z);

        let xx = x1 * x2; // 1
        let yy = y1 * y2; // 2
        let zz = z1 * z2; // 3
        let xy_pairs = ((x1 + y1) * (x2 + y2)) - (xx + yy); // 4,5,6,7,8
        let yz_pairs = ((y1 + z1) * (y2 + z2)) - (yy + zz); // 9,10,11,12,13
        let xz_pairs = ((x1 + z1) * (x2 + z2)) - (xx + zz); // 14,15,16,17,18

        let bzz_part = xz_pairs - b * zz; // 19,20
        let bzz3_part = bzz_part + bzz_part + bzz_part; // 21,22
        let yy_m_bzz3 = yy - bzz3_part; // 23
        let yy_p_bzz3 = yy + bzz3_part; // 24

        let zz3 = zz + zz + zz; // 26,27
        let bxz_part = b * xz_pairs - (zz3 + xx); // 25,28,29
        let bxz3_part = bxz_part + bxz_part + bxz_part; // 30,31
        let xx3_m_zz3 = xx + xx + xx - zz3; // 32,33,34

        Self {
            x: (yy_p_bzz3 * xy_pairs) - (yz_pairs * bxz3_part), // 35,39,40
            y: (yy_p_bzz3 * yy_m_bzz3) + (xx3_m_zz3 * bxz3_part), // 36,37,38
            z: (yy_m_bzz3 * yz_pairs) + (xy_pairs * xx3_m_zz3), // 41,42,43
        }
    }

    /// Double a point using RCB Algorithm 6 (a=-3 specialized).
    /// Cost: 3S + 5M + a few additions.
    ///
    /// Transcribed from eprint 2015/1060 Algorithm 6.
    #[must_use]
    #[allow(clippy::similar_names)]
    pub fn double(&self) -> Self {
        let b = b();
        let (x, y, z) = (self.x, self.y, self.z);

        let xx = x * x; // 1
        let yy = y * y; // 2
        let zz = z * z; // 3
        let xy2 = (x * y) + (x * y); // 4, 5
        let xz2 = (x * z) + (x * z); // 6, 7

        let bzz_part = b * zz - xz2; // 8, 9
        let bzz3_part = bzz_part + bzz_part + bzz_part; // 10, 11
        let yy_m_bzz3 = yy - bzz3_part; // 12
        let yy_p_bzz3 = yy + bzz3_part; // 13
        let y_frag = yy_p_bzz3 * yy_m_bzz3; // 14
        let x_frag = yy_m_bzz3 * xy2; // 15

        let zz3 = zz + zz + zz; // 16, 17
        let bxz2_part = b * xz2 - (zz3 + xx); // 18, 19, 20
        let bxz6_part = bxz2_part + bxz2_part + bxz2_part; // 21, 22
        let xx3_m_zz3 = xx + xx + xx - zz3; // 23, 24, 25

        let y3 = y_frag + xx3_m_zz3 * bxz6_part; // 26, 27
        let yz2 = (y * z) + (y * z); // 28, 29
        let x3 = x_frag - bxz6_part * yz2; // 30, 31
        let z3_tmp = yz2 * yy; // 32
        let z3_tmp2 = z3_tmp + z3_tmp; // 33
        let z3 = z3_tmp2 + z3_tmp2; // 34

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Negate a point: (X:Y:Z) -> (X:-Y:Z).
    #[must_use]
    pub fn neg(&self) -> Self {
        Self {
            x: self.x,
            y: -self.y,
            z: self.z,
        }
    }

    /// Convert to affine (x, y) coordinates. Returns `None` for the identity
    /// point (where Z = 0).
    ///
    /// # Constant-time caveat
    ///
    /// The Z-inverse goes through `crypto-bigint = 0.6`'s
    /// `ConstMontyForm::invert` (safegcd / Bernstein-Yang), which is
    /// **documented** as constant-time but direct measurement on the
    /// project's dudect harness shows `|tau| ≈ 0.70` between different
    /// inputs. Callers that pass secret-derived `Z` (notably `mul_g(k)`
    /// inside the SM2 sign retry loop, where `k` is the secret nonce)
    /// inherit a measurable timing side-channel until v0.2 replaces the
    /// invert site with a Fermat-style `pow_bounded_exp`.
    /// See `SECURITY.md` for the full posture.
    #[must_use]
    pub fn to_affine(&self) -> Option<(Fp, Fp)> {
        let z_inv: subtle::CtOption<Fp> = self.z.invert();
        let z_inv: Option<Fp> = z_inv.into();
        let z_inv = z_inv?;
        Some((self.x * z_inv, self.y * z_inv))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::curve::b;
    use subtle::ConstantTimeEq;

    #[test]
    fn doubling_equals_self_addition() {
        let g = ProjectivePoint::generator();
        let g2_double = g.double();
        let g2_add = g.add(&g);
        assert!(
            bool::from(g2_double.ct_eq(&g2_add)),
            "doubling and self-addition must agree"
        );
    }

    #[test]
    fn add_with_identity_is_identity_law() {
        let g = ProjectivePoint::generator();
        let id = ProjectivePoint::identity();
        let lhs = g.add(&id);
        assert!(bool::from(lhs.ct_eq(&g)), "G + O = G");
    }

    #[test]
    fn add_with_negation_is_identity() {
        let g = ProjectivePoint::generator();
        let neg_g = g.neg();
        let sum = g.add(&neg_g);
        assert!(bool::from(sum.is_identity()), "G + (-G) = O");
    }

    /// 2G affine coordinates from the SM2 reference implementation,
    /// cross-validated against an independent Python affine-arithmetic
    /// computation.
    #[test]
    fn two_g_known_affine() {
        let g2 = ProjectivePoint::generator().double();
        let (x, y) = g2.to_affine().expect("2G is not infinity");
        assert_eq!(
            x.retrieve(),
            U256::from_be_hex("56CEFD60D7C87C000D58EF57FA73BA4D9C0DFA08C08A7331495C2E1DA3F2BD52")
        );
        assert_eq!(
            y.retrieve(),
            U256::from_be_hex("31B7E7E6CC8189F668535CE0F8EAF1BD6DE84C182F6C8E716F780D3A970A23C3")
        );
    }

    /// 3G = 2G + G. Independent KAT over `add` (the 2G KAT only exercises `double`).
    #[test]
    fn three_g_known_affine() {
        let g = ProjectivePoint::generator();
        let g3 = g.double().add(&g);
        let (x, y) = g3.to_affine().expect("3G is not infinity");
        assert_eq!(
            x.retrieve(),
            U256::from_be_hex("A97F7CD4B3C993B4BE2DAA8CDB41E24CA13F6BD945302244E26918F1D0509EBF")
        );
        assert_eq!(
            y.retrieve(),
            U256::from_be_hex("530B5DD88C688EF5CCC5CEC08A72150F7C400EE5CD045292AAACDD037458F6E6")
        );
    }

    #[test]
    fn to_affine_round_trip_via_double() {
        let g = ProjectivePoint::generator();
        let g2 = g.double();
        let (x, y) = g2.to_affine().expect("2G is not at infinity");
        let lhs = y * y;
        let three = Fp::new(&U256::from_u64(3));
        let rhs = x * x * x - three * x + b();
        assert_eq!(
            lhs.retrieve(),
            rhs.retrieve(),
            "2G affine coords must satisfy curve equation"
        );
    }
}
