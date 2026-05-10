//! SM2 scalar multiplication.
//!
//! Two paths:
//! - [`mul_var`] — variable-base k·P. 4-bit fixed-window, constant-time
//!   linear-scan table lookup via `subtle`.
//! - [`mul_g`] — fixed-base k·G. In v0.1 this delegates to [`mul_var`] with
//!   the curve generator; a precomputed comb table is deferred to v0.2.

use crate::sm2::curve::Fn;
use crate::sm2::point::ProjectivePoint;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Variable-base scalar multiplication k·P.
///
/// Constant-time-designed: the operation count and code path do not depend
/// on bits of `k` or coordinates of `P`. Table lookup uses constant-time
/// linear scan; window pre-build is unconditional.
#[must_use]
pub fn mul_var(k: &Fn, p: &ProjectivePoint) -> ProjectivePoint {
    let mut table: [ProjectivePoint; 16] = [ProjectivePoint::identity(); 16];
    table[1] = *p;
    for i in 2..16 {
        table[i] = table[i - 1].add(p);
    }

    // Read the scalar as 64 nibbles (256 bits / 4 = 64 windows), MSB-first.
    let k_be = k.retrieve().to_be_bytes();

    let mut acc = ProjectivePoint::identity();
    let mut first = true;

    for byte in k_be.as_ref() {
        // High nibble first.
        let nibbles = [byte >> 4, byte & 0x0F];
        for &nib in &nibbles {
            if !first {
                // Shift the accumulator left by 4 bits via four doublings.
                acc = acc.double().double().double().double();
            }
            // Constant-time linear scan: pick table[nib] without branching.
            let mut chosen = ProjectivePoint::identity();
            for (i, entry) in table.iter().enumerate() {
                #[allow(clippy::cast_possible_truncation)]
                let take: Choice = (i as u8).ct_eq(&nib);
                chosen = ProjectivePoint::conditional_select(&chosen, entry, take);
            }
            acc = acc.add(&chosen);
            first = false;
        }
    }
    acc
}

/// Fixed-base scalar multiplication k·G. Used in signing.
///
/// **v0.1 implementation:** delegates to [`mul_var`] with the generator.
/// v0.2 will replace this body with a precomputed comb table (~10-20×
/// speedup). The public signature is stable.
#[must_use]
pub fn mul_g(k: &Fn) -> ProjectivePoint {
    mul_var(k, &ProjectivePoint::generator())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::U256;

    #[test]
    fn scalar_one_is_identity_op() {
        let one = Fn::new(&U256::ONE);
        let g = ProjectivePoint::generator();
        let result = mul_var(&one, &g);
        assert!(bool::from(result.ct_eq(&g)), "1·G must equal G");
    }

    #[test]
    fn scalar_two_equals_double() {
        let two = Fn::new(&U256::from_u64(2));
        let g = ProjectivePoint::generator();
        let lhs = mul_var(&two, &g);
        let rhs = g.double();
        assert!(
            bool::from(lhs.ct_eq(&rhs)),
            "2·G via mul_var must equal G.double()"
        );
    }

    #[test]
    fn scalar_zero_is_identity() {
        let zero = Fn::new(&U256::ZERO);
        let g = ProjectivePoint::generator();
        let result = mul_var(&zero, &g);
        assert!(
            bool::from(result.is_identity()),
            "0·G must be the point at infinity"
        );
    }

    #[test]
    fn small_multiples_consistent_with_addition() {
        // 5·G via mul_var vs. iterated addition.
        let five = Fn::new(&U256::from_u64(5));
        let g = ProjectivePoint::generator();
        let via_mul = mul_var(&five, &g);
        let via_add = g.add(&g).add(&g).add(&g).add(&g);
        assert!(bool::from(via_mul.ct_eq(&via_add)));
    }

    /// GB/T 32918.2 Appendix A.2 — sample (D, P) pair.
    /// D = 0x3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8
    /// P = (Px, Py) where:
    ///   Px = 0x09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020
    ///   Py = 0xCCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13
    #[test]
    fn gbt32918_sample_dg_yields_p() {
        let d = Fn::new(&U256::from_be_hex(
            "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
        ));
        let p = mul_var(&d, &ProjectivePoint::generator());
        let (x, y) = p.to_affine().expect("D·G is not at infinity");
        assert_eq!(
            x.retrieve(),
            U256::from_be_hex("09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020")
        );
        assert_eq!(
            y.retrieve(),
            U256::from_be_hex("CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13")
        );
    }

    #[test]
    fn mul_g_matches_mul_var_with_generator() {
        let k = Fn::new(&U256::from_u64(0x1234_5678_9ABC_DEF0));
        let lhs = mul_g(&k);
        let rhs = mul_var(&k, &ProjectivePoint::generator());
        assert!(bool::from(lhs.ct_eq(&rhs)));
    }
}
