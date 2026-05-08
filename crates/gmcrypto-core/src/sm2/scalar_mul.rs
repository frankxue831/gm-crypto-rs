//! SM2 scalar multiplication.
//!
//! Two paths:
//! - [`mul_var`] — variable-base k·P. 4-bit fixed-window, constant-time
//!   linear-scan table lookup via `subtle`.
//! - `mul_g` — fixed-base k·G. Comb table built once at first use
//!   (lands in Task 13).

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

    for byte in &k_be {
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
}
