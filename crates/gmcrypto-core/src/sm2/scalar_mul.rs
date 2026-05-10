//! SM2 scalar multiplication.
//!
//! Two paths:
//! - [`mul_var`] — variable-base k·P. 4-bit fixed-window, constant-time
//!   linear-scan table lookup via `subtle`.
//! - [`mul_g`] — fixed-base k·G. v0.3 uses a precomputed comb table
//!   (see [`crate::sm2::comb_table`]) for ~5× speedup over v0.2's
//!   delegate-to-`mul_var` path. Constant-time-designed lookup
//!   preserved.

use crate::sm2::comb_table::{NUM_WINDOWS, WINDOW_BITS, comb_table};
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
/// v0.3 walks a precomputed comb table (64 sub-tables of 16 entries
/// each, lazily built once per process per [`crate::sm2::comb_table`]).
/// Each window's lookup runs a constant-time linear scan over the
/// 16-entry sub-table; the accumulation across windows uses
/// projective point addition. Total work per call: 64 sub-table
/// scans + 64 point additions, vs. v0.2's 256 doublings + 64
/// additions via [`mul_var`].
///
/// Constant-time-designed: every sub-table entry is touched on
/// every call regardless of the nibble value, and the scan output
/// is selected via [`subtle::ConditionallySelectable`]. Public
/// signature is unchanged from v0.2.
#[must_use]
pub fn mul_g(k: &Fn) -> ProjectivePoint {
    let table = comb_table();
    let k_be = k.retrieve().to_be_bytes();

    // Walk windows from LSB to MSB. The scalar is 256 bits, encoded as
    // 32 bytes big-endian. Window i (0..NUM_WINDOWS) covers bits
    // [4i, 4i+4). For each window, look up T[i][nibble_i] via
    // constant-time scan and add to the accumulator.
    let mut acc = ProjectivePoint::identity();
    for i in 0..NUM_WINDOWS {
        // Bit position from LSB: bits [4i, 4i+4).
        // Byte index from MSB: 31 - i/2; nibble: (i & 1) == 0 → low nibble.
        let bit = i * WINDOW_BITS;
        let byte_idx = 31 - bit / 8;
        let nibble = if i % 2 == 0 {
            k_be.as_ref()[byte_idx] & 0x0F
        } else {
            (k_be.as_ref()[byte_idx] >> 4) & 0x0F
        };

        // Constant-time linear scan over T[i][0..16].
        let mut chosen = ProjectivePoint::identity();
        let sub = &table.sub_tables[i];
        for (j, entry) in sub.iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let take: Choice = (j as u8).ct_eq(&nibble);
            chosen = ProjectivePoint::conditional_select(&chosen, entry, take);
        }
        acc = acc.add(&chosen);
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

    /// Battery test: `mul_g(k)` and `mul_var(k, &G)` agree on a wide
    /// range of scalars, including small, large, and pathological
    /// values (W6 equivalence regression). The comb-table walk is a
    /// distinct code path from `mul_var`'s 4-bit windowed mul; the
    /// two MUST produce identical points for every scalar.
    #[test]
    fn mul_g_matches_mul_var_battery() {
        let g = ProjectivePoint::generator();
        let n = *Fn::MODULUS.as_ref();
        let n_minus_one = n.wrapping_sub(&U256::ONE);
        let n_minus_two = n_minus_one.wrapping_sub(&U256::ONE);

        // Small + boundary values.
        let small_scalars: alloc::vec::Vec<U256> = [
            U256::ZERO,
            U256::ONE,
            U256::from_u64(2),
            U256::from_u64(15),
            U256::from_u64(16),
            U256::from_u64(255),
            U256::from_u64(256),
            U256::from_u64(0xFFFF_FFFF_FFFF_FFFF),
            n_minus_two,
            n_minus_one,
        ]
        .into_iter()
        .collect();

        // Some larger pseudo-random scalars (deterministic, so test is
        // reproducible).
        let randoms: alloc::vec::Vec<U256> = [
            "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
            "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0",
            "B9E5B7C12E48BAB7CC0E91A57F8A48E8C8F87DDD25EBF52F2A75E612CB1A9E4F",
            "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE",
            "8000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "00000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE",
        ]
        .iter()
        .map(|s| U256::from_be_hex(s))
        .collect();

        for k_u in small_scalars.iter().chain(randoms.iter()) {
            let k = Fn::new(k_u);
            let lhs = mul_g(&k);
            let rhs = mul_var(&k, &g);
            assert!(
                bool::from(lhs.ct_eq(&rhs)),
                "mul_g != mul_var for k = {k_u:#X}"
            );
        }
    }

    /// GB/T 32918.2 sample D: the comb-table `mul_g` must produce the
    /// same public point as the spec.
    #[test]
    fn mul_g_gbt32918_sample() {
        let d = Fn::new(&U256::from_be_hex(
            "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
        ));
        let p = mul_g(&d);
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
}
