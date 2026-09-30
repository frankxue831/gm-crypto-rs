//! GFNI SM4 S-box (v1.16, `docs/v1.16-scope.md` Q16.3).
//!
//! `S(x) = A·inv(A·x ⊕ B) ⊕ B` over SM4's field (`0x1F5`). GFNI inverts
//! in the AES field (`0x11B`), so both affine steps fold in the field
//! isomorphism `T` that maps SM4's generator to `0x23`, the smallest
//! root of SM4's polynomial in the AES field:
//! `y = GF2P8AFFINEQB(x, T·A, T(B))`, `S = GF2P8AFFINEINVQB(y, A·T⁻¹, B)`.
//! The test module re-derives every constant from the field definitions.

/// `T·A`, encoded for GF2P8AFFINEQB.
pub const PRE_MATRIX: u64 = 0x4C28_7DB9_1A22_505D;
/// `T(B)`.
pub const PRE_CONST: i32 = 0x3E;
/// `A·T⁻¹`, encoded for GF2P8AFFINEINVQB.
pub const POST_MATRIX: u64 = 0xF3AB_34A9_74A6_B589;
/// `B`.
pub const POST_CONST: i32 = 0xD3;

#[cfg(test)]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
mod tests {
    use super::{POST_CONST, POST_MATRIX, PRE_CONST, PRE_MATRIX};
    use crate::sm4::scalar::{AFFINE_B, affine_a, sbox_byte};

    /// Low byte of x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1 (SM4).
    const SM4_POLY_LOW: u8 = 0xF5;
    /// Low byte of x^8 + x^4 + x^3 + x + 1 (AES; what GFNI inverts in).
    const AES_POLY_LOW: u8 = 0x1B;

    fn gf_mul(mut a: u8, mut b: u8, poly_low: u8) -> u8 {
        let mut r = 0;
        while b != 0 {
            if b & 1 != 0 {
                r ^= a;
            }
            b >>= 1;
            let carry = a & 0x80 != 0;
            a <<= 1;
            if carry {
                a ^= poly_low;
            }
        }
        r
    }

    fn gf_inv(x: u8, poly_low: u8) -> u8 {
        (1..=255)
            .find(|&y| gf_mul(x, y, poly_low) == 1)
            .unwrap_or(0)
    }

    /// Smallest root of the SM4 polynomial in the AES field; mapping the
    /// SM4 generator to it defines the isomorphism `T`.
    fn root() -> u8 {
        (2..=255u8)
            .find(|&r| {
                let mut acc = 0u8;
                for bit in (0..=8).rev() {
                    acc = gf_mul(acc, r, AES_POLY_LOW);
                    acc ^= if bit == 8 {
                        1
                    } else {
                        (SM4_POLY_LOW >> bit) & 1
                    };
                }
                acc == 0
            })
            .expect("the SM4 polynomial splits in GF(2^8)")
    }

    fn iso(x: u8) -> u8 {
        let r = root();
        let mut power = 1u8;
        let mut out = 0u8;
        for j in 0..8 {
            if (x >> j) & 1 != 0 {
                out ^= power;
            }
            power = gf_mul(power, r, AES_POLY_LOW);
        }
        out
    }

    fn iso_inv(y: u8) -> u8 {
        (0..=255u8)
            .find(|&x| iso(x) == y)
            .expect("iso is a bijection")
    }

    /// Encodes a GF(2)-linear byte map as a GF2P8AFFINE matrix: output bit
    /// `i` is the parity of `x` AND matrix byte `7 - i` (Intel SDM).
    fn encode(f: impl Fn(u8) -> u8) -> u64 {
        let mut q = 0u64;
        for i in 0..8 {
            let mut row = 0u8;
            for j in 0..8 {
                if (f(1 << j) >> i) & 1 != 0 {
                    row |= 1 << j;
                }
            }
            q |= u64::from(row) << (8 * (7 - i));
        }
        q
    }

    /// Software model of GF2P8AFFINEQB on one byte.
    fn affine(x: u8, q: u64, b: i32) -> u8 {
        let mut out = 0u8;
        for i in 0..8 {
            let row = (q >> (8 * (7 - i))) as u8;
            out |= (((row & x).count_ones() & 1) as u8) << i;
        }
        out ^ b as u8
    }

    #[test]
    fn root_defines_a_field_isomorphism() {
        assert_eq!(root(), 0x23);
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(
                    iso(gf_mul(a, b, SM4_POLY_LOW)),
                    gf_mul(iso(a), iso(b), AES_POLY_LOW),
                    "T(a*b) != T(a)*T(b) for a=0x{a:02x} b=0x{b:02x}",
                );
            }
        }
    }

    #[test]
    fn constants_match_their_derivation() {
        assert_eq!(PRE_MATRIX, encode(|x| iso(affine_a(x))), "PRE_MATRIX = T·A");
        assert_eq!(PRE_CONST, i32::from(iso(AFFINE_B)), "PRE_CONST = T(B)");
        assert_eq!(
            POST_MATRIX,
            encode(|y| affine_a(iso_inv(y))),
            "POST_MATRIX = A·T⁻¹",
        );
        assert_eq!(POST_CONST, i32::from(AFFINE_B), "POST_CONST = B");
    }

    #[test]
    fn model_reproduces_the_sm4_sbox() {
        for x in 0..=255u8 {
            let y = affine(x, PRE_MATRIX, PRE_CONST);
            let s = affine(gf_inv(y, AES_POLY_LOW), POST_MATRIX, POST_CONST);
            assert_eq!(s, sbox_byte(x), "input 0x{x:02x}");
        }
    }
}
