//! Scalar bitsliced SM4 S-box primitives.
//!
//! Local re-implementation of the v0.4 W3 Boyar-Peralta Itoh-Tsujii
//! gate sequence (see [`super::sbox_x8`]'s module doc for the
//! re-implementation rationale: `gmcrypto_core::sm4::sbox_bitsliced`
//! is `pub(crate)`, so the sibling crate carries its own copy).
//!
//! Used by every SIMD entry point as the fallback path when the
//! target architecture doesn't have the relevant intrinsics, and by
//! the integration tests as the gold-standard reference for SIMD
//! lane equivalence.

/// SM4 GF(2^8) reduction polynomial constant.
pub(super) const SM4_GF_POLY: u8 = 0xF5;

/// Circulant matrix `A`'s first row. Row `i` is this byte rotated
/// right by `i` positions (MSB-first bit numbering).
const A_FIRST_ROW: u8 = 0xD3;

/// Affine constant `B` (additive).
pub(super) const AFFINE_B: u8 = 0xD3;

/// Pre-computed `A_FIRST_ROW.rotate_right(i)` for `i = 0..8`.
pub(super) const A_ROWS: [u8; 8] = [
    A_FIRST_ROW.rotate_right(0),
    A_FIRST_ROW.rotate_right(1),
    A_FIRST_ROW.rotate_right(2),
    A_FIRST_ROW.rotate_right(3),
    A_FIRST_ROW.rotate_right(4),
    A_FIRST_ROW.rotate_right(5),
    A_FIRST_ROW.rotate_right(6),
    A_FIRST_ROW.rotate_right(7),
];

/// Scalar `GF(2^8)` multiplication by [`SM4_GF_POLY`]. Russian-peasant
/// shift-and-XOR; constant-time over the bit pattern of `b`.
#[inline]
const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut r: u8 = 0;
    let mut i = 0;
    while i < 8 {
        let mask = 0u8.wrapping_sub(b & 1);
        r ^= a & mask;
        let high = 0u8.wrapping_sub((a >> 7) & 1);
        a = (a << 1) ^ (SM4_GF_POLY & high);
        b >>= 1;
        i += 1;
    }
    r
}

/// Scalar multiplicative inverse in `GF(2^8)` via Itoh-Tsujii
/// (`x^254` through 7 squarings + 6 multiplies). `gf_inv(0) = 0`.
#[inline]
const fn gf_inv(x: u8) -> u8 {
    let x2 = gf_mul(x, x);
    let x4 = gf_mul(x2, x2);
    let x8 = gf_mul(x4, x4);
    let x16 = gf_mul(x8, x8);
    let x32 = gf_mul(x16, x16);
    let x64 = gf_mul(x32, x32);
    let x128 = gf_mul(x64, x64);

    let r1 = gf_mul(x128, x64);
    let r2 = gf_mul(r1, x32);
    let r3 = gf_mul(r2, x16);
    let r4 = gf_mul(r3, x8);
    let r5 = gf_mul(r4, x4);
    gf_mul(r5, x2)
}

/// Scalar affine `A`: for each output bit `i`, compute parity of
/// `(A_ROWS[i] & x)`, then OR into bit position `7 - i`.
#[inline]
const fn affine_a(x: u8) -> u8 {
    let mut out: u8 = 0;
    let mut i = 0u32;
    while i < 8 {
        let row = A_ROWS[i as usize];
        let prod = row & x;
        let parity = (prod.count_ones() & 1) as u8;
        out |= parity << (7 - i);
        i += 1;
    }
    out
}

/// Scalar bitsliced SM4 S-box: `S(x) = A · INV(A·x ⊕ B) ⊕ B`.
///
/// Used directly as the per-byte scalar primitive by every
/// SIMD entry point's fallback path.
#[inline]
#[must_use]
pub(super) const fn sbox_byte(x: u8) -> u8 {
    let pre = affine_a(x) ^ AFFINE_B;
    let inv = gf_inv(pre);
    affine_a(inv) ^ AFFINE_B
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scalar `sbox_byte` reproduces well-known SM4 S-box entries.
    /// Spot-check the structure; the exhaustive table cross-check
    /// lives in `tests/lane_equivalence.rs`.
    #[test]
    fn scalar_sbox_self_consistent_on_zero_one() {
        assert_eq!(sbox_byte(0x00), 0xD6);
        assert_eq!(sbox_byte(0x01), 0x90);
    }
}
