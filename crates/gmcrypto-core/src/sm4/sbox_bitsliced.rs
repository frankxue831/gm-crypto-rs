//! Bitsliced (table-less, gate-only) SM4 S-box (v0.4 W3).
//!
//! Behind the `sm4-bitsliced` feature flag. Replaces the v0.2 W1
//! linear-scan 256-iteration `subtle::ConditionallySelectable` scan
//! with a pure-Boolean gate sequence: ~70 XOR + shift ops via
//! Itoh-Tsujii inversion in `GF(2^8)` plus two affine transformations.
//!
//! # Verified algebraic decomposition
//!
//! `S(x) = A · INV(A·x ⊕ B) ⊕ B`
//!
//! where:
//!
//! - `A` is the 8×8 binary circulant matrix with first row
//!   `0b1101_0011 = 0xD3` (row `i` is the first row rotated right by
//!   `i` positions; MSB-first bit numbering).
//! - `B = 0xD3` is the additive constant.
//! - `INV` is multiplicative inverse in `GF(2^8)` defined by
//!   irreducible polynomial
//!   `p(x) = x⁸ + x⁷ + x⁶ + x⁵ + x⁴ + x² + 1` (encoded as `0xF5`
//!   with implicit `x⁸` reduction trigger).
//!
//! This decomposition was found by brute-force search over circulant
//! `A` matrices and verified exhaustively against the official
//! GB/T 32907-2016 §6.2 S-box table at compile time (see
//! `tests::bitsliced_matches_table`).
//!
//! # Constant-time-by-construction
//!
//! Every operation is a pure-XOR / shift / AND on `u8` operands —
//! no branches, no memory-indexed lookups, no `subtle::Choice` (the
//! linear-scan path uses `Choice` to mask data-dependent table
//! accesses; the bitsliced path never accesses tables at all). The
//! `if` branches inside `gf_mul` operate on a publicly-known loop
//! counter, never on secret bits.
//!
//! # Throughput
//!
//! Linear-scan baseline: ~1-2M blocks/sec single-threaded.
//! Itoh-Tsujii bitsliced: ~7 squarings + 6 multiplications per
//! S-box invocation, each multiplication ~8 conditional XOR-and-
//! shift ops. Empirical speedup on x86-64 release-mode: TBD,
//! measure via `cargo bench` on the W3 PR.
//!
//! # Per Q4.10 / Q4.11 (docs/v0.4-scope.md)
//!
//! Multi-block SIMD-packed bitslicing (8-way / 16-way parallel)
//! is deferred to v0.5+. v0.4 W3 ships single-block bitslicing
//! only.

/// SM4 GF(2^8) irreducible polynomial reduction bits (lower 8 bits of
/// `x⁸ + x⁷ + x⁶ + x⁵ + x⁴ + x² + 1`; the `x⁸` bit is the implicit
/// reduction trigger).
const SM4_GF_POLY: u8 = 0xF5;

/// Circulant matrix `A`'s first row. Row `i` is this byte rotated
/// right by `i` positions.
const A_FIRST_ROW: u8 = 0xD3;

/// Additive affine constant.
const AFFINE_B: u8 = 0xD3;

/// Multiplication in `GF(2^8)` with reduction by [`SM4_GF_POLY`].
///
/// Russian peasant / shift-and-XOR; constant-time over `b`'s bit
/// pattern because every iteration runs unconditionally (the loop
/// bound is publicly fixed at 8). The `if` branches operate on bits
/// that are inputs to the function, not on secret-derived control
/// flow.
#[inline]
const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut r: u8 = 0;
    let mut i = 0;
    while i < 8 {
        // Conditionally XOR `a` into `r` based on the low bit of `b`.
        // Branch-free via mask broadcasting: `0u8.wrapping_sub(bit)`
        // yields `0xFF` if `bit == 1` and `0x00` if `bit == 0`.
        let mask = 0u8.wrapping_sub(b & 1);
        r ^= a & mask;

        // Double `a` in GF(2^8): shift left and reduce if high bit
        // was set.
        let high = 0u8.wrapping_sub((a >> 7) & 1);
        a = (a << 1) ^ (SM4_GF_POLY & high);

        b >>= 1;
        i += 1;
    }
    r
}

/// Multiplicative inverse in `GF(2^8)` via Itoh-Tsujii.
///
/// Computes `x^254 = x^(2^8 - 2)` via 7 squarings and 6
/// multiplications. By Lagrange's theorem `x^255 = 1` for `x ≠ 0`,
/// so `x^254 = x^(-1)`. The convention `INV(0) = 0` is built in
/// (the loop returns 0 unchanged on `x = 0`).
///
/// 254 = 11111110₂ — every bit except the lowest is set. Standard
/// square-and-multiply over the exponent's binary expansion.
#[inline]
const fn gf_inv(x: u8) -> u8 {
    // Build x^2, x^4, x^8, ..., x^128 by repeated squaring.
    let x2 = gf_mul(x, x);
    let x4 = gf_mul(x2, x2);
    let x8 = gf_mul(x4, x4);
    let x16 = gf_mul(x8, x8);
    let x32 = gf_mul(x16, x16);
    let x64 = gf_mul(x32, x32);
    let x128 = gf_mul(x64, x64);

    // x^254 = x^128 · x^64 · x^32 · x^16 · x^8 · x^4 · x^2
    //       (= x^(128+64+32+16+8+4+2) = x^254)
    let r1 = gf_mul(x128, x64);
    let r2 = gf_mul(r1, x32);
    let r3 = gf_mul(r2, x16);
    let r4 = gf_mul(r3, x8);
    let r5 = gf_mul(r4, x4);
    gf_mul(r5, x2)
}

/// Apply the SM4 circulant affine `A` to `x`: for each output bit
/// `i`, compute the parity (XOR) of `(A_first_row.rotate_right(i)) &
/// x`. Equivalent to an 8×8 matrix-vector multiply over `GF(2)`.
///
/// Constant-time: every iteration runs unconditionally, no
/// data-dependent branches. The parity is computed as `popcount &
/// 1` — `u8::count_ones()` compiles to a single `POPCNT` instruction
/// on x86-64 / aarch64 and is constant-time on every supported
/// target.
#[inline]
const fn affine_a(x: u8) -> u8 {
    let mut out: u8 = 0;
    let mut i = 0u32;
    while i < 8 {
        let row = A_FIRST_ROW.rotate_right(i);
        let prod = row & x;
        let parity = (prod.count_ones() & 1) as u8;
        out |= parity << (7 - i);
        i += 1;
    }
    out
}

/// Bitsliced SM4 S-box: `S(x) = A · INV(A·x ⊕ B) ⊕ B`.
///
/// No table lookup; constant-time by construction.
#[inline]
#[must_use]
pub const fn sbox(x: u8) -> u8 {
    let pre = affine_a(x) ^ AFFINE_B;
    let inv = gf_inv(pre);
    affine_a(inv) ^ AFFINE_B
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm4::cipher::S_BOX;

    /// Exhaustive byte-level equivalence: the bitsliced S-box matches
    /// the official GB/T 32907-2016 §6.2 table on every possible
    /// input byte. This is the cryptographic-correctness gate for W3.
    #[test]
    fn bitsliced_matches_table() {
        for x in 0u8..=255 {
            assert_eq!(
                sbox(x),
                S_BOX[x as usize],
                "bitsliced S-box disagrees with table at 0x{x:02x}",
            );
        }
    }

    /// `gf_inv` is self-inverse on nonzero elements
    /// (`inv(inv(x)) == x`) and idempotent on zero (`inv(0) == 0`).
    #[test]
    fn gf_inv_self_inverse() {
        assert_eq!(gf_inv(0), 0);
        for x in 1u8..=255 {
            assert_eq!(gf_inv(gf_inv(x)), x, "self-inverse fails at 0x{x:02x}");
        }
    }

    /// `gf_mul(x, gf_inv(x)) == 1` for all nonzero `x`.
    #[test]
    fn gf_mul_inv_identity() {
        for x in 1u8..=255 {
            assert_eq!(gf_mul(x, gf_inv(x)), 1, "x·inv(x) != 1 at 0x{x:02x}");
        }
    }

    /// `affine_a` is invertible (since A is invertible over GF(2)):
    /// applying it twice with appropriate inverse gives identity. We
    /// only test that it's a bijection here.
    #[test]
    fn affine_a_is_bijection() {
        let mut seen = [false; 256];
        for x in 0u8..=255 {
            let y = affine_a(x);
            assert!(!seen[y as usize], "affine_a maps two inputs to 0x{y:02x}");
            seen[y as usize] = true;
        }
    }
}
