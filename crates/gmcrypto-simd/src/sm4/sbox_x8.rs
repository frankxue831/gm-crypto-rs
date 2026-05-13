//! 8-way packed bitsliced SM4 S-box (v0.5 W4 phase 2).
//!
//! Public entry point: [`sbox_x8`]. Operates on 8 independent S-box
//! inputs packed as `[u8; 8]`, returning `[u8; 8]`. Internally
//! dispatches to one of two paths:
//!
//! - [`sbox_x8_avx2`] (x86_64 only, guarded by runtime AVX2 detection
//!   via [`crate::has_avx2`]) — translates the v0.4 W3 single-block
//!   Itoh-Tsujii gate sequence to byte-parallel AVX2 intrinsics on
//!   `__m256i`. Only the low 8 bytes of the 256-bit register carry
//!   real data; the upper 24 bytes are unused (phase 2 trade-off —
//!   phase 3 widens the packing to 32 bytes/lane via the
//!   `Sm4CbcDecryptor` fanout path).
//! - [`sbox_x8_scalar`] (always available) — calls the local
//!   single-block [`sbox_byte`] 8 times.
//!
//! # Algorithm — re-implementation note
//!
//! The Boyar-Peralta GF(2^8) Itoh-Tsujii gate sequence is duplicated
//! between this crate and `gmcrypto_core::sm4::sbox_bitsliced` rather
//! than shared via a widened `pub(crate)` visibility. CLAUDE.md
//! pins "Don't expose the bitsliced helpers publicly" — so the
//! sibling crate carries its own copy and the
//! `tests/lane_equivalence.rs` integration test cross-checks both
//! paths against the public GB/T 32907-2016 §6.2 S-box table.
//!
//! # Constant-time discipline
//!
//! Both paths are constant-time by construction. The AVX2 path uses
//! `_mm256_*` intrinsics with publicly-fixed loop counts; no table
//! lookups, no secret-dependent branches, no `_mm256_shuffle_*`
//! against secret-derived indices. The scalar path's gate sequence
//! mirrors the v0.4 W3 single-block bitslice already gated by the
//! existing `ct_sm4_encrypt_block_bitsliced` dudect target.

use crate::detect::has_avx2;

/// SM4 GF(2^8) reduction polynomial constant.
const SM4_GF_POLY: u8 = 0xF5;

/// Circulant matrix `A`'s first row. Row `i` is this byte rotated
/// right by `i` positions (MSB-first bit numbering).
const A_FIRST_ROW: u8 = 0xD3;

/// Affine constant `B` (additive).
const AFFINE_B: u8 = 0xD3;

/// Pre-computed `A_FIRST_ROW.rotate_right(i)` for `i = 0..8`.
const A_ROWS: [u8; 8] = [
    A_FIRST_ROW.rotate_right(0),
    A_FIRST_ROW.rotate_right(1),
    A_FIRST_ROW.rotate_right(2),
    A_FIRST_ROW.rotate_right(3),
    A_FIRST_ROW.rotate_right(4),
    A_FIRST_ROW.rotate_right(5),
    A_FIRST_ROW.rotate_right(6),
    A_FIRST_ROW.rotate_right(7),
];

// ============================================================
// Scalar path — local re-implementation of the v0.4 W3 gate sequence
// ============================================================

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
#[inline]
#[must_use]
const fn sbox_byte(x: u8) -> u8 {
    let pre = affine_a(x) ^ AFFINE_B;
    let inv = gf_inv(pre);
    affine_a(inv) ^ AFFINE_B
}

/// Scalar fallback: 8 sequential calls into [`sbox_byte`]. Always
/// available; selected at runtime when AVX2 is not present.
#[must_use]
pub fn sbox_x8_scalar(input: &[u8; 8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    let mut i = 0;
    while i < 8 {
        out[i] = sbox_byte(input[i]);
        i += 1;
    }
    out
}

// ============================================================
// Dispatch
// ============================================================

/// 8-way packed bitsliced SM4 S-box dispatch.
///
/// On x86_64 with AVX2 available at runtime, calls
/// [`sbox_x8_avx2`]. Otherwise delegates to [`sbox_x8_scalar`].
///
/// Byte-identical output to the v0.4 W3 single-block bitslice for
/// every input byte across every lane (verified exhaustively in
/// `tests/lane_equivalence.rs`).
#[must_use]
#[inline]
pub fn sbox_x8(input: &[u8; 8]) -> [u8; 8] {
    #[cfg(target_arch = "x86_64")]
    {
        if has_avx2() {
            // SAFETY: `has_avx2()` returned `true`, so the running
            // CPU supports AVX2 and the AVX2 intrinsics inside
            // `sbox_x8_avx2` are sound to invoke. The function takes
            // a fixed-size array reference and returns a fixed-size
            // array by value — no raw pointers cross the unsafe
            // boundary.
            return unsafe { sbox_x8_avx2(input) };
        }
    }
    let _ = has_avx2();
    sbox_x8_scalar(input)
}

// ============================================================
// x86_64 AVX2 path
// ============================================================

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m256i, _mm256_add_epi8, _mm256_and_si256, _mm256_cmpgt_epi8, _mm256_loadu_si256,
    _mm256_or_si256, _mm256_set1_epi8, _mm256_setzero_si256, _mm256_slli_epi16, _mm256_srli_epi16,
    _mm256_storeu_si256, _mm256_sub_epi8, _mm256_xor_si256,
};

/// AVX2 byte-parallel SM4 S-box on 8 independent inputs.
///
/// Direct gate-by-gate translation of the scalar path to byte-
/// parallel AVX2 intrinsics on `__m256i`. The 8 input bytes occupy
/// the low 8 bytes of the 256-bit register; the upper 24 bytes
/// carry junk and are never read out.
///
/// # Safety
///
/// Caller must guarantee the host CPU supports AVX2. The public
/// entry point [`sbox_x8`] verifies this via [`has_avx2`] (cached
/// `cpufeatures` check) before calling.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn sbox_x8_avx2(input: &[u8; 8]) -> [u8; 8] {
    // Stage the 8 input bytes into a 32-byte buffer; only the low 8
    // bytes carry real data, the upper 24 bytes are zero-padded.
    let mut staged = [0u8; 32];
    staged[..8].copy_from_slice(input);
    let x = _mm256_loadu_si256(staged.as_ptr().cast::<__m256i>());

    let b_const = _mm256_set1_epi8(AFFINE_B as i8);

    // pre = affine_a(x) ^ B
    let pre = _mm256_xor_si256(affine_a_simd(x), b_const);
    // inv = gf_inv(pre)
    let inv = gf_inv_simd(pre);
    // out = affine_a(inv) ^ B
    let out = _mm256_xor_si256(affine_a_simd(inv), b_const);

    // Read the low 8 bytes back into a fixed-size array.
    let mut staged_out = [0u8; 32];
    _mm256_storeu_si256(staged_out.as_mut_ptr().cast::<__m256i>(), out);
    let mut result = [0u8; 8];
    result.copy_from_slice(&staged_out[..8]);
    result
}

/// Byte-parallel `GF(2^8)` multiplication by [`SM4_GF_POLY`].
///
/// # Safety
///
/// Same AVX2 precondition as the caller.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn gf_mul_simd(mut a: __m256i, mut b: __m256i) -> __m256i {
    let mut r = _mm256_setzero_si256();
    let one = _mm256_set1_epi8(1);
    let poly = _mm256_set1_epi8(SM4_GF_POLY as i8);
    let mask_lo7 = _mm256_set1_epi8(0x7F);

    let mut i = 0;
    while i < 8 {
        // mask = 0xFF per byte if bit 0 of b set, else 0x00.
        let bit0 = _mm256_and_si256(b, one);
        let mask = _mm256_sub_epi8(_mm256_setzero_si256(), bit0);
        r = _mm256_xor_si256(r, _mm256_and_si256(a, mask));

        // high = 0xFF per byte if bit 7 of a set, else 0x00.
        // `cmpgt_epi8(0, a)` treats `a` as signed; `0 > a` iff bit 7
        // of `a` is set.
        let high = _mm256_cmpgt_epi8(_mm256_setzero_si256(), a);

        // Byte-wise SHL by 1: `a + a` wraps within each byte, so
        // the high bit is naturally truncated.
        let a_shl1 = _mm256_add_epi8(a, a);
        a = _mm256_xor_si256(a_shl1, _mm256_and_si256(poly, high));

        // Byte-wise SHR by 1: `srli_epi16` bleeds the high byte's
        // bit 0 into the low byte's bit 7 within each 16-bit lane,
        // so mask off bit 7 of every byte.
        let b_shr1 = _mm256_srli_epi16(b, 1);
        b = _mm256_and_si256(b_shr1, mask_lo7);

        i += 1;
    }
    r
}

/// Byte-parallel multiplicative inverse in `GF(2^8)` via
/// Itoh-Tsujii.
///
/// # Safety
///
/// Same AVX2 precondition as the caller.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn gf_inv_simd(x: __m256i) -> __m256i {
    let x2 = gf_mul_simd(x, x);
    let x4 = gf_mul_simd(x2, x2);
    let x8 = gf_mul_simd(x4, x4);
    let x16 = gf_mul_simd(x8, x8);
    let x32 = gf_mul_simd(x16, x16);
    let x64 = gf_mul_simd(x32, x32);
    let x128 = gf_mul_simd(x64, x64);

    let r1 = gf_mul_simd(x128, x64);
    let r2 = gf_mul_simd(r1, x32);
    let r3 = gf_mul_simd(r2, x16);
    let r4 = gf_mul_simd(r3, x8);
    let r5 = gf_mul_simd(r4, x4);
    gf_mul_simd(r5, x2)
}

/// Byte-parallel SM4 affine `A`: per output bit `i ∈ 0..8`, compute
/// parity of `(A_ROWS[i] & x)`, then OR into bit position `7 - i`.
///
/// # Safety
///
/// Same AVX2 precondition as the caller.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn affine_a_simd(x: __m256i) -> __m256i {
    let mut out = _mm256_setzero_si256();
    let row0 = _mm256_set1_epi8(A_ROWS[0] as i8);
    let row1 = _mm256_set1_epi8(A_ROWS[1] as i8);
    let row2 = _mm256_set1_epi8(A_ROWS[2] as i8);
    let row3 = _mm256_set1_epi8(A_ROWS[3] as i8);
    let row4 = _mm256_set1_epi8(A_ROWS[4] as i8);
    let row5 = _mm256_set1_epi8(A_ROWS[5] as i8);
    let row6 = _mm256_set1_epi8(A_ROWS[6] as i8);
    let row7 = _mm256_set1_epi8(A_ROWS[7] as i8);

    // For each i ∈ 0..8: parity(row_i & x) ⟶ bit (7 - i) of output.
    // parity_simd returns 0/1 in bit 0 of each byte; epi16 SHL by
    // (7 - i) for i ∈ 0..8 shifts that bit into position (7 - i)
    // within each byte without crossing byte boundaries (shift
    // amounts < 8 keep input-bit-0 within its own byte).
    out = _mm256_or_si256(
        out,
        _mm256_slli_epi16(parity_simd(_mm256_and_si256(row0, x)), 7),
    );
    out = _mm256_or_si256(
        out,
        _mm256_slli_epi16(parity_simd(_mm256_and_si256(row1, x)), 6),
    );
    out = _mm256_or_si256(
        out,
        _mm256_slli_epi16(parity_simd(_mm256_and_si256(row2, x)), 5),
    );
    out = _mm256_or_si256(
        out,
        _mm256_slli_epi16(parity_simd(_mm256_and_si256(row3, x)), 4),
    );
    out = _mm256_or_si256(
        out,
        _mm256_slli_epi16(parity_simd(_mm256_and_si256(row4, x)), 3),
    );
    out = _mm256_or_si256(
        out,
        _mm256_slli_epi16(parity_simd(_mm256_and_si256(row5, x)), 2),
    );
    out = _mm256_or_si256(
        out,
        _mm256_slli_epi16(parity_simd(_mm256_and_si256(row6, x)), 1),
    );
    out = _mm256_or_si256(out, parity_simd(_mm256_and_si256(row7, x)));
    out
}

/// Byte-parallel parity (XOR of all 8 bits per byte) via the
/// standard XOR-tree reduction. Output: bit 0 of each byte is the
/// parity; upper bits within each byte may carry junk (caller masks
/// or ignores).
///
/// # Safety
///
/// Same AVX2 precondition as the caller.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn parity_simd(x: __m256i) -> __m256i {
    let p = _mm256_xor_si256(x, _mm256_srli_epi16(x, 4));
    let p = _mm256_xor_si256(p, _mm256_srli_epi16(p, 2));
    let p = _mm256_xor_si256(p, _mm256_srli_epi16(p, 1));
    _mm256_and_si256(p, _mm256_set1_epi8(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scalar `sbox_byte` reproduces the v0.4 W3 single-block bitslice
    /// on every input byte. Spot-check the structure; the exhaustive
    /// table cross-check lives in `tests/lane_equivalence.rs`.
    #[test]
    fn scalar_sbox_self_consistent_on_zero_one() {
        // S(0) = 0xD6 (well-known SM4 S-box entry).
        assert_eq!(sbox_byte(0x00), 0xD6);
        // S(1) = 0x90.
        assert_eq!(sbox_byte(0x01), 0x90);
    }

    /// Mixed-lane scalar test: 8 distinct inputs per call.
    #[test]
    fn scalar_mixed_lanes() {
        let input: [u8; 8] = [0x00, 0x01, 0x55, 0xAA, 0xFF, 0x80, 0x7F, 0x42];
        let out = sbox_x8_scalar(&input);
        for (lane, (&inp, &got)) in input.iter().zip(out.iter()).enumerate() {
            let expected = sbox_byte(inp);
            assert_eq!(
                got, expected,
                "lane {lane} disagrees at input 0x{inp:02x}: got 0x{got:02x}, want 0x{expected:02x}",
            );
        }
    }
}
