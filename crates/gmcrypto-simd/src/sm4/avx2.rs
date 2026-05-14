//! Byte-parallel AVX2 primitives for the SM4 bitsliced S-box.
//!
//! Shared between [`super::sbox_x8`] (phase 2: 8 bytes packed in the
//! low lanes of `__m256i`) and [`super::sbox_x32`] (phase 3: full
//! 32 bytes packed across the entire register). The same gate
//! sequence runs at both widths; only the load/store framing
//! differs.
//!
//! Every function in this module is `#[target_feature(enable =
//! "avx2")] unsafe fn` and `pub(super) unsafe fn`. Callers must
//! guarantee the host CPU supports AVX2 — the dispatch entry points
//! ([`super::sbox_x8::sbox_x8`], [`super::sbox_x32::sbox_x32`])
//! verify via the cached `cpufeatures` check
//! ([`crate::has_avx2`]) before invoking.

#![cfg(target_arch = "x86_64")]

use core::arch::x86_64::{
    __m256i, _mm256_add_epi8, _mm256_and_si256, _mm256_cmpgt_epi8, _mm256_or_si256,
    _mm256_set1_epi8, _mm256_setzero_si256, _mm256_slli_epi16, _mm256_srli_epi16, _mm256_sub_epi8,
    _mm256_xor_si256,
};

use super::scalar::{A_ROWS, AFFINE_B, SM4_GF_POLY};

/// Byte-parallel `GF(2^8)` multiplication by [`SM4_GF_POLY`].
///
/// Russian-peasant shift-and-XOR, byte-parallel across all 32 lanes
/// of the input `__m256i`s. Constant-time over `b`'s bit pattern
/// (the loop bound is publicly fixed at 8).
///
/// # Safety
///
/// Caller must guarantee AVX2 support on the host CPU.
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
pub(super) unsafe fn gf_mul(mut a: __m256i, mut b: __m256i) -> __m256i {
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

/// Byte-parallel multiplicative inverse in `GF(2^8)` via Itoh-Tsujii.
///
/// # Safety
///
/// Caller must guarantee AVX2 support on the host CPU.
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
pub(super) unsafe fn gf_inv(x: __m256i) -> __m256i {
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

/// Byte-parallel SM4 affine `A`: per output bit `i ∈ 0..8`, compute
/// parity of `(A_ROWS[i] & x)`, then OR into bit position `7 - i`.
///
/// # Safety
///
/// Caller must guarantee AVX2 support on the host CPU.
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
pub(super) unsafe fn affine_a(x: __m256i) -> __m256i {
    let row0 = _mm256_set1_epi8(A_ROWS[0] as i8);
    let row1 = _mm256_set1_epi8(A_ROWS[1] as i8);
    let row2 = _mm256_set1_epi8(A_ROWS[2] as i8);
    let row3 = _mm256_set1_epi8(A_ROWS[3] as i8);
    let row4 = _mm256_set1_epi8(A_ROWS[4] as i8);
    let row5 = _mm256_set1_epi8(A_ROWS[5] as i8);
    let row6 = _mm256_set1_epi8(A_ROWS[6] as i8);
    let row7 = _mm256_set1_epi8(A_ROWS[7] as i8);

    // For each i ∈ 0..8: parity(row_i & x) ⟶ bit (7 - i) of output.
    // `parity` returns 0/1 in bit 0 of each byte; epi16 SHL by
    // (7 - i) for i ∈ 0..8 shifts that bit into position (7 - i)
    // within each byte without crossing byte boundaries (shift
    // amounts < 8 keep input-bit-0 within its own byte).
    let mut out = _mm256_setzero_si256();
    out = _mm256_or_si256(out, _mm256_slli_epi16(parity(_mm256_and_si256(row0, x)), 7));
    out = _mm256_or_si256(out, _mm256_slli_epi16(parity(_mm256_and_si256(row1, x)), 6));
    out = _mm256_or_si256(out, _mm256_slli_epi16(parity(_mm256_and_si256(row2, x)), 5));
    out = _mm256_or_si256(out, _mm256_slli_epi16(parity(_mm256_and_si256(row3, x)), 4));
    out = _mm256_or_si256(out, _mm256_slli_epi16(parity(_mm256_and_si256(row4, x)), 3));
    out = _mm256_or_si256(out, _mm256_slli_epi16(parity(_mm256_and_si256(row5, x)), 2));
    out = _mm256_or_si256(out, _mm256_slli_epi16(parity(_mm256_and_si256(row6, x)), 1));
    out = _mm256_or_si256(out, parity(_mm256_and_si256(row7, x)));
    out
}

/// Byte-parallel parity (XOR of all 8 bits per byte) via the
/// standard XOR-tree reduction. Output: bit 0 of each byte is the
/// parity; upper bits within each byte may carry junk (caller masks
/// or ignores).
///
/// # Safety
///
/// Caller must guarantee AVX2 support on the host CPU.
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
pub(super) unsafe fn parity(x: __m256i) -> __m256i {
    let p = _mm256_xor_si256(x, _mm256_srli_epi16(x, 4));
    let p = _mm256_xor_si256(p, _mm256_srli_epi16(p, 2));
    let p = _mm256_xor_si256(p, _mm256_srli_epi16(p, 1));
    _mm256_and_si256(p, _mm256_set1_epi8(1))
}

/// Compose the S-box gate sequence on a 32-byte-packed AVX2
/// register: `pre = affine_a(x) ^ B`, `inv = gf_inv(pre)`,
/// `out = affine_a(inv) ^ B`.
///
/// Used by both `sbox_x8` (which stages 8 input bytes into the low
/// lanes and ignores the upper 24 after the round) and `sbox_x32`
/// (which packs the full 32 bytes).
///
/// # Safety
///
/// Caller must guarantee AVX2 support on the host CPU.
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
pub(super) unsafe fn sbox_round(x: __m256i) -> __m256i {
    let b_const = _mm256_set1_epi8(AFFINE_B as i8);
    let pre = _mm256_xor_si256(affine_a(x), b_const);
    let inv = gf_inv(pre);
    _mm256_xor_si256(affine_a(inv), b_const)
}
