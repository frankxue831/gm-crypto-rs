//! x86_64 GHASH multiplication via PCLMULQDQ.
//!
//! Uses Intel's carryless-multiplication instruction (`pclmulqdq`,
//! Westmere+ 2010 / AMD Bulldozer+ 2011) to compute `H · X` in
//! `GF(2^128) / (x^128 + x^7 + x^2 + x + 1)`.
//!
//! # Algorithm
//!
//! Same bit-reversal-within-byte transformation as [`super::software`]
//! to put inputs in "natural" polynomial-bit-order (bit `i` of u128 =
//! coefficient of `x^i`). Multiplication is then a 4-CLMUL schoolbook
//! over the 64-bit halves, and reduction folds the high-128 bits into
//! the low-128 bits via bit-serial shift-XOR with the reduction
//! constant `0x87` (= `x^7 + x^2 + x + 1` in natural rep).
//!
//! The CLMUL acceleration of the multiplication step alone is the
//! primary win; bit-serial reduction keeps the code small and
//! constant-time. A fast Barrett-style CLMUL-based reduction is a
//! candidate optimization for v0.9+ if profiling demands.

#![cfg(target_arch = "x86_64")]

use core::arch::x86_64::{
    __m128i, _mm_clmulepi64_si128, _mm_loadu_si128, _mm_setzero_si128, _mm_storeu_si128,
    _mm_xor_si128,
};

/// Reverse the bit order within a single byte.
#[inline]
const fn reverse_byte(b: u8) -> u8 {
    let b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4);
    let b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2);
    ((b & 0xAA) >> 1) | ((b & 0x55) << 1)
}

#[inline]
const fn natural_bytes(b: &[u8; 16]) -> [u8; 16] {
    let mut buf = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        buf[i] = reverse_byte(b[i]);
        i += 1;
    }
    buf
}

#[inline]
const fn from_natural_bytes(b: &[u8; 16]) -> [u8; 16] {
    natural_bytes(b)
}

/// GHASH multiplication via PCLMULQDQ.
///
/// # Safety
///
/// Caller must guarantee the host CPU supports PCLMULQDQ and SSE2. The
/// public entry point [`super::ghash_mul`] verifies this via
/// [`crate::detect::has_pclmulqdq`] (cached `cpufeatures` check) before
/// calling.
#[target_feature(enable = "pclmulqdq,sse2")]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn ghash_mul_clmul(h: &[u8; 16], x: &[u8; 16]) -> [u8; 16] {
    // Bit-reverse each byte so the standard CLMUL polynomial arithmetic
    // matches NIST GHASH bit ordering. After this transform, a `u128`
    // loaded little-endian from these bytes has bit i = coefficient of
    // x^i (i.e. "natural" polynomial representation).
    let h_n = natural_bytes(h);
    let x_n = natural_bytes(x);

    let h_vec = _mm_loadu_si128(h_n.as_ptr().cast::<__m128i>());
    let x_vec = _mm_loadu_si128(x_n.as_ptr().cast::<__m128i>());

    // Schoolbook 4-CLMUL: 64-bit halves a_lo (bits 0..64), a_hi (bits
    // 64..128). `imm8 = 0x00` multiplies a_lo·b_lo, `0x11` multiplies
    // a_hi·b_hi, `0x10` multiplies a_hi·b_lo, `0x01` multiplies
    // a_lo·b_hi. (Per Intel's documentation: imm8[4] selects b's
    // half, imm8[0] selects a's half.)
    let t00 = _mm_clmulepi64_si128(h_vec, x_vec, 0x00);
    let t01 = _mm_clmulepi64_si128(h_vec, x_vec, 0x01);
    let t10 = _mm_clmulepi64_si128(h_vec, x_vec, 0x10);
    let t11 = _mm_clmulepi64_si128(h_vec, x_vec, 0x11);

    // Each tXY is a 128-bit polynomial product. The full 256-bit
    // product P is laid out as:
    //   P[0..128]   = t00
    //   P[64..192]  ^= t01 ^ t10
    //   P[128..256] ^= t11
    //
    // We can compute this directly via 192-bit (24-byte) buffer:
    let p_low = _mm_xor_si128(_mm_setzero_si128(), t00);
    let p_high = _mm_xor_si128(_mm_setzero_si128(), t11);

    // Combine the middle products: t01 ^ t10 spans bits 64..192.
    let middle = _mm_xor_si128(t01, t10);

    // Store p_low, middle, p_high into a 32-byte scratch buffer
    // organized as bits 0..128 (p_low), bits 64..192 (middle XOR), bits
    // 128..256 (p_high). Then read out as a 32-byte polynomial product
    // and reduce.
    let mut scratch = [0u8; 32];
    let mut p_low_bytes = [0u8; 16];
    let mut p_high_bytes = [0u8; 16];
    let mut middle_bytes = [0u8; 16];
    _mm_storeu_si128(p_low_bytes.as_mut_ptr().cast::<__m128i>(), p_low);
    _mm_storeu_si128(p_high_bytes.as_mut_ptr().cast::<__m128i>(), p_high);
    _mm_storeu_si128(middle_bytes.as_mut_ptr().cast::<__m128i>(), middle);

    // scratch[0..16] = p_low
    // scratch[8..24] ^= middle (offset by 64 bits = 8 bytes)
    // scratch[16..32] ^= p_high
    scratch[..16].copy_from_slice(&p_low_bytes);
    for i in 0..16 {
        scratch[8 + i] ^= middle_bytes[i];
    }
    for i in 0..16 {
        scratch[16 + i] ^= p_high_bytes[i];
    }

    // Reduce the 32-byte polynomial product mod the GHASH reduction.
    // In natural rep, bit (128 + j) of the 256-bit product needs to be
    // XOR'd into bit (7 + j), (2 + j), (1 + j), (0 + j) of the low half
    // (mod 128 — but high bits of j stay below 128 since j < 128 and
    // 7 + j < 135). Since 7 + j can exceed 128, the reduction needs to
    // be applied iteratively from the highest bit down.
    //
    // Bit-serial reduction: for each high bit, shift down by 128 and
    // XOR the reduction polynomial. Equivalently, walk the high 128
    // bits from bit 255 down to bit 128, XORing 0x87 into bit (j - 121)
    // .. (j - 128). Cleaner: load scratch as two u128s and do 128
    // iterations of "shift the combined value down by one position",
    // applying reduction where needed.
    //
    // Simplest correct path: convert scratch back to a 256-bit value,
    // walk the high bits, XOR 0x87 shifted into the low half. Since
    // this is a public-data reduction (no secret-dependence in the
    // bit positions), the loop bound is fixed at 128 iterations.
    // Bit-serial reduction of the 256-bit polynomial product mod
    // `x^128 + x^7 + x^2 + x + 1`. Each set bit at polynomial position
    // `128 + i` contributes to positions {i, i+1, i+2, i+7}. When
    // `i + 7 >= 128`, the contribution lands in the high half itself —
    // a secondary reduction that the descending iteration order
    // absorbs by re-processing those high-half bits when we reach
    // their (lower) index. After 128 iterations every original and
    // induced high bit has been folded into the low half.
    let mut low = u128::from_le_bytes(scratch[..16].try_into().unwrap_or([0; 16]));
    let mut high = u128::from_le_bytes(scratch[16..].try_into().unwrap_or([0; 16]));

    let mut idx: i32 = 127;
    while idx >= 0 {
        #[allow(clippy::cast_sign_loss)]
        let i = idx as u32;
        let bit = (high >> i) & 1;
        let mask = 0u128.wrapping_sub(bit);

        let positions = [i, i + 1, i + 2, i + 7];
        for &p in &positions {
            if p < 128 {
                low ^= (1u128 << p) & mask;
            } else {
                // p < 256 always holds (i <= 127, p <= 134).
                high ^= (1u128 << (p - 128)) & mask;
            }
        }
        high &= !(1u128 << i);
        idx -= 1;
    }
    let _ = high;

    // Convert back to GHASH byte order.
    let out_natural = low.to_le_bytes();
    from_natural_bytes(&out_natural)
}

// Cross-check tests against the software reference live in
// `tests/ghash_lane_equivalence.rs` (integration tests can use `std`
// for skip-printing on hosts without PCLMULQDQ).
