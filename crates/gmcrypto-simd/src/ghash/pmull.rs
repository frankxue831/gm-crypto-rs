//! aarch64 GHASH multiplication via NEON PMULL64.
//!
//! Uses the ARMv8.0 Crypto Extensions `pmull`/`pmull2` instructions
//! (Rust intrinsics `vmull_p64` / `vmull_high_p64`) to compute `H · X`
//! in `GF(2^128) / (x^128 + x^7 + x^2 + x + 1)`.
//!
//! # Algorithm
//!
//! Same bit-reversal-within-byte transformation as [`super::software`]
//! and [`super::clmul`]. Schoolbook 4-PMULL64 over the 64-bit halves,
//! reduction via bit-serial shift-XOR with the reduction constant.
//!
//! # CPU feature requirement
//!
//! `vmull_p64` is part of the ARMv8.0 Crypto Extensions ("aes" feature
//! in the Rust target-feature vocabulary), which is optional in
//! ARMv8.0 but ubiquitous in practice (all Apple Silicon, all modern
//! aarch64 server / mobile chips). Runtime detection lives in
//! [`crate::detect::has_pmull`].

#![cfg(target_arch = "aarch64")]

use core::arch::aarch64::{
    veorq_u8, vld1q_u8, vmull_p64, vreinterpretq_u8_p128, vreinterpretq_u64_u8, vst1q_u8,
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

/// GHASH multiplication via NEON PMULL64.
///
/// # Safety
///
/// Caller must guarantee the host aarch64 CPU supports the AES
/// extension (PMULL64). The public entry point [`super::ghash_mul`]
/// verifies this via [`crate::detect::has_pmull`] (cached
/// `cpufeatures` check) before calling.
#[target_feature(enable = "neon,aes")]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn ghash_mul_pmull(h: &[u8; 16], x: &[u8; 16]) -> [u8; 16] {
    // Bit-reverse each byte (NIST GHASH → natural polynomial-bit order).
    let h_n = natural_bytes(h);
    let x_n = natural_bytes(x);

    // Load into NEON registers as 64-bit halves.
    let h_vec_u8 = vld1q_u8(h_n.as_ptr());
    let x_vec_u8 = vld1q_u8(x_n.as_ptr());
    let h_u64 = vreinterpretq_u64_u8(h_vec_u8);
    let x_u64 = vreinterpretq_u64_u8(x_vec_u8);

    // Extract 64-bit halves as `u64` for `vmull_p64`. Lane 0 is low
    // half (bits 0..64), lane 1 is high half (bits 64..128). The
    // intrinsic signature takes `p64` (which is a type alias for u64
    // in the polynomial-arithmetic sense).
    let h_lo: u64 = core::arch::aarch64::vgetq_lane_u64(h_u64, 0);
    let h_hi: u64 = core::arch::aarch64::vgetq_lane_u64(h_u64, 1);
    let x_lo: u64 = core::arch::aarch64::vgetq_lane_u64(x_u64, 0);
    let x_hi: u64 = core::arch::aarch64::vgetq_lane_u64(x_u64, 1);

    // Schoolbook 4-PMULL64 products. Each `vmull_p64` returns a
    // `poly128_t` which we reinterpret as `uint8x16_t` for XOR-friendly
    // handling.
    let t00 = vreinterpretq_u8_p128(vmull_p64(h_lo, x_lo));
    let t01 = vreinterpretq_u8_p128(vmull_p64(h_lo, x_hi));
    let t10 = vreinterpretq_u8_p128(vmull_p64(h_hi, x_lo));
    let t11 = vreinterpretq_u8_p128(vmull_p64(h_hi, x_hi));

    // Bring the four 128-bit products into the 256-bit polynomial-
    // product layout:
    //   P[0..128]   = t00
    //   P[64..192]  ^= t01 ^ t10
    //   P[128..256] ^= t11
    let middle = veorq_u8(t01, t10);

    // Store into a 32-byte scratch buffer, then reduce.
    let mut p_low_bytes = [0u8; 16];
    let mut p_high_bytes = [0u8; 16];
    let mut middle_bytes = [0u8; 16];
    vst1q_u8(p_low_bytes.as_mut_ptr(), t00);
    vst1q_u8(p_high_bytes.as_mut_ptr(), t11);
    vst1q_u8(middle_bytes.as_mut_ptr(), middle);

    let mut scratch = [0u8; 32];
    scratch[..16].copy_from_slice(&p_low_bytes);
    for i in 0..16 {
        scratch[8 + i] ^= middle_bytes[i];
    }
    for i in 0..16 {
        scratch[16 + i] ^= p_high_bytes[i];
    }

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

        // Four contribution positions in the 256-bit polynomial layout.
        let positions = [i, i + 1, i + 2, i + 7];
        for &p in &positions {
            if p < 128 {
                low ^= (1u128 << p) & mask;
            } else {
                // p < 256 always holds (i <= 127, p <= 134).
                high ^= (1u128 << (p - 128)) & mask;
            }
        }
        // Clear the bit just processed so the loop invariant ("bits
        // we've finished processing are zero") holds.
        high &= !(1u128 << i);
        idx -= 1;
    }
    let _ = high;

    // Convert back to GHASH byte order.
    let out_natural = low.to_le_bytes();
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = reverse_byte(out_natural[i]);
        i += 1;
    }
    out
}

// Cross-check tests against the software reference live in
// `tests/ghash_lane_equivalence.rs` (integration tests can use `std`
// for skip-printing on hosts without the AES extension).
