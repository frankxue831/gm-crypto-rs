//! Byte-parallel NEON primitives for the SM4 bitsliced S-box.
//!
//! Used by [`super::sbox_x16`] (v0.6 W6: 16 bytes packed across a
//! `uint8x16_t` NEON register; 4 SM4 blocks × 4 `tau` bytes per
//! round = 16 bytes per call). NEON is a baseline architectural
//! feature on `aarch64` (the ARMv8 reference manual mandates
//! Advanced SIMD on every conforming implementation), so this
//! module is `cfg(target_arch = "aarch64")` with no runtime CPU
//! detect — codex's phase 2 hint, confirmed in Q5.12 and Q6.3.
//!
//! NEON has native byte-wise shifts (`vshlq_n_u8` / `vshrq_n_u8`)
//! so the translation is cleaner than the AVX2 path (which has to
//! mask after `_mm256_srli_epi16` to avoid inter-byte bleed).

#![cfg(target_arch = "aarch64")]

use core::arch::aarch64::{
    uint8x16_t, vandq_u8, vdupq_n_u8, veorq_u8, vld1q_u8, vorrq_u8, vshlq_n_u8, vshrq_n_u8,
    vst1q_u8, vsubq_u8,
};

use super::scalar::{A_ROWS, AFFINE_B, SM4_GF_POLY};

/// Byte-parallel `GF(2^8)` multiplication by [`SM4_GF_POLY`] on
/// `uint8x16_t`. Russian-peasant shift-and-XOR, 8 unrolled
/// iterations.
///
/// # Safety
///
/// Caller must be running on `aarch64`. NEON is the architectural
/// baseline; no runtime feature check is required.
#[allow(unsafe_op_in_unsafe_fn)]
pub(super) unsafe fn gf_mul(mut a: uint8x16_t, mut b: uint8x16_t) -> uint8x16_t {
    let mut r = vdupq_n_u8(0);
    let one = vdupq_n_u8(1);
    let poly = vdupq_n_u8(SM4_GF_POLY);

    let mut i = 0;
    while i < 8 {
        // mask = 0xFF per byte if bit 0 of b set, else 0x00.
        // `vsubq_u8(0, bit0)` = `-bit0` wraps to 0xFF when bit0=1.
        let bit0 = vandq_u8(b, one);
        let mask = vsubq_u8(vdupq_n_u8(0), bit0);
        r = veorq_u8(r, vandq_u8(a, mask));

        // high = 0xFF per byte if bit 7 of a set, else 0x00.
        // Byte-wise right-shift by 7 isolates bit 7 to bit 0; negate
        // via `vsubq_u8(0, ...)` for the 0xFF/0x00 mask.
        let high_bit = vshrq_n_u8(a, 7);
        let high = vsubq_u8(vdupq_n_u8(0), high_bit);

        // a = (a << 1) ^ (poly & high). NEON `vshlq_n_u8` is
        // byte-wise (no inter-byte bleed); high bit is truncated
        // automatically.
        let a_shl1 = vshlq_n_u8(a, 1);
        a = veorq_u8(a_shl1, vandq_u8(poly, high));

        // b >>= 1, byte-wise (no inter-byte bleed on NEON).
        b = vshrq_n_u8(b, 1);

        i += 1;
    }
    r
}

/// Byte-parallel multiplicative inverse in `GF(2^8)` via Itoh-Tsujii.
///
/// # Safety
///
/// Same as [`gf_mul`].
#[allow(unsafe_op_in_unsafe_fn)]
pub(super) unsafe fn gf_inv(x: uint8x16_t) -> uint8x16_t {
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

/// Byte-parallel SM4 affine `A` on `uint8x16_t`.
///
/// # Safety
///
/// Same as [`gf_mul`].
#[allow(unsafe_op_in_unsafe_fn)]
pub(super) unsafe fn affine_a(x: uint8x16_t) -> uint8x16_t {
    let row0 = vdupq_n_u8(A_ROWS[0]);
    let row1 = vdupq_n_u8(A_ROWS[1]);
    let row2 = vdupq_n_u8(A_ROWS[2]);
    let row3 = vdupq_n_u8(A_ROWS[3]);
    let row4 = vdupq_n_u8(A_ROWS[4]);
    let row5 = vdupq_n_u8(A_ROWS[5]);
    let row6 = vdupq_n_u8(A_ROWS[6]);
    let row7 = vdupq_n_u8(A_ROWS[7]);

    // For each i ∈ 0..8: parity(row_i & x) → bit (7 - i) of output.
    // `parity` returns 0/1 in bit 0 of each byte; `vshlq_n_u8` is
    // byte-wise so the shift stays within each lane.
    let mut out = vdupq_n_u8(0);
    out = vorrq_u8(out, vshlq_n_u8(parity(vandq_u8(row0, x)), 7));
    out = vorrq_u8(out, vshlq_n_u8(parity(vandq_u8(row1, x)), 6));
    out = vorrq_u8(out, vshlq_n_u8(parity(vandq_u8(row2, x)), 5));
    out = vorrq_u8(out, vshlq_n_u8(parity(vandq_u8(row3, x)), 4));
    out = vorrq_u8(out, vshlq_n_u8(parity(vandq_u8(row4, x)), 3));
    out = vorrq_u8(out, vshlq_n_u8(parity(vandq_u8(row5, x)), 2));
    out = vorrq_u8(out, vshlq_n_u8(parity(vandq_u8(row6, x)), 1));
    out = vorrq_u8(out, parity(vandq_u8(row7, x)));
    out
}

/// Byte-parallel parity (XOR-tree) on `uint8x16_t`. Bit 0 of each
/// byte holds the parity; upper bits may carry junk.
///
/// # Safety
///
/// Same as [`gf_mul`].
#[allow(unsafe_op_in_unsafe_fn)]
pub(super) unsafe fn parity(x: uint8x16_t) -> uint8x16_t {
    let p = veorq_u8(x, vshrq_n_u8(x, 4));
    let p = veorq_u8(p, vshrq_n_u8(p, 2));
    let p = veorq_u8(p, vshrq_n_u8(p, 1));
    vandq_u8(p, vdupq_n_u8(1))
}

/// Compose the S-box gate sequence on a `uint8x16_t`:
/// `pre = affine_a(x) ^ B`, `inv = gf_inv(pre)`,
/// `out = affine_a(inv) ^ B`.
///
/// # Safety
///
/// Same as [`gf_mul`].
#[allow(unsafe_op_in_unsafe_fn)]
pub(super) unsafe fn sbox_round(x: uint8x16_t) -> uint8x16_t {
    let b_const = vdupq_n_u8(AFFINE_B);
    let pre = veorq_u8(affine_a(x), b_const);
    let inv = gf_inv(pre);
    veorq_u8(affine_a(inv), b_const)
}

/// Convenience wrapper for the load/store framing of a
/// 16-byte buffer through the NEON gate sequence.
///
/// # Safety
///
/// Same as [`gf_mul`].
#[allow(unsafe_op_in_unsafe_fn)]
pub(super) unsafe fn sbox_x16_impl(input: &[u8; 16]) -> [u8; 16] {
    let x = vld1q_u8(input.as_ptr());
    let out = sbox_round(x);
    let mut result = [0u8; 16];
    vst1q_u8(result.as_mut_ptr(), out);
    result
}
