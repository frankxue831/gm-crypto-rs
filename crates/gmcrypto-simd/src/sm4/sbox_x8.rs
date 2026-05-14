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
//!   real data; the upper 24 bytes are unused. v0.6 W6 added
//!   [`super::sbox_x32`] which uses the full 32-byte width for the
//!   `Sm4CbcDecryptor` batch fanout path.
//! - [`sbox_x8_scalar`] (always available) — calls the local
//!   single-block [`super::scalar::sbox_byte`] 8 times.
//!
//! # Algorithm — re-implementation note
//!
//! The Boyar-Peralta GF(2^8) Itoh-Tsujii gate sequence is duplicated
//! between this crate and `gmcrypto_core::sm4::sbox_bitsliced` rather
//! than shared via a widened `pub(crate)` visibility. CLAUDE.md
//! pins "Don't expose the bitsliced helpers publicly" — so the
//! sibling crate carries its own copy (in [`super::scalar`]) and
//! `tests/lane_equivalence.rs` cross-checks both paths against the
//! public GB/T 32907-2016 §6.2 S-box table.
//!
//! # Constant-time discipline
//!
//! Both paths are constant-time by construction. The AVX2 path uses
//! `_mm256_*` intrinsics with publicly-fixed loop counts; no table
//! lookups, no secret-dependent branches, no `_mm256_shuffle_*`
//! against secret-derived indices. The scalar path's gate sequence
//! mirrors the v0.4 W3 single-block bitslice already gated by the
//! existing `ct_sm4_encrypt_block_bitsliced` dudect target.

use super::scalar::sbox_byte;
use crate::detect::has_avx2;

/// Scalar fallback: 8 sequential calls into
/// [`super::scalar::sbox_byte`]. Always available; selected at
/// runtime when AVX2 is not present.
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
use core::arch::x86_64::{__m256i, _mm256_loadu_si256, _mm256_storeu_si256};

/// AVX2 byte-parallel SM4 S-box on 8 independent inputs.
///
/// Stages 8 input bytes into the low 8 lanes of a 256-bit register
/// (upper 24 lanes carry junk but are never read out) and runs the
/// shared AVX2 gate sequence from [`super::avx2`].
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

    let out = super::avx2::sbox_round(x);

    // Read the low 8 bytes back into a fixed-size array.
    let mut staged_out = [0u8; 32];
    _mm256_storeu_si256(staged_out.as_mut_ptr().cast::<__m256i>(), out);
    let mut result = [0u8; 8];
    result.copy_from_slice(&staged_out[..8]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

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
