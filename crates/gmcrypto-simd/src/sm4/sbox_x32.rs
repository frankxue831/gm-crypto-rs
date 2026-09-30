//! 32-way packed bitsliced SM4 S-box (v0.6 W6).
//!
//! Public entry point: [`sbox_x32`]. Operates on 32 independent
//! S-box inputs packed as `[u8; 32]`, returning `[u8; 32]`. The
//! intended consumer is `gmcrypto_core::sm4::cbc_streaming::
//! Sm4CbcDecryptor::process_chunk`'s 8-block batched CBC-decrypt
//! fanout: 8 SM4 blocks × 4 `tau` bytes per round = 32 bytes per
//! call, zero wasted lanes (vs phase 2's [`super::sbox_x8`] which
//! uses only 8 of the 32 lanes per round).
//!
//! # Dispatch
//!
//! - On `x86_64` with AVX2 available at runtime: `sbox_x32_avx2`
//!   — the full 32-byte AVX2 path. Same shared gate sequence as
//!   [`super::sbox_x8`] (`super::avx2::sbox_round`); the only
//!   difference is no staging-buffer overhead.
//! - Elsewhere (non-x86_64, or x86_64 without AVX2): falls back to
//!   [`sbox_x32_scalar`] — a 32-iteration loop calling the local
//!   single-block `super::scalar::sbox_byte`. Designed so the
//!   non-AVX2 fallback is not slower than calling
//!   `super::sbox_x8_scalar` four times (codex flag #1 from the
//!   v0.6 W6 phase 3 scope consultation).
//!
//! # Constant-time discipline
//!
//! Same as [`super::sbox_x8`]: shared AVX2 gate sequence (no table
//! lookups, no secret-derived branches); scalar path is the same
//! gate-only `sbox_byte` from `super::scalar`.

use super::scalar::sbox_byte;
use crate::detect::has_avx2;

/// Scalar fallback: 32 sequential calls into
/// `super::scalar::sbox_byte`. Always available.
#[must_use]
pub fn sbox_x32_scalar(input: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = sbox_byte(input[i]);
        i += 1;
    }
    out
}

/// 32-way packed bitsliced SM4 S-box dispatch.
///
/// On `x86_64` with AVX2: calls `sbox_x32_avx2`. Otherwise
/// [`sbox_x32_scalar`].
///
/// Byte-identical output to applying `super::scalar::sbox_byte`
/// to each input byte (verified exhaustively in
/// `tests/lane_position_x32.rs` with lane-position-shifted sweeps
/// per Q6.8 / codex's phase 3 flag #4).
#[must_use]
#[inline]
pub fn sbox_x32(input: &[u8; 32]) -> [u8; 32] {
    #[cfg(target_arch = "x86_64")]
    {
        if has_avx2() {
            // SAFETY: `has_avx2()` returned `true`, so the host CPU
            // supports AVX2 and the AVX2 intrinsics inside
            // `sbox_x32_avx2` are sound to invoke. Fixed-size array
            // reference in; fixed-size array out — no raw pointers
            // cross the unsafe boundary.
            return unsafe { sbox_x32_avx2(input) };
        }
    }
    let _ = has_avx2();
    sbox_x32_scalar(input)
}

// ============================================================
// x86_64 AVX2 path
// ============================================================

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{__m256i, _mm256_loadu_si256, _mm256_storeu_si256};

/// AVX2 byte-parallel SM4 S-box on 32 independent inputs (full
/// `__m256i` register width).
///
/// Loads the 32 input bytes into one AVX2 register, runs the shared
/// AVX2 gate sequence from [`super::avx2`], stores back to a 32-byte
/// output buffer. No staging-buffer overhead vs [`super::sbox_x8`].
///
/// # Safety
///
/// Caller must guarantee the host CPU supports AVX2. The public
/// entry point [`sbox_x32`] verifies this via [`has_avx2`] (cached
/// `cpufeatures` check) before calling.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
// `cast_ptr_alignment`: the pointer casts feed `_mm256_loadu_si256` /
// `_mm256_storeu_si256`, which take unaligned addresses by definition.
#[allow(unsafe_op_in_unsafe_fn, clippy::cast_ptr_alignment)]
pub unsafe fn sbox_x32_avx2(input: &[u8; 32]) -> [u8; 32] {
    let x = _mm256_loadu_si256(input.as_ptr().cast::<__m256i>());
    let out = super::avx2::sbox_round(x);
    let mut result = [0u8; 32];
    _mm256_storeu_si256(result.as_mut_ptr().cast::<__m256i>(), out);
    result
}

/// GFNI SM4 S-box on 32 independent inputs (v1.16,
/// `docs/v1.16-scope.md` Q16.3): two GFNI instructions per register
/// instead of the AVX2 gate sequence. Byte-identical to
/// [`sbox_x32_scalar`] (exhaustive lane tests below; run under Intel SDE
/// in CI).
///
/// Compiled only on `x86_64` with rustc >= 1.89 (build.rs cfg).
///
/// # Safety
///
/// Caller must guarantee the host CPU supports GFNI and AVX2
/// ([`crate::detect::has_gfni_avx2`]).
#[cfg(all(target_arch = "x86_64", gmcrypto_simd_gfni))]
#[target_feature(enable = "gfni,avx2")]
#[allow(unsafe_op_in_unsafe_fn, clippy::incompatible_msrv)]
pub unsafe fn sbox_x32_gfni(input: &[u8; 32]) -> [u8; 32] {
    let x = _mm256_loadu_si256(input.as_ptr().cast::<__m256i>());
    let out = super::gfni::sbox_round(x);
    let mut result = [0u8; 32];
    _mm256_storeu_si256(result.as_mut_ptr().cast::<__m256i>(), out);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scalar path on the full 32-byte input matches per-byte
    /// sbox_byte for every lane.
    #[test]
    fn scalar_full_width_matches_sbox_byte() {
        // i ∈ 0..32, fits in u8 with room to spare.
        #[allow(clippy::cast_possible_truncation)]
        let input: [u8; 32] = core::array::from_fn(|i| i as u8);
        let out = sbox_x32_scalar(&input);
        for (lane, (&inp, &got)) in input.iter().zip(out.iter()).enumerate() {
            assert_eq!(
                got,
                sbox_byte(inp),
                "scalar x32 lane {lane} disagrees at input 0x{inp:02x}",
            );
        }
    }

    /// v1.16 Q16.4 — the SDE CI job sets `GMCRYPTO_SIMD_EXPECT_GFNI=1`.
    /// If the GFNI path is not compiled in or not detected there, fail
    /// loudly instead of silently testing the fallback.
    #[test]
    fn gfni_path_present_when_expected() {
        extern crate std;
        if std::env::var_os("GMCRYPTO_SIMD_EXPECT_GFNI").is_some() {
            assert!(
                crate::detect::has_gfni_avx2(),
                "GMCRYPTO_SIMD_EXPECT_GFNI is set but the GFNI+AVX2 path is unavailable",
            );
        }
    }

    /// v1.16 — every byte value in every lane position: GFNI kernel ==
    /// scalar gate circuit, and filler lanes stay `S(0)`.
    #[cfg(all(target_arch = "x86_64", gmcrypto_simd_gfni))]
    #[test]
    fn gfni_lane_position_sweep() {
        if !crate::detect::has_gfni_avx2() {
            return;
        }
        for b in 0u8..=255 {
            for lane in 0..32 {
                let mut input = [0u8; 32];
                input[lane] = b;
                // SAFETY: `has_gfni_avx2()` returned `true` above.
                let out = unsafe { sbox_x32_gfni(&input) };
                for (l, &got) in out.iter().enumerate() {
                    let want = if l == lane {
                        sbox_byte(b)
                    } else {
                        sbox_byte(0)
                    };
                    assert_eq!(got, want, "byte 0x{b:02x} lane {lane}, output lane {l}");
                }
            }
        }
    }

    /// v1.16 — 32 distinct bytes per call, 256 offsets: catches any
    /// cross-lane mixing the one-hot sweep cannot.
    #[cfg(all(target_arch = "x86_64", gmcrypto_simd_gfni))]
    #[test]
    fn gfni_matches_scalar_on_distinct_inputs() {
        if !crate::detect::has_gfni_avx2() {
            return;
        }
        for start in 0u8..=255 {
            #[allow(clippy::cast_possible_truncation)]
            let input: [u8; 32] =
                core::array::from_fn(|i| start.wrapping_add((i as u8).wrapping_mul(37)));
            // SAFETY: `has_gfni_avx2()` returned `true` above.
            let got = unsafe { sbox_x32_gfni(&input) };
            assert_eq!(got, sbox_x32_scalar(&input), "offset 0x{start:02x}");
        }
    }
}
