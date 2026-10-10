//! Four-byte packed bitsliced SM4 S-box (issue #163 serial-`tau` repair).
//!
//! Public entry point: [`sbox_x4`]. Operates on 4 independent S-box
//! inputs packed as `[u8; 4]`, returning `[u8; 4]`. The intended
//! consumer is `gmcrypto_core::sm4::cipher::tau` under
//! `sm4-bitsliced-simd`: one call replaces four one-byte-to-x8
//! broadcasts.
//!
//! # Dispatch
//!
//! - **aarch64:** stage the four bytes in the first four lanes of a
//!   fixed x16 buffer (remaining lanes public zeros), invoke the
//!   existing NEON x16 gate circuit once, return the first four
//!   outputs. NEON is compile-time baseline; no runtime detect.
//!   Must not go through [`super::sbox_x16::sbox_x16`] on any other
//!   target (that dispatcher is 16 scalar calls off-aarch64).
//! - **`x86_64` where `has_gfni_avx2()` holds** (rustc >= 1.89 builds;
//!   v1.16): `sbox_x4_gfni`, one 128-bit register through two GFNI
//!   instructions. Selected under the 10% rule; the record is above
//!   [`sbox_x4`].
//! - **other `x86_64`:** exactly four scalar gate-circuit calls. AVX2 is
//!   not the production branch: the 10% improvement rule could not
//!   be measured on the `AArch64` implementation host. The AVX2
//!   candidate remains `sbox_x4_avx2` for tests. Must not call
//!   [`super::sbox_x8::sbox_x8`] (its non-AVX2 fallback is eight
//!   scalar calls).
//! - **other targets:** [`sbox_x4_scalar`].
//!
//! [`sbox_x8`](super::sbox_x8) is kept as an internal AVX2 candidate
//! and test surface (v0.6 Q6.9). Removing the core one-byte adapter
//! does not delete that module.

use super::scalar::sbox_byte;

/// Scalar fallback: exactly four calls into
/// `super::scalar::sbox_byte`. Always available.
///
/// Takes `&[u8; 4]` to match [`super::sbox_x8::sbox_x8`] / x16 / x32
/// (lane-oriented array refs). Clippy's 8-byte pass-by-value
/// threshold would otherwise rewrite only this width.
#[must_use]
#[allow(clippy::trivially_copy_pass_by_ref)]
pub fn sbox_x4_scalar(input: &[u8; 4]) -> [u8; 4] {
    [
        sbox_byte(input[0]),
        sbox_byte(input[1]),
        sbox_byte(input[2]),
        sbox_byte(input[3]),
    ]
}

/// Four-byte packed bitsliced SM4 S-box dispatch.
///
/// On `aarch64`, one NEON x16 invocation with public-zero filler
/// lanes. On `x86_64` where `has_gfni_avx2()` holds (rustc >= 1.89
/// builds), `sbox_x4_gfni`. Elsewhere, exactly four scalar gate-circuit
/// calls.
//
// v1.16 GFNI-vs-scalar decision (x4 10% rule of
// docs/sm4-single-block-simd-repair-design.md; docs/v1.16-scope.md §7):
// - Date: 2026-09-30
// - CPU: "Intel(R) Xeon(R) 6973P-C", hosted ubuntu-24.04 runner
// - rustc: 1.98.1 (48a229cea 2026-09-01), release, sm4-bitsliced-simd
// - Key-construction medians (five alternating samples): four scalar
//   calls 11939.6 ns, GFNI 171.9 ns
// - Pre-keyed single-block medians: four scalar calls 11640.9 ns,
//   GFNI 191.8 ns
// - Rule: select only if >= 10% faster for BOTH. Met (~60x both).
// - Selection: GFNI where detected; four scalar calls otherwise.
// Evidence: research branch `research/v1.16-gfni-x4-measure` (never
// merged), Actions run 36679336946.
#[must_use]
#[inline]
#[allow(clippy::trivially_copy_pass_by_ref)]
pub fn sbox_x4(input: &[u8; 4]) -> [u8; 4] {
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: NEON is a baseline architectural feature on
        // `aarch64`. `sbox_x4_neon` stages a fixed-size array and
        // returns a fixed-size array — no raw pointers cross the
        // unsafe boundary.
        unsafe { sbox_x4_neon(input) }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        #[cfg(all(target_arch = "x86_64", gmcrypto_simd_gfni))]
        {
            if crate::detect::has_gfni_avx2() {
                // SAFETY: `has_gfni_avx2()` returned `true`, so GFNI is
                // available and the intrinsics inside `sbox_x4_gfni` are
                // sound to invoke. Fixed-size array in and out; no raw
                // pointers cross the unsafe boundary.
                return unsafe { sbox_x4_gfni(input) };
            }
        }
        sbox_x4_scalar(input)
    }
}

/// Stage four S-box bytes into the first four lanes of an x16
/// buffer. Remaining lanes are public zeros.
#[cfg(target_arch = "aarch64")]
#[inline]
fn stage_x16(input: [u8; 4]) -> [u8; 16] {
    let mut staged = [0u8; 16];
    staged[..4].copy_from_slice(&input);
    staged
}

#[cfg(target_arch = "aarch64")]
fn first_four(out: [u8; 16]) -> [u8; 4] {
    let mut result = [0u8; 4];
    result.copy_from_slice(&out[..4]);
    result
}

/// NEON four-byte S-box: one x16 gate-circuit invocation.
///
/// # Safety
///
/// Caller must be running on `aarch64` (NEON is baseline).
#[cfg(target_arch = "aarch64")]
#[allow(unsafe_op_in_unsafe_fn)]
#[allow(clippy::trivially_copy_pass_by_ref)]
pub unsafe fn sbox_x4_neon(input: &[u8; 4]) -> [u8; 4] {
    let staged = stage_x16(*input);
    let out = super::sbox_x16::sbox_x16_neon(&staged);
    first_four(out)
}

// ============================================================
// x86_64 AVX2 candidate (not the production sbox_x4 branch)
// ============================================================
//
// AVX2-vs-scalar decision (issue #163 / design 10% rule):
// - Date: 2026-08-22
// - CPU: not measured (implementation host is aarch64-apple-darwin)
// - rustc: not measured on an AVX2 host
// - Key-construction medians: n/a
// - Pre-keyed single-block medians: n/a
// - Rule: select AVX2 only if repeated median is ≥10% faster for
//   BOTH key construction and pre-keyed single-block encryption
// - Selection: four scalar calls. Either condition "cannot be
//   measured" ⇒ production uses `sbox_x4_scalar`. Existing x32
//   batch AVX2 is unchanged.
//
// The candidate below exists so x86 tests can exercise one direct
// x8 AVX2 invocation on four real lanes. Production `sbox_x4` does
// not call it.

/// AVX2 four-byte S-box candidate: one x8 gate-circuit invocation
/// with four public-zero filler lanes.
///
/// # Safety
///
/// Caller must guarantee the host CPU supports AVX2.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
#[allow(clippy::trivially_copy_pass_by_ref)]
pub unsafe fn sbox_x4_avx2(input: &[u8; 4]) -> [u8; 4] {
    let mut staged = [0u8; 8];
    staged[..4].copy_from_slice(input);
    let out = super::sbox_x8::sbox_x8_avx2(&staged);
    [out[0], out[1], out[2], out[3]]
}

// ============================================================
// x86_64 GFNI candidate (v1.16, docs/v1.16-scope.md §7)
// ============================================================

#[cfg(all(target_arch = "x86_64", gmcrypto_simd_gfni))]
use core::arch::x86_64::{_mm_cvtsi32_si128, _mm_cvtsi128_si32};

/// GFNI four-byte S-box: the four bytes go into the low 32 bits of one
/// 128-bit register (other lanes public zeros), through the two GFNI
/// instructions, and back. No memory staging, no pointer casts.
///
/// Compiled only on `x86_64` with rustc >= 1.89 (build.rs cfg).
///
/// # Safety
///
/// Caller must guarantee the host CPU supports GFNI
/// ([`crate::detect::has_gfni_avx2`]).
#[cfg(all(target_arch = "x86_64", gmcrypto_simd_gfni))]
#[target_feature(enable = "gfni")]
#[allow(unsafe_op_in_unsafe_fn, clippy::trivially_copy_pass_by_ref)]
pub unsafe fn sbox_x4_gfni(input: &[u8; 4]) -> [u8; 4] {
    let x = _mm_cvtsi32_si128(i32::from_le_bytes(*input));
    let out = super::gfni::sbox_round_128(x);
    _mm_cvtsi128_si32(out).to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_matches_sbox_byte() {
        let input = [0x00, 0x01, 0x55, 0xAA];
        let out = sbox_x4_scalar(&input);
        for (lane, (&inp, &got)) in input.iter().zip(out.iter()).enumerate() {
            assert_eq!(
                got,
                sbox_byte(inp),
                "scalar x4 lane {lane} disagrees at input 0x{inp:02x}",
            );
        }
    }

    /// v1.16 — every byte value in each of the four lanes: GFNI x4 ==
    /// scalar gate circuit, and the other lanes stay `S(0)`.
    #[cfg(all(target_arch = "x86_64", gmcrypto_simd_gfni))]
    #[test]
    fn gfni_lane_position_sweep() {
        if !crate::detect::has_gfni_avx2() {
            return;
        }
        for b in 0u8..=255 {
            for lane in 0..4 {
                let mut input = [0u8; 4];
                input[lane] = b;
                // SAFETY: `has_gfni_avx2()` returned `true` above.
                let out = unsafe { sbox_x4_gfni(&input) };
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

    /// v1.16 — four distinct bytes per call over all 256 offsets.
    #[cfg(all(target_arch = "x86_64", gmcrypto_simd_gfni))]
    #[test]
    fn gfni_matches_scalar_on_distinct_inputs() {
        if !crate::detect::has_gfni_avx2() {
            return;
        }
        for start in 0u8..=255 {
            let input = [
                start,
                start.wrapping_add(37),
                start.wrapping_add(101),
                start.wrapping_add(200),
            ];
            // SAFETY: `has_gfni_avx2()` returned `true` above.
            let got = unsafe { sbox_x4_gfni(&input) };
            assert_eq!(got, sbox_x4_scalar(&input), "offset 0x{start:02x}");
        }
    }
}
