//! 16-way packed bitsliced SM4 S-box (v0.6 W6).
//!
//! Public entry point: [`sbox_x16`]. Operates on 16 independent
//! S-box inputs packed as `[u8; 16]`, returning `[u8; 16]`. The
//! intended consumer is `gmcrypto_core::sm4::cbc_streaming::
//! Sm4CbcDecryptor::process_chunk`'s 4-block batched CBC-decrypt
//! fanout on `aarch64`: 4 SM4 blocks × 4 `tau` bytes per round =
//! 16 bytes per call, packed across the full 128-bit `uint8x16_t`
//! NEON register.
//!
//! # Dispatch
//!
//! - On `aarch64`: `sbox_x16_neon` — NEON is a compile-time
//!   architectural baseline (Q5.12 + Q6.3); no runtime CPU detect.
//! - Elsewhere (any non-aarch64 target): falls back to
//!   [`sbox_x16_scalar`] — a 16-iteration loop calling the local
//!   single-block `super::scalar::sbox_byte`.
//!
//! # Constant-time discipline
//!
//! Same as [`super::sbox_x8`]: shared NEON gate sequence (no table
//! lookups, no secret-derived branches); scalar path is the same
//! gate-only `sbox_byte` from `super::scalar`.

use super::scalar::sbox_byte;

/// Scalar fallback: 16 sequential calls into
/// `super::scalar::sbox_byte`. Always available.
#[must_use]
pub fn sbox_x16_scalar(input: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = sbox_byte(input[i]);
        i += 1;
    }
    out
}

/// 16-way packed bitsliced SM4 S-box dispatch.
///
/// On `aarch64`: calls `sbox_x16_neon`. Otherwise
/// [`sbox_x16_scalar`].
///
/// Byte-identical output to applying `super::scalar::sbox_byte`
/// to each input byte (verified exhaustively in
/// `tests/lane_position_x16.rs` with lane-position-shifted sweeps
/// per Q6.8 / codex's phase 3 flag #4).
#[must_use]
#[inline]
pub fn sbox_x16(input: &[u8; 16]) -> [u8; 16] {
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: NEON is a baseline architectural feature on
        // `aarch64` (ARMv8 reference manual mandates Advanced SIMD
        // on every conforming implementation). The intrinsics in
        // `super::neon` are guaranteed available; no runtime CPU
        // detect needed. Fixed-size array reference in; fixed-size
        // array out — no raw pointers cross the unsafe boundary.
        unsafe { sbox_x16_neon(input) }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        sbox_x16_scalar(input)
    }
}

/// NEON byte-parallel SM4 S-box on 16 independent inputs.
///
/// # Safety
///
/// Caller must be running on `aarch64` (NEON is baseline; no
/// runtime feature check needed). The public dispatch entry
/// [`sbox_x16`] gates this via `cfg(target_arch = "aarch64")`.
#[cfg(target_arch = "aarch64")]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn sbox_x16_neon(input: &[u8; 16]) -> [u8; 16] {
    super::neon::sbox_x16_impl(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scalar path on the full 16-byte input matches per-byte
    /// sbox_byte for every lane.
    #[test]
    fn scalar_full_width_matches_sbox_byte() {
        // i ∈ 0..16, fits in u8 with room to spare.
        #[allow(clippy::cast_possible_truncation)]
        let input: [u8; 16] = core::array::from_fn(|i| i as u8);
        let out = sbox_x16_scalar(&input);
        for (lane, (&inp, &got)) in input.iter().zip(out.iter()).enumerate() {
            assert_eq!(
                got,
                sbox_byte(inp),
                "scalar x16 lane {lane} disagrees at input 0x{inp:02x}",
            );
        }
    }
}
