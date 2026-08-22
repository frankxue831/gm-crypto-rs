//! Four-byte SIMD-packed bitsliced SM4 S-box (issue #163).
//!
//! Behind the `sm4-bitsliced-simd` feature flag. [`sbox_word`] is the
//! only production entry: one sibling [`sbox_x4`] call for the four
//! independent bytes of an SM4 word. The one-byte-to-x8 broadcast
//! adapter (`sbox(u8)` replicating `[x; 8]`) is removed so `tau`
//! cannot regress to four x8 dispatches.
//!
//! Full batches continue through [`sbox_x16`] / [`sbox_x32`].
//! [`sbox_x8`] remains in the sibling crate as an internal AVX2
//! candidate and test surface (v0.6 Q6.9); this module does not call
//! it.
//!
//! Measured 2026-08-22 on Apple M1 Pro, rustc 1.94.1, release:
//! pre-keyed `encrypt_block` ~1.4×10⁵ blocks/s. The 1 MiB CCM/GCM
//! success-encrypt vs forged-decrypt matrix (three `sm4-aead*`
//! feature sets) is in CHANGELOG Unreleased. GCM forged decrypt is
//! GHASH-bound (~36 MiB/s on all three); SIMD moves CCM forged from
//! ~0.39 MiB/s (`sm4-bitsliced`) to ~1.66 MiB/s.
//!
//! [`sbox_x4`]: gmcrypto_simd::sm4::sbox_x4::sbox_x4
//! [`sbox_x8`]: gmcrypto_simd::sm4::sbox_x8::sbox_x8
//! [`sbox_x16`]: gmcrypto_simd::sm4::sbox_x16::sbox_x16
//! [`sbox_x32`]: gmcrypto_simd::sm4::sbox_x32::sbox_x32

/// SM4 S-box on four independent bytes (one SM4 word after
/// `u32::to_be_bytes`).
///
/// Byte-identical to four [`super::sbox_bitsliced::sbox`] calls.
/// Architecture dispatch lives in the sibling crate.
#[inline]
#[must_use]
pub fn sbox_word(input: [u8; 4]) -> [u8; 4] {
    gmcrypto_simd::sm4::sbox_x4::sbox_x4(&input)
}
