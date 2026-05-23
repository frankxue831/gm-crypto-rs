//! SM4 in XTS mode (XEX-based tweaked-codebook with ciphertext stealing)
//! per **GB/T 17964-2021** — the SM4 national standard for the XTS tweakable
//! mode (GM-T OID `1.2.156.10197.1.104.10`).
//!
//! # What XTS is for
//!
//! XTS is a length-preserving, *tweakable* block-cipher mode designed for
//! random-access **disk/sector encryption**. Each data unit (sector) is
//! encrypted independently under a per-unit 16-byte *tweak* (the data-unit
//! number). It produces no ciphertext expansion and **no authentication tag**.
//!
//! # GB/T 17964 vs IEEE 1619
//!
//! This is the **GB** variant (`xts_standard=GB` in OpenSSL), **not** IEEE 1619
//! (the AES-XTS standard). The two differ in the GF(2¹²⁸) tweak-doubling
//! convention — GB/T 17964 uses the bit-reflected (GHASH-style) representation
//! — so they produce *different* ciphertext for multi-block / non-aligned data.
//! `mode_xts` is byte-identical to OpenSSL 3.x EVP `SM4-XTS` with
//! `xts_standard=GB`.
//!
//! # No authentication
//!
//! XTS provides **confidentiality only**. [`decrypt`] returning `Some` does
//! **not** mean the ciphertext is authentic — an attacker can flip ciphertext
//! and the plaintext changes unpredictably but undetectably. Callers needing
//! integrity must use an AEAD mode ([`super::mode_gcm`] / [`super::mode_ccm`]),
//! not XTS.
//!
//! # Tweak-uniqueness contract (caller-owned)
//!
//! The caller MUST supply a **unique** 16-byte `tweak` per data unit under a
//! given key — in disk use, the tweak is the sector number. Reusing a
//! `(key, tweak)` pair across different plaintexts leaks equality structure
//! (XTS is deterministic). The encoding of a sector number into the 16-byte
//! tweak (endianness/width) is the caller's responsibility; this module
//! consumes the raw 16 bytes as-is. Same posture as the CTR/GCM nonce
//! contracts.
//!
//! # Keys
//!
//! The 32-byte `key` is `Key1 ‖ Key2`: `Key1` encrypts the data blocks,
//! `Key2` encrypts the tweak. GB/T 17964 (and FIPS) mandate `Key1 ≠ Key2`;
//! equal halves are rejected with `None`.
//!
//! # Length bounds & failure mode
//!
//! `16 ≤ data_unit.len() ≤ 2²⁰·16` (16 MiB) — the NIST SP 800-38E ceiling of
//! 2²⁰ blocks per data unit. Lengths of any value in that range are supported,
//! including non-block-multiples via ciphertext stealing. Both [`encrypt`] and
//! [`decrypt`] return `Option<Vec<u8>>`; `None` is returned only for input
//! validation (`len` out of range, or `Key1 == Key2`). No distinguishing
//! variants, per the workspace failure-mode invariant. XTS has no tag, so there
//! is no MAC-failure path.
//!
//! # KAT sourcing
//!
//! gmssl 3.1.1 lacks XTS. KAT vectors come from OpenSSL 3.x EVP `SM4-XTS`
//! (`xts_standard=GB`); see [`docs/v0.12-xts-kat-sourcing.md`].
//!
//! # API
//!
//! ```rust
//! # #[cfg(feature = "sm4-xts")] {
//! use gmcrypto_core::sm4::{mode_xts, mode_xts::XTS_KEY_SIZE};
//!
//! let key: [u8; XTS_KEY_SIZE] = [
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
//!     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//!     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
//! ];
//! let tweak: [u8; 16] = [0x11; 16];
//! let plaintext = b"a full data unit at least 16 bytes long";
//!
//! let ct = mode_xts::encrypt(&key, &tweak, plaintext).expect("valid");
//! let pt = mode_xts::decrypt(&key, &tweak, &ct).expect("valid");
//! assert_eq!(pt, plaintext);
//! # }
//! ```

use alloc::vec::Vec;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::cipher::{BLOCK_SIZE, KEY_SIZE, Sm4Cipher};

/// XTS combined key size: `Key1 ‖ Key2`, two SM4-128 keys (32 bytes).
pub const XTS_KEY_SIZE: usize = 2 * KEY_SIZE;

/// NIST SP 800-38E maximum: 2²⁰ blocks per data unit (16 MiB).
const MAX_LEN: usize = (1 << 20) * BLOCK_SIZE;

/// Multiply a 128-bit value by the GF(2¹²⁸) primitive element α (= x) in the
/// **GB/T 17964-2021** bit-reflected (GHASH-style) representation.
///
/// Treat byte 0 as the leading byte; right-shift the 128-bit value by one bit
/// (carry each byte's LSB into the next byte's MSB). If the bit shifted off the
/// end (LSB of byte 15) is 1, XOR the reduce constant `0xE1` into byte 0.
/// (`0xE1` is the bit-reversed `0x87`; IEEE 1619 uses the opposite little-endian
/// `<<1` / `0x87` convention, which yields *different* ciphertext.)
///
/// Constant-time: the reduce is a masked XOR, never a branch on the
/// (secret-derived) tweak. `carry` is 0 or 1; `wrapping_neg()` maps it to a
/// 0x00 / 0xFF mask.
fn mul_alpha(t: &mut [u8; BLOCK_SIZE]) {
    let mut carry = 0u8;
    for b in t.iter_mut() {
        let next = *b & 1;
        *b = (*b >> 1) | (carry << 7);
        carry = next;
    }
    t[0] ^= 0xE1 & carry.wrapping_neg();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_alpha_no_carry_is_plain_right_shift() {
        // byte0 = 0x02 (LSB clear) -> right-shift -> 0x01, no carry out.
        let mut t = [0u8; 16];
        t[0] = 0x02;
        mul_alpha(&mut t);
        let mut expected = [0u8; 16];
        expected[0] = 0x01;
        assert_eq!(t, expected);
    }

    #[test]
    fn mul_alpha_carry_xors_0xe1() {
        // LSB of byte 15 set -> shifts off the end -> carry -> XOR 0xE1 into byte 0.
        let mut t = [0u8; 16];
        t[15] = 0x01;
        mul_alpha(&mut t);
        let mut expected = [0u8; 16];
        expected[0] = 0xE1;
        assert_eq!(t, expected);
    }
}
