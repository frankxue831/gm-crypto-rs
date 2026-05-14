//! SM4 in CTR mode (counter mode) per GM/T 0002-2012 §5.4 and NIST
//! SP 800-38A §6.5.
//!
//! # Counter contract
//!
//! Per NIST SP 800-38A §6.5, CTR counters must be **unique-per-key** —
//! never reused across messages under the same key. This is the
//! *opposite* contract from CBC's IV (which must be *unpredictable*).
//! Caller-supplied: this module does not generate counters. Reusing
//! a `(key, counter)` pair across two distinct plaintexts leaks
//! `plaintext1 ⊕ plaintext2` on the overlap (the canonical "two-time
//! pad" attack on stream ciphers).
//!
//! # No authenticity
//!
//! CTR is a stream cipher and is **unauthenticated** — every plaintext
//! bit is `XORed` with one keystream bit, so an attacker who flips a
//! ciphertext bit flips the plaintext bit at the same offset. Callers
//! needing integrity:
//!
//! - Pair with HMAC-SM3 in encrypt-then-MAC: compute the MAC over
//!   `counter || ciphertext` and verify before invoking [`decrypt`].
//! - Wait for SM4-GCM / SM4-CCM AEAD modes in v0.8+ (scope doc at
//!   `docs/v0.7-aead-scope.md`).
//!
//! # Counter encoding
//!
//! The 16-byte `counter` block is treated as a 128-bit **big-endian**
//! integer. Per-block keystream is `SM4_E(key, counter + i)` for
//! `i = 0..N-1`, BE add, wrap on overflow at `2^128`. Matches GM/T
//! 0002-2012 §5.4 and RFC 3686 §4 semantics.
//!
//! # API
//!
//! ```rust
//! use gmcrypto_core::sm4::{BLOCK_SIZE, KEY_SIZE, mode_ctr};
//!
//! let key: [u8; KEY_SIZE] = [0x42; KEY_SIZE];
//! let counter: [u8; BLOCK_SIZE] = [0x01; BLOCK_SIZE];
//! let plaintext = b"hello world";
//!
//! let ciphertext = mode_ctr::encrypt(&key, &counter, plaintext);
//! let recovered = mode_ctr::decrypt(&key, &counter, &ciphertext);
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! Output length always equals input length (no padding). [`decrypt`]
//! cannot fail — there is no padding to validate and no authenticity
//! check — so the return type is `Vec<u8>`, not `Option<Vec<u8>>`.

use alloc::vec::Vec;

use super::cipher::{BLOCK_SIZE, KEY_SIZE, Sm4Cipher};

/// Encrypt `plaintext` under (`key`, `counter`) in SM4-CTR mode.
///
/// See module-level docstring for the counter contract — callers must
/// never reuse a `(key, counter)` pair across distinct plaintexts.
#[must_use]
pub fn encrypt(key: &[u8; KEY_SIZE], counter: &[u8; BLOCK_SIZE], plaintext: &[u8]) -> Vec<u8> {
    apply_keystream(key, counter, plaintext)
}

/// Decrypt `ciphertext` under (`key`, `counter`) in SM4-CTR mode.
///
/// CTR is its own inverse — this is byte-identical to [`encrypt`].
/// Both names exist as a readability affordance for caller code.
#[must_use]
pub fn decrypt(key: &[u8; KEY_SIZE], counter: &[u8; BLOCK_SIZE], ciphertext: &[u8]) -> Vec<u8> {
    apply_keystream(key, counter, ciphertext)
}

fn apply_keystream(key: &[u8; KEY_SIZE], counter: &[u8; BLOCK_SIZE], input: &[u8]) -> Vec<u8> {
    let cipher = Sm4Cipher::new(key);
    let block_count = input.len().div_ceil(BLOCK_SIZE);

    // Build the counter block stream (counter, counter+1, ..., counter+N-1).
    // `encrypt_blocks` (v0.7 W1) routes this through the SIMD batch path
    // on `x86_64` AVX2 / `aarch64` NEON when `sm4-bitsliced-simd` is on.
    let mut keystream: Vec<[u8; BLOCK_SIZE]> = (0..block_count)
        .map(|i| counter_add(counter, i as u128))
        .collect();
    cipher.encrypt_blocks(&mut keystream);

    // XOR keystream with input. Output is byte-truncated to input.len()
    // so non-block-multiple inputs produce output of the same length.
    let mut out = Vec::with_capacity(input.len());
    for (i, &b) in input.iter().enumerate() {
        let block_idx = i / BLOCK_SIZE;
        let lane = i % BLOCK_SIZE;
        out.push(b ^ keystream[block_idx][lane]);
    }
    out
}

/// Treat `counter` as a 128-bit big-endian integer; return
/// `(counter + offset) mod 2^128`, BE-encoded.
const fn counter_add(counter: &[u8; BLOCK_SIZE], offset: u128) -> [u8; BLOCK_SIZE] {
    let n = u128::from_be_bytes(*counter);
    n.wrapping_add(offset).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctr_round_trip_is_identity() {
        let key: [u8; 16] = [0x42; 16];
        let counter: [u8; 16] = [0x01; 16];
        #[allow(clippy::cast_possible_truncation)]
        for len in 0..=64usize {
            let plaintext: Vec<u8> = (0..len).map(|i| (i ^ 0xAB) as u8).collect();
            let ciphertext = encrypt(&key, &counter, &plaintext);
            assert_eq!(ciphertext.len(), plaintext.len(), "len mismatch at {len}");
            let recovered = decrypt(&key, &counter, &ciphertext);
            assert_eq!(recovered, plaintext, "round-trip at length {len}");
        }
    }

    #[test]
    fn ctr_keystream_matches_ecb_of_counter_blocks() {
        // The CTR keystream for input=zeros is exactly the SM4-ECB
        // encryption of the counter blocks. Single-block sanity check;
        // the multi-block exhaustive cross-check lives in
        // `tests/sm4_ctr_kat.rs`.
        let key: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let counter: [u8; 16] = [0u8; 16];

        let zeros = [0u8; 16];
        let ctr_out = encrypt(&key, &counter, &zeros);

        let mut ecb_out = counter;
        Sm4Cipher::new(&key).encrypt_block(&mut ecb_out);

        assert_eq!(&ctr_out[..], &ecb_out[..]);
    }

    #[test]
    fn counter_add_wraps_at_2_to_128() {
        let max_counter: [u8; 16] = [0xFF; 16];
        let next = counter_add(&max_counter, 1);
        assert_eq!(next, [0u8; 16], "counter must wrap at 2^128");
    }

    #[test]
    fn empty_input_returns_empty_output() {
        let key = [0u8; 16];
        let counter = [0u8; 16];
        assert!(encrypt(&key, &counter, &[]).is_empty());
        assert!(decrypt(&key, &counter, &[]).is_empty());
    }
}
