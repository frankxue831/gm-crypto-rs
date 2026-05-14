//! Streaming SM4-CTR cipher (v0.7 W3).
//!
//! Stateful counterpart to [`super::mode_ctr`]'s single-shot
//! [`encrypt`] / [`decrypt`]: usable when the plaintext isn't
//! available all at once (network framing, file streaming, etc).
//!
//! See [`super::mode_ctr`]'s module docstring for the counter
//! contract, the no-authenticity caveat, and the BE counter-encoding
//! semantics — the same rules apply here. CTR is its own inverse, so
//! [`Sm4CtrCipher`] serves both directions; there's no separate
//! `Sm4CtrEncryptor` / `Sm4CtrDecryptor` split (compare with CBC's
//! [`super::cbc_streaming`] which needs separate types for the
//! padding-bookkeeping asymmetry).
//!
//! [`encrypt`]: super::mode_ctr::encrypt
//! [`decrypt`]: super::mode_ctr::decrypt

use alloc::vec::Vec;

use super::cipher::{BLOCK_SIZE, KEY_SIZE, Sm4Cipher};

/// Streaming SM4-CTR cipher.
///
/// Construct with [`Sm4CtrCipher::new`], feed input/output buffer
/// pairs through [`update`], drop or [`finalize`] when done. Single
/// struct serves both encrypt and decrypt (CTR is symmetric).
///
/// State machine:
///
/// - `counter`: next 128-bit BE counter to evaluate.
/// - `leftover`: the most recently evaluated keystream block.
/// - `leftover_pos`: in `0..=16`. Bytes `[leftover_pos..16]` of
///   `leftover` are unconsumed keystream from a previous partial
///   call; on next [`update`] they're consumed first before the
///   counter advances.
///
/// Internal invariant: when `leftover_pos == 16`, no carried-over
/// keystream; the next byte requires a fresh `encrypt_block` of
/// `counter`. Initial state is `leftover_pos = 16` (no leftover).
///
/// [`update`]: Sm4CtrCipher::update
/// [`finalize`]: Sm4CtrCipher::finalize
pub struct Sm4CtrCipher {
    cipher: Sm4Cipher,
    counter: [u8; BLOCK_SIZE],
    leftover: [u8; BLOCK_SIZE],
    leftover_pos: usize,
}

impl Sm4CtrCipher {
    /// Construct from a 16-byte key and a 16-byte initial counter.
    /// Counter is treated as a 128-bit BE integer; per-block
    /// keystream is `SM4_E(key, counter + i)` for `i = 0..N-1`.
    #[must_use]
    pub fn new(key: &[u8; KEY_SIZE], counter: &[u8; BLOCK_SIZE]) -> Self {
        Self {
            cipher: Sm4Cipher::new(key),
            counter: *counter,
            leftover: [0u8; BLOCK_SIZE],
            // Signals "no carried-over keystream" — the first `update`
            // will generate a fresh block from `counter`.
            leftover_pos: BLOCK_SIZE,
        }
    }

    /// Consume `input` and write `input.len()` bytes of output. The
    /// output buffer must be at least as long as the input; only the
    /// leading `input.len()` bytes are written.
    ///
    /// # Panics
    ///
    /// Panics if `output.len() < input.len()`.
    pub fn update(&mut self, input: &[u8], output: &mut [u8]) {
        assert!(
            output.len() >= input.len(),
            "Sm4CtrCipher::update: output buffer too short ({} < {})",
            output.len(),
            input.len(),
        );
        let mut i = 0usize;

        // Step 1: drain any carried-over keystream from a previous
        // call. Bytes [self.leftover_pos..16] of self.leftover are
        // unconsumed and apply to the leading bytes of `input`.
        while i < input.len() && self.leftover_pos < BLOCK_SIZE {
            output[i] = input[i] ^ self.leftover[self.leftover_pos];
            self.leftover_pos += 1;
            i += 1;
        }

        // Step 2: process the largest aligned run of full keystream
        // blocks via the SIMD batch path in `Sm4Cipher::encrypt_blocks`
        // (v0.7 W1 — fans through `sbox_x32` / `sbox_x16` under
        // `sm4-bitsliced-simd`).
        let remaining = input.len() - i;
        let full_blocks = remaining / BLOCK_SIZE;
        if full_blocks > 0 {
            let mut keystream: Vec<[u8; BLOCK_SIZE]> = (0..full_blocks)
                .map(|j| counter_add(&self.counter, j as u128))
                .collect();
            self.cipher.encrypt_blocks(&mut keystream);

            for (b, ks) in keystream.iter().enumerate() {
                let off = i + b * BLOCK_SIZE;
                for lane in 0..BLOCK_SIZE {
                    output[off + lane] = input[off + lane] ^ ks[lane];
                }
            }
            self.counter = counter_add(&self.counter, full_blocks as u128);
            i += full_blocks * BLOCK_SIZE;
        }

        // Step 3: tail — strictly less than one block remains.
        // Generate one keystream block from the current counter,
        // consume what's needed, save the rest as leftover for the
        // next `update` call.
        if i < input.len() {
            self.leftover = self.counter;
            self.cipher.encrypt_block(&mut self.leftover);
            self.counter = counter_add(&self.counter, 1);
            self.leftover_pos = 0;
            while i < input.len() {
                output[i] = input[i] ^ self.leftover[self.leftover_pos];
                self.leftover_pos += 1;
                i += 1;
            }
        }
    }

    /// Finalize and drop the cipher. CTR has no padding to flush and
    /// no authenticity bits to emit, so this is a stateless drop.
    /// Provided for symmetry with [`super::cbc_streaming`] and so
    /// the call site reads intuitively.
    pub fn finalize(self) {
        // Drop self.
    }
}

/// Treat `counter` as a 128-bit big-endian integer; return
/// `(counter + offset) mod 2^128`, BE-encoded.
const fn counter_add(counter: &[u8; BLOCK_SIZE], offset: u128) -> [u8; BLOCK_SIZE] {
    let n = u128::from_be_bytes(*counter);
    n.wrapping_add(offset).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::sm4::mode_ctr;

    const KEY: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    const COUNTER: [u8; 16] = [0x42u8; 16];

    #[allow(clippy::cast_possible_truncation)]
    fn make_plaintext(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| {
                let s = (i as u32).wrapping_mul(0x9E37_79B9);
                (s ^ (s >> 17)) as u8
            })
            .collect()
    }

    /// Single-shot through the streaming API matches the single-shot
    /// top-level function from `mode_ctr`.
    #[test]
    fn streaming_single_call_matches_single_shot() {
        for len in 0..=33 {
            let plaintext = make_plaintext(len);
            let mut out = vec![0u8; len];
            let mut cipher = Sm4CtrCipher::new(&KEY, &COUNTER);
            cipher.update(&plaintext, &mut out);
            cipher.finalize();

            let expected = mode_ctr::encrypt(&KEY, &COUNTER, &plaintext);
            assert_eq!(out, expected, "single-call divergence at length {len}");
        }
    }

    /// Chunked `update` at every chunk size 1..=17 produces
    /// byte-identical output to a single-shot call. Exercises the
    /// leftover-keystream-buffer state machine across every
    /// possible carry position.
    #[test]
    fn chunked_update_sweep_matches_single_shot() {
        let total = 64;
        let plaintext = make_plaintext(total);
        let reference = mode_ctr::encrypt(&KEY, &COUNTER, &plaintext);

        for chunk_size in 1..=17 {
            let mut cipher = Sm4CtrCipher::new(&KEY, &COUNTER);
            let mut out = vec![0u8; total];
            let mut written = 0;
            while written < total {
                let take = chunk_size.min(total - written);
                cipher.update(
                    &plaintext[written..written + take],
                    &mut out[written..written + take],
                );
                written += take;
            }
            cipher.finalize();
            assert_eq!(
                out, reference,
                "chunked update divergence at chunk_size {chunk_size}",
            );
        }
    }

    /// Round-trip through the streaming API: encrypt then decrypt
    /// recovers plaintext at every length 0..=33.
    #[test]
    fn streaming_round_trip_is_identity() {
        for len in 0..=33 {
            let plaintext = make_plaintext(len);
            let mut ciphertext = vec![0u8; len];
            let mut enc = Sm4CtrCipher::new(&KEY, &COUNTER);
            enc.update(&plaintext, &mut ciphertext);
            enc.finalize();

            let mut recovered = vec![0u8; len];
            let mut dec = Sm4CtrCipher::new(&KEY, &COUNTER);
            dec.update(&ciphertext, &mut recovered);
            dec.finalize();

            assert_eq!(recovered, plaintext, "streaming round-trip at length {len}");
        }
    }

    /// Empty input through `update` is a no-op.
    #[test]
    fn empty_update() {
        let mut cipher = Sm4CtrCipher::new(&KEY, &COUNTER);
        let mut out = [];
        cipher.update(&[], &mut out);
        cipher.finalize();
    }
}
