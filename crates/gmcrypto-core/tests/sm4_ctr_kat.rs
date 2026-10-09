//! SM4-CTR Known-Answer Tests (v0.7 W2).
//!
//! GM/T 0002-2012 publishes a single SM4-ECB test vector (Appendix A.1)
//! but no CTR-specific vectors. The natural KAT for SM4-CTR is to
//! derive its correctness from the ECB primitive: for any input,
//! `CTR(key, counter)[i] = input[i] ^ SM4_ECB(key, counter + i/16)[i%16]`.
//! This file verifies that identity exhaustively at every length 0..=64
//! against representative counters, then crosses the x86 eight-block
//! SIMD batch boundaries with multiple batches and partial-block tails.
//! Bytewise BE counter increments provide an oracle independent of the
//! production mode's `u128` addition, including carries and `2^128` wrap.
//!
//! The single GM/T ECB KAT (key=0x0123456789abcdeffedcba9876543210,
//! plaintext=key, ciphertext=0x681edf34d206965e86b3e94f536e4246)
//! is exercised by `sm4_kat` and implicitly by every CTR test below
//! that uses the same key.

use gmcrypto_core::sm4::{BLOCK_SIZE, KEY_SIZE, Sm4Cipher, mode_ctr};

/// GB/T 32907-2016 §A.1 sample key.
const KEY: [u8; KEY_SIZE] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];

/// Compute the CTR keystream for `block_count` successive counter
/// blocks by direct SM4-ECB calls. Reference oracle for the CTR
/// equivalence assertions below.
fn ecb_keystream(key: &[u8; KEY_SIZE], counter: &[u8; BLOCK_SIZE], block_count: usize) -> Vec<u8> {
    let cipher = Sm4Cipher::new(key);
    let mut out = Vec::with_capacity(block_count * BLOCK_SIZE);
    let mut counter_block = *counter;
    for _ in 0..block_count {
        let mut buf = counter_block;
        cipher.encrypt_block(&mut buf);
        out.extend_from_slice(&buf);

        // Increment the byte string directly, rather than sharing the
        // production CTR mode's u128 conversion/addition implementation.
        for byte in counter_block.iter_mut().rev() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
    }
    out
}

/// Check both public operations against a per-block composition oracle.
/// Feeding the same input to both also checks CTR's inverse identity without
/// allowing matching encryption/decryption errors to hide in a round trip.
fn assert_ctr_matches_ecb(key: &[u8; KEY_SIZE], counter: &[u8; BLOCK_SIZE], len: usize) {
    let input = make_plaintext(len);
    let keystream = ecb_keystream(key, counter, len.div_ceil(BLOCK_SIZE));
    let expected: Vec<u8> = input
        .iter()
        .zip(keystream.iter())
        .map(|(p, k)| p ^ k)
        .collect();

    assert_eq!(
        mode_ctr::encrypt(key, counter, &input),
        expected,
        "encrypt ≠ ECB-keystream XOR input at length {len}, counter={counter:02x?}, key={key:02x?}",
    );
    assert_eq!(
        mode_ctr::decrypt(key, counter, &input),
        expected,
        "decrypt ≠ ECB-keystream XOR input at length {len}, counter={counter:02x?}, key={key:02x?}",
    );
}

/// Deterministic plaintext generator.
#[allow(clippy::cast_possible_truncation)]
fn make_plaintext(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let seed = (i as u32).wrapping_mul(0x9E37_79B9);
            (seed ^ (seed >> 17)) as u8
        })
        .collect()
}

/// For counter = 0, every length 0..=64: CTR(key, 0, plaintext)
/// matches `plaintext XOR ecb_keystream`.
#[test]
fn ctr_equals_ecb_keystream_xor_plaintext_at_counter_zero() {
    let counter = [0u8; BLOCK_SIZE];
    for len in 0..=64 {
        assert_ctr_matches_ecb(&KEY, &counter, len);
    }
}

/// Same identity but with a mid-range counter value — verifies the
/// BE increment path doesn't drift mid-stream.
#[test]
fn ctr_equals_ecb_keystream_at_midrange_counter() {
    let counter: [u8; BLOCK_SIZE] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
        0xf0,
    ];
    for len in [1usize, 15, 16, 17, 31, 32, 33, 63, 64] {
        assert_ctr_matches_ecb(&KEY, &counter, len);
    }
}

/// x86 SIMD consumes eight counter blocks per batch. The 256-byte timed
/// window is two batches; include shorter inputs, a third batch, and tails.
/// Carries occur at block offsets 8 and 16, including across the low 32-bit
/// field so an accidental GCM-style inc32 cannot satisfy this CTR oracle.
#[test]
fn ctr_matches_ecb_across_simd_batches_and_counter_carries() {
    let mut byte_carry = [0x42; BLOCK_SIZE];
    byte_carry[15] = 0xf8;
    let mut word_carry = [0x42; BLOCK_SIZE];
    word_carry[12..].copy_from_slice(&[0xff, 0xff, 0xff, 0xf8]);
    let mut wrap_at_second_batch = [0xff; BLOCK_SIZE];
    wrap_at_second_batch[15] = 0xf8;
    let mut wrap_at_third_batch = [0xff; BLOCK_SIZE];
    wrap_at_third_batch[15] = 0xf0;

    for key in [KEY, [0xa5; KEY_SIZE]] {
        for counter in [
            [0; BLOCK_SIZE],
            byte_carry,
            word_carry,
            wrap_at_second_batch,
            wrap_at_third_batch,
        ] {
            for boundary in [7 * BLOCK_SIZE, 128, 256, 384] {
                for len in [boundary - 1, boundary, boundary + 1] {
                    assert_ctr_matches_ecb(&key, &counter, len);
                }
            }
        }
    }
}

/// Counter wraps at `2^128`: starting near the max counter and
/// running two blocks crosses the wrap. Verify both blocks decrypt
/// correctly.
#[test]
fn ctr_wraps_counter_at_2_to_128() {
    let counter: [u8; BLOCK_SIZE] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff,
    ];
    let plaintext = make_plaintext(32); // exactly two blocks; second crosses wrap
    let ciphertext = mode_ctr::encrypt(&KEY, &counter, &plaintext);

    // Manually compute: block 0 keystream = ECB(KEY, 0xFF..FF);
    // block 1 keystream = ECB(KEY, 0x00..00) (wrap to zero).
    let cipher = Sm4Cipher::new(&KEY);
    let mut k0 = counter;
    cipher.encrypt_block(&mut k0);
    let mut k1 = [0u8; BLOCK_SIZE];
    cipher.encrypt_block(&mut k1);

    let mut expected_ct = [0u8; 32];
    for i in 0..16 {
        expected_ct[i] = plaintext[i] ^ k0[i];
        expected_ct[16 + i] = plaintext[16 + i] ^ k1[i];
    }
    assert_eq!(
        &ciphertext[..],
        &expected_ct[..],
        "wrap-block keystream mismatch"
    );
    assert_eq!(mode_ctr::decrypt(&KEY, &counter, &expected_ct), plaintext);
}

/// CTR is its own inverse: `decrypt` and `encrypt` produce
/// byte-identical output on the same input. Verify across lengths.
#[test]
fn decrypt_equals_encrypt() {
    let counter = [0x42u8; BLOCK_SIZE];
    for len in 0..=64 {
        assert_ctr_matches_ecb(&KEY, &counter, len);
    }
}

/// Empty input produces empty output (no padding, no failure mode).
#[test]
fn empty_input() {
    let counter = [0u8; BLOCK_SIZE];
    assert_eq!(mode_ctr::encrypt(&KEY, &counter, &[]), [] as [u8; 0]);
    assert_eq!(mode_ctr::decrypt(&KEY, &counter, &[]), [] as [u8; 0]);
}
