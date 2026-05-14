//! Cross-check that the v0.7 W1 public batch API on `Sm4Cipher`
//! (`encrypt_blocks` / `decrypt_blocks`) is byte-identical to N
//! sequential per-block calls.
//!
//! Sweeps every length 0..=33 — covers empty input, single block,
//! partial-SIMD-batch tails, full SIMD batches (8 on `x86_64`; 4 on
//! `aarch64`), and multi-batch + tail combinations on either arch.

use gmcrypto_core::sm4::{BLOCK_SIZE, KEY_SIZE, Sm4Cipher};

/// GB/T 32907-2016 §A.1 sample key. The KAT plaintext-to-ciphertext
/// transformation is exercised in `sm4_kat`; here we only need a
/// well-known key so byte-equivalence assertions are reproducible.
const KEY: [u8; KEY_SIZE] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];

/// Deterministic block generator — small mixing function over
/// `(block_index, lane_index)`. Avoids pulling in `rand` as a dev-dep
/// and keeps assertion failure messages independent of run-to-run
/// variation.
#[allow(clippy::cast_possible_truncation)] // intentional: seed → u8.
fn make_blocks(n: usize) -> Vec<[u8; BLOCK_SIZE]> {
    let mut out = Vec::with_capacity(n);
    for block_index in 0..n {
        let mut block = [0u8; BLOCK_SIZE];
        for (lane_index, byte) in block.iter_mut().enumerate() {
            let seed = (block_index as u32)
                .wrapping_mul(0x9E37_79B9)
                .wrapping_add(lane_index as u32);
            *byte = (seed ^ (seed >> 17) ^ (seed >> 9)) as u8;
        }
        out.push(block);
    }
    out
}

#[test]
fn encrypt_blocks_matches_per_block_at_every_length() {
    let cipher = Sm4Cipher::new(&KEY);
    for n in 0..=33 {
        let blocks = make_blocks(n);
        let mut batched = blocks.clone();
        let mut sequential = blocks.clone();

        cipher.encrypt_blocks(&mut batched);
        for block in &mut sequential {
            cipher.encrypt_block(block);
        }

        assert_eq!(
            batched, sequential,
            "encrypt_blocks divergence at length {n}",
        );
    }
}

#[test]
fn decrypt_blocks_matches_per_block_at_every_length() {
    let cipher = Sm4Cipher::new(&KEY);
    for n in 0..=33 {
        let blocks = make_blocks(n);
        let mut batched = blocks.clone();
        let mut sequential = blocks.clone();

        cipher.decrypt_blocks(&mut batched);
        for block in &mut sequential {
            cipher.decrypt_block(block);
        }

        assert_eq!(
            batched, sequential,
            "decrypt_blocks divergence at length {n}",
        );
    }
}

#[test]
fn round_trip_encrypt_then_decrypt_is_identity() {
    let cipher = Sm4Cipher::new(&KEY);
    for n in 0..=33 {
        let original = make_blocks(n);
        let mut buf = original.clone();
        cipher.encrypt_blocks(&mut buf);
        cipher.decrypt_blocks(&mut buf);
        assert_eq!(buf, original, "round-trip divergence at length {n}");
    }
}

/// Lengths that straddle the SIMD batch boundary on both arches.
/// On `x86_64` `SIMD_BATCH=8` so 7 / 8 / 9 / 15 / 16 / 17 exercise
/// (tail-only, exact, single-batch + tail, batch + max tail,
/// two-batches, two-batches + tail). On `aarch64` `SIMD_BATCH=4` so
/// the same sweep at lengths 3 / 4 / 5 / 7 / 8 / 9 covers it.
/// The 0..=33 sweep above subsumes both; this test is a named
/// callout for readers debugging a batch-boundary failure.
#[test]
fn batch_boundary_named_lengths_round_trip() {
    let cipher = Sm4Cipher::new(&KEY);
    for &n in &[3usize, 4, 5, 7, 8, 9, 15, 16, 17, 32, 33] {
        let original = make_blocks(n);
        let mut buf = original.clone();
        cipher.encrypt_blocks(&mut buf);
        cipher.decrypt_blocks(&mut buf);
        assert_eq!(
            buf, original,
            "boundary round-trip divergence at length {n}"
        );
    }
}
