//! Fuzz target: SM4-CBC ENCRYPT — DIFFERENTIAL (single-shot vs streaming)
//! plus an encrypt->decrypt round-trip.
//!
//! Existing CBC fuzzing only covered the decrypt side; this exercises the
//! PKCS#7 padding and the streaming-encryptor's partial-block buffering.
//!
//! Invariants for arbitrary key / iv / plaintext:
//!   * single-shot `mode_cbc::encrypt` byte-equals the streaming
//!     `Sm4CbcEncryptor` (drained via `take_output` across arbitrary chunk
//!     boundaries, then `finalize`);
//!   * `mode_cbc::decrypt` of that ciphertext recovers the original plaintext.
#![no_main]

use gmcrypto_core::sm4::{mode_cbc, Sm4CbcEncryptor, BLOCK_SIZE, KEY_SIZE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least key + IV; the remainder is the plaintext.
    if data.len() < KEY_SIZE + BLOCK_SIZE {
        return;
    }
    let key: [u8; KEY_SIZE] = data[..KEY_SIZE].try_into().unwrap();
    let iv: [u8; BLOCK_SIZE] = data[KEY_SIZE..KEY_SIZE + BLOCK_SIZE].try_into().unwrap();
    let pt = &data[KEY_SIZE + BLOCK_SIZE..];

    // Single-shot reference.
    let oneshot = mode_cbc::encrypt(&key, &iv, pt);

    // Streaming: feed plaintext in irregular chunks relative to the 16-byte
    // block, draining ready ciphertext after each update.
    const SIZES: [usize; 7] = [1, 3, 7, 16, 17, 31, 64];
    let mut enc = Sm4CbcEncryptor::new(&key, &iv);
    let mut streamed = Vec::new();
    let mut rest = pt;
    let mut i = 0usize;
    while !rest.is_empty() {
        let n = SIZES[i % SIZES.len()].min(rest.len());
        enc.update(&rest[..n]);
        streamed.extend_from_slice(&enc.take_output());
        rest = &rest[n..];
        i += 1;
    }
    streamed.extend_from_slice(&enc.finalize());

    assert_eq!(
        oneshot,
        streamed,
        "SM4-CBC one-shot vs streaming ciphertext mismatch ({}-byte pt)",
        pt.len()
    );

    // Round-trip: decrypt must recover the original plaintext.
    let recovered = mode_cbc::decrypt(&key, &iv, &oneshot)
        .expect("CBC decrypt of self-produced ciphertext must succeed");
    assert_eq!(
        recovered, pt,
        "SM4-CBC encrypt->decrypt round-trip mismatch"
    );
});
