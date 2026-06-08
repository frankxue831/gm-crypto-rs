//! Fuzz target: SM4-CCM ENCRYPT->DECRYPT round-trip.
//!
//! CCM has no streaming API, so (unlike CBC/GCM) there is no single-shot vs
//! streaming differential. The oracle is that decrypt recovers the plaintext,
//! and that a tampered tag is rejected. Existing CCM fuzzing covered only the
//! decrypt parser.
//!
//! Layout: [key:16][tag_len_sel:1][nonce_len_sel:1][aad_len:1][nonce][aad][pt..]
//! tag_len and nonce_len are mapped into the valid CCM ranges so most inputs
//! reach real AEAD work instead of parameter rejection.
#![no_main]

use gmcrypto_core::sm4::{mode_ccm, KEY_SIZE};
use libfuzzer_sys::fuzz_target;

const VALID_TAG_LENS: [usize; 7] = [4, 6, 8, 10, 12, 14, 16];

fuzz_target!(|data: &[u8]| {
    if data.len() < KEY_SIZE + 3 {
        return;
    }
    let key: [u8; KEY_SIZE] = data[..KEY_SIZE].try_into().unwrap();
    let mut rest = &data[KEY_SIZE..];

    let tag_len = VALID_TAG_LENS[(rest[0] as usize) % VALID_TAG_LENS.len()];
    let nonce_len = 7 + (rest[1] as usize) % 7; // CCM nonce length is 7..=13
    let aad_len = rest[2] as usize;
    rest = &rest[3..];

    if rest.len() < nonce_len {
        return;
    }
    let nonce = &rest[..nonce_len];
    rest = &rest[nonce_len..];

    let aad_len = aad_len.min(rest.len());
    let (aad, pt) = rest.split_at(aad_len);

    let ct_tag = match mode_ccm::encrypt(&key, nonce, aad, pt, tag_len) {
        Some(v) => v,
        None => return,
    };

    // Round-trip: decrypt+verify recovers the plaintext.
    let recovered = mode_ccm::decrypt(&key, nonce, aad, &ct_tag, tag_len)
        .expect("CCM decrypt of self-produced ciphertext must succeed");
    assert_eq!(
        recovered, pt,
        "SM4-CCM encrypt->decrypt round-trip mismatch"
    );

    // A single-bit-flipped tag byte (last byte) must be rejected.
    let mut tampered = ct_tag;
    let last = tampered.len() - 1; // ct_tag has length >= tag_len >= 4
    tampered[last] ^= 0x01;
    assert!(
        mode_ccm::decrypt(&key, nonce, aad, &tampered, tag_len).is_none(),
        "SM4-CCM must reject a tampered tag"
    );
});
