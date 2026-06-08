//! Fuzz target: SM4-XTS ENCRYPT->DECRYPT round-trip.
//!
//! XTS has no streaming API; the oracle is that decrypt recovers the plaintext
//! across the ciphertext-stealing tail (data units that are not a whole number
//! of blocks). Existing XTS fuzzing covered only the decrypt path.
//!
//! XTS requires a data unit of at least one block (16 bytes) and Key1 != Key2
//! (weak-key check). Inputs are massaged to satisfy both so they reach real XTS
//! work rather than being rejected up front.
//!
//! Layout: [key:32][tweak:16][data_unit..(>=16)]
#![no_main]

use gmcrypto_core::sm4::mode_xts::{self, XTS_KEY_SIZE};
use gmcrypto_core::sm4::BLOCK_SIZE;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 32-byte key + 16-byte tweak + at least one 16-byte block of data.
    if data.len() < XTS_KEY_SIZE + BLOCK_SIZE + BLOCK_SIZE {
        return;
    }
    let mut key: [u8; XTS_KEY_SIZE] = data[..XTS_KEY_SIZE].try_into().unwrap();
    // XTS rejects Key1 == Key2; perturb a byte if the fuzzer produced equal
    // halves so the input still reaches real encryption.
    if key[..BLOCK_SIZE] == key[BLOCK_SIZE..] {
        key[BLOCK_SIZE] ^= 0x01;
    }
    let tweak: [u8; BLOCK_SIZE] = data[XTS_KEY_SIZE..XTS_KEY_SIZE + BLOCK_SIZE]
        .try_into()
        .unwrap();
    let data_unit = &data[XTS_KEY_SIZE + BLOCK_SIZE..];

    let ct = match mode_xts::encrypt(&key, &tweak, data_unit) {
        Some(v) => v,
        None => return,
    };
    let recovered = mode_xts::decrypt(&key, &tweak, &ct)
        .expect("XTS decrypt of self-produced ciphertext must succeed");
    assert_eq!(
        recovered, data_unit,
        "SM4-XTS encrypt->decrypt round-trip mismatch"
    );
});
