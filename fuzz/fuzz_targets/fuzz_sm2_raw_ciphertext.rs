//! Fuzz target: the raw SM2 ciphertext decoders (`decode_c1c3c2` modern +
//! `decode_c1c2c3_legacy`). Both validate the C1 tag/length, field-element
//! bounds, and C1 on-curve. Invariant: any input returns `Some`/`None`.
#![no_main]

use gmcrypto_core::sm2::raw_ciphertext;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = raw_ciphertext::decode_c1c3c2(data);
    let _ = raw_ciphertext::decode_c1c2c3_legacy(data);
});
