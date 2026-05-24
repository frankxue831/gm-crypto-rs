//! Fuzz target: `asn1::ciphertext::decode` (GM/T 0009 SM2 ciphertext
//! SEQUENCE { x, y, hash, ciphertext }). Validates structure, field-element
//! bounds, and C1 on-curve. Invariant: any input returns `Some`/`None`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = gmcrypto_core::asn1::ciphertext::decode(data);
});
