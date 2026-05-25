//! Fuzz target: `sm4::mode_xts::decrypt` (SM4-XTS GB/T 17964, ciphertext
//! stealing). Layout (front-to-back): [key:32][tweak:16][data_unit:rest].
//! Invariant: any input returns `Some`/`None` (single `None` — bad length or
//! Key1==Key2) — never panics, incl. the CTS tail and the α-doubling chain.
#![no_main]

use arbitrary::Unstructured;
use gmcrypto_core::sm4::mode_xts;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let key: [u8; 32] = u.arbitrary().unwrap_or([0u8; 32]);
    let tweak: [u8; 16] = u.arbitrary().unwrap_or([0u8; 16]);
    let data_unit = u.take_rest();
    let _ = mode_xts::decrypt(&key, &tweak, data_unit);
});
