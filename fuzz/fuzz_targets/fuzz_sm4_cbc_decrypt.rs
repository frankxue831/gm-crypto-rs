//! Fuzz target: `sm4::mode_cbc::decrypt` (SM4-CBC + PKCS#7 unpad).
//! Layout (front-to-back): [key:16][iv:16][ciphertext:rest].
//! Invariant: any input returns `Some`/`None` (single `None` — no padding
//! oracle) — never panics on bad length / bad padding.
#![no_main]

use arbitrary::Unstructured;
use gmcrypto_core::sm4::mode_cbc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let key: [u8; 16] = u.arbitrary().unwrap_or([0u8; 16]);
    let iv: [u8; 16] = u.arbitrary().unwrap_or([0u8; 16]);
    let ct = u.take_rest();
    let _ = mode_cbc::decrypt(&key, &iv, ct);
});
