//! Fuzz target: `sm4::mode_gcm::decrypt` (fixed 16-byte tag) AND
//! `decrypt_with_tag_len` (variable tag; length inferred + validated).
//! Layout (front-to-back, all bounded): [key:16][tag16:16][nl:1][nonce:nl]
//! [al:1][aad:al][tl:1][tag_var:tl][ciphertext:rest], where the 1-byte
//! length selectors are taken modulo a small cap so both valid and malformed
//! nonce/aad/tag lengths are explored.
//! Invariant: any input returns `Some`/`None` (constant-time tag compare) —
//! never panics.
#![no_main]

use arbitrary::Unstructured;
use gmcrypto_core::sm4::mode_gcm;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let key: [u8; 16] = u.arbitrary().unwrap_or([0u8; 16]);
    let tag16: [u8; 16] = u.arbitrary().unwrap_or([0u8; 16]);

    let nl = (u.arbitrary::<u8>().unwrap_or(0) % 17) as usize; // 0..=16
    let nonce = match u.bytes(nl) {
        Ok(b) => b.to_vec(),
        Err(_) => return,
    };
    let al = (u.arbitrary::<u8>().unwrap_or(0) % 33) as usize; // 0..=32
    let aad = match u.bytes(al) {
        Ok(b) => b.to_vec(),
        Err(_) => return,
    };
    let tl = (u.arbitrary::<u8>().unwrap_or(0) % 19) as usize; // 0..=18 (valid + invalid)
    let tag_var = match u.bytes(tl) {
        Ok(b) => b.to_vec(),
        Err(_) => return,
    };
    let ct = u.take_rest();

    let _ = mode_gcm::decrypt(&key, &nonce, &aad, ct, &tag16);
    let _ = mode_gcm::decrypt_with_tag_len(&key, &nonce, &aad, ct, &tag_var);
});
