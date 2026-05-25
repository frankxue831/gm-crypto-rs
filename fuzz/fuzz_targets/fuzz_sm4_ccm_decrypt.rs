//! Fuzz target: `sm4::mode_ccm::decrypt` (SM4-CCM; CBC-MAC + CTR).
//! Layout (front-to-back, all bounded): [key:16][nl:1][nonce:nl][al:1]
//! [aad:al][tag_len_sel:1][ciphertext_with_tag:rest], where the 1-byte
//! selectors are taken modulo small caps so valid (nonce 7..13, tag_len in
//! {4,6,8,10,12,14,16}) and malformed lengths are both explored.
//! Invariant: any input returns `Some`/`None` (constant-time tag compare) —
//! never panics.
#![no_main]

use arbitrary::Unstructured;
use gmcrypto_core::sm4::mode_ccm;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let key: [u8; 16] = u.arbitrary().unwrap_or([0u8; 16]);

    let nl = (u.arbitrary::<u8>().unwrap_or(0) % 21) as usize; // 0..=20 (valid 7..=13)
    let nonce = match u.bytes(nl) {
        Ok(b) => b.to_vec(),
        Err(_) => return,
    };
    let al = (u.arbitrary::<u8>().unwrap_or(0) % 33) as usize; // 0..=32
    let aad = match u.bytes(al) {
        Ok(b) => b.to_vec(),
        Err(_) => return,
    };
    let tag_len = (u.arbitrary::<u8>().unwrap_or(0) % 18) as usize; // valid subset + invalid
    let ct_with_tag = u.take_rest();

    let _ = mode_ccm::decrypt(&key, &nonce, &aad, ct_with_tag, tag_len);
});
