//! Fuzz target: SM4-CCM incremental-input buffered decryptor
//! (`Sm4CcmDecryptor`), a DIFFERENTIAL oracle against the single-shot
//! `mode_ccm::decrypt` (v1.12 Q12.9).
//!
//! Layout (front-consuming, all bounded):
//! `[key:16][tl:1][tag:tl'][nl:1][nonce:nl'][al:1][aad:al'][chunk_len:1][ciphertext:rest]`
//! with `tl' = tl % 18` (0..=17 — the seven valid CCM tag lengths AND
//! invalid ones, so the `None == None` arm is exercised), `nl' = nl % 17`,
//! `al' = al % 33`. The single-shot oracle takes `ct ‖ tag` plus `tag_len`
//! (NOT GCM's split `(ct, tag)`): `decrypt(key, nonce, aad, ct‖tag,
//! tag.len())`. Streaming side: `Sm4CcmDecryptor::new` (a `None` there is
//! the streaming side's `None`), feed `ct` in chunks of `max(1, chunk_len)`,
//! `finalize_verify(&tag)`. The two `Option<Vec<u8>>`s MUST be equal for
//! EVERY input. Invariant: never panics.
#![no_main]

use arbitrary::Unstructured;
use gmcrypto_core::sm4::mode_ccm;
use gmcrypto_core::sm4::Sm4CcmDecryptor;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let key: [u8; 16] = u.arbitrary().unwrap_or([0u8; 16]);

    let tl = (u.arbitrary::<u8>().unwrap_or(0) % 18) as usize; // 0..=17
    let tag = match u.bytes(tl) {
        Ok(b) => b.to_vec(),
        Err(_) => return,
    };
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
    let chunk_len = u.arbitrary::<u8>().unwrap_or(0) as usize;
    let ct = u.take_rest();

    // Single-shot oracle: ct || tag, tag_len = tag.len().
    let mut ct_with_tag = ct.to_vec();
    ct_with_tag.extend_from_slice(&tag);
    let want = mode_ccm::decrypt(&key, &nonce, &aad, &ct_with_tag, tag.len());

    // Incremental: construct (None here == streaming None), feed, verify.
    let step = chunk_len.max(1);
    let got = match Sm4CcmDecryptor::new(&key, &nonce, &aad) {
        None => None,
        Some(mut dec) => {
            let mut off = 0;
            while off < ct.len() {
                let end = (off + step).min(ct.len());
                dec.update(&ct[off..end]);
                off = end;
            }
            dec.finalize_verify(&tag)
        }
    };

    assert_eq!(
        got, want,
        "SM4-CCM buffered decrypt diverged from single-shot (tag_len={}, nonce_len={}, chunk_len={chunk_len})",
        tag.len(),
        nonce.len()
    );
});
