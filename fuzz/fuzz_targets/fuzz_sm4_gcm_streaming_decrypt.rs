//! Fuzz target: SM4-GCM **streaming** decryptor (`Sm4GcmDecryptor`), a
//! DIFFERENTIAL oracle against the single-shot `mode_gcm::decrypt` (v0.20 W1).
//!
//! Layout (front-to-back, all bounded):
//! `[key:16][tag:16][nl:1][nonce:nl][al:1][aad:al][chunk_len:1][ciphertext:rest]`,
//! where `nl` (0..=16) and `al` (0..=32) are taken modulo a small cap so both
//! valid and malformed nonce/aad lengths are explored. A **fixed 16-byte tag**
//! is used deliberately (the `mode_gcm::decrypt` path) — truncated-tag is a
//! deferred extension. The ciphertext is fed to the streaming decryptor in
//! fixed-size chunks of `max(1, chunk_len)`, then `finalize_verify(&tag)`. The
//! result MUST byte-equal `mode_gcm::decrypt` fed all-at-once — both `None`
//! (tag mismatch / bad params), or both `Some(pt)` — for EVERY input. The
//! streaming decryptor is differential-KAT-equal to single-shot across
//! arbitrary chunking, so any divergence is a genuine bug. The GCM payload
//! ceiling differs between the two paths only above 2^36-ish bytes, which
//! `-max_len` keeps unreachable. Invariant: never panics.
#![no_main]

use arbitrary::Unstructured;
use gmcrypto_core::sm4::mode_gcm;
use gmcrypto_core::sm4::Sm4GcmDecryptor;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let key: [u8; 16] = u.arbitrary().unwrap_or([0u8; 16]);
    let tag: [u8; 16] = u.arbitrary().unwrap_or([0u8; 16]);

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

    // Single-shot oracle (fixed 16-byte tag).
    let want = mode_gcm::decrypt(&key, &nonce, &aad, ct, &tag);

    // Streaming: feed `ct` in fixed-size chunks of max(1, chunk_len), then verify.
    let step = chunk_len.max(1);
    let mut dec = Sm4GcmDecryptor::new(&key, &nonce, &aad);
    let mut off = 0;
    while off < ct.len() {
        let end = (off + step).min(ct.len());
        dec.update(&ct[off..end]);
        off = end;
    }
    let got = dec.finalize_verify(&tag);

    assert_eq!(
        got, want,
        "SM4-GCM streaming decrypt diverged from single-shot (chunk_len={chunk_len})"
    );
});
