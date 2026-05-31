//! Fuzz target: SM4-CBC **streaming** decryptor (`Sm4CbcDecryptor`), a
//! DIFFERENTIAL oracle against the single-shot `mode_cbc::decrypt` (v0.20 W1).
//!
//! Layout (front-to-back): `[key:16][iv:16][chunk_len:1][ciphertext:rest]`.
//! The ciphertext is fed to the streaming decryptor in fixed-size chunks of
//! `max(1, chunk_len)` (a `chunk_len` of 0 ⇒ one chunk), then `finalize()`.
//! The result MUST byte-equal `mode_cbc::decrypt` fed all-at-once — both
//! `None`, or both `Some(pt)` with equal plaintext — for EVERY input (the
//! streaming path is just a chunked re-expression of the same computation,
//! incl. the buffer-back-by-one PKCS#7 boundary). Any divergence is a genuine
//! bug. Invariant: never panics.
#![no_main]

use arbitrary::Unstructured;
use gmcrypto_core::sm4::mode_cbc;
use gmcrypto_core::sm4::Sm4CbcDecryptor;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let key: [u8; 16] = u.arbitrary().unwrap_or([0u8; 16]);
    let iv: [u8; 16] = u.arbitrary().unwrap_or([0u8; 16]);
    let chunk_len = u.arbitrary::<u8>().unwrap_or(0) as usize;
    let ct = u.take_rest();

    // Single-shot oracle.
    let want = mode_cbc::decrypt(&key, &iv, ct);

    // Streaming: feed `ct` in fixed-size chunks of max(1, chunk_len).
    let step = chunk_len.max(1);
    let mut dec = Sm4CbcDecryptor::new(&key, &iv);
    let mut off = 0;
    while off < ct.len() {
        let end = (off + step).min(ct.len());
        dec.update(&ct[off..end]);
        off = end;
    }
    let got = dec.finalize();

    assert_eq!(
        got, want,
        "SM4-CBC streaming decrypt diverged from single-shot (chunk_len={chunk_len})"
    );
});
