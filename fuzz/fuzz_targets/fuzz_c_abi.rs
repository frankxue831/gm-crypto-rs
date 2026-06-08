//! Fuzz target: the `gmcrypto-c` C ABI surface.
//!
//! Drives the `extern "C"` entry points the way a C caller would — raw
//! pointers + lengths + caller-owned output buffers — with attacker-controlled
//! bytes, to exercise the `unsafe` slice-reconstruction, null-checks, output
//! buffer-capacity handling, and opaque-handle lifecycle in
//! `gmcrypto-c/src/lib.rs`. Closes the "the C ABI layer has no dedicated fuzz
//! target" gap (every Rust-side parser is fuzzed; the FFI shim was not).
//!
//! The first byte selects an operation family:
//!   * ops 0–4 drive the happy-path contract (valid pointers, adequately sized
//!     buffers, each opaque handle freed exactly once — a handle consumed by
//!     `finalize()` is never also `free()`d);
//!   * op 5 drives NULL-pointer rejection: every guarded entry point must
//!     return `GMCRYPTO_ERR` (asserted), never deref or panic across FFI;
//!   * op 6 drives the output-capacity check with a deliberately undersized
//!     `out_capacity`: the call must reject (return value) without writing past
//!     the buffer (ASAN would catch an overflow).
//!
//! It does NOT probe documented-UB contract *violations* (e.g. double-free, or
//! passing a non-null but too-small fixed-size buffer) — those are caller UB by
//! design and out of scope.
#![no_main]

use gmcrypto_c::*;
use libfuzzer_sys::fuzz_target;
use std::ptr;

// A fixed, valid SM2 private scalar in [1, n-2] (same value the SM2 decrypt
// seed generator uses), so the decrypt path is reachable with attacker DER.
const FIXED_D: [u8; GMCRYPTO_SM2_SCALAR_SIZE] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
];

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // First byte selects the entry point under test; the rest is the payload.
    let op = data[0];
    let body = &data[1..];

    // SAFETY: ops 0–4 pass valid (ptr, len) for the documented fixed sizes,
    // output buffers large enough for the worst-case write, and free each
    // opaque handle exactly once. Op 5 passes NULL pointers to guarded entry
    // points (which must report GMCRYPTO_ERR). Op 6 passes a real but small
    // buffer with a matching (small) out_capacity, exercising the capacity
    // check. No call violates the documented pointer/length contract.
    unsafe {
        match op % 7 {
            // (0) Single-shot SM3 over arbitrary bytes.
            0 => {
                let mut digest = [0u8; GMCRYPTO_SM3_DIGEST_SIZE];
                let _ = gmcrypto_sm3_hash(body.as_ptr(), body.len(), digest.as_mut_ptr());
            }

            // (1) Streaming SM3 lifecycle: new -> update(chunks) -> finalize.
            //     finalize() CONSUMES the handle, so it is NOT also freed.
            1 => {
                let h = gmcrypto_sm3_new();
                if !h.is_null() {
                    for chunk in body.chunks(7) {
                        let _ = gmcrypto_sm3_update(h, chunk.as_ptr(), chunk.len());
                    }
                    let mut digest = [0u8; GMCRYPTO_SM3_DIGEST_SIZE];
                    let _ = gmcrypto_sm3_finalize(h, digest.as_mut_ptr());
                    // h was consumed by finalize(); do NOT free.
                }
            }

            // (2) SM2 public-key parse from a 65-byte SEC1 point, then export
            //     round-trip. Bytes are arbitrary (most are invalid points).
            2 => {
                let mut sec1 = [0u8; GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE];
                let n = body.len().min(sec1.len());
                sec1[..n].copy_from_slice(&body[..n]);
                let pk = gmcrypto_sm2_pubkey_new(sec1.as_ptr());
                if !pk.is_null() {
                    let mut out = [0u8; GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE];
                    let _ = gmcrypto_sm2_pubkey_to_sec1_uncompressed(pk, out.as_mut_ptr());
                    gmcrypto_sm2_pubkey_free(pk);
                }
            }

            // (3) SM4-CBC decrypt: key / IV / ciphertext carved from the input.
            //     CBC plaintext is never longer than the ciphertext, so an
            //     out buffer of ct_len is always sufficient.
            3 => {
                if body.len() >= GMCRYPTO_SM4_KEY_SIZE + GMCRYPTO_SM4_BLOCK_SIZE {
                    let (key, r1) = body.split_at(GMCRYPTO_SM4_KEY_SIZE);
                    let (iv, ct) = r1.split_at(GMCRYPTO_SM4_BLOCK_SIZE);
                    let mut out = vec![0u8; ct.len().max(1)];
                    let mut out_len = 0usize;
                    let _ = gmcrypto_sm4_cbc_decrypt(
                        key.as_ptr(),
                        iv.as_ptr(),
                        ct.as_ptr(),
                        ct.len(),
                        out.as_mut_ptr(),
                        out.len(),
                        &mut out_len,
                    );
                }
            }

            // (4) SM2 decrypt with a FIXED valid private key + attacker DER
            //     ciphertext. Plaintext <= ciphertext length, so out=body.len()
            //     is a safe upper bound.
            4 => {
                let sk = gmcrypto_sm2_privkey_new(FIXED_D.as_ptr());
                if !sk.is_null() {
                    let mut out = vec![0u8; body.len().max(1)];
                    let mut out_len = 0usize;
                    let _ = gmcrypto_sm2_decrypt(
                        sk,
                        body.as_ptr(),
                        body.len(),
                        out.as_mut_ptr(),
                        out.len(),
                        &mut out_len,
                    );
                    gmcrypto_sm2_privkey_free(sk);
                }
            }

            // (5) NULL-pointer rejection: guarded entry points must return
            //     GMCRYPTO_ERR rather than dereference or panic across FFI.
            5 => {
                let mut digest = [0u8; GMCRYPTO_SM3_DIGEST_SIZE];
                let mut out = [0u8; 32];
                let mut out_len = 0usize;
                assert_eq!(
                    gmcrypto_sm3_hash(ptr::null(), 1, digest.as_mut_ptr()),
                    GMCRYPTO_ERR
                );
                assert_eq!(
                    gmcrypto_sm3_hash(body.as_ptr(), body.len(), ptr::null_mut()),
                    GMCRYPTO_ERR
                );
                assert_eq!(
                    gmcrypto_sm3_finalize(ptr::null_mut(), digest.as_mut_ptr()),
                    GMCRYPTO_ERR
                );
                assert_eq!(
                    gmcrypto_sm4_cbc_decrypt(
                        ptr::null(),
                        ptr::null(),
                        body.as_ptr(),
                        body.len(),
                        out.as_mut_ptr(),
                        out.len(),
                        &mut out_len,
                    ),
                    GMCRYPTO_ERR
                );
                assert_eq!(
                    gmcrypto_sm2_decrypt(
                        ptr::null::<gmcrypto_sm2_privkey_t>(),
                        body.as_ptr(),
                        body.len(),
                        out.as_mut_ptr(),
                        out.len(),
                        &mut out_len,
                    ),
                    GMCRYPTO_ERR
                );
            }

            // (6) Undersized output buffer: a real 1-byte buffer with
            //     out_capacity=1. The capacity check must reject without
            //     writing past the buffer (ASAN catches any overflow).
            _ => {
                let mut tiny = [0u8; 1];
                let mut out_len = 0usize;
                if body.len() >= GMCRYPTO_SM4_KEY_SIZE + GMCRYPTO_SM4_BLOCK_SIZE {
                    let (key, r1) = body.split_at(GMCRYPTO_SM4_KEY_SIZE);
                    let (iv, ct) = r1.split_at(GMCRYPTO_SM4_BLOCK_SIZE);
                    let _ = gmcrypto_sm4_cbc_decrypt(
                        key.as_ptr(),
                        iv.as_ptr(),
                        ct.as_ptr(),
                        ct.len(),
                        tiny.as_mut_ptr(),
                        tiny.len(),
                        &mut out_len,
                    );
                }
                let sk = gmcrypto_sm2_privkey_new(FIXED_D.as_ptr());
                if !sk.is_null() {
                    let _ = gmcrypto_sm2_decrypt(
                        sk,
                        body.as_ptr(),
                        body.len(),
                        tiny.as_mut_ptr(),
                        tiny.len(),
                        &mut out_len,
                    );
                    gmcrypto_sm2_privkey_free(sk);
                }
            }
        }
    }
});
