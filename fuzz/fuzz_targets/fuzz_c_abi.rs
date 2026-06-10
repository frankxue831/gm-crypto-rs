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
//!     the buffer (ASAN would catch an overflow);
//!   * op 7 (v1.2) drives the SM2 key-exchange handle lifecycle with
//!     attacker-controlled peer wire bytes (`R`: 65, `S`: 32) against fixed
//!     static keys + a fixed deterministic ephemeral: initiator `confirm` and
//!     responder `respond`/`finish` including the consume-on-success and
//!     spent-handle-on-failed-respond paths (the second respond after a
//!     failure is ASSERTED to fail).
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

/// The SEC1 public point for [`FIXED_D`], derived once via the core (the
/// fuzz target plays both KX roles against itself — a valid static peer).
fn fixed_pub_sec1() -> &'static [u8; GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE] {
    static P: std::sync::OnceLock<[u8; GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE]> =
        std::sync::OnceLock::new();
    P.get_or_init(|| {
        let key: gmcrypto_core::sm2::Sm2PrivateKey =
            Option::from(gmcrypto_core::sm2::Sm2PrivateKey::from_bytes_be(&FIXED_D))
                .expect("FIXED_D is a valid scalar");
        key.public_key().to_sec1_uncompressed()
    })
}

/// Deterministic RNG callback for the KX op (op 7): every draw is
/// 0x5A-filled, so the local ephemeral is a fixed valid scalar and the
/// op stays reproducible (no OS RNG nondeterminism in the fuzz loop).
unsafe extern "C" fn fixed_fill_rng(
    _context: *mut core::ffi::c_void,
    buf: *mut u8,
    buf_len: usize,
) -> core::ffi::c_int {
    if buf.is_null() && buf_len > 0 {
        return -1;
    }
    // SAFETY: `buf` is valid for `buf_len` bytes per the callback contract
    // (the shim always passes a real slice).
    unsafe { std::slice::from_raw_parts_mut(buf, buf_len) }.fill(0x5A);
    0
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // First byte selects the entry point under test; the rest is the payload.
    let op = data[0];
    let body = &data[1..];

    // SAFETY: ops 0–4 and 7 pass valid (ptr, len) for the documented fixed
    // sizes, output buffers large enough for the worst-case write, and free
    // each opaque handle exactly once (handles consumed by finalize/confirm/
    // finish are never also freed). Op 5 passes NULL pointers to guarded
    // entry points (which must report GMCRYPTO_ERR). Op 6 passes a real but
    // small buffer with a matching (small) out_capacity, exercising the
    // capacity check. No call violates the documented pointer/length
    // contract.
    unsafe {
        match op % 8 {
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

            // (7) SM2 key exchange (v1.2): fixed static keys + fixed 0x5A
            //     ephemeral; the PEER's wire bytes (R: 65, S: 32, carved from
            //     the front of the body, zero-padded) are attacker-controlled.
            //     Initiator side: new_with_rng -> confirm(attacker R_B, S_B)
            //     [confirm consumes — no free]. Responder side: new ->
            //     respond_with_rng(attacker R_A); on success drive
            //     finish(attacker S_A) [consumes]; on failure the handle is
            //     SPENT — a retry respond is asserted to fail, then freed.
            7 => {
                let mut r_bytes = [0u8; GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE];
                let n = body.len().min(r_bytes.len());
                r_bytes[..n].copy_from_slice(&body[..n]);
                let rest = &body[n..];
                let mut s_bytes = [0u8; GMCRYPTO_SM2_KX_CONFIRM_SIZE];
                let m = rest.len().min(s_bytes.len());
                s_bytes[..m].copy_from_slice(&rest[..m]);

                let sk = gmcrypto_sm2_privkey_new(FIXED_D.as_ptr());
                let pk = gmcrypto_sm2_pubkey_new(fixed_pub_sec1().as_ptr());
                if !sk.is_null() && !pk.is_null() {
                    // Initiator lifecycle against attacker (R_B, S_B).
                    let mut r_a = [0u8; GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE];
                    let init = gmcrypto_sm2_kx_initiator_new_with_rng(
                        sk,
                        pk,
                        ptr::null(),
                        0,
                        ptr::null(),
                        0,
                        16,
                        Some(fixed_fill_rng),
                        ptr::null_mut(),
                        r_a.as_mut_ptr(),
                    );
                    if !init.is_null() {
                        let mut key = [0u8; 16];
                        let mut s_a = [0u8; GMCRYPTO_SM2_KX_CONFIRM_SIZE];
                        let _ = gmcrypto_sm2_kx_initiator_confirm(
                            init,
                            r_bytes.as_ptr(),
                            s_bytes.as_ptr(),
                            key.as_mut_ptr(),
                            s_a.as_mut_ptr(),
                        );
                        // init was consumed by confirm; do NOT free.
                    }

                    // Responder lifecycle against attacker R_A.
                    let resp =
                        gmcrypto_sm2_kx_responder_new(sk, pk, ptr::null(), 0, ptr::null(), 0, 16);
                    if !resp.is_null() {
                        let mut r_b = [0u8; GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE];
                        let mut s_b = [0u8; GMCRYPTO_SM2_KX_CONFIRM_SIZE];
                        let rc = gmcrypto_sm2_kx_responder_respond_with_rng(
                            resp,
                            r_bytes.as_ptr(),
                            Some(fixed_fill_rng),
                            ptr::null_mut(),
                            r_b.as_mut_ptr(),
                            s_b.as_mut_ptr(),
                        );
                        if rc == GMCRYPTO_OK {
                            // Valid attacker point: drive finish with the
                            // attacker S_A (consumes the handle).
                            let mut key = [0u8; 16];
                            let _ = gmcrypto_sm2_kx_responder_finish(
                                resp,
                                s_bytes.as_ptr(),
                                key.as_mut_ptr(),
                            );
                        } else {
                            // Failed respond SPENDS the handle: a retry with
                            // the same bytes must also fail; then free.
                            assert_eq!(
                                gmcrypto_sm2_kx_responder_respond(
                                    resp,
                                    r_bytes.as_ptr(),
                                    r_b.as_mut_ptr(),
                                    s_b.as_mut_ptr(),
                                ),
                                GMCRYPTO_ERR
                            );
                            gmcrypto_sm2_kx_responder_free(resp);
                        }
                    }
                }
                if !sk.is_null() {
                    gmcrypto_sm2_privkey_free(sk);
                }
                if !pk.is_null() {
                    gmcrypto_sm2_pubkey_free(pk);
                }
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
