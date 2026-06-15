//! Rust-equivalence smoke test for every `gmcrypto-c` FFI entry
//! point. Each test:
//!
//! 1. Calls the FFI fn via Rust's own `extern "C"` interop
//!    (re-declaring the C signature locally).
//! 2. Calls the equivalent `gmcrypto-core` API directly.
//! 3. Asserts the bytes match.
//!
//! This is the v0.4 W4 cryptographic-correctness gate. If a C
//! consumer would see different bytes than a Rust caller of
//! `gmcrypto-core`, this test catches it.

#![allow(unsafe_code)]
#![allow(clippy::missing_safety_doc)]
// The c_smoke test passes `&mut usize` to FFI fns that expect
// `*mut usize`; this is intentional and constant across tests.
#![allow(unknown_lints)]
#![allow(clippy::implicit_borrow_as_raw_pointer)]
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::used_underscore_binding)]

use core::ptr;

use gmcrypto_c::{
    GMCRYPTO_ERR, GMCRYPTO_OK, GMCRYPTO_SM2_SCALAR_SIZE, GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE,
    gmcrypto_hmac_sm3, gmcrypto_hmac_sm3_finalize, gmcrypto_hmac_sm3_new, gmcrypto_hmac_sm3_t,
    gmcrypto_hmac_sm3_update, gmcrypto_hmac_sm3_verify, gmcrypto_pbkdf2_hmac_sm3,
    gmcrypto_rng_callback, gmcrypto_sm2_decrypt, gmcrypto_sm2_decrypt_c1c2c3_legacy,
    gmcrypto_sm2_decrypt_c1c3c2, gmcrypto_sm2_encrypt, gmcrypto_sm2_encrypt_c1c3c2,
    gmcrypto_sm2_encrypt_with_rng, gmcrypto_sm2_privkey_free, gmcrypto_sm2_privkey_from_pkcs8,
    gmcrypto_sm2_privkey_new, gmcrypto_sm2_privkey_t, gmcrypto_sm2_privkey_to_pkcs8,
    gmcrypto_sm2_privkey_to_sec1_be, gmcrypto_sm2_pubkey_free, gmcrypto_sm2_pubkey_new,
    gmcrypto_sm2_pubkey_t, gmcrypto_sm2_pubkey_to_sec1_uncompressed, gmcrypto_sm2_sign,
    gmcrypto_sm2_sign_with_rng, gmcrypto_sm2_verify, gmcrypto_sm3_finalize, gmcrypto_sm3_free,
    gmcrypto_sm3_hash, gmcrypto_sm3_new, gmcrypto_sm3_t, gmcrypto_sm3_update,
    gmcrypto_sm4_cbc_decrypt, gmcrypto_sm4_cbc_decryptor_finalize, gmcrypto_sm4_cbc_decryptor_free,
    gmcrypto_sm4_cbc_decryptor_new, gmcrypto_sm4_cbc_decryptor_t,
    gmcrypto_sm4_cbc_decryptor_update, gmcrypto_sm4_cbc_encrypt,
    gmcrypto_sm4_cbc_encryptor_finalize, gmcrypto_sm4_cbc_encryptor_free,
    gmcrypto_sm4_cbc_encryptor_new, gmcrypto_sm4_cbc_encryptor_t,
    gmcrypto_sm4_cbc_encryptor_update, gmcrypto_sm4_decrypt_block, gmcrypto_sm4_encrypt_block,
    gmcrypto_sm4_free, gmcrypto_sm4_new, gmcrypto_sm4_t,
};
use hex_literal::hex;

// ============================================================
// SM3
// ============================================================

#[test]
fn sm3_hash_matches_core() {
    let mut out = [0u8; 32];
    let r = unsafe { gmcrypto_sm3_hash(b"abc".as_ptr(), 3, out.as_mut_ptr()) };
    assert_eq!(r, GMCRYPTO_OK);
    assert_eq!(
        out,
        hex!("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
    );
    assert_eq!(out, gmcrypto_core::sm3::hash(b"abc"));
}

#[test]
fn sm3_streaming_matches_core() {
    let h: *mut gmcrypto_sm3_t = gmcrypto_sm3_new();
    assert!(!h.is_null());
    let mut out = [0u8; 32];
    unsafe {
        assert_eq!(gmcrypto_sm3_update(h, b"a".as_ptr(), 1), GMCRYPTO_OK);
        assert_eq!(gmcrypto_sm3_update(h, b"bc".as_ptr(), 2), GMCRYPTO_OK);
        assert_eq!(gmcrypto_sm3_finalize(h, out.as_mut_ptr()), GMCRYPTO_OK);
    }
    assert_eq!(out, gmcrypto_core::sm3::hash(b"abc"));
}

#[test]
fn sm3_empty_via_ffi() {
    let mut out = [0u8; 32];
    let r = unsafe { gmcrypto_sm3_hash(ptr::null(), 0, out.as_mut_ptr()) };
    assert_eq!(r, GMCRYPTO_OK);
    assert_eq!(out, gmcrypto_core::sm3::hash(&[]));
}

#[test]
fn sm3_null_out_rejected() {
    let r = unsafe { gmcrypto_sm3_hash(b"abc".as_ptr(), 3, ptr::null_mut()) };
    assert_eq!(r, GMCRYPTO_ERR);
}

#[test]
fn sm3_free_null_is_noop() {
    unsafe { gmcrypto_sm3_free(ptr::null_mut()) };
}

// ============================================================
// HMAC-SM3
// ============================================================

#[test]
fn hmac_sm3_single_shot_matches_core() {
    let key = [0x0bu8; 20];
    let msg = b"Hi There";
    let mut tag = [0u8; 32];
    let r = unsafe {
        gmcrypto_hmac_sm3(
            key.as_ptr(),
            key.len(),
            msg.as_ptr(),
            msg.len(),
            tag.as_mut_ptr(),
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    assert_eq!(tag, gmcrypto_core::hmac::hmac_sm3(&key, msg));
}

#[test]
fn hmac_sm3_streaming_matches_core() {
    let key = b"Jefe";
    let msg = b"what do ya want for nothing?";
    let h: *mut gmcrypto_hmac_sm3_t = unsafe { gmcrypto_hmac_sm3_new(key.as_ptr(), key.len()) };
    assert!(!h.is_null());
    let mut tag = [0u8; 32];
    unsafe {
        // Feed in two chunks to exercise streaming.
        assert_eq!(gmcrypto_hmac_sm3_update(h, msg.as_ptr(), 5), GMCRYPTO_OK);
        assert_eq!(
            gmcrypto_hmac_sm3_update(h, msg[5..].as_ptr(), msg.len() - 5),
            GMCRYPTO_OK,
        );
        assert_eq!(gmcrypto_hmac_sm3_finalize(h, tag.as_mut_ptr()), GMCRYPTO_OK);
    }
    assert_eq!(tag, gmcrypto_core::hmac::hmac_sm3(key, msg));
}

#[test]
fn hmac_sm3_verify_matches_core() {
    let key = [0x0bu8; 20];
    let msg = b"Hi There";
    let expected = gmcrypto_core::hmac::hmac_sm3(&key, msg);

    let h = unsafe { gmcrypto_hmac_sm3_new(key.as_ptr(), key.len()) };
    assert!(!h.is_null());
    unsafe {
        assert_eq!(
            gmcrypto_hmac_sm3_update(h, msg.as_ptr(), msg.len()),
            GMCRYPTO_OK
        );
        assert_eq!(
            gmcrypto_hmac_sm3_verify(h, expected.as_ptr()),
            GMCRYPTO_OK,
            "valid tag accepted",
        );
    }

    // And one that should fail.
    let mut wrong = expected;
    wrong[0] ^= 1;
    let h2 = unsafe { gmcrypto_hmac_sm3_new(key.as_ptr(), key.len()) };
    unsafe {
        assert_eq!(
            gmcrypto_hmac_sm3_update(h2, msg.as_ptr(), msg.len()),
            GMCRYPTO_OK
        );
        assert_eq!(
            gmcrypto_hmac_sm3_verify(h2, wrong.as_ptr()),
            GMCRYPTO_ERR,
            "wrong tag rejected",
        );
    }
}

// ============================================================
// PBKDF2-HMAC-SM3
// ============================================================

#[test]
fn pbkdf2_hmac_sm3_matches_core() {
    let pw = b"password";
    let salt = b"salt";
    let mut via_ffi = [0u8; 32];
    let mut via_core = [0u8; 32];
    let r = unsafe {
        gmcrypto_pbkdf2_hmac_sm3(
            pw.as_ptr(),
            pw.len(),
            salt.as_ptr(),
            salt.len(),
            4096,
            via_ffi.as_mut_ptr(),
            via_ffi.len(),
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    gmcrypto_core::kdf::pbkdf2_hmac_sm3(pw, salt, 4096, &mut via_core).unwrap();
    assert_eq!(via_ffi, via_core);
}

#[test]
fn pbkdf2_zero_iters_rejected() {
    let mut out = [0u8; 32];
    let r = unsafe {
        gmcrypto_pbkdf2_hmac_sm3(
            b"pw".as_ptr(),
            2,
            b"salt".as_ptr(),
            4,
            0, // iterations == 0 → Failed per the failure-mode invariant
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert_eq!(r, GMCRYPTO_ERR);
}

// ============================================================
// SM4 single-block + CBC
// ============================================================

#[test]
fn sm4_single_block_matches_core() {
    let key = hex!("0123456789abcdeffedcba9876543210");
    let pt = hex!("0123456789abcdeffedcba9876543210");
    let expected_ct = hex!("681edf34d206965e86b3e94f536e4246");

    let cipher: *mut gmcrypto_sm4_t = unsafe { gmcrypto_sm4_new(key.as_ptr()) };
    assert!(!cipher.is_null());
    let mut buf = pt;
    unsafe {
        assert_eq!(
            gmcrypto_sm4_encrypt_block(cipher, buf.as_mut_ptr()),
            GMCRYPTO_OK
        );
    }
    assert_eq!(buf, expected_ct);
    // Decrypt round-trip.
    unsafe {
        assert_eq!(
            gmcrypto_sm4_decrypt_block(cipher, buf.as_mut_ptr()),
            GMCRYPTO_OK
        );
    }
    assert_eq!(buf, pt);
    unsafe { gmcrypto_sm4_free(cipher) };
}

#[test]
fn sm4_cbc_round_trip() {
    let key = [0x42u8; 16];
    let iv = [0x37u8; 16];
    let pt = b"the quick brown fox jumps over"; // 30 bytes
    let mut ct = vec![0u8; 64]; // capacity > pt + padding
    let mut actual = 0usize;
    let r = unsafe {
        gmcrypto_sm4_cbc_encrypt(
            key.as_ptr(),
            iv.as_ptr(),
            pt.as_ptr(),
            pt.len(),
            ct.as_mut_ptr(),
            ct.len(),
            &mut actual,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    // 30 bytes → 32 bytes after PKCS#7 pad.
    assert_eq!(actual, 32);
    ct.truncate(actual);

    // Compare with the core API directly.
    let core_ct = gmcrypto_core::sm4::mode_cbc::encrypt(&key, &iv, pt);
    assert_eq!(ct, core_ct);

    // Round-trip decrypt.
    let mut pt_back = vec![0u8; 64];
    let mut actual_pt = 0usize;
    let r = unsafe {
        gmcrypto_sm4_cbc_decrypt(
            key.as_ptr(),
            iv.as_ptr(),
            ct.as_ptr(),
            ct.len(),
            pt_back.as_mut_ptr(),
            pt_back.len(),
            &mut actual_pt,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    assert_eq!(actual_pt, pt.len());
    pt_back.truncate(actual_pt);
    assert_eq!(pt_back.as_slice(), pt.as_slice());
}

#[test]
fn sm4_cbc_too_small_buffer_returns_required_len() {
    let key = [0u8; 16];
    let iv = [0u8; 16];
    let pt = [0u8; 100]; // → 112 bytes after pad
    let mut out = [0u8; 16]; // too small
    let mut actual = 0usize;
    let r = unsafe {
        gmcrypto_sm4_cbc_encrypt(
            key.as_ptr(),
            iv.as_ptr(),
            pt.as_ptr(),
            pt.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut actual,
        )
    };
    assert_eq!(r, GMCRYPTO_ERR);
    assert_eq!(actual, 112, "required length reported");
}

// ============================================================
// SM4-CBC streaming (v0.5 W1)
// ============================================================

/// Helper: streaming-encrypt `pt` in `chunks` chunks via the FFI.
/// Returns the ciphertext.
fn ffi_stream_encrypt(key: &[u8; 16], iv: &[u8; 16], pt: &[u8], chunk_size: usize) -> Vec<u8> {
    let enc: *mut gmcrypto_sm4_cbc_encryptor_t =
        unsafe { gmcrypto_sm4_cbc_encryptor_new(key.as_ptr(), iv.as_ptr()) };
    assert!(!enc.is_null());

    let mut ciphertext = Vec::new();
    let mut offset = 0;
    while offset < pt.len() {
        let take = chunk_size.min(pt.len() - offset);
        let chunk = &pt[offset..offset + take];
        // Per the contract, cap = chunk.len() + 16 upper-bounds emit.
        let mut buf = vec![0u8; chunk.len() + 16];
        let mut actual = 0usize;
        let rc = unsafe {
            gmcrypto_sm4_cbc_encryptor_update(
                enc,
                chunk.as_ptr(),
                chunk.len(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut actual,
            )
        };
        assert_eq!(rc, GMCRYPTO_OK);
        buf.truncate(actual);
        ciphertext.extend_from_slice(&buf);
        offset += take;
    }

    // finalize emits exactly one block (the padded trailing block).
    let mut final_buf = [0u8; 16];
    let mut final_actual = 0usize;
    let rc = unsafe {
        gmcrypto_sm4_cbc_encryptor_finalize(
            enc,
            final_buf.as_mut_ptr(),
            final_buf.len(),
            &mut final_actual,
        )
    };
    assert_eq!(rc, GMCRYPTO_OK);
    assert_eq!(final_actual, 16);
    ciphertext.extend_from_slice(&final_buf);
    // enc is freed by finalize — do NOT call _free.
    ciphertext
}

/// Helper: streaming-decrypt `ct` in `chunks` chunks via the FFI.
/// Returns `Some(plaintext)` on success, `None` on any failure.
fn ffi_stream_decrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    ct: &[u8],
    chunk_size: usize,
) -> Option<Vec<u8>> {
    let dec: *mut gmcrypto_sm4_cbc_decryptor_t =
        unsafe { gmcrypto_sm4_cbc_decryptor_new(key.as_ptr(), iv.as_ptr()) };
    if dec.is_null() {
        return None;
    }

    let mut plaintext = Vec::new();
    let mut offset = 0;
    while offset < ct.len() {
        let take = chunk_size.min(ct.len() - offset);
        let chunk = &ct[offset..offset + take];
        let mut buf = vec![0u8; chunk.len() + 16];
        let mut actual = 0usize;
        let rc = unsafe {
            gmcrypto_sm4_cbc_decryptor_update(
                dec,
                chunk.as_ptr(),
                chunk.len(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut actual,
            )
        };
        if rc != GMCRYPTO_OK {
            unsafe { gmcrypto_sm4_cbc_decryptor_free(dec) };
            return None;
        }
        buf.truncate(actual);
        plaintext.extend_from_slice(&buf);
        offset += take;
    }

    // finalize emits at most 16 bytes (the strip of the held-back block).
    let mut final_buf = [0u8; 16];
    let mut final_actual = 0usize;
    let rc = unsafe {
        gmcrypto_sm4_cbc_decryptor_finalize(
            dec,
            final_buf.as_mut_ptr(),
            final_buf.len(),
            &mut final_actual,
        )
    };
    // dec is freed by finalize regardless of success — do NOT call _free.
    if rc != GMCRYPTO_OK {
        return None;
    }
    plaintext.extend_from_slice(&final_buf[..final_actual]);
    Some(plaintext)
}

#[test]
fn sm4_cbc_streaming_encrypt_matches_single_shot() {
    let key = [0x42u8; 16];
    let iv = [0x37u8; 16];
    let pt = b"the quick brown fox jumps over the lazy dog";

    // Single-shot (golden).
    let golden = gmcrypto_core::sm4::mode_cbc::encrypt(&key, &iv, pt);

    // Streaming with chunk_size=7 (deliberately non-multiple of 16 to
    // exercise the partial-block buffer path).
    let streamed = ffi_stream_encrypt(&key, &iv, pt, 7);
    assert_eq!(streamed, golden, "streaming encrypt matches single-shot");
}

#[test]
fn sm4_cbc_streaming_decrypt_matches_single_shot() {
    let key = [0x42u8; 16];
    let iv = [0x37u8; 16];
    let pt = b"the quick brown fox jumps over the lazy dog";
    let ct = gmcrypto_core::sm4::mode_cbc::encrypt(&key, &iv, pt);

    let streamed = ffi_stream_decrypt(&key, &iv, &ct, 5).expect("decrypt ok");
    assert_eq!(streamed, pt, "streaming decrypt matches plaintext");
}

#[test]
fn sm4_cbc_streaming_chunk_boundary_invariance() {
    let key = [0x11u8; 16];
    let iv = [0x22u8; 16];
    // 100 bytes — exercises 6 full blocks plus a 4-byte trailing
    // partial.
    let pt: Vec<u8> = (0u8..100).collect();
    let golden = gmcrypto_core::sm4::mode_cbc::encrypt(&key, &iv, &pt);

    // Try a sweep of chunk sizes; every one must match the single-shot
    // result byte-for-byte.
    for chunk in [1usize, 2, 5, 13, 15, 16, 17, 31, 32, 33, 100] {
        let streamed = ffi_stream_encrypt(&key, &iv, &pt, chunk);
        assert_eq!(
            streamed, golden,
            "chunk size {chunk} should yield identical ciphertext"
        );
    }
}

#[test]
fn sm4_cbc_streaming_round_trip_chunk_boundary_invariance() {
    let key = [0x9bu8; 16];
    let iv = [0xa7u8; 16];
    let pt: Vec<u8> = (0u8..=255).collect(); // 256 bytes = 16 full blocks
    let ct = gmcrypto_core::sm4::mode_cbc::encrypt(&key, &iv, &pt);

    for chunk in [1usize, 7, 16, 17, 64, 256] {
        let plaintext = ffi_stream_decrypt(&key, &iv, &ct, chunk).expect("decrypt ok");
        assert_eq!(plaintext, pt, "chunk size {chunk} must round-trip cleanly");
    }
}

#[test]
fn sm4_cbc_streaming_decrypt_rejects_truncated() {
    let key = [0u8; 16];
    let iv = [0u8; 16];
    // 7 bytes of "ciphertext" — not a multiple of 16. Finalize MUST
    // reject (single GMCRYPTO_ERR, no plaintext leak).
    let bogus_ct = [0x00u8; 7];
    let res = ffi_stream_decrypt(&key, &iv, &bogus_ct, 7);
    assert!(res.is_none(), "truncated input must collapse to None");
}

#[test]
fn sm4_cbc_streaming_decrypt_rejects_bad_padding() {
    let key = [0x55u8; 16];
    let iv = [0x66u8; 16];
    // Construct a valid 32-byte ciphertext, then flip the last byte
    // (corrupts the PKCS#7 padding-strip's pad-len byte).
    let pt = b"sixteen-bytes ok";
    let mut ct = gmcrypto_core::sm4::mode_cbc::encrypt(&key, &iv, pt);
    let last = ct.len() - 1;
    ct[last] ^= 0x80;
    let res = ffi_stream_decrypt(&key, &iv, &ct, 16);
    assert!(res.is_none(), "bad padding must collapse to None");
}

#[test]
fn sm4_cbc_streaming_free_null_is_noop() {
    // Both free fns accept NULL — must not crash.
    unsafe { gmcrypto_sm4_cbc_encryptor_free(ptr::null_mut()) };
    unsafe { gmcrypto_sm4_cbc_decryptor_free(ptr::null_mut()) };
}

// ============================================================
// SM2 keys + sign / verify
// ============================================================

fn fresh_sm2_keys() -> (*mut gmcrypto_sm2_privkey_t, *mut gmcrypto_sm2_pubkey_t) {
    use gmcrypto_core::sm2::Sm2PrivateKey;

    // v0.5 W5 — `Sm2PrivateKey::new(U256)` renamed to `from_scalar` and
    // gated behind `crypto-bigint-scalar`. The c_smoke test uses the
    // always-on `from_bytes_be` constructor instead.
    let d_be: [u8; 32] = hex!("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
    let key = Sm2PrivateKey::from_bytes_be(&d_be).expect("valid d");
    let scalar_bytes: [u8; 32] = key.to_bytes_be();
    let pub_bytes: [u8; 65] = key.public_key().to_sec1_uncompressed();

    let priv_ptr = unsafe { gmcrypto_sm2_privkey_new(scalar_bytes.as_ptr()) };
    let pub_ptr = unsafe { gmcrypto_sm2_pubkey_new(pub_bytes.as_ptr()) };
    assert!(!priv_ptr.is_null());
    assert!(!pub_ptr.is_null());
    (priv_ptr, pub_ptr)
}

#[test]
fn sm2_key_roundtrip_through_ffi() {
    let (priv_ptr, pub_ptr) = fresh_sm2_keys();
    let mut priv_bytes = [0u8; GMCRYPTO_SM2_SCALAR_SIZE];
    let mut pub_bytes = [0u8; GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE];
    unsafe {
        assert_eq!(
            gmcrypto_sm2_privkey_to_sec1_be(priv_ptr, priv_bytes.as_mut_ptr()),
            GMCRYPTO_OK
        );
        assert_eq!(
            gmcrypto_sm2_pubkey_to_sec1_uncompressed(pub_ptr, pub_bytes.as_mut_ptr()),
            GMCRYPTO_OK
        );
        gmcrypto_sm2_privkey_free(priv_ptr);
        gmcrypto_sm2_pubkey_free(pub_ptr);
    }
    // Re-import via the same bytes; should succeed and produce the same export.
    let priv2 = unsafe { gmcrypto_sm2_privkey_new(priv_bytes.as_ptr()) };
    let pub2 = unsafe { gmcrypto_sm2_pubkey_new(pub_bytes.as_ptr()) };
    assert!(!priv2.is_null() && !pub2.is_null());
    let mut priv2_bytes = [0u8; GMCRYPTO_SM2_SCALAR_SIZE];
    let mut pub2_bytes = [0u8; GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE];
    unsafe {
        gmcrypto_sm2_privkey_to_sec1_be(priv2, priv2_bytes.as_mut_ptr());
        gmcrypto_sm2_pubkey_to_sec1_uncompressed(pub2, pub2_bytes.as_mut_ptr());
        gmcrypto_sm2_privkey_free(priv2);
        gmcrypto_sm2_pubkey_free(pub2);
    }
    assert_eq!(priv_bytes, priv2_bytes);
    assert_eq!(pub_bytes, pub2_bytes);
}

#[test]
fn sm2_sign_verify_round_trip_via_ffi() {
    let (priv_ptr, pub_ptr) = fresh_sm2_keys();
    let msg = b"the quick brown fox jumps over the lazy dog";
    let mut sig = vec![0u8; 128]; // generous capacity
    let mut sig_len = 0usize;
    let r = unsafe {
        gmcrypto_sm2_sign(
            priv_ptr,
            ptr::null(),
            0, // use DEFAULT_SIGNER_ID
            msg.as_ptr(),
            msg.len(),
            sig.as_mut_ptr(),
            sig.len(),
            &mut sig_len,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    sig.truncate(sig_len);

    let v = unsafe {
        gmcrypto_sm2_verify(
            pub_ptr,
            ptr::null(),
            0,
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
        )
    };
    assert_eq!(v, GMCRYPTO_OK, "valid sig accepted");

    // Tamper one byte and re-verify.
    let mut tampered = sig.clone();
    tampered[5] ^= 1;
    let v2 = unsafe {
        gmcrypto_sm2_verify(
            pub_ptr,
            ptr::null(),
            0,
            msg.as_ptr(),
            msg.len(),
            tampered.as_ptr(),
            tampered.len(),
        )
    };
    assert_eq!(v2, GMCRYPTO_ERR, "tampered sig rejected");

    unsafe {
        gmcrypto_sm2_privkey_free(priv_ptr);
        gmcrypto_sm2_pubkey_free(pub_ptr);
    }
}

#[test]
fn sm2_encrypt_decrypt_round_trip_via_ffi() {
    let (priv_ptr, pub_ptr) = fresh_sm2_keys();
    let pt = b"hello SM2 via C ABI";
    let mut ct = vec![0u8; 512];
    let mut ct_len = 0usize;
    let r = unsafe {
        gmcrypto_sm2_encrypt(
            pub_ptr,
            pt.as_ptr(),
            pt.len(),
            ct.as_mut_ptr(),
            ct.len(),
            &mut ct_len,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    ct.truncate(ct_len);

    let mut pt_back = vec![0u8; 256];
    let mut pt_len = 0usize;
    let r = unsafe {
        gmcrypto_sm2_decrypt(
            priv_ptr,
            ct.as_ptr(),
            ct.len(),
            pt_back.as_mut_ptr(),
            pt_back.len(),
            &mut pt_len,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    pt_back.truncate(pt_len);
    assert_eq!(pt_back.as_slice(), pt.as_slice());

    unsafe {
        gmcrypto_sm2_privkey_free(priv_ptr);
        gmcrypto_sm2_pubkey_free(pub_ptr);
    }
}

// ============================================================
// SM2 raw byte-concat ciphertext (v0.5 W2)
// ============================================================

#[test]
fn sm2_encrypt_c1c3c2_round_trip_via_ffi() {
    let (priv_ptr, pub_ptr) = fresh_sm2_keys();
    let pt = b"hello SM2 raw bytes";
    // Output is exactly 65 + 32 + pt.len() bytes.
    let expected_len = 65 + 32 + pt.len();
    let mut ct = vec![0u8; 256];
    let mut ct_len = 0usize;
    let r = unsafe {
        gmcrypto_sm2_encrypt_c1c3c2(
            pub_ptr,
            pt.as_ptr(),
            pt.len(),
            ct.as_mut_ptr(),
            ct.len(),
            &mut ct_len,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    assert_eq!(ct_len, expected_len, "raw c1c3c2 size is 65+32+msg_len");
    ct.truncate(ct_len);

    // First byte of C1 is the SEC1 uncompressed tag.
    assert_eq!(ct[0], 0x04);

    let mut pt_back = vec![0u8; 256];
    let mut pt_len = 0usize;
    let r = unsafe {
        gmcrypto_sm2_decrypt_c1c3c2(
            priv_ptr,
            ct.as_ptr(),
            ct.len(),
            pt_back.as_mut_ptr(),
            pt_back.len(),
            &mut pt_len,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    pt_back.truncate(pt_len);
    assert_eq!(pt_back.as_slice(), pt.as_slice());

    unsafe {
        gmcrypto_sm2_privkey_free(priv_ptr);
        gmcrypto_sm2_pubkey_free(pub_ptr);
    }
}

#[test]
fn sm2_decrypt_c1c2c3_legacy_via_ffi() {
    // Construct a legacy C1||C2||C3 ciphertext via the gmcrypto-core
    // surface (no encode-legacy emit fn — by design).
    use gmcrypto_core::asn1::ciphertext::decode as der_decode;
    use gmcrypto_core::sm2::raw_ciphertext::{C1_LEN, C3_LEN, encode_c1c3c2};
    use gmcrypto_core::sm2::{Sm2PrivateKey, encrypt as core_encrypt};

    // v0.5 W5 — use `from_bytes_be` (always-on); `new(U256)` removed.
    let d_be: [u8; 32] = hex!("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
    let key = Sm2PrivateKey::from_bytes_be(&d_be).expect("valid d");
    let pub_key = key.public_key();

    let pt = b"legacy ordering";
    let mut rng = getrandom::SysRng;
    let der_ct = core_encrypt(&pub_key, pt, &mut rng).expect("encrypt ok");
    let parsed = der_decode(&der_ct).expect("DER decode ok");

    // First emit the modern C1||C3||C2 byte ordering, then rearrange
    // to the legacy C1||C2||C3 ordering: same C1 (65 bytes) then C2
    // (variable, equals encrypted plaintext length) then C3 (32 bytes).
    let modern = encode_c1c3c2(&parsed);
    assert_eq!(modern.len(), C1_LEN + C3_LEN + pt.len());
    let c1 = &modern[..C1_LEN];
    let c3 = &modern[C1_LEN..C1_LEN + C3_LEN];
    let c2 = &modern[C1_LEN + C3_LEN..];
    let mut legacy = Vec::new();
    legacy.extend_from_slice(c1);
    legacy.extend_from_slice(c2);
    legacy.extend_from_slice(c3);

    // Pass key into the FFI through SEC1 import.
    let scalar_bytes: [u8; 32] = key.to_bytes_be();
    let priv_ptr = unsafe { gmcrypto_sm2_privkey_new(scalar_bytes.as_ptr()) };
    assert!(!priv_ptr.is_null());

    let mut pt_back = vec![0u8; 256];
    let mut pt_len = 0usize;
    let r = unsafe {
        gmcrypto_sm2_decrypt_c1c2c3_legacy(
            priv_ptr,
            legacy.as_ptr(),
            legacy.len(),
            pt_back.as_mut_ptr(),
            pt_back.len(),
            &mut pt_len,
        )
    };
    assert_eq!(r, GMCRYPTO_OK, "legacy decrypt of constructed legacy ct");
    pt_back.truncate(pt_len);
    assert_eq!(pt_back.as_slice(), pt.as_slice());

    // And confirm that the legacy entry point REJECTS modern ordering
    // — no auto-detection, per the W2 cbindgen-header doc.
    let mut pt_back2 = vec![0u8; 256];
    let mut pt_len2 = 0usize;
    let r2 = unsafe {
        gmcrypto_sm2_decrypt_c1c2c3_legacy(
            priv_ptr,
            modern.as_ptr(),
            modern.len(),
            pt_back2.as_mut_ptr(),
            pt_back2.len(),
            &mut pt_len2,
        )
    };
    assert_eq!(
        r2, GMCRYPTO_ERR,
        "modern ordering through legacy fn must fail"
    );

    unsafe { gmcrypto_sm2_privkey_free(priv_ptr) };
}

#[test]
fn sm2_decrypt_c1c3c2_rejects_modern_wrong_format() {
    // Modern ct fed to a corrupted prefix → MAC mismatch.
    let (priv_ptr, pub_ptr) = fresh_sm2_keys();
    let pt = b"modern";
    let mut ct = vec![0u8; 256];
    let mut ct_len = 0usize;
    let r = unsafe {
        gmcrypto_sm2_encrypt_c1c3c2(
            pub_ptr,
            pt.as_ptr(),
            pt.len(),
            ct.as_mut_ptr(),
            ct.len(),
            &mut ct_len,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    ct.truncate(ct_len);

    // Flip a byte inside C3 (the MAC) — must collapse to GMCRYPTO_ERR
    // without leaking plaintext.
    ct[65 + 5] ^= 0x80;

    let mut pt_back = vec![0u8; 256];
    let mut pt_len_back = 0usize;
    let r = unsafe {
        gmcrypto_sm2_decrypt_c1c3c2(
            priv_ptr,
            ct.as_ptr(),
            ct.len(),
            pt_back.as_mut_ptr(),
            pt_back.len(),
            &mut pt_len_back,
        )
    };
    assert_eq!(r, GMCRYPTO_ERR);

    unsafe {
        gmcrypto_sm2_privkey_free(priv_ptr);
        gmcrypto_sm2_pubkey_free(pub_ptr);
    }
}

#[test]
fn sm2_decrypt_c1c3c2_rejects_truncated() {
    let (priv_ptr, pub_ptr) = fresh_sm2_keys();
    // < C1 + C3 = 97 bytes, so decode_c1c3c2 rejects at parse time.
    let bogus = [0u8; 96];
    let mut pt_back = vec![0u8; 256];
    let mut pt_len = 0usize;
    let r = unsafe {
        gmcrypto_sm2_decrypt_c1c3c2(
            priv_ptr,
            bogus.as_ptr(),
            bogus.len(),
            pt_back.as_mut_ptr(),
            pt_back.len(),
            &mut pt_len,
        )
    };
    assert_eq!(r, GMCRYPTO_ERR, "too-short input must collapse to ERR");

    unsafe {
        gmcrypto_sm2_privkey_free(priv_ptr);
        gmcrypto_sm2_pubkey_free(pub_ptr);
    }
}

// ============================================================
// SM2 RNG callback (v0.5 W3) — used in tests below.
// ============================================================

/// Simple deterministic byte-pool RNG: callbacks pull bytes from a
/// Vec<u8> until exhausted, then fail. Used to drive sign-with-rng
/// tests without depending on the system RNG.
struct ByteRng {
    pool: Vec<u8>,
    cursor: usize,
}

/// Trampoline that interprets the opaque `context` as a `*mut ByteRng`.
/// SAFETY: caller MUST pass a valid `*mut ByteRng` as context.
unsafe extern "C" fn byte_rng_callback(
    context: *mut core::ffi::c_void,
    buf: *mut u8,
    buf_len: usize,
) -> core::ffi::c_int {
    if context.is_null() || (buf.is_null() && buf_len > 0) {
        return -1;
    }
    // SAFETY: caller asserts context is *mut ByteRng.
    let rng = unsafe { &mut *(context.cast::<ByteRng>()) };
    if rng.cursor + buf_len > rng.pool.len() {
        return -1;
    }
    // SAFETY: buf is valid for buf_len bytes per the FFI contract.
    let dst = unsafe { core::slice::from_raw_parts_mut(buf, buf_len) };
    dst.copy_from_slice(&rng.pool[rng.cursor..rng.cursor + buf_len]);
    rng.cursor += buf_len;
    0
}

/// Trampoline that always fails (returns 1). Used to test the
/// callback-error path.
unsafe extern "C" fn always_fail_rng_callback(
    _context: *mut core::ffi::c_void,
    _buf: *mut u8,
    _buf_len: usize,
) -> core::ffi::c_int {
    1
}

#[test]
fn sm2_sign_with_rng_round_trip_via_ffi() {
    let (priv_ptr, pub_ptr) = fresh_sm2_keys();
    // ByteRng's pool is large enough to satisfy multiple draws across
    // the sign retry budget (~2 retries × 32 bytes each, plus padding).
    let mut rng = ByteRng {
        pool: vec![0x42u8; 4096],
        cursor: 0,
    };
    let msg = b"hello W3 RNG callback";
    let mut sig = vec![0u8; 256];
    let mut sig_len = 0usize;
    let callback: gmcrypto_rng_callback = Some(byte_rng_callback);
    let r = unsafe {
        gmcrypto_sm2_sign_with_rng(
            priv_ptr,
            ptr::null(),
            0, // default signer id
            msg.as_ptr(),
            msg.len(),
            callback,
            (&raw mut rng).cast::<core::ffi::c_void>(),
            sig.as_mut_ptr(),
            sig.len(),
            &mut sig_len,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    assert!(rng.cursor > 0, "callback was called");
    sig.truncate(sig_len);

    // Verify with the public key — sign-with-rng must produce a
    // valid signature against the regular verify path.
    let v = unsafe {
        gmcrypto_sm2_verify(
            pub_ptr,
            ptr::null(),
            0,
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
        )
    };
    assert_eq!(v, GMCRYPTO_OK, "sign-with-rng signature verifies");

    unsafe {
        gmcrypto_sm2_privkey_free(priv_ptr);
        gmcrypto_sm2_pubkey_free(pub_ptr);
    }
}

#[test]
fn sm2_encrypt_with_rng_round_trip_via_ffi() {
    let (priv_ptr, pub_ptr) = fresh_sm2_keys();
    let mut rng = ByteRng {
        pool: vec![0xa5u8; 4096],
        cursor: 0,
    };
    let pt = b"hello SM2 encrypt with rng";
    let mut ct = vec![0u8; 512];
    let mut ct_len = 0usize;
    let callback: gmcrypto_rng_callback = Some(byte_rng_callback);
    let r = unsafe {
        gmcrypto_sm2_encrypt_with_rng(
            pub_ptr,
            pt.as_ptr(),
            pt.len(),
            callback,
            (&raw mut rng).cast::<core::ffi::c_void>(),
            ct.as_mut_ptr(),
            ct.len(),
            &mut ct_len,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    assert!(rng.cursor > 0, "callback was called");
    ct.truncate(ct_len);

    // Round-trip through the regular decrypt path.
    let mut pt_back = vec![0u8; 256];
    let mut pt_len_back = 0usize;
    let r = unsafe {
        gmcrypto_sm2_decrypt(
            priv_ptr,
            ct.as_ptr(),
            ct.len(),
            pt_back.as_mut_ptr(),
            pt_back.len(),
            &mut pt_len_back,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    pt_back.truncate(pt_len_back);
    assert_eq!(pt_back.as_slice(), pt.as_slice());

    unsafe {
        gmcrypto_sm2_privkey_free(priv_ptr);
        gmcrypto_sm2_pubkey_free(pub_ptr);
    }
}

#[test]
fn sm2_sign_with_rng_callback_failure_returns_err() {
    let (priv_ptr, pub_ptr) = fresh_sm2_keys();
    let msg = b"x";
    let mut sig = vec![0u8; 256];
    let mut sig_len = 0usize;
    let callback: gmcrypto_rng_callback = Some(always_fail_rng_callback);
    let r = unsafe {
        gmcrypto_sm2_sign_with_rng(
            priv_ptr,
            ptr::null(),
            0,
            msg.as_ptr(),
            msg.len(),
            callback,
            ptr::null_mut(),
            sig.as_mut_ptr(),
            sig.len(),
            &mut sig_len,
        )
    };
    assert_eq!(
        r, GMCRYPTO_ERR,
        "callback always-failing must surface as GMCRYPTO_ERR"
    );

    unsafe {
        gmcrypto_sm2_privkey_free(priv_ptr);
        gmcrypto_sm2_pubkey_free(pub_ptr);
    }
}

#[test]
fn sm2_sign_with_rng_null_callback_rejected() {
    let (priv_ptr, pub_ptr) = fresh_sm2_keys();
    let msg = b"x";
    let mut sig = vec![0u8; 256];
    let mut sig_len = 0usize;
    let callback: gmcrypto_rng_callback = None;
    let r = unsafe {
        gmcrypto_sm2_sign_with_rng(
            priv_ptr,
            ptr::null(),
            0,
            msg.as_ptr(),
            msg.len(),
            callback,
            ptr::null_mut(),
            sig.as_mut_ptr(),
            sig.len(),
            &mut sig_len,
        )
    };
    assert_eq!(r, GMCRYPTO_ERR, "null callback rejected up-front");

    unsafe {
        gmcrypto_sm2_privkey_free(priv_ptr);
        gmcrypto_sm2_pubkey_free(pub_ptr);
    }
}

#[test]
fn sm2_pkcs8_round_trip_via_ffi() {
    let (priv_ptr, _pub_ptr) = fresh_sm2_keys();
    let pwd = b"secret-password";
    let mut pem = vec![0u8; 4096];
    let mut pem_len = 0usize;
    let r = unsafe {
        gmcrypto_sm2_privkey_to_pkcs8(
            priv_ptr,
            pwd.as_ptr(),
            pwd.len(),
            1024, // iterations
            pem.as_mut_ptr(),
            pem.len(),
            &mut pem_len,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    pem.truncate(pem_len);

    // Read it back.
    let mut imported: *mut gmcrypto_sm2_privkey_t = ptr::null_mut();
    let r = unsafe {
        gmcrypto_sm2_privkey_from_pkcs8(
            pem.as_ptr(),
            pem.len(),
            pwd.as_ptr(),
            pwd.len(),
            &mut imported,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    assert!(!imported.is_null());

    // Exported scalar bytes should match the original.
    let mut original_bytes = [0u8; GMCRYPTO_SM2_SCALAR_SIZE];
    let mut imported_bytes = [0u8; GMCRYPTO_SM2_SCALAR_SIZE];
    unsafe {
        gmcrypto_sm2_privkey_to_sec1_be(priv_ptr, original_bytes.as_mut_ptr());
        gmcrypto_sm2_privkey_to_sec1_be(imported, imported_bytes.as_mut_ptr());
    }
    assert_eq!(original_bytes, imported_bytes);

    // Wrong password fails.
    let mut imported2: *mut gmcrypto_sm2_privkey_t = ptr::null_mut();
    let r = unsafe {
        gmcrypto_sm2_privkey_from_pkcs8(
            pem.as_ptr(),
            pem.len(),
            b"wrong".as_ptr(),
            5,
            &mut imported2,
        )
    };
    assert_eq!(r, GMCRYPTO_ERR);
    assert!(imported2.is_null());

    unsafe {
        gmcrypto_sm2_privkey_free(priv_ptr);
        gmcrypto_sm2_privkey_free(imported);
        gmcrypto_sm2_pubkey_free(_pub_ptr);
    }
}

#[test]
fn sm2_privkey_out_of_range_returns_null() {
    let zero = [0u8; 32]; // d == 0 is out of [1, n-2]
    let p = unsafe { gmcrypto_sm2_privkey_new(zero.as_ptr()) };
    assert!(p.is_null());
}

#[test]
fn sm2_pubkey_malformed_returns_null() {
    let mut bad = [0u8; 65];
    bad[0] = 0x05; // non-uncompressed prefix
    let p = unsafe { gmcrypto_sm2_pubkey_new(bad.as_ptr()) };
    assert!(p.is_null());
}

// ============================================================
// Version
// ============================================================

#[test]
fn version_string_matches_crate() {
    let p = gmcrypto_c::gmcrypto_version();
    assert!(!p.is_null());
    // SAFETY: gmcrypto_version returns a static NUL-terminated CStr.
    let s = unsafe { core::ffi::CStr::from_ptr(p) };
    // gmcrypto_version() is derived from CARGO_PKG_VERSION, so it must track
    // the crate version exactly (the literal previously drifted to "0.4.0").
    let v = s.to_str().expect("ASCII version string");
    assert_eq!(
        v,
        env!("CARGO_PKG_VERSION"),
        "FFI version {v} must equal the crate version",
    );
}

// ============================================================
// SM4 AEAD — single-shot (v0.9 W4). Gated on `sm4-aead`.
// ============================================================

use gmcrypto_c::{
    gmcrypto_sm4_ccm_decrypt, gmcrypto_sm4_ccm_encrypt, gmcrypto_sm4_gcm_decrypt,
    gmcrypto_sm4_gcm_decrypt_with_tag_len, gmcrypto_sm4_gcm_decryptor_finalize_verify,
    gmcrypto_sm4_gcm_decryptor_free, gmcrypto_sm4_gcm_decryptor_new,
    gmcrypto_sm4_gcm_decryptor_update, gmcrypto_sm4_gcm_encrypt,
    gmcrypto_sm4_gcm_encrypt_with_tag_len, gmcrypto_sm4_gcm_encryptor_finalize,
    gmcrypto_sm4_gcm_encryptor_finalize_with_tag_len, gmcrypto_sm4_gcm_encryptor_free,
    gmcrypto_sm4_gcm_encryptor_new, gmcrypto_sm4_gcm_encryptor_update,
};

#[test]
fn sm4_gcm_round_trip_matches_core() {
    let key = [0x42u8; 16];
    let nonce = [0x01u8; 12];
    let aad = b"associated header";
    let pt = b"the quick brown fox jumps over the lazy dog"; // 43 bytes

    let mut ct = vec![0u8; pt.len()];
    let mut ct_actual = 0usize;
    let mut tag = [0u8; 16];
    let r = unsafe {
        gmcrypto_sm4_gcm_encrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            pt.as_ptr(),
            pt.len(),
            ct.as_mut_ptr(),
            ct.len(),
            &mut ct_actual,
            tag.as_mut_ptr(),
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    assert_eq!(ct_actual, pt.len());

    // Byte-equivalence with the core API.
    let (core_ct, core_tag) =
        gmcrypto_core::sm4::mode_gcm::encrypt(&key, &nonce, aad, pt).expect("under ceiling");
    assert_eq!(ct, core_ct);
    assert_eq!(tag, core_tag);

    // Round-trip decrypt through the FFI.
    let mut pt_back = vec![0u8; ct.len()];
    let mut pt_actual = 0usize;
    let r = unsafe {
        gmcrypto_sm4_gcm_decrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            ct.as_ptr(),
            ct.len(),
            tag.as_ptr(),
            pt_back.as_mut_ptr(),
            pt_back.len(),
            &mut pt_actual,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    pt_back.truncate(pt_actual);
    assert_eq!(pt_back.as_slice(), pt.as_slice());
}

#[test]
fn sm4_gcm_tampered_tag_returns_err() {
    let key = [0x42u8; 16];
    let nonce = [0x01u8; 12];
    let aad = b"h";
    let pt = b"tamper target";
    let (ct, mut tag) =
        gmcrypto_core::sm4::mode_gcm::encrypt(&key, &nonce, aad, pt).expect("under ceiling");
    tag[0] ^= 0x01;
    let mut pt_back = vec![0u8; ct.len()];
    let mut pt_actual = 0usize;
    let r = unsafe {
        gmcrypto_sm4_gcm_decrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            ct.as_ptr(),
            ct.len(),
            tag.as_ptr(),
            pt_back.as_mut_ptr(),
            pt_back.len(),
            &mut pt_actual,
        )
    };
    assert_eq!(r, GMCRYPTO_ERR);
}

#[test]
fn sm4_gcm_tag_len_12_round_trip_matches_core() {
    let key = [0x42u8; 16];
    let nonce = [0x01u8; 12];
    let aad = b"hdr";
    let pt = b"truncated tag round trip";
    let tag_len = 12usize;

    let mut ct = vec![0u8; pt.len()];
    let mut ct_actual = 0usize;
    let mut tag = vec![0u8; tag_len];
    let r = unsafe {
        gmcrypto_sm4_gcm_encrypt_with_tag_len(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            pt.as_ptr(),
            pt.len(),
            tag_len,
            ct.as_mut_ptr(),
            ct.len(),
            &mut ct_actual,
            tag.as_mut_ptr(),
        )
    };
    assert_eq!(r, GMCRYPTO_OK);

    let tl = gmcrypto_core::sm4::GcmTagLen::new(tag_len).unwrap();
    let (core_ct, core_tag) =
        gmcrypto_core::sm4::mode_gcm::encrypt_with_tag_len(&key, &nonce, aad, pt, tl)
            .expect("under ceiling");
    assert_eq!(ct, core_ct);
    assert_eq!(tag, core_tag);

    let mut pt_back = vec![0u8; ct.len()];
    let mut pt_actual = 0usize;
    let r = unsafe {
        gmcrypto_sm4_gcm_decrypt_with_tag_len(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            ct.as_ptr(),
            ct.len(),
            tag.as_ptr(),
            tag_len,
            pt_back.as_mut_ptr(),
            pt_back.len(),
            &mut pt_actual,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    pt_back.truncate(pt_actual);
    assert_eq!(pt_back.as_slice(), pt.as_slice());
}

#[test]
fn sm4_gcm_invalid_tag_len_returns_err() {
    let key = [0x42u8; 16];
    let nonce = [0x01u8; 12];
    let aad = b"h";
    let pt = b"x";
    let mut ct = vec![0u8; pt.len()];
    let mut ct_actual = 0usize;
    let mut tag = vec![0u8; 5];
    // tag_len = 5 is not in {4,8,12,13,14,15,16}.
    let r = unsafe {
        gmcrypto_sm4_gcm_encrypt_with_tag_len(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            pt.as_ptr(),
            pt.len(),
            5,
            ct.as_mut_ptr(),
            ct.len(),
            &mut ct_actual,
            tag.as_mut_ptr(),
        )
    };
    assert_eq!(r, GMCRYPTO_ERR);
}

#[test]
fn sm4_ccm_round_trip_matches_core() {
    let key = [0x42u8; 16];
    let nonce = [0x01u8; 12];
    let aad = b"associated header";
    let pt = b"the quick brown fox"; // 19 bytes
    let tag_len = 16usize;

    // Output is ciphertext ‖ tag = pt.len() + tag_len.
    let mut out = vec![0u8; pt.len() + tag_len];
    let mut out_actual = 0usize;
    let r = unsafe {
        gmcrypto_sm4_ccm_encrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            pt.as_ptr(),
            pt.len(),
            tag_len,
            out.as_mut_ptr(),
            out.len(),
            &mut out_actual,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    assert_eq!(out_actual, pt.len() + tag_len);

    let core_out = gmcrypto_core::sm4::mode_ccm::encrypt(&key, &nonce, aad, pt, tag_len)
        .expect("valid params");
    assert_eq!(out, core_out);

    // Round-trip decrypt through the FFI.
    let mut pt_back = vec![0u8; pt.len()];
    let mut pt_actual = 0usize;
    let r = unsafe {
        gmcrypto_sm4_ccm_decrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            out.as_ptr(),
            out.len(),
            tag_len,
            pt_back.as_mut_ptr(),
            pt_back.len(),
            &mut pt_actual,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    pt_back.truncate(pt_actual);
    assert_eq!(pt_back.as_slice(), pt.as_slice());
}

#[test]
fn sm4_ccm_invalid_nonce_len_returns_err() {
    let key = [0x42u8; 16];
    let nonce = [0x01u8; 6]; // 6 < 7, out of range
    let aad = b"h";
    let pt = b"x";
    let tag_len = 16usize;
    let mut out = vec![0u8; pt.len() + tag_len];
    let mut out_actual = 0usize;
    let r = unsafe {
        gmcrypto_sm4_ccm_encrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            pt.as_ptr(),
            pt.len(),
            tag_len,
            out.as_mut_ptr(),
            out.len(),
            &mut out_actual,
        )
    };
    assert_eq!(r, GMCRYPTO_ERR);
}

// ============================================================
// SM4-GCM AEAD — streaming / incremental-input (v0.10). Gated on
// `sm4-aead`.
// ============================================================

#[test]
fn sm4_gcm_encryptor_new_then_free_is_clean() {
    let key = [0x42u8; 16];
    let nonce = [0x01u8; 12];
    let aad = b"hdr";
    let enc = unsafe {
        gmcrypto_sm4_gcm_encryptor_new(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
        )
    };
    assert!(!enc.is_null());
    // free without finalizing (abort path) must not leak / crash.
    unsafe { gmcrypto_sm4_gcm_encryptor_free(enc) };
    // free(NULL) is a no-op.
    unsafe { gmcrypto_sm4_gcm_encryptor_free(core::ptr::null_mut()) };
}

#[test]
fn sm4_gcm_encryptor_chunked_matches_core() {
    let key = [0x42u8; 16];
    let nonce = [0x01u8; 12];
    let aad = b"associated header";
    let pt: Vec<u8> = (0..200u8).map(|i| i ^ (i >> 3)).collect();

    let enc = unsafe {
        gmcrypto_sm4_gcm_encryptor_new(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
        )
    };
    assert!(!enc.is_null());

    let mut ct = Vec::new();
    for chunk in pt.chunks(17) {
        let mut buf = vec![0u8; chunk.len()];
        let mut actual = 0usize;
        let r = unsafe {
            gmcrypto_sm4_gcm_encryptor_update(
                enc,
                chunk.as_ptr(),
                chunk.len(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut actual,
            )
        };
        assert_eq!(r, GMCRYPTO_OK);
        assert_eq!(actual, chunk.len()); // GCM ct len == pt len
        ct.extend_from_slice(&buf[..actual]);
    }
    // free here (update-only test): finalize would consume the handle,
    // but we are not exercising the tag in this test.
    unsafe { gmcrypto_sm4_gcm_encryptor_free(enc) };

    let (core_ct, _core_tag) =
        gmcrypto_core::sm4::mode_gcm::encrypt(&key, &nonce, aad, &pt).expect("under ceiling");
    assert_eq!(ct, core_ct);
}

#[test]
fn sm4_gcm_encryptor_finalize_matches_core() {
    let key = [0x42u8; 16];
    let nonce = [0x01u8; 12];
    let aad = b"hdr";
    let pt = b"finalize emits the tag";

    // full 16-byte tag
    let enc = unsafe {
        gmcrypto_sm4_gcm_encryptor_new(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
        )
    };
    let mut ct = vec![0u8; pt.len()];
    let mut actual = 0usize;
    assert_eq!(
        unsafe {
            gmcrypto_sm4_gcm_encryptor_update(
                enc,
                pt.as_ptr(),
                pt.len(),
                ct.as_mut_ptr(),
                ct.len(),
                &mut actual,
            )
        },
        GMCRYPTO_OK
    );
    let mut tag = [0u8; 16];
    assert_eq!(
        unsafe { gmcrypto_sm4_gcm_encryptor_finalize(enc, tag.as_mut_ptr()) },
        GMCRYPTO_OK
    );
    let (core_ct, core_tag) =
        gmcrypto_core::sm4::mode_gcm::encrypt(&key, &nonce, aad, pt).expect("under ceiling");
    assert_eq!(ct, core_ct);
    assert_eq!(tag, core_tag);

    // truncated 12-byte tag
    let enc = unsafe {
        gmcrypto_sm4_gcm_encryptor_new(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
        )
    };
    let mut ct2 = vec![0u8; pt.len()];
    let mut a2 = 0usize;
    assert_eq!(
        unsafe {
            gmcrypto_sm4_gcm_encryptor_update(
                enc,
                pt.as_ptr(),
                pt.len(),
                ct2.as_mut_ptr(),
                ct2.len(),
                &mut a2,
            )
        },
        GMCRYPTO_OK
    );
    let mut tag12 = vec![0u8; 12];
    let mut tl_actual = 0usize;
    assert_eq!(
        unsafe {
            gmcrypto_sm4_gcm_encryptor_finalize_with_tag_len(
                enc,
                12,
                tag12.as_mut_ptr(),
                tag12.len(),
                &mut tl_actual,
            )
        },
        GMCRYPTO_OK
    );
    assert_eq!(tl_actual, 12);
    assert_eq!(tag12.as_slice(), &core_tag[..12]);
}

#[test]
fn sm4_gcm_decryptor_new_then_free_is_clean() {
    let key = [0x42u8; 16];
    let nonce = [0x01u8; 12];
    let aad = b"hdr";
    let dec = unsafe {
        gmcrypto_sm4_gcm_decryptor_new(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
        )
    };
    assert!(!dec.is_null());
    // abort path: free without verifying must not leak / crash.
    unsafe { gmcrypto_sm4_gcm_decryptor_free(dec) };
    // free(NULL) is a no-op.
    unsafe { gmcrypto_sm4_gcm_decryptor_free(core::ptr::null_mut()) };
}

#[test]
fn sm4_gcm_decryptor_chunked_round_trip() {
    let key = [0x42u8; 16];
    let nonce = [0x01u8; 12];
    let aad = b"associated header";
    let pt: Vec<u8> = (0..200u8).map(|i| i ^ (i >> 3)).collect();
    let (ct, tag) =
        gmcrypto_core::sm4::mode_gcm::encrypt(&key, &nonce, aad, &pt).expect("under ceiling");

    let dec = unsafe {
        gmcrypto_sm4_gcm_decryptor_new(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
        )
    };
    assert!(!dec.is_null());
    for chunk in ct.chunks(11) {
        let r = unsafe { gmcrypto_sm4_gcm_decryptor_update(dec, chunk.as_ptr(), chunk.len()) };
        assert_eq!(r, GMCRYPTO_OK);
    }
    let mut out = vec![0u8; ct.len()];
    let mut actual = 0usize;
    let r = unsafe {
        gmcrypto_sm4_gcm_decryptor_finalize_verify(
            dec,
            tag.as_ptr(),
            tag.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut actual,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    out.truncate(actual);
    assert_eq!(out, pt);
}

#[test]
fn sm4_gcm_decryptor_tamper_and_bad_len_return_err() {
    let key = [0x42u8; 16];
    let nonce = [0x01u8; 12];
    let aad = b"h";
    let pt = b"tamper target across the c boundary";
    let (ct, mut tag) =
        gmcrypto_core::sm4::mode_gcm::encrypt(&key, &nonce, aad, pt).expect("under ceiling");

    // tampered tag → ERR, out_actual_len zeroed, no plaintext.
    tag[0] ^= 0x01;
    let dec = unsafe {
        gmcrypto_sm4_gcm_decryptor_new(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
        )
    };
    unsafe { gmcrypto_sm4_gcm_decryptor_update(dec, ct.as_ptr(), ct.len()) };
    let mut out = vec![0u8; ct.len()];
    let mut actual = 7usize; // sentinel; must be overwritten to 0
    let r = unsafe {
        gmcrypto_sm4_gcm_decryptor_finalize_verify(
            dec,
            tag.as_ptr(),
            tag.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut actual,
        )
    };
    assert_eq!(r, GMCRYPTO_ERR);
    assert_eq!(actual, 0);

    // invalid tag_len (5 ∉ valid set) → ERR.
    let (ct2, tag2) =
        gmcrypto_core::sm4::mode_gcm::encrypt(&key, &nonce, aad, pt).expect("under ceiling");
    let dec2 = unsafe {
        gmcrypto_sm4_gcm_decryptor_new(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
        )
    };
    unsafe { gmcrypto_sm4_gcm_decryptor_update(dec2, ct2.as_ptr(), ct2.len()) };
    let mut out2 = vec![0u8; ct2.len()];
    let mut a2 = 0usize;
    let r2 = unsafe {
        gmcrypto_sm4_gcm_decryptor_finalize_verify(
            dec2,
            tag2.as_ptr(),
            5,
            out2.as_mut_ptr(),
            out2.len(),
            &mut a2,
        )
    };
    assert_eq!(r2, GMCRYPTO_ERR);
}

#[test]
fn sm4_gcm_streaming_c_encrypt_c_decrypt_with_truncated_tag() {
    let key = [0x42u8; 16];
    let nonce = [0x07u8; 12];
    let aad = b"cross direction";
    let pt: Vec<u8> = (0..137u8).map(|i| i.wrapping_mul(31)).collect();

    // Encrypt via C streaming with a 12-byte tag, chunked by 13.
    let enc = unsafe {
        gmcrypto_sm4_gcm_encryptor_new(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
        )
    };
    let mut ct = Vec::new();
    for chunk in pt.chunks(13) {
        let mut buf = vec![0u8; chunk.len()];
        let mut a = 0usize;
        assert_eq!(
            unsafe {
                gmcrypto_sm4_gcm_encryptor_update(
                    enc,
                    chunk.as_ptr(),
                    chunk.len(),
                    buf.as_mut_ptr(),
                    buf.len(),
                    &mut a,
                )
            },
            GMCRYPTO_OK
        );
        ct.extend_from_slice(&buf[..a]);
    }
    let mut tag = vec![0u8; 12];
    let mut tl = 0usize;
    assert_eq!(
        unsafe {
            gmcrypto_sm4_gcm_encryptor_finalize_with_tag_len(
                enc,
                12,
                tag.as_mut_ptr(),
                tag.len(),
                &mut tl,
            )
        },
        GMCRYPTO_OK
    );

    // Decrypt via C streaming, different chunking (16).
    let dec = unsafe {
        gmcrypto_sm4_gcm_decryptor_new(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
        )
    };
    for chunk in ct.chunks(16) {
        assert_eq!(
            unsafe { gmcrypto_sm4_gcm_decryptor_update(dec, chunk.as_ptr(), chunk.len()) },
            GMCRYPTO_OK
        );
    }
    let mut out = vec![0u8; ct.len()];
    let mut actual = 0usize;
    assert_eq!(
        unsafe {
            gmcrypto_sm4_gcm_decryptor_finalize_verify(
                dec,
                tag.as_ptr(),
                tag.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut actual,
            )
        },
        GMCRYPTO_OK
    );
    out.truncate(actual);
    assert_eq!(out, pt);
}

#[test]
fn sm4_gcm_streaming_empty_plaintext() {
    let key = [0x42u8; 16];
    let nonce = [0x09u8; 12];
    let aad = b"aad only";
    let enc = unsafe {
        gmcrypto_sm4_gcm_encryptor_new(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
        )
    };
    let mut tag = [0u8; 16];
    assert_eq!(
        unsafe { gmcrypto_sm4_gcm_encryptor_finalize(enc, tag.as_mut_ptr()) },
        GMCRYPTO_OK
    );
    let dec = unsafe {
        gmcrypto_sm4_gcm_decryptor_new(
            key.as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
        )
    };
    let mut out = [0u8; 1];
    let mut actual = 9usize;
    assert_eq!(
        unsafe {
            gmcrypto_sm4_gcm_decryptor_finalize_verify(
                dec,
                tag.as_ptr(),
                tag.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut actual,
            )
        },
        GMCRYPTO_OK
    );
    assert_eq!(actual, 0);

    // cross-check the tag matches core single-shot on empty plaintext.
    let (_core_ct, core_tag) =
        gmcrypto_core::sm4::mode_gcm::encrypt(&key, &nonce, aad, &[]).expect("under ceiling");
    assert_eq!(tag, core_tag);
}

// ============================================================
// v0.13 — SM4-XTS single-shot FFI (cfg-gated on `sm4-xts`).
// ============================================================

use gmcrypto_c::{GMCRYPTO_SM4_XTS_KEY_SIZE, gmcrypto_sm4_xts_decrypt, gmcrypto_sm4_xts_encrypt};

fn xts_key() -> [u8; GMCRYPTO_SM4_XTS_KEY_SIZE] {
    let mut k = [0u8; GMCRYPTO_SM4_XTS_KEY_SIZE];
    k[..16].fill(0x11);
    k[16..].fill(0x22);
    k
}

/// Encrypt via FFI == core `mode_xts::encrypt`, then FFI decrypt round-trips,
/// on a whole-block (48-byte = 3-block) data unit.
#[test]
fn sm4_xts_round_trip_whole_block_matches_core() {
    let key = xts_key();
    let tweak = [0x33u8; 16];
    let pt: Vec<u8> = (0u8..48).collect();

    let mut ct = vec![0u8; pt.len()];
    let mut ct_actual = 0usize;
    let r = unsafe {
        gmcrypto_sm4_xts_encrypt(
            key.as_ptr(),
            tweak.as_ptr(),
            pt.as_ptr(),
            pt.len(),
            ct.as_mut_ptr(),
            ct.len(),
            &mut ct_actual,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    assert_eq!(ct_actual, pt.len());

    let core_ct = gmcrypto_core::sm4::mode_xts::encrypt(&key, &tweak, &pt).expect("valid params");
    assert_eq!(ct, core_ct);

    let mut pt_back = vec![0u8; ct.len()];
    let mut pt_actual = 0usize;
    let r = unsafe {
        gmcrypto_sm4_xts_decrypt(
            key.as_ptr(),
            tweak.as_ptr(),
            ct.as_ptr(),
            ct.len(),
            pt_back.as_mut_ptr(),
            pt_back.len(),
            &mut pt_actual,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    pt_back.truncate(pt_actual);
    assert_eq!(pt_back, pt);
}

/// Same equivalence + round-trip on a CTS (non-block-multiple, 50-byte) data
/// unit — exercises the ciphertext-stealing tail across the FFI boundary.
#[test]
fn sm4_xts_round_trip_cts_matches_core() {
    let key = xts_key();
    let tweak = [0x33u8; 16];
    let pt: Vec<u8> = (0u8..50).collect();

    let mut ct = vec![0u8; pt.len()];
    let mut ct_actual = 0usize;
    let r = unsafe {
        gmcrypto_sm4_xts_encrypt(
            key.as_ptr(),
            tweak.as_ptr(),
            pt.as_ptr(),
            pt.len(),
            ct.as_mut_ptr(),
            ct.len(),
            &mut ct_actual,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    assert_eq!(ct_actual, pt.len());

    let core_ct = gmcrypto_core::sm4::mode_xts::encrypt(&key, &tweak, &pt).expect("valid params");
    assert_eq!(ct, core_ct);

    let mut pt_back = vec![0u8; ct.len()];
    let mut pt_actual = 0usize;
    let r = unsafe {
        gmcrypto_sm4_xts_decrypt(
            key.as_ptr(),
            tweak.as_ptr(),
            ct.as_ptr(),
            ct.len(),
            pt_back.as_mut_ptr(),
            pt_back.len(),
            &mut pt_actual,
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    pt_back.truncate(pt_actual);
    assert_eq!(pt_back, pt);
}

/// Data unit shorter than one block (15 bytes) → single `GMCRYPTO_ERR`.
#[test]
fn sm4_xts_short_data_returns_err() {
    let key = xts_key();
    let tweak = [0x33u8; 16];
    let pt = [0u8; 15];
    let mut out = [0u8; 15];
    let mut actual = 0usize;
    let r = unsafe {
        gmcrypto_sm4_xts_encrypt(
            key.as_ptr(),
            tweak.as_ptr(),
            pt.as_ptr(),
            pt.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut actual,
        )
    };
    assert_eq!(r, GMCRYPTO_ERR);
}

/// Weak key (`Key1 == Key2`) → single `GMCRYPTO_ERR` (stricter than OpenSSL's
/// default provider; matches the core GB/T 17964 guard).
#[test]
fn sm4_xts_weak_key_returns_err() {
    let key = [0x11u8; GMCRYPTO_SM4_XTS_KEY_SIZE]; // both halves identical
    let tweak = [0x33u8; 16];
    let pt = [0u8; 32];
    let mut out = [0u8; 32];
    let mut actual = 0usize;
    let r = unsafe {
        gmcrypto_sm4_xts_encrypt(
            key.as_ptr(),
            tweak.as_ptr(),
            pt.as_ptr(),
            pt.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut actual,
        )
    };
    assert_eq!(r, GMCRYPTO_ERR);
}

/// Too-small output buffer → `GMCRYPTO_ERR`, with `*out_actual_len` set to the
/// required (== data) length.
#[test]
fn sm4_xts_small_buffer_returns_err_with_required_len() {
    let key = xts_key();
    let tweak = [0x33u8; 16];
    let pt = [0u8; 32];
    let mut actual = 0usize;
    let r = unsafe {
        gmcrypto_sm4_xts_encrypt(
            key.as_ptr(),
            tweak.as_ptr(),
            pt.as_ptr(),
            pt.len(),
            ptr::null_mut(),
            0,
            &mut actual,
        )
    };
    assert_eq!(r, GMCRYPTO_ERR);
    assert_eq!(actual, pt.len());
}

// ============================================================
// v0.16 — SM4-XTS multi-sector (disk) FFI (cfg-gated on `sm4-xts`).
//
// In-place over a contiguous run of equal-size sectors; sector i under
// tweak = LE-128(start_sector + i). Byte-identical to core
// mode_xts::{encrypt_sectors,decrypt_sectors}. Distinct shape from the
// single-shot XTS FFI above: no out/out_capacity/out_actual_len (the
// transform is in place + length-preserving), start_sector is uint64_t.
// ============================================================

use gmcrypto_c::{gmcrypto_sm4_xts_decrypt_sectors, gmcrypto_sm4_xts_encrypt_sectors};

/// Deterministic test pattern of `len` bytes (mirrors the v0.15 core sector
/// test). The `i as u8` truncation is the intended byte-cycling pattern.
#[allow(clippy::cast_possible_truncation)]
fn xts_pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ 0xA5)
        .collect()
}

/// Multi-sector (3 × 512 B) in-place encrypt via FFI == core
/// `encrypt_sectors`; FFI decrypt restores the original in place.
#[test]
fn sm4_xts_sectors_round_trip_matches_core() {
    let key = xts_key();
    let sector_size = 512usize;
    let start_sector = 42u64;
    let plain = xts_pattern(sector_size * 3);

    // FFI encrypt in place.
    let mut buf = plain.clone();
    let r = unsafe {
        gmcrypto_sm4_xts_encrypt_sectors(
            key.as_ptr(),
            sector_size,
            start_sector,
            buf.as_mut_ptr(),
            buf.len(),
        )
    };
    assert_eq!(r, GMCRYPTO_OK);

    // == core encrypt_sectors on an identical clone.
    let mut core_buf = plain.clone();
    gmcrypto_core::sm4::mode_xts::encrypt_sectors(
        &key,
        sector_size,
        u128::from(start_sector),
        &mut core_buf,
    )
    .expect("valid params");
    assert_eq!(buf, core_buf);

    // FFI decrypt restores the plaintext in place.
    let r = unsafe {
        gmcrypto_sm4_xts_decrypt_sectors(
            key.as_ptr(),
            sector_size,
            start_sector,
            buf.as_mut_ptr(),
            buf.len(),
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    assert_eq!(buf, plain);
}

/// Small sectors (3 × 32 B) at `start_sector = 0xfe` so the LE counter crosses
/// a byte boundary (0xfe → 0xff → 0x100) mid-run; FFI == core.
#[test]
fn sm4_xts_sectors_byte_boundary_matches_core() {
    let key = xts_key();
    let sector_size = 32usize;
    let start_sector = 0xfeu64;
    let plain = xts_pattern(sector_size * 3);

    let mut buf = plain.clone();
    let r = unsafe {
        gmcrypto_sm4_xts_encrypt_sectors(
            key.as_ptr(),
            sector_size,
            start_sector,
            buf.as_mut_ptr(),
            buf.len(),
        )
    };
    assert_eq!(r, GMCRYPTO_OK);

    // `plain` is unused after this, so move it into the core buffer.
    let mut core_buf = plain;
    gmcrypto_core::sm4::mode_xts::encrypt_sectors(
        &key,
        sector_size,
        u128::from(start_sector),
        &mut core_buf,
    )
    .expect("valid params");
    assert_eq!(buf, core_buf);
}

/// A high 64-bit starting LBA (crosses the 2^32 boundary in the LE tweak
/// counter) round-trips — exercises the `uint64_t → u128` widening with no
/// overflow (the overflow `None` is unreachable through this FFI).
#[test]
fn sm4_xts_sectors_high_lba_round_trip() {
    let key = xts_key();
    let sector_size = 512usize;
    let start_sector = 0xFFFF_FFFF_FFFF_0000u64;
    let plain = xts_pattern(sector_size * 2);

    let mut buf = plain.clone();
    let r = unsafe {
        gmcrypto_sm4_xts_encrypt_sectors(
            key.as_ptr(),
            sector_size,
            start_sector,
            buf.as_mut_ptr(),
            buf.len(),
        )
    };
    assert_eq!(r, GMCRYPTO_OK);

    let mut core_buf = plain.clone();
    gmcrypto_core::sm4::mode_xts::encrypt_sectors(
        &key,
        sector_size,
        u128::from(start_sector),
        &mut core_buf,
    )
    .expect("valid params");
    assert_eq!(buf, core_buf);

    let r = unsafe {
        gmcrypto_sm4_xts_decrypt_sectors(
            key.as_ptr(),
            sector_size,
            start_sector,
            buf.as_mut_ptr(),
            buf.len(),
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    assert_eq!(buf, plain);
}

/// `sector_size` not a multiple of 16 → `GMCRYPTO_ERR`; `buf` untouched.
#[test]
fn sm4_xts_sectors_bad_sector_size_buf_untouched() {
    let key = xts_key();
    let mut buf = [0xABu8; 40];
    let before = buf;
    let r = unsafe {
        gmcrypto_sm4_xts_encrypt_sectors(key.as_ptr(), 20, 0, buf.as_mut_ptr(), buf.len())
    };
    assert_eq!(r, GMCRYPTO_ERR);
    assert_eq!(buf, before, "buf must be untouched on validation failure");
}

/// `buf_len` not a whole multiple of `sector_size` → `GMCRYPTO_ERR`; `buf`
/// untouched.
#[test]
fn sm4_xts_sectors_non_multiple_buf_untouched() {
    let key = xts_key();
    let mut buf = [0xCDu8; 24]; // 24 is not a multiple of the 16-byte sector
    let before = buf;
    let r = unsafe {
        gmcrypto_sm4_xts_encrypt_sectors(key.as_ptr(), 16, 0, buf.as_mut_ptr(), buf.len())
    };
    assert_eq!(r, GMCRYPTO_ERR);
    assert_eq!(buf, before, "buf must be untouched on validation failure");
}

/// Weak key (`Key1 == Key2`) → `GMCRYPTO_ERR`; `buf` untouched.
#[test]
fn sm4_xts_sectors_weak_key_buf_untouched() {
    let key = [0x11u8; GMCRYPTO_SM4_XTS_KEY_SIZE]; // both halves identical
    let mut buf = [0xEFu8; 32];
    let before = buf;
    let r = unsafe {
        gmcrypto_sm4_xts_encrypt_sectors(key.as_ptr(), 16, 0, buf.as_mut_ptr(), buf.len())
    };
    assert_eq!(r, GMCRYPTO_ERR);
    assert_eq!(buf, before, "buf must be untouched on weak-key reject");
}

/// Empty `buf` passed as `(NULL, 0)` (the natural C "no data" call) is a vacuous
/// `GMCRYPTO_OK`; but the key is still validated, so an empty run under a weak
/// key is still `GMCRYPTO_ERR`.
#[test]
fn sm4_xts_sectors_empty_buf_ok_weak_err() {
    let key = xts_key();
    let r = unsafe { gmcrypto_sm4_xts_encrypt_sectors(key.as_ptr(), 512, 0, ptr::null_mut(), 0) };
    assert_eq!(r, GMCRYPTO_OK);

    let weak = [0x11u8; GMCRYPTO_SM4_XTS_KEY_SIZE];
    let r = unsafe { gmcrypto_sm4_xts_encrypt_sectors(weak.as_ptr(), 512, 0, ptr::null_mut(), 0) };
    assert_eq!(r, GMCRYPTO_ERR);
}

/// Null `buf` with non-zero `buf_len` → `GMCRYPTO_ERR`.
#[test]
fn sm4_xts_sectors_null_buf_returns_err() {
    let key = xts_key();
    let r = unsafe { gmcrypto_sm4_xts_encrypt_sectors(key.as_ptr(), 16, 0, ptr::null_mut(), 32) };
    assert_eq!(r, GMCRYPTO_ERR);
}

/// Null `key` → `GMCRYPTO_ERR`; `buf` untouched (reject before any mutation).
#[test]
fn sm4_xts_sectors_null_key_buf_untouched() {
    let mut buf = [0x5Cu8; 32];
    let before = buf;
    let r = unsafe { gmcrypto_sm4_xts_encrypt_sectors(ptr::null(), 16, 0, buf.as_mut_ptr(), 32) };
    assert_eq!(r, GMCRYPTO_ERR);
    assert_eq!(buf, before, "buf must be untouched on null-key reject");
}

/// Decrypt-side error path (guards against encrypt/decrypt copy-paste
/// asymmetry): weak key + bad `sector_size` both → `GMCRYPTO_ERR`, buf
/// untouched, via `gmcrypto_sm4_xts_decrypt_sectors`.
#[test]
fn sm4_xts_sectors_decrypt_errors_buf_untouched() {
    let weak = [0x11u8; GMCRYPTO_SM4_XTS_KEY_SIZE];
    let mut buf = [0x9Au8; 32];
    let before = buf;
    let r = unsafe { gmcrypto_sm4_xts_decrypt_sectors(weak.as_ptr(), 16, 0, buf.as_mut_ptr(), 32) };
    assert_eq!(r, GMCRYPTO_ERR);
    assert_eq!(
        buf, before,
        "buf must be untouched on weak-key decrypt reject"
    );

    // Bad sector_size (20, not a multiple of 16) on a correctly-sized 40-byte
    // buffer → ERR, buf untouched.
    let key = xts_key();
    let mut buf2 = [0x9Au8; 40];
    let before2 = buf2;
    let r = unsafe { gmcrypto_sm4_xts_decrypt_sectors(key.as_ptr(), 20, 0, buf2.as_mut_ptr(), 40) };
    assert_eq!(r, GMCRYPTO_ERR);
    assert_eq!(
        buf2, before2,
        "buf must be untouched on bad sector_size decrypt reject"
    );
}

/// Regression test for the W0 key/buf aliasing fix: pass `key` and `buf` as
/// **overlapping** views into one backing buffer (a caller error, but it must
/// not be UB). The shim copies the 32-byte key into an owned array before
/// constructing `&mut buf`, so the result equals encrypting the original
/// plaintext under the original key — captured here from non-overlapping
/// copies taken before the call.
#[test]
fn sm4_xts_sectors_key_buf_overlap_ok() {
    // backing[0..32] is the key view (Key1 = [0..16], Key2 = [16..32], which
    // differ under this pattern); backing[16..48] is the buf view (2 × 16-byte
    // sectors). The two views overlap on bytes [16..32].
    let mut backing = [0u8; 48];
    backing.copy_from_slice(&xts_pattern(48));
    let start_sector = 7u64;

    // Reference under NON-overlapping copies, captured before any mutation.
    let key_ref: [u8; GMCRYPTO_SM4_XTS_KEY_SIZE] = backing[0..32].try_into().unwrap();
    let mut buf_ref = backing[16..48].to_vec();
    gmcrypto_core::sm4::mode_xts::encrypt_sectors(
        &key_ref,
        16,
        u128::from(start_sector),
        &mut buf_ref,
    )
    .expect("valid params");

    // FFI with overlapping key/buf views into `backing` (both raw pointers are
    // derived from one base; the shim copies the key before mutating buf).
    let base = backing.as_mut_ptr();
    let key_ptr: *const u8 = base;
    let buf_ptr: *mut u8 = unsafe { base.add(16) };
    let r = unsafe { gmcrypto_sm4_xts_encrypt_sectors(key_ptr, 16, start_sector, buf_ptr, 32) };
    assert_eq!(r, GMCRYPTO_OK);
    assert_eq!(
        &backing[16..48],
        &buf_ref[..],
        "overlap result must match the non-overlap reference"
    );
}

// ============================================================
// SM2 key exchange (GM/T 0003.3) — v1.2 FFI
// ============================================================

use gmcrypto_c::{
    GMCRYPTO_SM2_KX_CONFIRM_SIZE, gmcrypto_sm2_kx_initiator_confirm,
    gmcrypto_sm2_kx_initiator_free, gmcrypto_sm2_kx_initiator_new,
    gmcrypto_sm2_kx_initiator_new_with_rng, gmcrypto_sm2_kx_responder_finish,
    gmcrypto_sm2_kx_responder_free, gmcrypto_sm2_kx_responder_new,
    gmcrypto_sm2_kx_responder_respond, gmcrypto_sm2_kx_responder_respond_with_rng,
};
use gmcrypto_core::sm2::key_exchange::{
    Sm2KxConfirm, Sm2KxEphemeralPoint, Sm2KxInitiator, Sm2KxResponder,
};

const KX_PT: usize = GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE; // R_A / R_B (65)
const KX_CT: usize = GMCRYPTO_SM2_KX_CONFIRM_SIZE; // S_A / S_B (32)
/// The FFI's `id_len == 0` default — also the GM/T 0003.5 KAT ID.
const KX_ID: &[u8] = b"1234567812345678";

// GM/T 0003.5 / GB/T 32918.5 recommended-curve worked example — the
// same vectors as crates/gmcrypto-core/tests/sm2_kx_kat.rs.
const KX_D_A: [u8; 32] = hex!("81EB26E941BB5AF16DF116495F90695272AE2CD63D6C4AE1678418BE48230029");
const KX_D_B: [u8; 32] = hex!("785129917D45A9EA5437A59356B82338EAADDA6CEB199088F14AE10DEFA229B5");
const KX_R_A_EPH: [u8; 32] =
    hex!("D4DE15474DB74D06491C440D305E012400990F3E390C7E87153C12DB2EA60BB3");
const KX_R_B_EPH: [u8; 32] =
    hex!("7E07124814B309489125EAED101113164EBF0F3458C5BD88335C1F9D596243D6");
const KX_R_A_SEC1: [u8; 65] = hex!(
    "0464CED1BDBC99D590049B434D0FD73428CF608A5DB8FE5CE07F15026940BAE40E376629C7AB21E7DB260922499DDB118F07CE8EAAE3E7720AFEF6A5CC062070C0"
);
const KX_R_B_SEC1: [u8; 65] = hex!(
    "04ACC27688A6F7B706098BC91FF3AD1BFF7DC2802CDB14CCCCDB0A90471F9BD7072FEDAC0494B2FFC4D6853876C79B8F301C6573AD0AA50F39FC87181E1A1B46FE"
);
const KX_EXPECT_K: [u8; 16] = hex!("6C89347354DE2484C60B4AB1FDE4C6E5");
const KX_EXPECT_S_B: [u8; 32] =
    hex!("D3A0FE15DEE185CEAE907A6B595CC32A266ED7B3367E9983A896DC32FA20F8EB");
const KX_EXPECT_S_A: [u8; 32] =
    hex!("18C7894B3816DF16CF07B05C5EC0BEF5D655D58F779CC1B400A4F3884644DB88");

/// Build `(priv, pub)` FFI handles for a big-endian scalar.
fn kx_keypair(d_be: &[u8; 32]) -> (*mut gmcrypto_sm2_privkey_t, *mut gmcrypto_sm2_pubkey_t) {
    use gmcrypto_core::sm2::Sm2PrivateKey;
    let key = Sm2PrivateKey::from_bytes_be(d_be).expect("valid d");
    let pub_bytes: [u8; 65] = key.public_key().to_sec1_uncompressed();
    let priv_ptr = unsafe { gmcrypto_sm2_privkey_new(d_be.as_ptr()) };
    let pub_ptr = unsafe { gmcrypto_sm2_pubkey_new(pub_bytes.as_ptr()) };
    assert!(!priv_ptr.is_null());
    assert!(!pub_ptr.is_null());
    (priv_ptr, pub_ptr)
}

fn kx_free_keys(handles: &[(*mut gmcrypto_sm2_privkey_t, *mut gmcrypto_sm2_pubkey_t)]) {
    for &(d, p) in handles {
        unsafe {
            gmcrypto_sm2_privkey_free(d);
            gmcrypto_sm2_pubkey_free(p);
        }
    }
}

/// Trampoline that fills EVERY draw with the same 32 bytes (context =
/// `*mut [u8; 32]`) — the FFI twin of the core KAT's `FixedScalarRng`,
/// so a fixed standard ephemeral can be driven through `_with_rng`.
unsafe extern "C" fn fixed32_rng_callback(
    context: *mut core::ffi::c_void,
    buf: *mut u8,
    buf_len: usize,
) -> core::ffi::c_int {
    if context.is_null() || buf.is_null() || buf_len != 32 {
        return -1;
    }
    // SAFETY: caller asserts context is *mut [u8; 32].
    let bytes = unsafe { &*(context.cast::<[u8; 32]>()) };
    // SAFETY: buf is valid for buf_len bytes per the FFI contract.
    let dst = unsafe { core::slice::from_raw_parts_mut(buf, buf_len) };
    dst.copy_from_slice(bytes);
    0
}

/// FFI initiator ↔ FFI responder full handshake (OS RNG): both sides
/// must agree on a non-degenerate key and both tags must verify.
#[test]
fn sm2_kx_ffi_handshake_keys_match() {
    const KLEN: usize = 32;
    let a = kx_keypair(&[0x21u8; 32]);
    let b = kx_keypair(&[0x47u8; 32]);

    let mut r_a = [0u8; KX_PT];
    let init = unsafe {
        gmcrypto_sm2_kx_initiator_new(
            a.0,
            b.1,
            ptr::null(),
            0,
            ptr::null(),
            0,
            KLEN,
            r_a.as_mut_ptr(),
        )
    };
    assert!(!init.is_null());

    let resp =
        unsafe { gmcrypto_sm2_kx_responder_new(b.0, a.1, ptr::null(), 0, ptr::null(), 0, KLEN) };
    assert!(!resp.is_null());

    let mut r_b = [0u8; KX_PT];
    let mut s_b = [0u8; KX_CT];
    let r = unsafe {
        gmcrypto_sm2_kx_responder_respond(resp, r_a.as_ptr(), r_b.as_mut_ptr(), s_b.as_mut_ptr())
    };
    assert_eq!(r, GMCRYPTO_OK);

    let mut key_a = [0u8; KLEN];
    let mut s_a = [0u8; KX_CT];
    let r = unsafe {
        gmcrypto_sm2_kx_initiator_confirm(
            init,
            r_b.as_ptr(),
            s_b.as_ptr(),
            key_a.as_mut_ptr(),
            s_a.as_mut_ptr(),
        )
    };
    assert_eq!(r, GMCRYPTO_OK);

    let mut key_b = [0u8; KLEN];
    let r = unsafe { gmcrypto_sm2_kx_responder_finish(resp, s_a.as_ptr(), key_b.as_mut_ptr()) };
    assert_eq!(r, GMCRYPTO_OK);

    assert_eq!(key_a, key_b, "FFI initiator and responder keys differ");
    assert!(key_a.iter().any(|&x| x != 0), "degenerate all-zero key");
    kx_free_keys(&[a, b]);
}

/// FFI initiator ↔ PURE-RUST core responder: a C caller and a Rust
/// caller must interoperate byte-for-byte on the wire.
#[test]
fn sm2_kx_ffi_initiator_against_rust_responder() {
    use gmcrypto_core::sm2::Sm2PrivateKey;
    const KLEN: usize = 16;
    let a = kx_keypair(&[0x33u8; 32]);
    let db = Sm2PrivateKey::from_bytes_be(&[0x55u8; 32]).unwrap();
    let (b_priv_ffi, b_pub_ffi) = kx_keypair(&[0x55u8; 32]);
    let pa_rust = Sm2PrivateKey::from_bytes_be(&[0x33u8; 32])
        .unwrap()
        .public_key();

    let mut r_a = [0u8; KX_PT];
    let init = unsafe {
        gmcrypto_sm2_kx_initiator_new(
            a.0,
            b_pub_ffi,
            ptr::null(),
            0,
            ptr::null(),
            0,
            KLEN,
            r_a.as_mut_ptr(),
        )
    };
    assert!(!init.is_null());

    // Pure-Rust responder consumes the FFI initiator's wire bytes.
    let resp = Sm2KxResponder::new(&db, &pa_rust, KX_ID, KX_ID, KLEN).unwrap();
    let (rb, sb, waiting) = resp
        .respond(
            &Sm2KxEphemeralPoint::from_bytes(&r_a),
            &mut getrandom::SysRng,
        )
        .unwrap();

    let mut key_a = [0u8; KLEN];
    let mut s_a = [0u8; KX_CT];
    let r = unsafe {
        gmcrypto_sm2_kx_initiator_confirm(
            init,
            rb.to_bytes().as_ptr(),
            sb.to_bytes().as_ptr(),
            key_a.as_mut_ptr(),
            s_a.as_mut_ptr(),
        )
    };
    assert_eq!(r, GMCRYPTO_OK, "FFI initiator rejected the Rust responder");

    let key_b = waiting
        .finish(&Sm2KxConfirm::from_bytes(&s_a))
        .expect("Rust responder rejected the FFI initiator's S_A");
    assert_eq!(key_a.as_slice(), key_b.as_bytes());
    kx_free_keys(&[a, (b_priv_ffi, b_pub_ffi)]);
}

/// PURE-RUST core initiator ↔ FFI responder (the reverse direction).
#[test]
fn sm2_kx_rust_initiator_against_ffi_responder() {
    use gmcrypto_core::sm2::Sm2PrivateKey;
    const KLEN: usize = 16;
    let da = Sm2PrivateKey::from_bytes_be(&[0x66u8; 32]).unwrap();
    let pb_rust = Sm2PrivateKey::from_bytes_be(&[0x77u8; 32])
        .unwrap()
        .public_key();
    let a = kx_keypair(&[0x66u8; 32]);
    let b = kx_keypair(&[0x77u8; 32]);

    let init = Sm2KxInitiator::new(&da, &pb_rust, KX_ID, KX_ID, KLEN).unwrap();
    let (ra, init_waiting) = init.produce_ephemeral(&mut getrandom::SysRng).unwrap();

    let resp =
        unsafe { gmcrypto_sm2_kx_responder_new(b.0, a.1, ptr::null(), 0, ptr::null(), 0, KLEN) };
    assert!(!resp.is_null());
    let mut r_b = [0u8; KX_PT];
    let mut s_b = [0u8; KX_CT];
    let r = unsafe {
        gmcrypto_sm2_kx_responder_respond(
            resp,
            ra.to_bytes().as_ptr(),
            r_b.as_mut_ptr(),
            s_b.as_mut_ptr(),
        )
    };
    assert_eq!(
        r, GMCRYPTO_OK,
        "FFI responder rejected the Rust initiator's R_A"
    );

    let (key_a, sa) = init_waiting
        .confirm(
            &Sm2KxEphemeralPoint::from_bytes(&r_b),
            &Sm2KxConfirm::from_bytes(&s_b),
        )
        .expect("Rust initiator rejected the FFI responder's reply");

    let mut key_b = [0u8; KLEN];
    let r = unsafe {
        gmcrypto_sm2_kx_responder_finish(resp, sa.to_bytes().as_ptr(), key_b.as_mut_ptr())
    };
    assert_eq!(
        r, GMCRYPTO_OK,
        "FFI responder rejected the Rust initiator's S_A"
    );
    assert_eq!(key_a.as_bytes(), key_b.as_slice());
    kx_free_keys(&[a, b]);
}

/// THE HEADLINE (scope Q2.3): the GM/T 0003.5 recommended-curve worked
/// example reproduced byte-for-byte THROUGH THE C ABI — fixed standard
/// ephemerals via `_with_rng`, every wire value asserted against the
/// standard (`R_A`, `R_B`, `S_B`, `S_A`, `K` on both sides). The ids
/// ride the FFI default (`len == 0` → `"1234567812345678"`), which is
/// exactly the worked example's ID for both parties.
#[test]
fn sm2_kx_kat_through_ffi() {
    const KLEN: usize = 16;
    let a = kx_keypair(&KX_D_A);
    let b = kx_keypair(&KX_D_B);

    let mut eph_a = KX_R_A_EPH;
    let mut r_a = [0u8; KX_PT];
    let init = unsafe {
        gmcrypto_sm2_kx_initiator_new_with_rng(
            a.0,
            b.1,
            ptr::null(),
            0,
            ptr::null(),
            0,
            KLEN,
            Some(fixed32_rng_callback),
            (&raw mut eph_a).cast::<core::ffi::c_void>(),
            r_a.as_mut_ptr(),
        )
    };
    assert!(!init.is_null());
    assert_eq!(r_a, KX_R_A_SEC1, "R_A != standard through the FFI");

    let resp =
        unsafe { gmcrypto_sm2_kx_responder_new(b.0, a.1, ptr::null(), 0, ptr::null(), 0, KLEN) };
    assert!(!resp.is_null());
    let mut eph_b = KX_R_B_EPH;
    let mut r_b = [0u8; KX_PT];
    let mut s_b = [0u8; KX_CT];
    let r = unsafe {
        gmcrypto_sm2_kx_responder_respond_with_rng(
            resp,
            r_a.as_ptr(),
            Some(fixed32_rng_callback),
            (&raw mut eph_b).cast::<core::ffi::c_void>(),
            r_b.as_mut_ptr(),
            s_b.as_mut_ptr(),
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    assert_eq!(r_b, KX_R_B_SEC1, "R_B != standard through the FFI");
    assert_eq!(s_b, KX_EXPECT_S_B, "S_B != standard through the FFI");

    let mut key_a = [0u8; KLEN];
    let mut s_a = [0u8; KX_CT];
    let r = unsafe {
        gmcrypto_sm2_kx_initiator_confirm(
            init,
            r_b.as_ptr(),
            s_b.as_ptr(),
            key_a.as_mut_ptr(),
            s_a.as_mut_ptr(),
        )
    };
    assert_eq!(r, GMCRYPTO_OK);
    assert_eq!(
        key_a, KX_EXPECT_K,
        "K (initiator) != standard through the FFI"
    );
    assert_eq!(s_a, KX_EXPECT_S_A, "S_A != standard through the FFI");

    let mut key_b = [0u8; KLEN];
    let r = unsafe { gmcrypto_sm2_kx_responder_finish(resp, s_a.as_ptr(), key_b.as_mut_ptr()) };
    assert_eq!(r, GMCRYPTO_OK);
    assert_eq!(
        key_b, KX_EXPECT_K,
        "K (responder) != standard through the FFI"
    );
    kx_free_keys(&[a, b]);
}

/// Tampered `S_B` at confirm → ERR (handle consumed either way).
#[test]
fn sm2_kx_confirm_rejects_tampered_s_b() {
    const KLEN: usize = 16;
    let a = kx_keypair(&[0x21u8; 32]);
    let b = kx_keypair(&[0x47u8; 32]);
    let mut r_a = [0u8; KX_PT];
    let init = unsafe {
        gmcrypto_sm2_kx_initiator_new(
            a.0,
            b.1,
            ptr::null(),
            0,
            ptr::null(),
            0,
            KLEN,
            r_a.as_mut_ptr(),
        )
    };
    let resp =
        unsafe { gmcrypto_sm2_kx_responder_new(b.0, a.1, ptr::null(), 0, ptr::null(), 0, KLEN) };
    let mut r_b = [0u8; KX_PT];
    let mut s_b = [0u8; KX_CT];
    assert_eq!(
        unsafe {
            gmcrypto_sm2_kx_responder_respond(
                resp,
                r_a.as_ptr(),
                r_b.as_mut_ptr(),
                s_b.as_mut_ptr(),
            )
        },
        GMCRYPTO_OK
    );
    s_b[0] ^= 1; // tamper
    let mut key_a = [0u8; KLEN];
    let mut s_a = [0u8; KX_CT];
    assert_eq!(
        unsafe {
            gmcrypto_sm2_kx_initiator_confirm(
                init,
                r_b.as_ptr(),
                s_b.as_ptr(),
                key_a.as_mut_ptr(),
                s_a.as_mut_ptr(),
            )
        },
        GMCRYPTO_ERR,
        "tampered S_B accepted by the FFI"
    );
    unsafe { gmcrypto_sm2_kx_responder_free(resp) };
    kx_free_keys(&[a, b]);
}

/// Tampered `S_A` at finish → ERR; the responder never releases K.
#[test]
fn sm2_kx_finish_rejects_tampered_s_a() {
    const KLEN: usize = 16;
    let a = kx_keypair(&[0x21u8; 32]);
    let b = kx_keypair(&[0x47u8; 32]);
    let mut r_a = [0u8; KX_PT];
    let init = unsafe {
        gmcrypto_sm2_kx_initiator_new(
            a.0,
            b.1,
            ptr::null(),
            0,
            ptr::null(),
            0,
            KLEN,
            r_a.as_mut_ptr(),
        )
    };
    let resp =
        unsafe { gmcrypto_sm2_kx_responder_new(b.0, a.1, ptr::null(), 0, ptr::null(), 0, KLEN) };
    let mut r_b = [0u8; KX_PT];
    let mut s_b = [0u8; KX_CT];
    assert_eq!(
        unsafe {
            gmcrypto_sm2_kx_responder_respond(
                resp,
                r_a.as_ptr(),
                r_b.as_mut_ptr(),
                s_b.as_mut_ptr(),
            )
        },
        GMCRYPTO_OK
    );
    let mut key_a = [0u8; KLEN];
    let mut s_a = [0u8; KX_CT];
    assert_eq!(
        unsafe {
            gmcrypto_sm2_kx_initiator_confirm(
                init,
                r_b.as_ptr(),
                s_b.as_ptr(),
                key_a.as_mut_ptr(),
                s_a.as_mut_ptr(),
            )
        },
        GMCRYPTO_OK
    );
    s_a[31] ^= 0x80; // tamper
    let mut key_b = [0u8; KLEN];
    assert_eq!(
        unsafe { gmcrypto_sm2_kx_responder_finish(resp, s_a.as_ptr(), key_b.as_mut_ptr()) },
        GMCRYPTO_ERR,
        "tampered S_A accepted by the FFI"
    );
    kx_free_keys(&[a, b]);
}

/// Corrupt (off-curve) `R_A` → respond fails AND spends the handle:
/// a retry with the GOOD bytes must also fail (the Rust responder was
/// consumed by the failed attempt — documented `Spent` semantics).
#[test]
fn sm2_kx_respond_rejects_corrupt_r_a_and_spends_handle() {
    const KLEN: usize = 16;
    let a = kx_keypair(&[0x21u8; 32]);
    let b = kx_keypair(&[0x47u8; 32]);
    let mut r_a = [0u8; KX_PT];
    let init = unsafe {
        gmcrypto_sm2_kx_initiator_new(
            a.0,
            b.1,
            ptr::null(),
            0,
            ptr::null(),
            0,
            KLEN,
            r_a.as_mut_ptr(),
        )
    };
    assert!(!init.is_null());
    let resp =
        unsafe { gmcrypto_sm2_kx_responder_new(b.0, a.1, ptr::null(), 0, ptr::null(), 0, KLEN) };
    let mut bad = r_a;
    bad[10] ^= 1; // off-curve x
    let mut r_b = [0u8; KX_PT];
    let mut s_b = [0u8; KX_CT];
    assert_eq!(
        unsafe {
            gmcrypto_sm2_kx_responder_respond(
                resp,
                bad.as_ptr(),
                r_b.as_mut_ptr(),
                s_b.as_mut_ptr(),
            )
        },
        GMCRYPTO_ERR,
        "off-curve R_A accepted"
    );
    // Spent: the good bytes can no longer succeed on this handle.
    assert_eq!(
        unsafe {
            gmcrypto_sm2_kx_responder_respond(
                resp,
                r_a.as_ptr(),
                r_b.as_mut_ptr(),
                s_b.as_mut_ptr(),
            )
        },
        GMCRYPTO_ERR,
        "spent responder accepted a retry"
    );
    unsafe {
        gmcrypto_sm2_kx_responder_free(resp);
        gmcrypto_sm2_kx_initiator_free(init);
    }
    kx_free_keys(&[a, b]);
}

/// A stray second `_respond` returns ERR WITHOUT disturbing the
/// in-flight state: the handshake still completes afterwards.
#[test]
fn sm2_kx_double_respond_rejected_but_preserves_state() {
    const KLEN: usize = 16;
    let a = kx_keypair(&[0x21u8; 32]);
    let b = kx_keypair(&[0x47u8; 32]);
    let mut r_a = [0u8; KX_PT];
    let init = unsafe {
        gmcrypto_sm2_kx_initiator_new(
            a.0,
            b.1,
            ptr::null(),
            0,
            ptr::null(),
            0,
            KLEN,
            r_a.as_mut_ptr(),
        )
    };
    let resp =
        unsafe { gmcrypto_sm2_kx_responder_new(b.0, a.1, ptr::null(), 0, ptr::null(), 0, KLEN) };
    let mut r_b = [0u8; KX_PT];
    let mut s_b = [0u8; KX_CT];
    assert_eq!(
        unsafe {
            gmcrypto_sm2_kx_responder_respond(
                resp,
                r_a.as_ptr(),
                r_b.as_mut_ptr(),
                s_b.as_mut_ptr(),
            )
        },
        GMCRYPTO_OK
    );
    // Misuse: second respond → ERR, state preserved.
    let mut r_b2 = [0u8; KX_PT];
    let mut s_b2 = [0u8; KX_CT];
    assert_eq!(
        unsafe {
            gmcrypto_sm2_kx_responder_respond(
                resp,
                r_a.as_ptr(),
                r_b2.as_mut_ptr(),
                s_b2.as_mut_ptr(),
            )
        },
        GMCRYPTO_ERR,
        "double respond accepted"
    );
    // The original transcript still confirms + finishes.
    let mut key_a = [0u8; KLEN];
    let mut s_a = [0u8; KX_CT];
    assert_eq!(
        unsafe {
            gmcrypto_sm2_kx_initiator_confirm(
                init,
                r_b.as_ptr(),
                s_b.as_ptr(),
                key_a.as_mut_ptr(),
                s_a.as_mut_ptr(),
            )
        },
        GMCRYPTO_OK
    );
    let mut key_b = [0u8; KLEN];
    assert_eq!(
        unsafe { gmcrypto_sm2_kx_responder_finish(resp, s_a.as_ptr(), key_b.as_mut_ptr()) },
        GMCRYPTO_OK,
        "in-flight state was destroyed by the misuse call"
    );
    assert_eq!(key_a, key_b);
    kx_free_keys(&[a, b]);
}

/// `_finish` before a successful `_respond` → ERR (handle consumed).
#[test]
fn sm2_kx_finish_before_respond_rejected() {
    const KLEN: usize = 16;
    let a = kx_keypair(&[0x21u8; 32]);
    let b = kx_keypair(&[0x47u8; 32]);
    let resp =
        unsafe { gmcrypto_sm2_kx_responder_new(b.0, a.1, ptr::null(), 0, ptr::null(), 0, KLEN) };
    assert!(!resp.is_null());
    let s_a = [0u8; KX_CT];
    let mut key_b = [0u8; KLEN];
    assert_eq!(
        unsafe { gmcrypto_sm2_kx_responder_finish(resp, s_a.as_ptr(), key_b.as_mut_ptr()) },
        GMCRYPTO_ERR,
        "finish before respond accepted"
    );
    kx_free_keys(&[a, b]);
}

/// Null pointers → NULL handle, never a crash.
#[test]
fn sm2_kx_null_inputs_rejected() {
    const KLEN: usize = 16;
    let a = kx_keypair(&[0x21u8; 32]);
    let b = kx_keypair(&[0x47u8; 32]);
    let mut r_a = [0u8; KX_PT];

    // Null key handles.
    assert!(
        unsafe {
            gmcrypto_sm2_kx_initiator_new(
                ptr::null(),
                b.1,
                ptr::null(),
                0,
                ptr::null(),
                0,
                KLEN,
                r_a.as_mut_ptr(),
            )
        }
        .is_null()
    );
    assert!(
        unsafe {
            gmcrypto_sm2_kx_initiator_new(
                a.0,
                ptr::null(),
                ptr::null(),
                0,
                ptr::null(),
                0,
                KLEN,
                r_a.as_mut_ptr(),
            )
        }
        .is_null()
    );
    assert!(
        unsafe {
            gmcrypto_sm2_kx_responder_new(ptr::null(), a.1, ptr::null(), 0, ptr::null(), 0, KLEN)
        }
        .is_null()
    );

    // Null R_A out-buffer.
    assert!(
        unsafe {
            gmcrypto_sm2_kx_initiator_new(
                a.0,
                b.1,
                ptr::null(),
                0,
                ptr::null(),
                0,
                KLEN,
                ptr::null_mut(),
            )
        }
        .is_null()
    );

    // Free on NULL is a no-op.
    unsafe {
        gmcrypto_sm2_kx_initiator_free(ptr::null_mut());
        gmcrypto_sm2_kx_responder_free(ptr::null_mut());
    }
    kx_free_keys(&[a, b]);
}

/// Bad `klen` and null / failing RNG callbacks → NULL handle.
#[test]
fn sm2_kx_bad_klen_and_rng_callback_rejected() {
    const KLEN: usize = 16;
    let a = kx_keypair(&[0x21u8; 32]);
    let b = kx_keypair(&[0x47u8; 32]);
    let mut r_a = [0u8; KX_PT];

    // klen == 0 (core validate_params reject).
    assert!(
        unsafe {
            gmcrypto_sm2_kx_initiator_new(
                a.0,
                b.1,
                ptr::null(),
                0,
                ptr::null(),
                0,
                0,
                r_a.as_mut_ptr(),
            )
        }
        .is_null()
    );
    assert!(
        unsafe { gmcrypto_sm2_kx_responder_new(b.0, a.1, ptr::null(), 0, ptr::null(), 0, 0) }
            .is_null()
    );

    // Null / failing RNG callback on the _with_rng variants.
    assert!(
        unsafe {
            gmcrypto_sm2_kx_initiator_new_with_rng(
                a.0,
                b.1,
                ptr::null(),
                0,
                ptr::null(),
                0,
                KLEN,
                None,
                ptr::null_mut(),
                r_a.as_mut_ptr(),
            )
        }
        .is_null()
    );
    assert!(
        unsafe {
            gmcrypto_sm2_kx_initiator_new_with_rng(
                a.0,
                b.1,
                ptr::null(),
                0,
                ptr::null(),
                0,
                KLEN,
                Some(always_fail_rng_callback),
                ptr::null_mut(),
                r_a.as_mut_ptr(),
            )
        }
        .is_null()
    );
    kx_free_keys(&[a, b]);
}

// ============================================================
// v1.4 — X.509-with-SM2 certificate FFI (Q4.1–Q4.15 in
// docs/v1.4-scope.md). Fixtures are the committed gmssl 3.1.1
// CA + leaf from the v1.3 core KAT; every assertion is
// structural/relational vs the Rust core, never specific bytes.
// ============================================================

use gmcrypto_c::{
    gmcrypto_x509_certificate_extensions_raw, gmcrypto_x509_certificate_free,
    gmcrypto_x509_certificate_from_der, gmcrypto_x509_certificate_is_self_issued,
    gmcrypto_x509_certificate_issuer_raw, gmcrypto_x509_certificate_not_after,
    gmcrypto_x509_certificate_not_before, gmcrypto_x509_certificate_serial_raw,
    gmcrypto_x509_certificate_subject_public_key, gmcrypto_x509_certificate_subject_raw,
    gmcrypto_x509_certificate_t, gmcrypto_x509_certificate_tbs_raw,
    gmcrypto_x509_certificate_verify_signature, gmcrypto_x509_certificate_verify_signature_with_id,
    gmcrypto_x509_time_t,
};
use gmcrypto_core::x509::Certificate;

const X509_CA_DER: &[u8] = include_bytes!("../../gmcrypto-core/tests/data/x509_ca.der");
const X509_LEAF_DER: &[u8] = include_bytes!("../../gmcrypto-core/tests/data/x509_leaf.der");

/// Parse a fixture through the FFI; panics on NULL.
fn x509_parse(der: &[u8]) -> *mut gmcrypto_x509_certificate_t {
    let cert = unsafe { gmcrypto_x509_certificate_from_der(der.as_ptr(), der.len()) };
    assert!(!cert.is_null(), "fixture must parse through the FFI");
    cert
}

/// Drive one copy-out accessor with the two-call discovery convention.
fn x509_copy_out_helper(
    f: unsafe extern "C" fn(
        *const gmcrypto_x509_certificate_t,
        *mut u8,
        usize,
        *mut usize,
    ) -> core::ffi::c_int,
    cert: *const gmcrypto_x509_certificate_t,
) -> Vec<u8> {
    let mut needed = 0usize;
    // Length discovery: zero capacity reports the required length.
    unsafe { f(cert, ptr::null_mut(), 0, &mut needed) };
    let mut buf = vec![0u8; needed.max(1)];
    let mut actual = 0usize;
    let rc = unsafe { f(cert, buf.as_mut_ptr(), buf.len(), &mut actual) };
    assert_eq!(rc, GMCRYPTO_OK);
    buf.truncate(actual);
    buf
}

#[test]
fn x509_ffi_accessors_match_core() {
    // Both fixtures: the CA carries the real serial pad-strip pin (13 wire
    // bytes -> 12 stripped, high bit set); the leaf serial was never padded.
    for der in [X509_CA_DER, X509_LEAF_DER] {
        let core = Certificate::from_der(der).unwrap();
        let cert = x509_parse(der);
        assert_eq!(
            x509_copy_out_helper(gmcrypto_x509_certificate_tbs_raw, cert),
            core.tbs_raw()
        );
        assert_eq!(
            x509_copy_out_helper(gmcrypto_x509_certificate_serial_raw, cert),
            core.serial_raw()
        );
        assert_eq!(
            x509_copy_out_helper(gmcrypto_x509_certificate_issuer_raw, cert),
            core.issuer_raw()
        );
        assert_eq!(
            x509_copy_out_helper(gmcrypto_x509_certificate_subject_raw, cert),
            core.subject_raw()
        );
        // gmssl emits v3 extensions — present, non-empty, byte-equal.
        let ext = x509_copy_out_helper(gmcrypto_x509_certificate_extensions_raw, cert);
        assert!(!ext.is_empty());
        assert_eq!(ext, core.extensions_raw().unwrap());
        unsafe { gmcrypto_x509_certificate_free(cert) };
    }
    // The pad-strip pin through the ABI (mirrors the v1.3 core KAT).
    let ca = x509_parse(X509_CA_DER);
    let serial = x509_copy_out_helper(gmcrypto_x509_certificate_serial_raw, ca);
    assert_eq!(serial.len(), 12);
    assert_ne!(serial[0] & 0x80, 0, "stripped first byte has the high bit");
    unsafe { gmcrypto_x509_certificate_free(ca) };
}

/// Q4.6: surgically remove the `[3]` extensions block from the leaf and
/// patch the two enclosing SEQUENCE lengths. The now-invalid signature is
/// irrelevant — `from_der` never verifies.
fn leaf_without_extensions() -> Vec<u8> {
    let core = Certificate::from_der(X509_LEAF_DER).unwrap();
    let ext_seq = core.extensions_raw().unwrap();
    let pos = X509_LEAF_DER
        .windows(ext_seq.len())
        .position(|w| w == ext_seq)
        .unwrap();
    // The [3] EXPLICIT wrapper (0xA3 + DER length) directly precedes it.
    let wrap_start = if X509_LEAF_DER[pos - 2] == 0xA3 {
        pos - 2
    } else if X509_LEAF_DER[pos - 3] == 0xA3 && X509_LEAF_DER[pos - 2] == 0x81 {
        pos - 3
    } else {
        assert_eq!(X509_LEAF_DER[pos - 4], 0xA3, "unexpected [3] length form");
        pos - 4
    };
    let removed = (pos + ext_seq.len()) - wrap_start;
    let mut t = X509_LEAF_DER[..wrap_start].to_vec();
    t.extend_from_slice(&X509_LEAF_DER[pos + ext_seq.len()..]);
    // Patch the outer Certificate SEQUENCE and tbs SEQUENCE lengths (both
    // long-form 0x82 for these fixtures; asserted).
    assert_eq!((t[0], t[1]), (0x30, 0x82));
    assert_eq!((t[4], t[5]), (0x30, 0x82));
    for len_at in [2usize, 6] {
        let old = (usize::from(t[len_at]) << 8) | usize::from(t[len_at + 1]);
        let new = old - removed;
        t[len_at] = u8::try_from(new >> 8).unwrap();
        t[len_at + 1] = u8::try_from(new & 0xff).unwrap();
    }
    t
}

#[test]
fn x509_ffi_extensions_absent_reports_zero_len() {
    let stripped = leaf_without_extensions();
    // Core agrees the surgery produced an extensionless parse.
    assert!(
        Certificate::from_der(&stripped)
            .expect("stripped leaf must still parse")
            .extensions_raw()
            .is_none()
    );
    let cert = x509_parse(&stripped);
    let mut buf = [0u8; 4];
    let mut actual = 7usize;
    let rc = unsafe {
        gmcrypto_x509_certificate_extensions_raw(cert, buf.as_mut_ptr(), buf.len(), &mut actual)
    };
    assert_eq!(rc, GMCRYPTO_OK);
    assert_eq!(actual, 0, "absent extensions == actual_len 0 (Q4.6)");
    unsafe { gmcrypto_x509_certificate_free(cert) };
}

#[test]
fn x509_ffi_rejects_malformed_der_and_null_args() {
    for bad in [
        &[][..],
        &[0x30, 0x00][..],
        &X509_LEAF_DER[..X509_LEAF_DER.len() - 1],
    ] {
        let p = unsafe { gmcrypto_x509_certificate_from_der(bad.as_ptr(), bad.len()) };
        assert!(p.is_null());
    }
    assert!(unsafe { gmcrypto_x509_certificate_from_der(ptr::null(), 7) }.is_null());
    // NULL-argument sweep on the copy-out shape: NULL cert and NULL
    // out_actual_len both collapse to the single error.
    let mut buf = [0u8; 64];
    let mut actual = 0usize;
    assert_eq!(
        unsafe {
            gmcrypto_x509_certificate_serial_raw(
                ptr::null(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut actual,
            )
        },
        GMCRYPTO_ERR
    );
    let cert = x509_parse(X509_LEAF_DER);
    assert_eq!(
        unsafe {
            gmcrypto_x509_certificate_serial_raw(cert, buf.as_mut_ptr(), buf.len(), ptr::null_mut())
        },
        GMCRYPTO_ERR
    );
    unsafe { gmcrypto_x509_certificate_free(cert) };
    // free(NULL) is a no-op.
    unsafe { gmcrypto_x509_certificate_free(ptr::null_mut()) };
}

#[test]
fn x509_ffi_copy_out_too_small_reports_required_len() {
    let cert = x509_parse(X509_CA_DER);
    let mut small = [0u8; 4];
    let mut actual = 0usize;
    let rc = unsafe {
        gmcrypto_x509_certificate_issuer_raw(cert, small.as_mut_ptr(), small.len(), &mut actual)
    };
    assert_eq!(rc, GMCRYPTO_ERR);
    let core = Certificate::from_der(X509_CA_DER).unwrap();
    assert_eq!(actual, core.issuer_raw().len());
    unsafe { gmcrypto_x509_certificate_free(cert) };
}

/// Build a `gmcrypto_sm2_pubkey_t` handle from a fixture certificate's
/// subject key (via the core parse + the existing pubkey FFI).
fn x509_subject_key_handle(der: &[u8]) -> *mut gmcrypto_sm2_pubkey_t {
    let core = Certificate::from_der(der).unwrap();
    let sec1 = core.subject_public_key().to_sec1_uncompressed();
    let key = unsafe { gmcrypto_sm2_pubkey_new(sec1.as_ptr()) };
    assert!(!key.is_null());
    key
}

#[test]
fn x509_ffi_verify_matrix() {
    let ca = x509_parse(X509_CA_DER);
    let leaf = x509_parse(X509_LEAF_DER);
    // Issuer key handles via the existing pubkey FFI, from the core parse.
    let ca_key = x509_subject_key_handle(X509_CA_DER);
    let leaf_key = x509_subject_key_handle(X509_LEAF_DER);

    // CA is self-signed; leaf verifies under the CA key only.
    assert_eq!(
        unsafe { gmcrypto_x509_certificate_verify_signature(ca, ca_key) },
        GMCRYPTO_OK
    );
    assert_eq!(
        unsafe { gmcrypto_x509_certificate_verify_signature(leaf, ca_key) },
        GMCRYPTO_OK
    );
    assert_eq!(
        unsafe { gmcrypto_x509_certificate_verify_signature(leaf, leaf_key) },
        GMCRYPTO_ERR
    );
    // Explicit default ID == id_len 0 == the no-id symbol.
    assert_eq!(
        unsafe {
            gmcrypto_x509_certificate_verify_signature_with_id(
                leaf,
                ca_key,
                b"1234567812345678".as_ptr(),
                16,
            )
        },
        GMCRYPTO_OK
    );
    // Wrong ID fails; NULL args fail.
    assert_eq!(
        unsafe {
            gmcrypto_x509_certificate_verify_signature_with_id(
                leaf,
                ca_key,
                b"WRONG-ID".as_ptr(),
                8,
            )
        },
        GMCRYPTO_ERR
    );
    assert_eq!(
        unsafe { gmcrypto_x509_certificate_verify_signature(ptr::null(), ca_key) },
        GMCRYPTO_ERR
    );
    assert_eq!(
        unsafe { gmcrypto_x509_certificate_verify_signature(leaf, ptr::null()) },
        GMCRYPTO_ERR
    );

    unsafe {
        gmcrypto_sm2_pubkey_free(ca_key);
        gmcrypto_sm2_pubkey_free(leaf_key);
        gmcrypto_x509_certificate_free(ca);
        gmcrypto_x509_certificate_free(leaf);
    }
}

#[test]
fn x509_ffi_tampered_tbs_fails_verify() {
    // Flip one bit inside the tbs span (offset 20 is inside the serial for
    // these fixtures); parse may fail OR verify must fail — never both
    // succeed (the signature covers the exact wire bytes).
    let mut t = X509_LEAF_DER.to_vec();
    t[20] ^= 0x01;
    let cert = unsafe { gmcrypto_x509_certificate_from_der(t.as_ptr(), t.len()) };
    if !cert.is_null() {
        let ca_key = x509_subject_key_handle(X509_CA_DER);
        assert_eq!(
            unsafe { gmcrypto_x509_certificate_verify_signature(cert, ca_key) },
            GMCRYPTO_ERR
        );
        unsafe { gmcrypto_sm2_pubkey_free(ca_key) };
        unsafe { gmcrypto_x509_certificate_free(cert) };
    }
}

#[test]
fn x509_ffi_times_and_self_issued_match_core() {
    let cert = x509_parse(X509_LEAF_DER);
    let core = Certificate::from_der(X509_LEAF_DER).unwrap();

    let mut t = gmcrypto_x509_time_t {
        year: 0,
        month: 0,
        day: 0,
        hour: 0,
        minute: 0,
        second: 0,
    };
    assert_eq!(
        unsafe { gmcrypto_x509_certificate_not_before(cert, &mut t) },
        GMCRYPTO_OK
    );
    let nb = core.not_before();
    assert_eq!(
        (t.year, t.month, t.day, t.hour, t.minute, t.second),
        (nb.year, nb.month, nb.day, nb.hour, nb.minute, nb.second)
    );
    assert_eq!(
        unsafe { gmcrypto_x509_certificate_not_after(cert, &mut t) },
        GMCRYPTO_OK
    );
    let na = core.not_after();
    assert_eq!(
        (t.year, t.month, t.day, t.hour, t.minute, t.second),
        (na.year, na.month, na.day, na.hour, na.minute, na.second)
    );
    assert_eq!(
        unsafe { gmcrypto_x509_certificate_not_before(cert, ptr::null_mut()) },
        GMCRYPTO_ERR
    );

    // Self-issued: out-param + status (Q4.9). Leaf no, CA yes; NULL cert
    // and NULL out-param both ERR with the out-param untouched.
    let mut flag = -1;
    assert_eq!(
        unsafe { gmcrypto_x509_certificate_is_self_issued(cert, &mut flag) },
        GMCRYPTO_OK
    );
    assert_eq!(flag, 0);
    let ca = x509_parse(X509_CA_DER);
    assert_eq!(
        unsafe { gmcrypto_x509_certificate_is_self_issued(ca, &mut flag) },
        GMCRYPTO_OK
    );
    assert_eq!(flag, 1);
    let mut untouched = -1;
    assert_eq!(
        unsafe { gmcrypto_x509_certificate_is_self_issued(ptr::null(), &mut untouched) },
        GMCRYPTO_ERR
    );
    assert_eq!(untouched, -1);
    assert_eq!(
        unsafe { gmcrypto_x509_certificate_is_self_issued(ca, ptr::null_mut()) },
        GMCRYPTO_ERR
    );

    unsafe { gmcrypto_x509_certificate_free(ca) };
    unsafe { gmcrypto_x509_certificate_free(cert) };
}

#[test]
fn x509_ffi_subject_key_handle_composes() {
    let cert = x509_parse(X509_LEAF_DER);
    let key = unsafe { gmcrypto_x509_certificate_subject_public_key(cert) };
    assert!(!key.is_null());
    // SEC1 export through the existing pubkey FFI equals the core's.
    let mut sec1 = [0u8; 65];
    assert_eq!(
        unsafe { gmcrypto_sm2_pubkey_to_sec1_uncompressed(key, sec1.as_mut_ptr()) },
        GMCRYPTO_OK
    );
    let core = Certificate::from_der(X509_LEAF_DER).unwrap();
    assert_eq!(sec1, core.subject_public_key().to_sec1_uncompressed());
    assert!(unsafe { gmcrypto_x509_certificate_subject_public_key(ptr::null()) }.is_null());
    unsafe { gmcrypto_sm2_pubkey_free(key) };
    unsafe { gmcrypto_x509_certificate_free(cert) };
}

// ============================================================
// TLCP toolkit (v1.9) — key schedule, no-confirm KX, record, chain/pair.
// ============================================================

mod tlcp_v1_9 {
    use super::*;
    use gmcrypto_c::{
        gmcrypto_sm2_kx_initiator_derive_unconfirmed, gmcrypto_sm2_kx_initiator_new,
        gmcrypto_sm2_kx_responder_new, gmcrypto_sm2_kx_responder_respond,
        gmcrypto_sm2_kx_responder_respond_unconfirmed,
        gmcrypto_sm2_kx_responder_respond_unconfirmed_with_rng, gmcrypto_tlcp_derive_key_block,
        gmcrypto_tlcp_derive_master_secret, gmcrypto_tlcp_deprotect_cbc,
        gmcrypto_tlcp_deprotect_gcm, gmcrypto_tlcp_finished_verify_data,
        gmcrypto_tlcp_protect_cbc, gmcrypto_tlcp_protect_cbc_with_rng, gmcrypto_tlcp_protect_gcm,
        gmcrypto_tlcp_record_keys_cbc_free, gmcrypto_tlcp_record_keys_cbc_new,
        gmcrypto_tlcp_record_keys_gcm_free, gmcrypto_tlcp_record_keys_gcm_new,
        gmcrypto_tlcp_verify_pair, gmcrypto_x509_certificate_basic_constraints,
        gmcrypto_x509_certificate_key_usage, gmcrypto_x509_certificate_t, gmcrypto_x509_verify_chain,
    };
    use gmcrypto_core::tlcp::key_schedule::{self, TlcpRole};
    use gmcrypto_core::tlcp::record::{self, RecordKeysCbc};

    const ROOT: &[u8] = include_bytes!("../../gmcrypto-core/tests/data/x509_chain_root.der");
    const INT: &[u8] = include_bytes!("../../gmcrypto-core/tests/data/x509_chain_int.der");
    const SIGN: &[u8] = include_bytes!("../../gmcrypto-core/tests/data/x509_chain_sign.der");
    const ENC: &[u8] = include_bytes!("../../gmcrypto-core/tests/data/x509_chain_enc.der");

    // ----- key schedule -----

    #[test]
    fn key_schedule_matches_core() {
        let pm = [0x11u8; 48];
        let cr = [0x22u8; 32];
        let sr = [0x33u8; 32];

        // master secret
        let mut ms = [0u8; 48];
        assert_eq!(
            unsafe {
                gmcrypto_tlcp_derive_master_secret(
                    pm.as_ptr(),
                    cr.as_ptr(),
                    sr.as_ptr(),
                    ms.as_mut_ptr(),
                )
            },
            GMCRYPTO_OK
        );
        let mut core_ms = [0u8; 48];
        key_schedule::derive_master_secret(&pm, &cr, &sr, &mut core_ms);
        assert_eq!(ms, core_ms);

        // key block (128 for CBC, then 40 for GCM)
        for len in [128usize, 40] {
            let mut kb = vec![0u8; len];
            assert_eq!(
                unsafe {
                    gmcrypto_tlcp_derive_key_block(
                        ms.as_ptr(),
                        cr.as_ptr(),
                        sr.as_ptr(),
                        kb.as_mut_ptr(),
                        kb.len(),
                    )
                },
                GMCRYPTO_OK
            );
            let mut core_kb = vec![0u8; len];
            key_schedule::derive_key_block(&ms, &cr, &sr, &mut core_kb);
            assert_eq!(kb, core_kb, "key block len {len}");
        }

        // Finished, both roles — and role-separation.
        let th = [0x44u8; 32];
        let mut client_vd = [0u8; 12];
        let mut server_vd = [0u8; 12];
        assert_eq!(
            unsafe {
                gmcrypto_tlcp_finished_verify_data(ms.as_ptr(), 0, th.as_ptr(), client_vd.as_mut_ptr())
            },
            GMCRYPTO_OK
        );
        assert_eq!(
            unsafe {
                gmcrypto_tlcp_finished_verify_data(ms.as_ptr(), 1, th.as_ptr(), server_vd.as_mut_ptr())
            },
            GMCRYPTO_OK
        );
        let mut core_client = [0u8; 12];
        let mut core_server = [0u8; 12];
        key_schedule::finished_verify_data(&ms, TlcpRole::Client, &th, &mut core_client);
        key_schedule::finished_verify_data(&ms, TlcpRole::Server, &th, &mut core_server);
        assert_eq!(client_vd, core_client);
        assert_eq!(server_vd, core_server);
        assert_ne!(client_vd, server_vd, "role separation");
    }

    #[test]
    fn key_schedule_bad_role_and_null_rejected() {
        let ms = [0u8; 48];
        let th = [0u8; 32];
        let mut vd = [0u8; 12];
        // role = 2 is invalid.
        assert_eq!(
            unsafe { gmcrypto_tlcp_finished_verify_data(ms.as_ptr(), 2, th.as_ptr(), vd.as_mut_ptr()) },
            GMCRYPTO_ERR
        );
        // NULL pre_master.
        let mut out = [0u8; 48];
        assert_eq!(
            unsafe {
                gmcrypto_tlcp_derive_master_secret(
                    ptr::null(),
                    th.as_ptr(),
                    th.as_ptr(),
                    out.as_mut_ptr(),
                )
            },
            GMCRYPTO_ERR
        );
    }

    // ----- no-confirmation SM2-KX -----

    fn free_keys(
        a_priv: *mut gmcrypto_sm2_privkey_t,
        a_pub: *mut gmcrypto_sm2_pubkey_t,
        b_priv: *mut gmcrypto_sm2_privkey_t,
        b_pub: *mut gmcrypto_sm2_pubkey_t,
    ) {
        unsafe {
            gmcrypto_sm2_privkey_free(a_priv);
            gmcrypto_sm2_pubkey_free(a_pub);
            gmcrypto_sm2_privkey_free(b_priv);
            gmcrypto_sm2_pubkey_free(b_pub);
        }
    }

    #[test]
    fn kx_unconfirmed_ffi_handshake_agrees() {
        let (a_priv, a_pub) = fresh_sm2_keys();
        let (b_priv, b_pub) = fresh_sm2_keys();
        let klen = 48usize;
        let mut r_a = [0u8; 65];
        let init = unsafe {
            gmcrypto_sm2_kx_initiator_new(
                a_priv,
                b_pub,
                ptr::null(),
                0,
                ptr::null(),
                0,
                klen,
                r_a.as_mut_ptr(),
            )
        };
        assert!(!init.is_null());
        let resp = unsafe {
            gmcrypto_sm2_kx_responder_new(b_priv, a_pub, ptr::null(), 0, ptr::null(), 0, klen)
        };
        assert!(!resp.is_null());

        let mut r_b = [0u8; 65];
        let mut key_b = vec![0u8; klen];
        assert_eq!(
            unsafe {
                gmcrypto_sm2_kx_responder_respond_unconfirmed(
                    resp,
                    r_a.as_ptr(),
                    r_b.as_mut_ptr(),
                    key_b.as_mut_ptr(),
                )
            },
            GMCRYPTO_OK
        );
        let mut key_a = vec![0u8; klen];
        assert_eq!(
            unsafe {
                gmcrypto_sm2_kx_initiator_derive_unconfirmed(init, r_b.as_ptr(), key_a.as_mut_ptr())
            },
            GMCRYPTO_OK
        );
        assert_eq!(key_a, key_b, "unconfirmed completers agree through the ABI");
        assert_ne!(key_a, vec![0u8; klen]);
        // init + resp were consumed + freed by the completers.
        free_keys(a_priv, a_pub, b_priv, b_pub);
    }

    #[test]
    fn kx_unconfirmed_with_rng_path_agrees() {
        let (a_priv, a_pub) = fresh_sm2_keys();
        let (b_priv, b_pub) = fresh_sm2_keys();
        let klen = 32usize;
        let mut r_a = [0u8; 65];
        let init = unsafe {
            gmcrypto_sm2_kx_initiator_new(
                a_priv,
                b_pub,
                ptr::null(),
                0,
                ptr::null(),
                0,
                klen,
                r_a.as_mut_ptr(),
            )
        };
        let resp = unsafe {
            gmcrypto_sm2_kx_responder_new(b_priv, a_pub, ptr::null(), 0, ptr::null(), 0, klen)
        };
        // _with_rng draws the responder ephemeral from a byte pool.
        let mut rng = ByteRng {
            pool: vec![0x5cu8; 4096],
            cursor: 0,
        };
        let mut r_b = [0u8; 65];
        let mut key_b = vec![0u8; klen];
        assert_eq!(
            unsafe {
                gmcrypto_sm2_kx_responder_respond_unconfirmed_with_rng(
                    resp,
                    r_a.as_ptr(),
                    Some(byte_rng_callback),
                    (&raw mut rng).cast::<core::ffi::c_void>(),
                    r_b.as_mut_ptr(),
                    key_b.as_mut_ptr(),
                )
            },
            GMCRYPTO_OK
        );
        assert!(rng.cursor > 0, "callback used");
        let mut key_a = vec![0u8; klen];
        assert_eq!(
            unsafe {
                gmcrypto_sm2_kx_initiator_derive_unconfirmed(init, r_b.as_ptr(), key_a.as_mut_ptr())
            },
            GMCRYPTO_OK
        );
        assert_eq!(key_a, key_b);
        free_keys(a_priv, a_pub, b_priv, b_pub);
    }

    #[test]
    fn kx_unconfirmed_negatives() {
        // NULL handles.
        let mut out65 = [0u8; 65];
        let mut key = [0u8; 48];
        assert_eq!(
            unsafe {
                gmcrypto_sm2_kx_initiator_derive_unconfirmed(
                    ptr::null_mut(),
                    out65.as_ptr(),
                    key.as_mut_ptr(),
                )
            },
            GMCRYPTO_ERR
        );
        assert_eq!(
            unsafe {
                gmcrypto_sm2_kx_responder_respond_unconfirmed(
                    ptr::null_mut(),
                    out65.as_ptr(),
                    out65.as_mut_ptr(),
                    key.as_mut_ptr(),
                )
            },
            GMCRYPTO_ERR
        );

        // A responder that already ran the CONFIRMED _respond is in Waiting,
        // not Fresh — respond_unconfirmed must single-ERR (and free it).
        let (a_priv, a_pub) = fresh_sm2_keys();
        let (b_priv, b_pub) = fresh_sm2_keys();
        let klen = 48usize;
        let mut r_a = [0u8; 65];
        let init = unsafe {
            gmcrypto_sm2_kx_initiator_new(
                a_priv,
                b_pub,
                ptr::null(),
                0,
                ptr::null(),
                0,
                klen,
                r_a.as_mut_ptr(),
            )
        };
        let resp = unsafe {
            gmcrypto_sm2_kx_responder_new(b_priv, a_pub, ptr::null(), 0, ptr::null(), 0, klen)
        };
        let mut r_b = [0u8; 65];
        let mut s_b = [0u8; 32];
        assert_eq!(
            unsafe {
                gmcrypto_sm2_kx_responder_respond(
                    resp,
                    r_a.as_ptr(),
                    r_b.as_mut_ptr(),
                    s_b.as_mut_ptr(),
                )
            },
            GMCRYPTO_OK
        );
        // Now Waiting → respond_unconfirmed rejects + frees.
        let mut key_b = vec![0u8; klen];
        assert_eq!(
            unsafe {
                gmcrypto_sm2_kx_responder_respond_unconfirmed(
                    resp,
                    r_a.as_ptr(),
                    r_b.as_mut_ptr(),
                    key_b.as_mut_ptr(),
                )
            },
            GMCRYPTO_ERR
        );
        // init still live → abandon it.
        unsafe { gmcrypto_c::gmcrypto_sm2_kx_initiator_free(init) };
        free_keys(a_priv, a_pub, b_priv, b_pub);
    }

    // ----- record protection -----

    fn cbc_carrier(
        block: &[u8; 128],
        role: core::ffi::c_int,
    ) -> *mut gmcrypto_c::gmcrypto_tlcp_record_keys_cbc_t {
        let k = unsafe { gmcrypto_tlcp_record_keys_cbc_new(role, block.as_ptr()) };
        assert!(!k.is_null());
        k
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn record_cbc_protect_round_trips_and_cross_checks_core() {
        let block = [0x11u8; 128];
        let keys = cbc_carrier(&block, 0);
        let core_keys = RecordKeysCbc::from_key_block(TlcpRole::Client, &block);
        let seq = 7u64;
        let ctype = 23u8;
        let version = [0x01u8, 0x01];
        let pt = b"tlcp record over the C ABI";

        // FFI protect (fixed IV via callback) → record core can deprotect.
        let iv = [0xABu8; 16];
        let mut rng = ByteRng {
            pool: iv.to_vec(),
            cursor: 0,
        };
        let mut out = vec![0u8; pt.len() + 16 + 32 + 32];
        let mut out_len = 0usize;
        assert_eq!(
            unsafe {
                gmcrypto_tlcp_protect_cbc_with_rng(
                    keys,
                    seq,
                    ctype,
                    version.as_ptr(),
                    pt.as_ptr(),
                    pt.len(),
                    Some(byte_rng_callback),
                    (&raw mut rng).cast::<core::ffi::c_void>(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut out_len,
                )
            },
            GMCRYPTO_OK
        );
        out.truncate(out_len);
        assert_eq!(&out[..16], &iv, "explicit IV is the callback's bytes");
        let core_pt = record::deprotect_cbc(&core_keys, seq, ctype, version, &out)
            .expect("core deprotects the FFI record");
        assert_eq!(core_pt, pt);

        // FFI deprotect of the FFI record.
        let mut back = vec![0u8; out.len()];
        let mut back_len = 0usize;
        assert_eq!(
            unsafe {
                gmcrypto_tlcp_deprotect_cbc(
                    keys,
                    seq,
                    ctype,
                    version.as_ptr(),
                    out.as_ptr(),
                    out.len(),
                    back.as_mut_ptr(),
                    back.len(),
                    &mut back_len,
                )
            },
            GMCRYPTO_OK
        );
        back.truncate(back_len);
        assert_eq!(back, pt);

        // A core-built record (SysRng IV) deprotects through the FFI too.
        let core_rec = record::protect_cbc(&core_keys, seq, ctype, version, pt, &mut getrandom::SysRng)
            .expect("core protect");
        let mut back2 = vec![0u8; core_rec.len()];
        let mut back2_len = 0usize;
        assert_eq!(
            unsafe {
                gmcrypto_tlcp_deprotect_cbc(
                    keys,
                    seq,
                    ctype,
                    version.as_ptr(),
                    core_rec.as_ptr(),
                    core_rec.len(),
                    back2.as_mut_ptr(),
                    back2.len(),
                    &mut back2_len,
                )
            },
            GMCRYPTO_OK
        );
        back2.truncate(back2_len);
        assert_eq!(back2, pt);

        // The SysRng protect variant also round-trips through FFI deprotect.
        let mut sys_rec = vec![0u8; pt.len() + 16 + 32 + 32];
        let mut sys_len = 0usize;
        assert_eq!(
            unsafe {
                gmcrypto_tlcp_protect_cbc(
                    keys,
                    seq,
                    ctype,
                    version.as_ptr(),
                    pt.as_ptr(),
                    pt.len(),
                    sys_rec.as_mut_ptr(),
                    sys_rec.len(),
                    &mut sys_len,
                )
            },
            GMCRYPTO_OK
        );
        sys_rec.truncate(sys_len);
        let core_back = record::deprotect_cbc(&core_keys, seq, ctype, version, &sys_rec)
            .expect("core deprotects the SysRng FFI record");
        assert_eq!(core_back, pt);

        unsafe { gmcrypto_tlcp_record_keys_cbc_free(keys) };
    }

    #[test]
    fn record_cbc_deprotect_bad_pad_and_bad_mac_both_single_err() {
        let block = [0x22u8; 128];
        let keys = cbc_carrier(&block, 0);
        let core_keys = RecordKeysCbc::from_key_block(TlcpRole::Client, &block);
        let seq = 5u64;
        let ctype = 23u8;
        let version = [0x01u8, 0x01];
        let pt = b"oracle indistinguishability";
        let record = record::protect_cbc(&core_keys, seq, ctype, version, pt, &mut getrandom::SysRng)
            .expect("protect");

        // (a) bad-pad leg: flip the LAST ciphertext byte → corrupt final block.
        let mut bad_pad = record.clone();
        *bad_pad.last_mut().unwrap() ^= 0x01;

        // (b) valid-pad-bad-MAC leg: deprotect with a DIFFERENT seq. The body
        // decrypts to the identical valid padding; only the MAC-over-header
        // (which includes seq) mismatches — the robust valid-pad construction.
        let bad_mac = record; // deprotected below with seq + 1.

        let mut out = vec![0xCCu8; 4096];
        for (rec, dseq, label) in [
            (&bad_pad, seq, "bad-pad"),
            (&bad_mac, seq + 1, "valid-pad-bad-MAC"),
        ] {
            let sentinel = 0xDEAD_BEEFusize;
            let mut out_len = sentinel;
            let before = out.clone();
            let rc = unsafe {
                gmcrypto_tlcp_deprotect_cbc(
                    keys,
                    dseq,
                    ctype,
                    version.as_ptr(),
                    rec.as_ptr(),
                    rec.len(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut out_len,
                )
            };
            assert_eq!(rc, GMCRYPTO_ERR, "{label} → single ERR");
            assert_eq!(out_len, sentinel, "{label}: out_actual_len untouched (not zeroed)");
            assert_eq!(out, before, "{label}: output buffer untouched (no plaintext leaked)");
        }
        unsafe { gmcrypto_tlcp_record_keys_cbc_free(keys) };
    }

    #[test]
    fn record_gcm_round_trip_and_tamper() {
        let block = [0x33u8; 40];
        let keys = unsafe { gmcrypto_tlcp_record_keys_gcm_new(0, block.as_ptr()) };
        assert!(!keys.is_null());
        let seq = 9u64;
        let ctype = 23u8;
        let version = [0x01u8, 0x01];
        let pt = b"gcm record via the C ABI";
        let mut rec = vec![0u8; pt.len() + 8 + 16];
        let mut rec_len = 0usize;
        assert_eq!(
            unsafe {
                gmcrypto_tlcp_protect_gcm(
                    keys,
                    seq,
                    ctype,
                    version.as_ptr(),
                    pt.as_ptr(),
                    pt.len(),
                    rec.as_mut_ptr(),
                    rec.len(),
                    &mut rec_len,
                )
            },
            GMCRYPTO_OK
        );
        rec.truncate(rec_len);

        let mut back = vec![0u8; rec.len()];
        let mut back_len = 0usize;
        assert_eq!(
            unsafe {
                gmcrypto_tlcp_deprotect_gcm(
                    keys,
                    seq,
                    ctype,
                    version.as_ptr(),
                    rec.as_ptr(),
                    rec.len(),
                    back.as_mut_ptr(),
                    back.len(),
                    &mut back_len,
                )
            },
            GMCRYPTO_OK
        );
        back.truncate(back_len);
        assert_eq!(back, pt);

        // Tamper the tag → single ERR.
        let mut tampered = rec.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        let mut out = vec![0u8; rec.len()];
        let mut out_len = 0usize;
        assert_eq!(
            unsafe {
                gmcrypto_tlcp_deprotect_gcm(
                    keys,
                    seq,
                    ctype,
                    version.as_ptr(),
                    tampered.as_ptr(),
                    tampered.len(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut out_len,
                )
            },
            GMCRYPTO_ERR
        );
        unsafe { gmcrypto_tlcp_record_keys_gcm_free(keys) };
    }

    #[test]
    fn record_keys_new_rejects_bad_role_and_null() {
        let block = [0u8; 128];
        assert!(unsafe { gmcrypto_tlcp_record_keys_cbc_new(2, block.as_ptr()) }.is_null());
        assert!(unsafe { gmcrypto_tlcp_record_keys_cbc_new(0, ptr::null()) }.is_null());
        // free(NULL) is safe.
        unsafe { gmcrypto_tlcp_record_keys_cbc_free(ptr::null_mut()) };
        unsafe { gmcrypto_tlcp_record_keys_gcm_free(ptr::null_mut()) };
    }

    // ----- chain / pair verification -----

    fn handle(der: &[u8]) -> *mut gmcrypto_x509_certificate_t {
        x509_parse(der)
    }

    #[test]
    fn verify_chain_through_abi_matches_core() {
        let sign = handle(SIGN);
        let int = handle(INT);
        let root = handle(ROOT);
        let chain = [sign.cast_const(), int.cast_const()];
        let anchors = [root.cast_const()];

        let mut verified = -1;
        assert_eq!(
            unsafe {
                gmcrypto_x509_verify_chain(
                    chain.as_ptr(),
                    chain.len(),
                    anchors.as_ptr(),
                    anchors.len(),
                    ptr::null(),
                    &mut verified,
                )
            },
            GMCRYPTO_OK
        );
        assert_eq!(verified, 1);
        // == core
        assert!(gmcrypto_core::x509::verify_chain(
            &[
                Certificate::from_der(SIGN).unwrap(),
                Certificate::from_der(INT).unwrap(),
            ],
            &[Certificate::from_der(ROOT).unwrap()],
            None,
        ));

        // Wrong anchor (the intermediate is not its own anchor) → verdict 0.
        let mut v2 = -1;
        let bad_anchor = [int.cast_const()];
        assert_eq!(
            unsafe {
                gmcrypto_x509_verify_chain(
                    chain.as_ptr(),
                    chain.len(),
                    bad_anchor.as_ptr(),
                    bad_anchor.len(),
                    ptr::null(),
                    &mut v2,
                )
            },
            GMCRYPTO_OK
        );
        assert_eq!(v2, 0, "over-depth/bad-chain is a verdict, not an error");

        for h in [sign, int, root] {
            unsafe { gmcrypto_x509_certificate_free(h) };
        }
    }

    #[test]
    fn verify_chain_null_semantics() {
        let sign = handle(SIGN);
        let chain = [sign.cast_const()];
        // NULL out_verified → ERR.
        assert_eq!(
            unsafe {
                gmcrypto_x509_verify_chain(chain.as_ptr(), 1, chain.as_ptr(), 1, ptr::null(), ptr::null_mut())
            },
            GMCRYPTO_ERR
        );
        // (NULL, 2) → ERR, out_verified untouched.
        let mut verified = 7;
        assert_eq!(
            unsafe {
                gmcrypto_x509_verify_chain(ptr::null(), 2, chain.as_ptr(), 1, ptr::null(), &mut verified)
            },
            GMCRYPTO_ERR
        );
        assert_eq!(verified, 7, "untouched on ERR");
        // A NULL element in an n>0 array → ERR.
        let with_null = [sign.cast_const(), ptr::null()];
        assert_eq!(
            unsafe {
                gmcrypto_x509_verify_chain(
                    with_null.as_ptr(),
                    2,
                    chain.as_ptr(),
                    1,
                    ptr::null(),
                    &mut verified,
                )
            },
            GMCRYPTO_ERR
        );
        // (NULL, 0) chain → OK + verdict 0 (empty chain does not verify).
        verified = 7;
        assert_eq!(
            unsafe {
                gmcrypto_x509_verify_chain(ptr::null(), 0, chain.as_ptr(), 1, ptr::null(), &mut verified)
            },
            GMCRYPTO_OK
        );
        assert_eq!(verified, 0);
        unsafe { gmcrypto_x509_certificate_free(sign) };
    }

    #[test]
    fn verify_pair_through_abi() {
        let sign = handle(SIGN);
        let enc = handle(ENC);
        let int = handle(INT);
        let root = handle(ROOT);
        let sign_chain = [sign.cast_const(), int.cast_const()];
        let enc_chain = [enc.cast_const(), int.cast_const()];
        let anchors = [root.cast_const()];

        let mut verified = -1;
        assert_eq!(
            unsafe {
                gmcrypto_tlcp_verify_pair(
                    sign_chain.as_ptr(),
                    sign_chain.len(),
                    enc_chain.as_ptr(),
                    enc_chain.len(),
                    anchors.as_ptr(),
                    anchors.len(),
                    ptr::null(),
                    &mut verified,
                )
            },
            GMCRYPTO_OK
        );
        assert_eq!(verified, 1, "real TLCP pair verifies end-to-end");

        // Swapping the roles (enc cert as the sign leaf) breaks role keyUsage.
        let mut v2 = -1;
        let swapped_sign = [enc.cast_const(), int.cast_const()];
        assert_eq!(
            unsafe {
                gmcrypto_tlcp_verify_pair(
                    swapped_sign.as_ptr(),
                    swapped_sign.len(),
                    enc_chain.as_ptr(),
                    enc_chain.len(),
                    anchors.as_ptr(),
                    anchors.len(),
                    ptr::null(),
                    &mut v2,
                )
            },
            GMCRYPTO_OK
        );
        assert_eq!(v2, 0, "enc cert lacks digitalSignature → not a valid sign leaf");

        for h in [sign, enc, int, root] {
            unsafe { gmcrypto_x509_certificate_free(h) };
        }
    }

    #[test]
    fn readers_match_core() {
        let sign = handle(SIGN);
        let int = handle(INT);

        let mut present = -1;
        let mut bits = 0u16;
        assert_eq!(
            unsafe { gmcrypto_x509_certificate_key_usage(sign, &mut present, &mut bits) },
            GMCRYPTO_OK
        );
        assert_eq!(present, 1);
        let core_ku = Certificate::from_der(SIGN).unwrap().key_usage().unwrap();
        assert_eq!(bits, core_ku.bits());
        assert!(bits & 1 == 1, "digitalSignature bit set");

        let mut p2 = -1;
        let mut is_ca = -1;
        let mut has_pl = -1;
        let mut pl = 0u32;
        assert_eq!(
            unsafe {
                gmcrypto_x509_certificate_basic_constraints(int, &mut p2, &mut is_ca, &mut has_pl, &mut pl)
            },
            GMCRYPTO_OK
        );
        assert_eq!(p2, 1);
        assert_eq!(is_ca, 1, "intermediate is a CA");

        // NULL → ERR.
        assert_eq!(
            unsafe { gmcrypto_x509_certificate_key_usage(ptr::null(), &mut present, &mut bits) },
            GMCRYPTO_ERR
        );

        unsafe { gmcrypto_x509_certificate_free(sign) };
        unsafe { gmcrypto_x509_certificate_free(int) };
    }
}
