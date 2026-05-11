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
    use crypto_bigint::U256;
    use gmcrypto_core::sm2::{Sm2PrivateKey, Sm2PublicKey};

    let d = U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
    let key = Sm2PrivateKey::new(d).expect("valid d");
    let scalar_bytes: [u8; 32] = key.to_sec1_be();
    let pub_bytes: [u8; 65] = Sm2PublicKey::from_point(key.public_key()).to_sec1_uncompressed();

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
    use crypto_bigint::U256;
    use gmcrypto_core::asn1::ciphertext::decode as der_decode;
    use gmcrypto_core::sm2::raw_ciphertext::{C1_LEN, C3_LEN, encode_c1c3c2};
    use gmcrypto_core::sm2::{Sm2PrivateKey, Sm2PublicKey, encrypt as core_encrypt};

    let d = U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
    let key = Sm2PrivateKey::new(d).expect("valid d");
    let pub_key = Sm2PublicKey::from_point(key.public_key());

    let pt = b"legacy ordering";
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
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
    let scalar_bytes: [u8; 32] = key.to_sec1_be();
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
    // v0.4 release-prep PR will bump the version to "0.4.0".
    let v = s.to_str().expect("ASCII version string");
    assert!(
        v == env!("CARGO_PKG_VERSION") || v == "0.4.0",
        "FFI version {v} should track crate version",
    );
}
