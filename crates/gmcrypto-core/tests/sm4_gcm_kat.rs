//! v0.8 W2 — SM4-GCM Known-Answer Tests.
//!
//! Cross-validate `sm4::mode_gcm` byte-for-byte against the gmssl
//! 3.1.1 `sm4 -gcm` CLI. The vectors below were generated on
//! 2026-05-15 against gmssl 3.1.1 (`GmSSL` on Homebrew) and committed
//! inline rather than as binary fixtures because they're small (≤ 31
//! bytes each) and reviewability matters.
//!
//! Re-generate (auditor-reproducible):
//!
//! ```text
//! # baseline
//! printf 'Hello, SM4-GCM' > pt.bin
//! gmssl sm4 -gcm -encrypt \
//!   -key 0123456789abcdeffedcba9876543210 \
//!   -iv  000102030405060708090a0b \
//!   -aad 'associated data' \
//!   -in pt.bin -out ct.bin
//! # ct.bin contains ciphertext (14 bytes) ‖ tag (16 bytes).
//! ```
//!
//! See `docs/v0.7-aead-scope.md` Q8.4 for the gmssl-as-KAT-source
//! rationale.
//!
//! This file's tests run under `--features sm4-aead`; the `[[test]]`
//! entry in `Cargo.toml` declares `required-features`.

#![cfg(feature = "sm4-aead")]

use gmcrypto_core::sm4::mode_gcm;

struct GcmVector {
    name: &'static str,
    key: [u8; 16],
    nonce: &'static [u8],
    aad: &'static [u8],
    plaintext: &'static [u8],
    ciphertext: &'static [u8],
    tag: [u8; 16],
}

const KEY_A: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];
const NONCE_12: [u8; 12] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
];

const VECTORS: &[GcmVector] = &[
    GcmVector {
        name: "baseline",
        key: KEY_A,
        nonce: &NONCE_12,
        aad: b"associated data",
        plaintext: b"Hello, SM4-GCM",
        ciphertext: &[
            0x1d, 0x44, 0x74, 0xfd, 0xde, 0x9d, 0x89, 0x4c, 0x29, 0xb4, 0xae, 0xec, 0x98, 0x11,
        ],
        tag: [
            0xa3, 0x05, 0x5d, 0x9b, 0x60, 0xb9, 0x46, 0x4c, 0xaf, 0x60, 0x14, 0xdf, 0x52, 0x62,
            0x70, 0x20,
        ],
    },
    GcmVector {
        name: "empty-pt",
        key: KEY_A,
        nonce: &NONCE_12,
        aad: b"aad-only",
        plaintext: &[],
        ciphertext: &[],
        tag: [
            0x38, 0x51, 0xd0, 0x50, 0x78, 0x36, 0x2a, 0x9b, 0x8e, 0x55, 0x58, 0x17, 0xe8, 0x7a,
            0x4a, 0xca,
        ],
    },
    GcmVector {
        name: "empty-aad",
        key: KEY_A,
        nonce: &NONCE_12,
        aad: &[],
        plaintext: b"Hello",
        ciphertext: &[0x1d, 0x44, 0x74, 0xfd, 0xde],
        tag: [
            0x37, 0x08, 0x04, 0xad, 0x0c, 0xdb, 0xb5, 0x63, 0xea, 0x8e, 0xce, 0xf2, 0xe2, 0x37,
            0xbe, 0x5d,
        ],
    },
    GcmVector {
        name: "short-pt-with-aad",
        key: KEY_A,
        nonce: &NONCE_12,
        aad: b"short",
        plaintext: b"ABCDE",
        ciphertext: &[0x14, 0x63, 0x5b, 0xd5, 0xf4],
        tag: [
            0x36, 0x25, 0x93, 0x11, 0x9a, 0xf9, 0x1e, 0x14, 0xa3, 0x2b, 0xc2, 0x5c, 0x6b, 0x30,
            0x59, 0x9e,
        ],
    },
];

#[test]
fn encrypt_matches_gmssl_vectors() {
    for v in VECTORS {
        let (ct, tag) = mode_gcm::encrypt(&v.key, v.nonce, v.aad, v.plaintext);
        assert_eq!(
            ct, v.ciphertext,
            "ciphertext divergence for scenario {:?}",
            v.name,
        );
        assert_eq!(tag, v.tag, "tag divergence for scenario {:?}", v.name);
    }
}

#[test]
fn decrypt_matches_gmssl_vectors() {
    for v in VECTORS {
        let recovered = mode_gcm::decrypt(&v.key, v.nonce, v.aad, v.ciphertext, &v.tag);
        assert_eq!(
            recovered.as_deref(),
            Some(v.plaintext),
            "decrypt failed for scenario {:?}",
            v.name,
        );
    }
}

/// Single-bit flip in the tag must cause decrypt to return None for
/// every vector.
#[test]
fn tampered_tag_fails_for_all_vectors() {
    for v in VECTORS {
        let mut bad_tag = v.tag;
        bad_tag[0] ^= 0x01;
        assert!(
            mode_gcm::decrypt(&v.key, v.nonce, v.aad, v.ciphertext, &bad_tag).is_none(),
            "tag-tamper not detected for scenario {:?}",
            v.name,
        );
    }
}

/// Single-byte flip in the AAD must cause decrypt to return None.
#[test]
fn tampered_aad_fails() {
    let v = &VECTORS[0]; // "baseline" has non-empty AAD
    let bad_aad = b"different aad val";
    assert!(
        mode_gcm::decrypt(&v.key, v.nonce, bad_aad, v.ciphertext, &v.tag).is_none(),
        "AAD-tamper not detected for baseline",
    );
}

// ---- v0.9 W1: truncated-tag KAT ----
//
// gmssl 3.1.1's `sm4 -gcm` has no tag-length flag — it always emits a
// 16-byte tag. So there is no external oracle for a shorter tag.
// However, NIST SP 800-38D §5.2.1.2 *defines* the truncated tag as
// exactly `MSB_t(full_tag)` — the first `t` bytes of the full 128-bit
// tag. Since `encrypt_matches_gmssl_vectors` above already proves our
// full 16-byte tag is byte-identical to gmssl for every vector, a
// truncated-tag KAT anchored on those same vectors is sound by
// composition: gmssl-validated full tag + spec-defined truncation =
// validated truncated tag. No second oracle is required.

use gmcrypto_core::sm4::mode_gcm::GcmTagLen;

/// `encrypt_with_tag_len` must reproduce the first `t` bytes of every
/// gmssl-validated full tag, for every permitted `t`, with byte-
/// identical ciphertext.
#[test]
fn encrypt_with_tag_len_matches_truncated_gmssl_tag() {
    for v in VECTORS {
        for &t in &[4usize, 8, 12, 13, 14, 15, 16] {
            let tl = GcmTagLen::new(t).unwrap();
            let (ct, tag) = mode_gcm::encrypt_with_tag_len(&v.key, v.nonce, v.aad, v.plaintext, tl);
            assert_eq!(
                ct, v.ciphertext,
                "ciphertext divergence for {:?} at tag_len {t}",
                v.name,
            );
            assert_eq!(
                tag.as_slice(),
                &v.tag[..t],
                "truncated tag != MSB_{t} of gmssl tag for {:?}",
                v.name,
            );
        }
    }
}

/// `decrypt_with_tag_len` round-trips every vector at every permitted
/// truncated length.
#[test]
fn decrypt_with_tag_len_round_trips_every_vector() {
    for v in VECTORS {
        for &t in &[4usize, 8, 12, 13, 14, 15, 16] {
            let truncated = &v.tag[..t];
            let recovered =
                mode_gcm::decrypt_with_tag_len(&v.key, v.nonce, v.aad, v.ciphertext, truncated);
            assert_eq!(
                recovered.as_deref(),
                Some(v.plaintext),
                "decrypt_with_tag_len failed for {:?} at tag_len {t}",
                v.name,
            );
        }
    }
}
