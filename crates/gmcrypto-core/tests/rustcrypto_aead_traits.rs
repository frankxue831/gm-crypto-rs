//! v1.11 — `RustCrypto` `aead` 0.6 trait-surface tests for SM4-GCM / SM4-CCM.
//!
//! Gated on `aead-traits` via a dedicated `[[test]]` target (Q11.10): folding
//! these into `rustcrypto_traits.rs` would widen that target's
//! `required-features` and silently unwire its existing CI leg.
//!
//! The premise under test is that the trait path is a **thin wrapper** — it must
//! reproduce the inherent `mode_gcm` / `mode_ccm` output byte-for-byte, and the
//! same gmssl-/OpenSSL-derived KAT vectors those modules are pinned to. The
//! wrappers add no cryptography, so anything that diverges here is a wrapper bug.
//!
//! UFCS throughout: inherent method names collide with trait method names once
//! both are in scope (the standing `CLAUDE.md` gotcha).

use aead::array::typenum::Unsigned;
use aead::consts::{U7, U12, U13, U16};
use aead::{Aead, AeadCore, AeadInOut, KeyInit, Payload, TagPosition};
use gmcrypto_core::sm4::mode_ccm;
use gmcrypto_core::sm4::mode_gcm;
use gmcrypto_core::sm4::{Sm4Ccm, Sm4Gcm};

/// gmssl 3.1.1 `sm4 -gcm` "baseline" vector, shared with `sm4_gcm_kat.rs`.
const KEY_A: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];
const NONCE_12: [u8; 12] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
];
const GCM_AAD: &[u8] = b"associated data";
const GCM_PT: &[u8] = b"Hello, SM4-GCM";
const GCM_CT: [u8; 14] = [
    0x1d, 0x44, 0x74, 0xfd, 0xde, 0x9d, 0x89, 0x4c, 0x29, 0xb4, 0xae, 0xec, 0x98, 0x11,
];
const GCM_TAG: [u8; 16] = [
    0xa3, 0x05, 0x5d, 0x9b, 0x60, 0xb9, 0x46, 0x4c, 0xaf, 0x60, 0x14, 0xdf, 0x52, 0x62, 0x70, 0x20,
];

fn gcm() -> Sm4Gcm {
    <Sm4Gcm as KeyInit>::new_from_slice(&KEY_A).expect("16-byte key")
}

// ---------------------------------------------------------------- GCM: KATs

/// The trait's postfix-`Aead::encrypt` must reproduce the gmssl KAT as `ct‖tag`.
#[test]
fn gcm_aead_encrypt_matches_gmssl_kat() {
    let out = Aead::encrypt(
        &gcm(),
        &NONCE_12.into(),
        Payload {
            msg: GCM_PT,
            aad: GCM_AAD,
        },
    )
    .expect("encrypt");

    let mut want = GCM_CT.to_vec();
    want.extend_from_slice(&GCM_TAG);
    assert_eq!(out, want, "trait ct‖tag must equal the gmssl KAT");
}

#[test]
fn gcm_aead_decrypt_recovers_kat_plaintext() {
    let mut wire = GCM_CT.to_vec();
    wire.extend_from_slice(&GCM_TAG);

    let pt = Aead::decrypt(
        &gcm(),
        &NONCE_12.into(),
        Payload {
            msg: &wire,
            aad: GCM_AAD,
        },
    )
    .expect("decrypt");

    assert_eq!(pt, GCM_PT);
}

#[test]
fn gcm_trait_surface_declares_the_canonical_profile() {
    assert_eq!(<Sm4Gcm as AeadCore>::NonceSize::USIZE, 12);
    assert_eq!(<Sm4Gcm as AeadCore>::TagSize::USIZE, 16);
    assert!(matches!(
        <Sm4Gcm as AeadCore>::TAG_POSITION,
        TagPosition::Postfix
    ));
}

// -------------------------------------------------- GCM: differential vs core

/// The whole assurance premise: the trait path is the native path.
#[test]
fn gcm_trait_matches_mode_gcm_including_empty_edges() {
    for (pt, aad) in [
        (GCM_PT, GCM_AAD),
        (&b""[..], GCM_AAD),
        (GCM_PT, &b""[..]),
        (&b""[..], &b""[..]),
    ] {
        let (want_ct, want_tag) =
            mode_gcm::encrypt(&KEY_A, &NONCE_12, aad, pt).expect("native encrypt");

        let got = Aead::encrypt(&gcm(), &NONCE_12.into(), Payload { msg: pt, aad })
            .expect("trait encrypt");

        let mut want = want_ct.clone();
        want.extend_from_slice(&want_tag);
        assert_eq!(got, want, "pt={} aad={}", pt.len(), aad.len());

        // ...and the trait must decrypt what the native path produced.
        let back = Aead::decrypt(&gcm(), &NONCE_12.into(), Payload { msg: &want, aad })
            .expect("trait decrypt of native output");
        assert_eq!(back, pt);
    }
}

/// Detached inout: encrypt into a separate out-buffer, tag returned separately.
#[test]
fn gcm_inout_detached_matches_native() {
    use aead::inout::InOutBuf;

    let mut buf = GCM_PT.to_vec();
    let tag = AeadInOut::encrypt_inout_detached(
        &gcm(),
        &NONCE_12.into(),
        GCM_AAD,
        InOutBuf::from(&mut buf[..]),
    )
    .expect("inout encrypt");

    assert_eq!(buf, GCM_CT, "in-place ciphertext");
    assert_eq!(tag.as_slice(), &GCM_TAG, "detached tag");

    AeadInOut::decrypt_inout_detached(
        &gcm(),
        &NONCE_12.into(),
        GCM_AAD,
        InOutBuf::from(&mut buf[..]),
        &tag,
    )
    .expect("inout decrypt");
    assert_eq!(buf, GCM_PT, "recovered plaintext");
}

/// The provided `Buffer`-based methods, which we get free from `AeadInOut`.
#[test]
fn gcm_in_place_roundtrips_a_vec() {
    let mut buf = GCM_PT.to_vec();
    AeadInOut::encrypt_in_place(&gcm(), &NONCE_12.into(), GCM_AAD, &mut buf).expect("encrypt");

    let mut want = GCM_CT.to_vec();
    want.extend_from_slice(&GCM_TAG);
    assert_eq!(buf, want, "postfix tag appended in place");

    AeadInOut::decrypt_in_place(&gcm(), &NONCE_12.into(), GCM_AAD, &mut buf).expect("decrypt");
    assert_eq!(buf, GCM_PT);
}

// ------------------------------------------------------------ GCM: negatives

#[test]
fn gcm_rejects_tampered_ciphertext_tag_and_aad() {
    let mut wire = GCM_CT.to_vec();
    wire.extend_from_slice(&GCM_TAG);

    // Tampered ciphertext byte.
    let mut bad_ct = wire.clone();
    bad_ct[0] ^= 0x01;
    assert!(
        Aead::decrypt(
            &gcm(),
            &NONCE_12.into(),
            Payload {
                msg: &bad_ct,
                aad: GCM_AAD
            }
        )
        .is_err(),
        "flipped ciphertext bit must fail"
    );

    // Tampered tag byte.
    let mut bad_tag = wire.clone();
    let last = bad_tag.len() - 1;
    bad_tag[last] ^= 0x01;
    assert!(
        Aead::decrypt(
            &gcm(),
            &NONCE_12.into(),
            Payload {
                msg: &bad_tag,
                aad: GCM_AAD
            }
        )
        .is_err(),
        "flipped tag bit must fail"
    );

    // Wrong AAD.
    assert!(
        Aead::decrypt(
            &gcm(),
            &NONCE_12.into(),
            Payload {
                msg: &wire,
                aad: b"wrong aad"
            }
        )
        .is_err(),
        "wrong aad must fail"
    );
}

#[test]
fn gcm_rejects_ciphertext_shorter_than_the_tag() {
    let short = [0u8; 4];
    assert!(
        Aead::decrypt(
            &gcm(),
            &NONCE_12.into(),
            Payload {
                msg: &short,
                aad: GCM_AAD
            }
        )
        .is_err(),
        "a wire shorter than one tag cannot be valid"
    );
}

#[test]
fn key_init_rejects_wrong_length_keys() {
    assert!(<Sm4Gcm as KeyInit>::new_from_slice(&[0u8; 15]).is_err());
    assert!(<Sm4Gcm as KeyInit>::new_from_slice(&[0u8; 17]).is_err());
    assert!(<Sm4Ccm as KeyInit>::new_from_slice(&[0u8; 15]).is_err());
}

// ---------------------------------------------------------------- CCM

#[test]
fn ccm_default_profile_matches_mode_ccm() {
    let cipher = <Sm4Ccm as KeyInit>::new_from_slice(&KEY_A).expect("key");
    let pt = b"Hello, SM4-CCM";
    let aad = b"associated data";

    let want = mode_ccm::encrypt(&KEY_A, &NONCE_12, aad, pt, 16).expect("native encrypt");
    let got = Aead::encrypt(&cipher, &NONCE_12.into(), Payload { msg: pt, aad }).expect("trait");

    assert_eq!(got, want, "trait ct‖tag == native ct‖tag");

    let back =
        Aead::decrypt(&cipher, &NONCE_12.into(), Payload { msg: &got, aad }).expect("decrypt");
    assert_eq!(back, pt);
}

#[test]
fn ccm_default_profile_is_tag16_nonce12() {
    assert_eq!(<Sm4Ccm as AeadCore>::NonceSize::USIZE, 12);
    assert_eq!(<Sm4Ccm as AeadCore>::TagSize::USIZE, 16);
    assert!(matches!(
        <Sm4Ccm as AeadCore>::TAG_POSITION,
        TagPosition::Postfix
    ));
}

/// The parameterization is the point of Q11.2: corners of the (M, N) grid must
/// each agree with the native call at that tag length and nonce length.
#[test]
fn ccm_parameter_corners_match_mode_ccm() {
    let pt = b"parameterized";
    let aad = b"aad";
    let nonce7 = [0u8; 7];
    let nonce13 = [0x0au8; 13];

    // (tag 4, nonce 7)
    let c47 = <Sm4Ccm<aead::consts::U4, U7> as KeyInit>::new_from_slice(&KEY_A).unwrap();
    let want = mode_ccm::encrypt(&KEY_A, &nonce7, aad, pt, 4).unwrap();
    let got = Aead::encrypt(&c47, &nonce7.into(), Payload { msg: pt, aad }).unwrap();
    assert_eq!(got, want, "tag=4 nonce=7");

    // (tag 16, nonce 13)
    let c1613 = <Sm4Ccm<U16, U13> as KeyInit>::new_from_slice(&KEY_A).unwrap();
    let want = mode_ccm::encrypt(&KEY_A, &nonce13, aad, pt, 16).unwrap();
    let got = Aead::encrypt(&c1613, &nonce13.into(), Payload { msg: pt, aad }).unwrap();
    assert_eq!(got, want, "tag=16 nonce=13");

    // (tag 8, nonce 12) round-trip through the trait only.
    let c812 = <Sm4Ccm<aead::consts::U8, U12> as KeyInit>::new_from_slice(&KEY_A).unwrap();
    let ct = Aead::encrypt(&c812, &NONCE_12.into(), Payload { msg: pt, aad }).unwrap();
    assert_eq!(ct.len(), pt.len() + 8, "tag=8 overhead");
    let back = Aead::decrypt(&c812, &NONCE_12.into(), Payload { msg: &ct, aad }).unwrap();
    assert_eq!(back, pt);
}

#[test]
fn ccm_rejects_tampered_wire() {
    let cipher = <Sm4Ccm as KeyInit>::new_from_slice(&KEY_A).unwrap();
    let pt = b"tamper me";
    let aad = b"aad";
    let mut wire = Aead::encrypt(&cipher, &NONCE_12.into(), Payload { msg: pt, aad }).unwrap();
    wire[0] ^= 0x01;
    assert!(Aead::decrypt(&cipher, &NONCE_12.into(), Payload { msg: &wire, aad }).is_err());
}

/// CCM's length gate: with a 13-byte nonce, `q = 2`, so the plaintext ceiling is
/// 2^16 − 1. Exceeding it must surface as the same opaque error as any other
/// failure — never a panic, never a distinguishable variant.
#[test]
fn ccm_plaintext_over_the_q_ceiling_errors() {
    let cipher = <Sm4Ccm<U16, U13> as KeyInit>::new_from_slice(&KEY_A).unwrap();
    let nonce13 = [0x0au8; 13];
    let too_long = vec![0u8; 65_536];

    assert!(
        Aead::encrypt(
            &cipher,
            &nonce13.into(),
            Payload {
                msg: &too_long,
                aad: b""
            }
        )
        .is_err(),
        "plaintext above the q=2 ceiling must error, not panic"
    );
}
