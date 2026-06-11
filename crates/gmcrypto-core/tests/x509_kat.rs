//! X.509-with-SM2 KAT + adversarial negatives (v1.3 Tasks 4–6).
//!
//! Fixtures: gmssl 3.1.1-generated self-signed SM2 CA + CA-issued leaf
//! (GM/T 0015 profile, chain-verified by gmssl before commit — see
//! `tests/data/x509_regen.md`). The fixtures regenerate to FRESH keys, so
//! every assertion here is structural / relational, never specific bytes.
#![cfg(feature = "x509")]

use gmcrypto_core::sm2::Sm2PublicKey;
use gmcrypto_core::x509::Certificate;

const CA_DER: &[u8] = include_bytes!("data/x509_ca.der");
const LEAF_DER: &[u8] = include_bytes!("data/x509_leaf.der");
const CA_PUB_SPKI: &[u8] = include_bytes!("data/x509_ca_pub.der");
const LEAF_PUB_SPKI: &[u8] = include_bytes!("data/x509_leaf_pub.der");

fn ca_key() -> Sm2PublicKey {
    gmcrypto_core::spki::decode(CA_PUB_SPKI).expect("CA SPKI fixture")
}
fn leaf_key() -> Sm2PublicKey {
    gmcrypto_core::spki::decode(LEAF_PUB_SPKI).expect("leaf SPKI fixture")
}

/// Locate the trailing signature BIT STRING TLV: it must extend exactly to
/// the end of the certificate. Returns the index of its tag byte.
fn sig_bitstring_offset(der: &[u8]) -> usize {
    for i in (0..der.len()).rev() {
        if der[i] == 0x03
            && i + 2 < der.len()
            && usize::from(der[i + 1]) == der.len() - i - 2
            && der[i + 2] == 0x00
        {
            return i;
        }
    }
    panic!("no trailing BIT STRING found");
}

// ---- Stage 1: parse fields (Task 4) ----

#[test]
fn fixtures_parse_and_expose_fields() {
    let ca = Certificate::from_der(CA_DER).expect("CA fixture must parse");
    let leaf = Certificate::from_der(LEAF_DER).expect("leaf fixture must parse");

    // Subject keys equal the gmssl-exported SPKI keys (no PartialEq on
    // Sm2PublicKey — compare SEC1 bytes).
    assert_eq!(
        ca.subject_public_key().to_sec1_uncompressed(),
        ca_key().to_sec1_uncompressed(),
        "CA subject key != exported key"
    );
    assert_eq!(
        leaf.subject_public_key().to_sec1_uncompressed(),
        leaf_key().to_sec1_uncompressed(),
        "leaf subject key != exported key"
    );

    // Self-issued by raw-Name byte equality: CA yes, leaf no — and the
    // leaf's issuer must equal the CA's subject.
    assert!(ca.is_self_issued());
    assert!(!leaf.is_self_issued());
    assert_eq!(leaf.issuer_raw(), ca.subject_raw());

    for c in [&ca, &leaf] {
        assert!(c.not_before() < c.not_after());
        assert!(!c.serial_raw().is_empty() && c.serial_raw().len() <= 20);
        assert!(c.extensions_raw().is_some(), "gmssl emits v3 extensions");
        assert!(!c.tbs_raw().is_empty());
        assert_eq!(c.tbs_raw()[0], 0x30, "tbs_raw must be the full TLV span");
    }
}

/// The committed CA serial has a 13-byte wire INTEGER content (0x00 pad +
/// 12 high-bit bytes) — `serial_raw` returns the PAD-STRIPPED 12 value
/// bytes (design §5.4 / review finding 3). The leaf serial (12 bytes,
/// no pad) stays 12. Both were pinned at fixture-generation time.
#[test]
fn serial_raw_is_pad_stripped() {
    let ca = Certificate::from_der(CA_DER).unwrap();
    let leaf = Certificate::from_der(LEAF_DER).unwrap();
    assert_eq!(ca.serial_raw().len(), 12);
    assert_eq!(leaf.serial_raw().len(), 12);
    // High bit set on the stripped first byte == the pad was real.
    assert!(ca.serial_raw()[0] & 0x80 != 0);
}

// ---- Stage 2: signature verification (Task 5) ----

#[test]
fn signatures_verify_against_the_right_keys_only() {
    let ca = Certificate::from_der(CA_DER).unwrap();
    let leaf = Certificate::from_der(LEAF_DER).unwrap();

    // Self-signed CA verifies with its own subject key.
    assert!(ca.verify_signature(&ca.subject_public_key()));
    // Leaf verifies against the CA key...
    assert!(leaf.verify_signature(&ca_key()));
    // ...and NOT against its own key,
    assert!(!leaf.verify_signature(&leaf_key()));
    // ...and not under a wrong ID (gmssl used the GM default for all
    // parties — see x509_regen.md).
    assert!(!leaf.verify_signature_with_id(&ca_key(), b"WRONG-ID"));
}

// ---- Stage 3: adversarial negatives (Task 6) ----

/// Every truncation of a valid certificate must collapse to `None` —
/// never panic (the failure-mode invariant on adversarial bytes).
#[test]
fn truncation_sweep_never_panics() {
    for der in [CA_DER, LEAF_DER] {
        for n in 0..der.len() {
            assert!(
                Certificate::from_der(&der[..n]).is_none(),
                "truncation to {n} bytes parsed"
            );
        }
    }
}

/// A trailing byte after the outer SEQUENCE must reject.
#[test]
fn trailing_byte_rejected() {
    let mut padded = LEAF_DER.to_vec();
    padded.push(0x00);
    assert!(Certificate::from_der(&padded).is_none());
}

/// Flip one bit in every tbsCertificate byte: the result must either fail
/// to parse or fail to verify — it must NEVER parse AND verify (the
/// signature covers the exact wire bytes).
#[test]
fn tbs_tamper_sweep() {
    let leaf = LEAF_DER;
    // tbs TLV: outer hdr is 30 82 LL LL (len > 255 for these certs), so
    // tbs starts at 4; its own header yields total length 4 + content.
    assert_eq!(leaf[0], 0x30);
    assert_eq!(leaf[1], 0x82);
    assert_eq!(leaf[4], 0x30);
    let tbs_start = 4;
    let tbs_total = if leaf[5] == 0x82 {
        4 + ((usize::from(leaf[6]) << 8) | usize::from(leaf[7]))
    } else {
        assert_eq!(leaf[5], 0x81);
        3 + usize::from(leaf[6])
    };
    let ca = ca_key();
    for i in tbs_start..tbs_start + tbs_total {
        let mut t = leaf.to_vec();
        t[i] ^= 0x01;
        if let Some(cert) = Certificate::from_der(&t) {
            assert!(
                !cert.verify_signature(&ca),
                "tampered tbs byte {i} still verified"
            );
        }
    }
}

/// Negative serial (high bit forced on the first value byte) must be
/// rejected by the strict INTEGER reader — the deliberate deviation from
/// RFC 5280's "gracefully handle" (review finding M1). Length-preserving.
#[test]
fn negative_serial_rejected() {
    // Locate the serial INTEGER: tbs hdr (4) + [0] version block. The
    // version block is A0 03 02 01 02 (5 bytes); serial tag follows.
    let leaf = LEAF_DER;
    let serial_tag = 4 + 4 + 5; // outer hdr + tbs hdr + version block
    assert_eq!(leaf[serial_tag], 0x02, "fixture layout: serial INTEGER");
    let first_value = serial_tag + 2;
    assert_eq!(
        leaf[first_value] & 0x80,
        0,
        "fixture layout: leaf serial is unpadded/positive"
    );
    let mut t = leaf.to_vec();
    t[first_value] |= 0x80; // now a negative INTEGER
    assert!(
        Certificate::from_der(&t).is_none(),
        "negative serial accepted"
    );
}

/// Patch the signature-algorithm OIDs (inner+outer, and each alone) to
/// a different OID → parse must reject (wrong-OID / outer≠inner).
#[test]
fn signature_oid_swap_rejected() {
    let leaf = LEAF_DER;
    // The sm2-sign-with-sm3 OID content appears exactly twice (inner+outer).
    let oid: &[u8] = &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x75];
    let hits: Vec<usize> = (0..leaf.len() - oid.len())
        .filter(|&i| &leaf[i..i + oid.len()] == oid)
        .collect();
    assert_eq!(hits.len(), 2, "expected inner+outer OID occurrences");
    for patch in [&hits[..1], &hits[1..], &hits[..]] {
        let mut t = leaf.to_vec();
        for &h in patch {
            t[h + oid.len() - 1] ^= 0x01; // still a well-formed OID, wrong value
        }
        assert!(
            Certificate::from_der(&t).is_none(),
            "swapped signature OID accepted (patched {patch:?})"
        );
    }
}

/// Non-zero unused-bits byte in the signature BIT STRING → parse reject.
#[test]
fn nonzero_bitstring_unused_bits_rejected() {
    let leaf = LEAF_DER;
    let bs = sig_bitstring_offset(leaf);
    let mut t = leaf.to_vec();
    t[bs + 2] = 0x01;
    assert!(Certificate::from_der(&t).is_none());
}

/// Garbage in the BIT STRING content PARSES but never VERIFIES — the
/// signature DER semantics live exclusively in `decode_sig` at verify time
/// (design §5.10).
#[test]
fn garbage_signature_parses_but_never_verifies() {
    let leaf = LEAF_DER;
    let bs = sig_bitstring_offset(leaf);
    let mut t = leaf.to_vec();
    for b in &mut t[bs + 3..] {
        *b = 0xAA;
    }
    let cert = Certificate::from_der(&t).expect("BIT STRING shape is still valid");
    assert!(!cert.verify_signature(&ca_key()));
}

/// Non-certificate inputs collapse to `None`, never panic.
#[test]
fn non_certificate_inputs_rejected() {
    assert!(Certificate::from_der(&[]).is_none());
    assert!(Certificate::from_der(&[0x30, 0x00]).is_none());
    assert!(Certificate::from_der(CA_PUB_SPKI).is_none()); // an SPKI, not a cert
    assert!(Certificate::from_der(&[0xff; 64]).is_none());
}
