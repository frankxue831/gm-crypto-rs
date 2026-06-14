//! v1.8 — X.509 chain-verification KAT over the `GmSSL` 3-level fixtures
//! (root CA → intermediate CA → [sign, enc] leaf pair; see
//! `tests/data/x509_regen.md`). Fixtures regenerate to FRESH keys, so every
//! assertion is structural / relational, never specific key bytes.
#![cfg(feature = "x509")]

use gmcrypto_core::x509::{Certificate, X509Time, verify_chain};

const ROOT: &[u8] = include_bytes!("data/x509_chain_root.der");
const INT: &[u8] = include_bytes!("data/x509_chain_int.der");
const SIGN: &[u8] = include_bytes!("data/x509_chain_sign.der");
const ENC: &[u8] = include_bytes!("data/x509_chain_enc.der");

fn parse(der: &[u8]) -> Certificate {
    Certificate::from_der(der).expect("fixture parses")
}

#[test]
fn readers_match_gmssl_keyusage() {
    let sign = parse(SIGN);
    let ku = sign.key_usage().expect("sign leaf keyUsage");
    assert!(ku.digital_signature() && ku.content_commitment());
    assert!(!ku.key_cert_sign() && !ku.key_encipherment());

    let enc = parse(ENC);
    let eku = enc.key_usage().expect("enc leaf keyUsage");
    assert!(eku.key_encipherment() && eku.data_encipherment() && eku.key_agreement());
    assert!(!eku.digital_signature());

    let int = parse(INT);
    assert!(int.basic_constraints().expect("int basicConstraints").is_ca);
    assert!(int.key_usage().expect("int keyUsage").key_cert_sign());

    // Leaves are not CAs.
    assert!(sign.basic_constraints().is_none_or(|b| !b.is_ca));
    assert!(enc.basic_constraints().is_none_or(|b| !b.is_ca));
}

#[test]
fn sign_and_enc_chains_verify_to_root() {
    assert!(verify_chain(
        &[parse(SIGN), parse(INT)],
        &[parse(ROOT)],
        None
    ));
    assert!(verify_chain(
        &[parse(ENC), parse(INT)],
        &[parse(ROOT)],
        None
    ));
}

#[test]
fn wrong_anchor_rejected() {
    // The intermediate is not its own anchor (its issuer is the root).
    assert!(!verify_chain(
        &[parse(SIGN), parse(INT)],
        &[parse(INT)],
        None
    ));
    // Leaf alone under root: the leaf's issuer is the intermediate, not root.
    assert!(!verify_chain(&[parse(SIGN)], &[parse(ROOT)], None));
    // No anchors at all.
    assert!(!verify_chain(&[parse(SIGN), parse(INT)], &[], None));
}

#[test]
fn time_window_enforced() {
    let sign = parse(SIGN);
    let inside = sign.not_before();
    let after = X509Time {
        year: sign.not_after().year + 5,
        ..sign.not_after()
    };
    assert!(verify_chain(
        &[parse(SIGN), parse(INT)],
        &[parse(ROOT)],
        Some(inside)
    ));
    assert!(!verify_chain(
        &[parse(SIGN), parse(INT)],
        &[parse(ROOT)],
        Some(after)
    ));
}

#[test]
fn tampered_leaf_rejected() {
    // Flip a mid-cert byte: it either fails to parse or fails to verify.
    let mut bad = SIGN.to_vec();
    let mid = bad.len() / 2;
    bad[mid] ^= 0x01;
    // Either it no longer parses, or it parses but no longer verifies.
    let rejected = Certificate::from_der(&bad)
        .is_none_or(|c| !verify_chain(&[c, parse(INT)], &[parse(ROOT)], None));
    assert!(rejected);
}
