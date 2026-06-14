//! v1.8 — TLCP certificate-PAIR verification KAT over the `GmSSL` fixtures.
//!
//! The sign + enc leaves were issued by one intermediate with one shared
//! subject DN (`CN=gmtest.example`) — a real TLCP double-cert pair (see
//! `tests/data/x509_regen.md`). Needs `tlcp,x509`.
#![cfg(all(feature = "tlcp", feature = "x509"))]

use gmcrypto_core::tlcp::chain::verify_pair;
use gmcrypto_core::x509::{Certificate, X509Time};

const ROOT: &[u8] = include_bytes!("data/x509_chain_root.der");
const INT: &[u8] = include_bytes!("data/x509_chain_int.der");
const SIGN: &[u8] = include_bytes!("data/x509_chain_sign.der");
const ENC: &[u8] = include_bytes!("data/x509_chain_enc.der");

fn parse(der: &[u8]) -> Certificate {
    Certificate::from_der(der).expect("fixture parses")
}

#[test]
fn real_tlcp_pair_verifies() {
    assert!(verify_pair(
        &[parse(SIGN), parse(INT)],
        &[parse(ENC), parse(INT)],
        &[parse(ROOT)],
        None,
    ));
}

#[test]
fn time_inside_and_outside() {
    let sign = parse(SIGN);
    let inside = sign.not_before();
    let after = X509Time {
        year: sign.not_after().year + 5,
        ..sign.not_after()
    };
    assert!(verify_pair(
        &[parse(SIGN), parse(INT)],
        &[parse(ENC), parse(INT)],
        &[parse(ROOT)],
        Some(inside),
    ));
    assert!(!verify_pair(
        &[parse(SIGN), parse(INT)],
        &[parse(ENC), parse(INT)],
        &[parse(ROOT)],
        Some(after),
    ));
}

#[test]
fn missing_anchor_rejected() {
    assert!(!verify_pair(
        &[parse(SIGN), parse(INT)],
        &[parse(ENC), parse(INT)],
        &[],
        None,
    ));
}

#[test]
fn swapped_pair_roles_rejected() {
    // Enc cert in the sign slot: it lacks digitalSignature → role reject.
    assert!(!verify_pair(
        &[parse(ENC), parse(INT)],
        &[parse(SIGN), parse(INT)],
        &[parse(ROOT)],
        None,
    ));
}
