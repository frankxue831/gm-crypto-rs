//! Fuzz target: X.509 chain + TLCP certificate-pair verification (v1.8).
//!
//! Carves the input into big-endian-`u16`-length-prefixed DER blobs, parses
//! each via `Certificate::from_der` (skipping the `None`s), then drives
//! `x509::verify_chain` and `tlcp::chain::verify_pair` over the parsed set in
//! several chain/anchor splittings (with and without a comparison time).
//! Invariant: no panic / no OOM / no hang — every verification collapses to a
//! plain `bool` regardless of how adversarial the certificate set is. The
//! committed seed is the 4 gmssl chain fixtures, length-prefixed, so the
//! success path (a real [sign, enc] pair to a root) is exercised from the
//! first run.
#![no_main]

use gmcrypto_core::tlcp::chain::verify_pair;
use gmcrypto_core::x509::{Certificate, verify_chain};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    let mut certs: Vec<Certificate> = Vec::new();
    while rest.len() >= 2 && certs.len() < 16 {
        let n = ((rest[0] as usize) << 8) | rest[1] as usize;
        let take = n.min(rest.len() - 2);
        if let Some(c) = Certificate::from_der(&rest[2..2 + take]) {
            certs.push(c);
        }
        rest = &rest[2 + take..];
    }
    if certs.is_empty() {
        return;
    }
    let t = Some(certs[0].not_before());

    // Whole list as a chain, with no anchors and self-anchored.
    let _ = verify_chain(&certs, &[], None);
    let _ = verify_chain(&certs, &certs, t);

    // Leaf vs the rest as anchors.
    let (head, tail) = certs.split_at(1);
    let _ = verify_chain(head, tail, None);
    let _ = verify_pair(head, head, tail, t);

    // A two-leg split for the pair primitive.
    if certs.len() >= 2 {
        let (a, b) = certs.split_at(certs.len() / 2);
        let _ = verify_pair(a, b, &certs, None);
    }
});
