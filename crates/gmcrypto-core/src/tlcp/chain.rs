//! TLCP (GB/T 38636 §4) certificate-PAIR verification.
//!
//! The [signature, encryption] double-cert profile over the generic
//! [`crate::x509::verify_chain`].
//!
//! **NOT endpoint authentication.** `verify_pair` returning `true` means
//! the sign and enc chains each link to a caller-trusted anchor, each leaf is
//! usable for its TLCP role (keyUsage), neither leaf is a CA, and the two
//! leaves share one identity (non-empty byte-equal subject + the same issuing
//! CA). It does **NOT** mean "this is the server I dialed" — endpoint
//! identity binding is the caller's, permanently (compare
//! [`crate::x509::Certificate::subject_raw`]). See `docs/tlcp-decomposition.md`
//! §4.
//!
//! Needs the `tlcp` **and** `x509` features (a TLCP cert-verifying consumer
//! enables both — the `sm2-key-exchange` / GCM-record "enable both"
//! precedent).

use crate::asn1::reader;
use crate::x509::{Certificate, KeyUsage, X509Time, verify_chain};

fn leaf_is_ca(c: &Certificate) -> bool {
    c.basic_constraints().is_some_and(|bc| bc.is_ca)
}

/// `true` if the subject `Name` is empty (`SEQUENCE` with no content). The
/// `subject_raw` TLV was validated as a SEQUENCE at parse, so a decode
/// failure here also counts as "empty" (fail-closed).
fn empty_subject(c: &Certificate) -> bool {
    reader::read_sequence(c.subject_raw()).is_none_or(|(content, _)| content.is_empty())
}

/// Verify a TLCP server's [signature, encryption] certificate pair.
///
/// `sign_chain` / `enc_chain` are each leaf-first in issuing order (the leaf
/// is the sign / enc cert respectively); `anchors` the trust set; `at_time`
/// the optional validity-window comparison. Single `bool` — never a reason
/// (the failure-mode invariant).
///
/// Returns `true` iff BOTH chains verify ([`verify_chain`]), the sign leaf
/// asserts `digitalSignature`, the enc leaf asserts `keyEncipherment` or
/// `keyAgreement`, neither leaf is a CA, and the two leaves share one
/// identity: a non-empty byte-equal `subject`, a byte-equal `issuer` Name,
/// and — to pin the issuer *key*, not just its Name (W2 review S1) — the
/// **same issuing chain** (equal length, byte-equal `tbs` from index 1 up).
///
/// **⚠ NOT endpoint authentication** — see the module docs. *Whose* identity
/// the pair carries is the caller's decision.
#[must_use]
pub fn verify_pair(
    sign_chain: &[Certificate],
    enc_chain: &[Certificate],
    anchors: &[Certificate],
    at_time: Option<X509Time>,
) -> bool {
    let (Some(s), Some(e)) = (sign_chain.first(), enc_chain.first()) else {
        return false;
    };
    // Role keyUsage — keyUsage MUST be present (`None` ⇒ reject for the role).
    if !s.key_usage().is_some_and(KeyUsage::digital_signature) {
        return false;
    }
    if !e
        .key_usage()
        .is_some_and(|k| k.key_encipherment() || k.key_agreement())
    {
        return false;
    }
    // Leaves must not be CAs.
    if leaf_is_ca(s) || leaf_is_ca(e) {
        return false;
    }
    // Pair binding: non-empty + equal subject + equal issuer Name.
    if empty_subject(s) || s.subject_raw() != e.subject_raw() || s.issuer_raw() != e.issuer_raw() {
        return false;
    }
    // S1 (W2 review): equal issuer Name does not pin the issuer KEY — require
    // the two legs to present the same issuing chain (byte-equal `tbs` from
    // index 1 up), pinning both leaves to one actual CA cert. Vacuous when
    // both legs are length-1 (the documented same-DN-anchor residual).
    if sign_chain.len() != enc_chain.len()
        || sign_chain[1..]
            .iter()
            .zip(&enc_chain[1..])
            .any(|(a, b)| a.tbs_raw() != b.tbs_raw())
    {
        return false;
    }
    verify_chain(sign_chain, anchors, at_time) && verify_chain(enc_chain, anchors, at_time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::test_support::{bc_ext, cert, key, ku_ext, name};
    use alloc::vec;
    use alloc::vec::Vec;

    /// The standard valid pair: root → int → {sign(digitalSignature),
    /// enc(keyEncipherment)} leaves sharing subject `server` + issuer `ca`.
    /// `int_a` / `int_b` are minted identically so their `tbs` is byte-equal
    /// (the S1 same-issuing-chain check passes).
    fn happy() -> (Vec<Certificate>, Vec<Certificate>, Vec<Certificate>) {
        let (rk, ik) = (key(1), key(2));
        let (rn, cn, sn) = (name(b"root"), name(b"ca"), name(b"server"));
        let ca_exts = [ku_ext(&[5], true), bc_ext(true, None, true)].concat();
        let root = cert(&rk, &rn, &rn, &rk.public_key(), &ca_exts);
        let int_a = cert(&rk, &rn, &cn, &ik.public_key(), &ca_exts);
        let int_b = cert(&rk, &rn, &cn, &ik.public_key(), &ca_exts);
        let sign_leaf = cert(&ik, &cn, &sn, &key(3).public_key(), &ku_ext(&[0], true));
        let enc_leaf = cert(&ik, &cn, &sn, &key(4).public_key(), &ku_ext(&[2], true));
        (vec![sign_leaf, int_a], vec![enc_leaf, int_b], vec![root])
    }

    #[test]
    fn valid_pair_verifies() {
        let (s, e, a) = happy();
        assert!(verify_pair(&s, &e, &a, None));
    }

    #[test]
    fn enc_key_agreement_only_accepted() {
        // ECDHE-suite enc cert: keyAgreement only (no keyEncipherment).
        let (rk, ik) = (key(1), key(2));
        let (rn, cn, sn) = (name(b"root"), name(b"ca"), name(b"server"));
        let ca_exts = [ku_ext(&[5], true), bc_ext(true, None, true)].concat();
        let root = cert(&rk, &rn, &rn, &rk.public_key(), &ca_exts);
        let int_a = cert(&rk, &rn, &cn, &ik.public_key(), &ca_exts);
        let int_b = cert(&rk, &rn, &cn, &ik.public_key(), &ca_exts);
        let sign_leaf = cert(&ik, &cn, &sn, &key(3).public_key(), &ku_ext(&[0], true));
        let enc_leaf = cert(&ik, &cn, &sn, &key(4).public_key(), &ku_ext(&[4], true));
        assert!(verify_pair(
            &[sign_leaf, int_a],
            &[enc_leaf, int_b],
            &[root],
            None
        ));
    }

    #[test]
    fn sign_leaf_without_digital_signature_rejected() {
        let (rk, ik) = (key(1), key(2));
        let (rn, cn, sn) = (name(b"root"), name(b"ca"), name(b"server"));
        let ca_exts = [ku_ext(&[5], true), bc_ext(true, None, true)].concat();
        let root = cert(&rk, &rn, &rn, &rk.public_key(), &ca_exts);
        let int_a = cert(&rk, &rn, &cn, &ik.public_key(), &ca_exts);
        let int_b = cert(&rk, &rn, &cn, &ik.public_key(), &ca_exts);
        // sign leaf asserts keyEncipherment, NOT digitalSignature.
        let sign_leaf = cert(&ik, &cn, &sn, &key(3).public_key(), &ku_ext(&[2], true));
        let enc_leaf = cert(&ik, &cn, &sn, &key(4).public_key(), &ku_ext(&[2], true));
        assert!(!verify_pair(
            &[sign_leaf, int_a],
            &[enc_leaf, int_b],
            &[root],
            None
        ));
    }

    #[test]
    fn enc_leaf_without_enc_bits_rejected() {
        let (rk, ik) = (key(1), key(2));
        let (rn, cn, sn) = (name(b"root"), name(b"ca"), name(b"server"));
        let ca_exts = [ku_ext(&[5], true), bc_ext(true, None, true)].concat();
        let root = cert(&rk, &rn, &rn, &rk.public_key(), &ca_exts);
        let int_a = cert(&rk, &rn, &cn, &ik.public_key(), &ca_exts);
        let int_b = cert(&rk, &rn, &cn, &ik.public_key(), &ca_exts);
        let sign_leaf = cert(&ik, &cn, &sn, &key(3).public_key(), &ku_ext(&[0], true));
        // enc leaf asserts digitalSignature only — no keyEncipherment/keyAgreement.
        let enc_leaf = cert(&ik, &cn, &sn, &key(4).public_key(), &ku_ext(&[0], true));
        assert!(!verify_pair(
            &[sign_leaf, int_a],
            &[enc_leaf, int_b],
            &[root],
            None
        ));
    }

    #[test]
    fn leaf_is_ca_rejected() {
        let (rk, ik) = (key(1), key(2));
        let (rn, cn, sn) = (name(b"root"), name(b"ca"), name(b"server"));
        let ca_exts = [ku_ext(&[5], true), bc_ext(true, None, true)].concat();
        let root = cert(&rk, &rn, &rn, &rk.public_key(), &ca_exts);
        let int_a = cert(&rk, &rn, &cn, &ik.public_key(), &ca_exts);
        let int_b = cert(&rk, &rn, &cn, &ik.public_key(), &ca_exts);
        // sign leaf carries basicConstraints CA=TRUE.
        let sign_exts = [ku_ext(&[0], true), bc_ext(true, None, true)].concat();
        let sign_leaf = cert(&ik, &cn, &sn, &key(3).public_key(), &sign_exts);
        let enc_leaf = cert(&ik, &cn, &sn, &key(4).public_key(), &ku_ext(&[2], true));
        assert!(!verify_pair(
            &[sign_leaf, int_a],
            &[enc_leaf, int_b],
            &[root],
            None
        ));
    }

    #[test]
    fn empty_subject_rejected() {
        let (rk, ik) = (key(1), key(2));
        let (rn, cn, empty) = (name(b"root"), name(b"ca"), name(b""));
        let ca_exts = [ku_ext(&[5], true), bc_ext(true, None, true)].concat();
        let root = cert(&rk, &rn, &rn, &rk.public_key(), &ca_exts);
        let int_a = cert(&rk, &rn, &cn, &ik.public_key(), &ca_exts);
        let int_b = cert(&rk, &rn, &cn, &ik.public_key(), &ca_exts);
        let sign_leaf = cert(&ik, &cn, &empty, &key(3).public_key(), &ku_ext(&[0], true));
        let enc_leaf = cert(&ik, &cn, &empty, &key(4).public_key(), &ku_ext(&[2], true));
        assert!(!verify_pair(
            &[sign_leaf, int_a],
            &[enc_leaf, int_b],
            &[root],
            None
        ));
    }

    #[test]
    fn different_subject_rejected() {
        let (rk, ik) = (key(1), key(2));
        let (rn, cn) = (name(b"root"), name(b"ca"));
        let ca_exts = [ku_ext(&[5], true), bc_ext(true, None, true)].concat();
        let root = cert(&rk, &rn, &rn, &rk.public_key(), &ca_exts);
        let int_a = cert(&rk, &rn, &cn, &ik.public_key(), &ca_exts);
        let int_b = cert(&rk, &rn, &cn, &ik.public_key(), &ca_exts);
        let sign_leaf = cert(
            &ik,
            &cn,
            &name(b"alice"),
            &key(3).public_key(),
            &ku_ext(&[0], true),
        );
        let enc_leaf = cert(
            &ik,
            &cn,
            &name(b"bob"),
            &key(4).public_key(),
            &ku_ext(&[2], true),
        );
        assert!(!verify_pair(
            &[sign_leaf, int_a],
            &[enc_leaf, int_b],
            &[root],
            None
        ));
    }

    #[test]
    fn s1_cross_ca_same_name_rejected() {
        // Two CAs share the Name "ca" but have DIFFERENT keys; both chain to
        // root. Leaves share subject + issuer-Name, but the issuing certs
        // (int_a vs int_b) have different tbs → S1 check rejects.
        let rk = key(1);
        let (ca_a, ca_b) = (key(2), key(8));
        let (rn, cn, sn) = (name(b"root"), name(b"ca"), name(b"server"));
        let ca_exts = [ku_ext(&[5], true), bc_ext(true, None, true)].concat();
        let root = cert(&rk, &rn, &rn, &rk.public_key(), &ca_exts);
        let int_a = cert(&rk, &rn, &cn, &ca_a.public_key(), &ca_exts);
        let int_b = cert(&rk, &rn, &cn, &ca_b.public_key(), &ca_exts);
        let sign_leaf = cert(&ca_a, &cn, &sn, &key(3).public_key(), &ku_ext(&[0], true));
        let enc_leaf = cert(&ca_b, &cn, &sn, &key(4).public_key(), &ku_ext(&[2], true));
        assert!(!verify_pair(
            &[sign_leaf, int_a],
            &[enc_leaf, int_b],
            &[root],
            None
        ));
    }
}
