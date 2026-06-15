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

use crate::x509::{Certificate, KeyUsage, X509Time, verify_chain_refs};

fn leaf_is_ca(c: &Certificate) -> bool {
    c.basic_constraints().is_some_and(|bc| bc.is_ca)
}

/// Verify a TLCP server's [signature, encryption] certificate pair.
///
/// `sign_chain` / `enc_chain` are each leaf-first in issuing order (the leaf
/// is the sign / enc cert respectively); `anchors` the trust set; `at_time`
/// the optional validity-window comparison. Single `bool` — never a reason
/// (the failure-mode invariant).
///
/// Returns `true` iff BOTH chains verify ([`crate::x509::verify_chain`]), the sign leaf
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
    let sign_chain: alloc::vec::Vec<&Certificate> = sign_chain.iter().collect();
    let enc_chain: alloc::vec::Vec<&Certificate> = enc_chain.iter().collect();
    let anchors: alloc::vec::Vec<&Certificate> = anchors.iter().collect();
    verify_pair_refs(&sign_chain, &enc_chain, &anchors, at_time)
}

/// Reference-slice form of [`verify_pair`] — the canonical implementation.
///
/// **Not public API and not SemVer-covered.** The C FFI shim verifies arrays
/// of certificate handles with it (`Certificate` is not `Clone`). Behaviour is
/// identical to [`verify_pair`].
#[doc(hidden)]
#[must_use]
pub fn verify_pair_refs(
    sign_chain: &[&Certificate],
    enc_chain: &[&Certificate],
    anchors: &[&Certificate],
    at_time: Option<X509Time>,
) -> bool {
    let (Some(&s), Some(&e)) = (sign_chain.first(), enc_chain.first()) else {
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
    if s.subject_is_empty()
        || s.subject_raw() != e.subject_raw()
        || s.issuer_raw() != e.issuer_raw()
    {
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
    verify_chain_refs(sign_chain, anchors, at_time)
        && verify_chain_refs(enc_chain, anchors, at_time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::Sm2PrivateKey;
    use crate::x509::test_support::{bc_ext, cert, key, ku_ext, name};
    use alloc::vec::Vec;

    /// Shared CA scaffold: a root anchor + two intermediates minted
    /// identically (so `int_a`/`int_b` have byte-equal `tbs` — the S1
    /// same-issuing-chain check passes for the normal one-CA case). Each test
    /// builds its own sign/enc leaves from `ik` to vary one property.
    struct Setup {
        ik: Sm2PrivateKey,
        cn: Vec<u8>,
        sn: Vec<u8>,
        root: Certificate,
        int_a: Certificate,
        int_b: Certificate,
    }

    fn setup() -> Setup {
        let (rk, ik) = (key(1), key(2));
        let (rn, cn, sn) = (name(b"root"), name(b"ca"), name(b"server"));
        let ca_exts = [ku_ext(&[5], true), bc_ext(true, None, true)].concat();
        Setup {
            root: cert(&rk, &rn, &rn, &rk.public_key(), &ca_exts),
            int_a: cert(&rk, &rn, &cn, &ik.public_key(), &ca_exts),
            int_b: cert(&rk, &rn, &cn, &ik.public_key(), &ca_exts),
            ik,
            cn,
            sn,
        }
    }

    /// Mint a `server`-subject sign/enc pair varying only their keyUsage,
    /// then assert `verify_pair`'s verdict. Consumes the `Setup`.
    fn assert_pair(s: Setup, sign_exts: &[u8], enc_exts: &[u8], expect: bool) {
        let sign = cert(&s.ik, &s.cn, &s.sn, &key(3).public_key(), sign_exts);
        let enc = cert(&s.ik, &s.cn, &s.sn, &key(4).public_key(), enc_exts);
        assert_eq!(
            verify_pair(&[sign, s.int_a], &[enc, s.int_b], &[s.root], None),
            expect
        );
    }

    #[test]
    fn valid_pair_verifies() {
        assert_pair(setup(), &ku_ext(&[0], true), &ku_ext(&[2], true), true);
    }

    #[test]
    fn enc_key_agreement_only_accepted() {
        // ECDHE-suite enc cert: keyAgreement (bit 4) only, no keyEncipherment.
        assert_pair(setup(), &ku_ext(&[0], true), &ku_ext(&[4], true), true);
    }

    #[test]
    fn sign_leaf_without_digital_signature_rejected() {
        // sign leaf asserts keyEncipherment, NOT digitalSignature.
        assert_pair(setup(), &ku_ext(&[2], true), &ku_ext(&[2], true), false);
    }

    #[test]
    fn enc_leaf_without_enc_bits_rejected() {
        // enc leaf asserts digitalSignature only — no encipherment/agreement.
        assert_pair(setup(), &ku_ext(&[0], true), &ku_ext(&[0], true), false);
    }

    #[test]
    fn leaf_is_ca_rejected() {
        // sign leaf carries basicConstraints CA=TRUE.
        let sign_exts = [ku_ext(&[0], true), bc_ext(true, None, true)].concat();
        assert_pair(setup(), &sign_exts, &ku_ext(&[2], true), false);
    }

    /// Build a pair with explicit per-leaf subjects (for the binding tests),
    /// then assert it is rejected.
    fn assert_subject_pair_rejected(s: Setup, sign_subj: &[u8], enc_subj: &[u8]) {
        let sign = cert(
            &s.ik,
            &s.cn,
            sign_subj,
            &key(3).public_key(),
            &ku_ext(&[0], true),
        );
        let enc = cert(
            &s.ik,
            &s.cn,
            enc_subj,
            &key(4).public_key(),
            &ku_ext(&[2], true),
        );
        assert!(!verify_pair(
            &[sign, s.int_a],
            &[enc, s.int_b],
            &[s.root],
            None
        ));
    }

    #[test]
    fn empty_subject_rejected() {
        assert_subject_pair_rejected(setup(), &name(b""), &name(b""));
    }

    #[test]
    fn different_subject_rejected() {
        assert_subject_pair_rejected(setup(), &name(b"alice"), &name(b"bob"));
    }

    #[test]
    fn s1_cross_ca_same_name_rejected() {
        // Two CAs share the Name "ca" but have DIFFERENT keys; both chain to
        // root. Leaves share subject + issuer-Name, but the issuing certs
        // (int_a vs int_b) have different tbs → S1 check rejects. (Can't use
        // `setup()` — it mints both intermediates from one key.)
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
