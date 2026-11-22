//! SM2 signature verification.
//!
//! Verify operates on public inputs (signature, public key, message/digest)
//! and does NOT need to defend against a timing oracle. Failure modes are
//! intentionally not distinguished — `verify_with_id` and `verify_digest`
//! return `bool`.

use crate::asn1::sig::decode_sig;
use crate::sm2::curve::Fn;
use crate::sm2::public_key::Sm2PublicKey;
use crate::sm2::scalar_mul::{mul_g, mul_var};
use crate::sm2::sign::{Sm2Digest, Sm2Hasher};
use crypto_bigint::U256;
use subtle::ConstantTimeEq;

/// Verify a DER-encoded `SEQUENCE { r, s }` signature against a precomputed
/// [`Sm2Digest`] (`e = SM3(Z_A || M)`).
///
/// Typically paired with [`Sm2Hasher`] when streaming a large message or
/// verifying with an externally computed GB/T 32918.2 digest wrapped via
/// [`Sm2Digest::from_precomputed_z_hash`].
///
/// `digest` **MUST** be `SM3(Z_A || M)` bound to `(public, id)` per
/// GB/T 32918.2, not raw `SM3(M)`.
///
/// Returns `true` iff the signature is valid for `(public, digest)`.
/// Returns `false` on any failure mode (identity public key, malformed DER,
/// out-of-range `r`/`s`, `r + s == 0 (mod n)`, signature mismatch) without
/// distinguishing between them.
#[must_use]
#[allow(clippy::many_single_char_names)]
pub fn verify_digest(public: &Sm2PublicKey, digest: &Sm2Digest, sig_der: &[u8]) -> bool {
    // Reject identity public key: a malicious caller could construct
    // `Sm2PublicKey::from_point(ProjectivePoint::identity())`. Without this
    // guard, `t * P = O`, so any `(r, s)` with `r == (e + x(s*G)) mod n`
    // would verify against the identity point. Per the function contract,
    // "returns false on any failure mode".
    if bool::from(public.point().is_identity()) {
        return false;
    }

    let Some((r_be, s_be)) = decode_sig(sig_der) else {
        return false;
    };
    // v0.22: `decode_sig` now yields 32-byte big-endian scalars (it keeps all
    // its strict-canonical + zero/length rejects internally). Reconstruct the
    // numeric `U256` here for the verify-side range / field checks below — the
    // checks are byte-for-byte the same as before the reshape.
    let r = U256::from_be_slice(&r_be);
    let s = U256::from_be_slice(&s_be);

    let n = *Fn::MODULUS.as_ref();
    if r == U256::ZERO || s == U256::ZERO {
        return false;
    }
    if r >= n || s >= n {
        return false;
    }

    let r_fn = Fn::new(&r);
    let s_fn = Fn::new(&s);
    let t = r_fn + s_fn;
    if bool::from(t.retrieve().ct_eq(&U256::ZERO)) {
        return false;
    }

    let e = Fn::new(&U256::from_be_slice(digest.as_bytes()));

    // (x1, _) = s·G + t·P
    let sg = mul_g(&s_fn);
    let tp = mul_var(&t, &public.point());
    let combined = sg.add(&tp);
    let Some((x1, _)) = combined.to_affine() else {
        return false;
    };

    let x1_in_n = Fn::new(&x1.retrieve());
    let r_check = (e + x1_in_n).retrieve();
    bool::from(r_check.ct_eq(&r))
}

/// Verify a DER-encoded `SEQUENCE { r, s }` signature.
///
/// Returns `true` iff the signature is valid for `(public, id, message)`.
/// Returns `false` on any failure mode (malformed DER, out-of-range `r`/`s`,
/// signature mismatch) without distinguishing between them.
#[must_use]
pub fn verify_with_id(public: &Sm2PublicKey, id: &[u8], message: &[u8], sig_der: &[u8]) -> bool {
    let Some(mut hasher) = Sm2Hasher::new(public, id) else {
        return false;
    };
    hasher.update(message);
    let digest = hasher.finalize();
    verify_digest(public, &digest, sig_der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::private_key::Sm2PrivateKey;
    use crate::sm2::sign::sign_with_id;
    use getrandom::SysRng;

    #[test]
    fn round_trip_random_message() {
        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid");
        let pk = key.public_key();
        let id = b"ALICE123@YAHOO.COM";
        let msg = b"hello world";
        let mut rng = SysRng;
        let sig = sign_with_id(&key, id, msg, &mut rng).expect("sign");
        assert!(verify_with_id(&pk, id, msg, &sig));
    }

    #[test]
    fn tampered_message_rejected() {
        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid");
        let pk = key.public_key();
        let id = b"ALICE123@YAHOO.COM";
        let mut rng = SysRng;
        let sig = sign_with_id(&key, id, b"original", &mut rng).expect("sign");
        assert!(!verify_with_id(&pk, id, b"tampered", &sig));
    }

    #[test]
    fn wrong_pubkey_rejected() {
        let d_a =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let d_b =
            U256::from_be_hex("0000000000000000000000000000000000000000000000000000000000000007");
        let key_a = Sm2PrivateKey::from_scalar_inner(d_a).expect("valid");
        let key_b = Sm2PrivateKey::from_scalar_inner(d_b).expect("valid");
        let pk_b = key_b.public_key();
        let id = b"ALICE123@YAHOO.COM";
        let msg = b"hello world";
        let mut rng = SysRng;
        let sig = sign_with_id(&key_a, id, msg, &mut rng).expect("sign");
        // sig is under key_a; verifying under key_b's public must fail.
        assert!(!verify_with_id(&pk_b, id, msg, &sig));
    }

    #[test]
    fn malformed_der_rejected() {
        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid");
        let pk = key.public_key();
        // Garbage signature bytes.
        assert!(!verify_with_id(&pk, b"id", b"msg", &[0u8; 8]));
        assert!(!verify_with_id(&pk, b"id", b"msg", &[]));
    }

    /// `Sm2PublicKey::from_point` is infallible by design (point validity
    /// is documented as the caller's responsibility), so a malicious
    /// caller could construct a public key from `ProjectivePoint::identity()`.
    /// The earlier code panicked inside `compute_z`'s `to_affine().expect(...)`;
    /// `verify_with_id` now rejects identity public keys at the API
    /// boundary, returning `false` per the documented contract.
    #[test]
    fn identity_public_key_rejected_no_panic() {
        use crate::sm2::point::ProjectivePoint;
        let pk = Sm2PublicKey::from_point(ProjectivePoint::identity());
        // Some valid-looking DER for r=1, s=1.
        let bogus_sig = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        // No panic; just `false`.
        assert!(!verify_with_id(&pk, b"id", b"msg", &bogus_sig));
    }

    /// Verify must reject IDs whose bit-length exceeds `u16::MAX`
    /// (i.e. byte length above `MAX_ID_LEN = 8191`). Earlier the
    /// `ENTL_A` field silently wrapped to a non-spec value.
    #[test]
    fn over_long_id_rejected() {
        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid");
        let pk = key.public_key();
        let too_long = alloc::vec![0u8; crate::sm2::sign::MAX_ID_LEN + 1];
        // Doesn't matter what the signature is — must be rejected before
        // ever touching it.
        assert!(!verify_with_id(&pk, &too_long, b"msg", &[0u8; 8]));
    }

    /// Explicit anti-forgery regression test: for an identity public key `P = O`,
    /// `t·P = O`, so any `(r, s)` satisfying `r = (e + x(s·G)) mod n` (with
    /// `r, s, r + s != 0 mod n`) would satisfy the algebraic verification equation
    /// if the leading `public.point().is_identity()` guard in `verify_digest`
    /// were missing. `verify_digest` MUST reject it as `false`.
    #[test]
    fn verify_digest_identity_public_key_anti_forgery() {
        use crate::sm2::point::ProjectivePoint;

        let identity_pk = Sm2PublicKey::from_point(ProjectivePoint::identity());
        let digest = Sm2Digest::from_precomputed_z_hash([0x11u8; 32]);
        let s_fn = Fn::new(&U256::ONE);

        let (x1, _) = mul_g(&s_fn).to_affine().expect("G is finite");
        let e = Fn::new(&U256::from_be_slice(digest.as_bytes()));
        let r_fn = e + Fn::new(&x1.retrieve());
        let r = r_fn.retrieve();
        let s = s_fn.retrieve();

        assert_ne!(r, U256::ZERO);
        assert_ne!(s, U256::ZERO);
        assert_ne!((r_fn + s_fn).retrieve(), U256::ZERO);

        let forged_der =
            crate::asn1::sig::encode_sig(&crate::u256_to_be32(&r), &crate::u256_to_be32(&s));
        assert!(!verify_digest(&identity_pk, &digest, &forged_der));
    }

    /// `verify_digest` rejects tampered digests, wrong public keys, digests
    /// bound to a different signer ID, and malformed DER signatures.
    #[test]
    fn verify_digest_negative_cases() {
        use crate::sm2::sign::sign_digest;

        let d_a =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let d_b =
            U256::from_be_hex("0000000000000000000000000000000000000000000000000000000000000007");
        let key_a = Sm2PrivateKey::from_scalar_inner(d_a).expect("valid");
        let key_b = Sm2PrivateKey::from_scalar_inner(d_b).expect("valid");
        let pk_a = key_a.public_key();
        let pk_b = key_b.public_key();

        let id = b"ALICE123@YAHOO.COM";
        let msg = b"hello digest";
        let mut hasher = Sm2Hasher::new(&pk_a, id).expect("valid pk/id");
        hasher.update(msg);
        let digest = hasher.finalize();

        let mut rng = SysRng;
        let sig = sign_digest(&key_a, &digest, &mut rng).expect("sign_digest");
        assert!(verify_digest(&pk_a, &digest, &sig));

        // 1-bit tampered digest.
        let mut tampered_bytes = *digest.as_bytes();
        tampered_bytes[0] ^= 0x01;
        let tampered_digest = Sm2Digest::from_precomputed_z_hash(tampered_bytes);
        assert!(!verify_digest(&pk_a, &tampered_digest, &sig));

        // Wrong public key.
        assert!(!verify_digest(&pk_b, &digest, &sig));

        // Same message under a different signer ID.
        let mut other_id_hasher = Sm2Hasher::new(&pk_a, b"OTHER-ID").expect("valid pk/id");
        other_id_hasher.update(msg);
        let other_id_digest = other_id_hasher.finalize();
        assert!(!verify_digest(&pk_a, &other_id_digest, &sig));

        // Malformed DER signatures.
        assert!(!verify_digest(&pk_a, &digest, &[]));
        assert!(!verify_digest(&pk_a, &digest, &[0u8; 8]));
    }
}
