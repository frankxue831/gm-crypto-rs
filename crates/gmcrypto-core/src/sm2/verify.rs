//! SM2 signature verification.
//!
//! Verify operates on public inputs (signature, public key, message) and
//! does NOT need to defend against a timing oracle. Failure modes are
//! intentionally not distinguished — `verify_with_id` returns `bool`.

use crate::asn1::sig::decode_sig;
use crate::sm2::curve::{Fn, NMod};
use crate::sm2::public_key::Sm2PublicKey;
use crate::sm2::scalar_mul::{mul_g, mul_var};
use crate::sm2::sign::compute_z;
use crate::sm3::Sm3;
use crypto_bigint::modular::ConstMontyParams;
use crypto_bigint::U256;
use subtle::ConstantTimeEq;

/// Verify a DER-encoded `SEQUENCE { r, s }` signature.
///
/// Returns `true` iff the signature is valid for `(public, id, message)`.
/// Returns `false` on any failure mode (malformed DER, out-of-range `r`/`s`,
/// signature mismatch) without distinguishing between them.
#[must_use]
#[allow(clippy::many_single_char_names)]
pub fn verify_with_id(public: &Sm2PublicKey, id: &[u8], message: &[u8], sig_der: &[u8]) -> bool {
    let Some((r, s)) = decode_sig(sig_der) else {
        return false;
    };

    let n = NMod::MODULUS.get();
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

    let z = compute_z(public, id);
    let mut h = Sm3::new();
    h.update(&z);
    h.update(message);
    let e_bytes = h.finalize();
    let e = Fn::new(&U256::from_be_slice(&e_bytes));

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::private_key::Sm2PrivateKey;
    use crate::sm2::sign::sign_with_id;
    use rand_core::OsRng;

    #[test]
    fn round_trip_random_message() {
        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key = Sm2PrivateKey::new(d).expect("valid");
        let pk = Sm2PublicKey::from_point(key.public_key());
        let id = b"ALICE123@YAHOO.COM";
        let msg = b"hello world";
        let sig = sign_with_id(&key, id, msg, &mut OsRng).expect("sign");
        assert!(verify_with_id(&pk, id, msg, &sig));
    }

    #[test]
    fn tampered_message_rejected() {
        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key = Sm2PrivateKey::new(d).expect("valid");
        let pk = Sm2PublicKey::from_point(key.public_key());
        let id = b"ALICE123@YAHOO.COM";
        let sig = sign_with_id(&key, id, b"original", &mut OsRng).expect("sign");
        assert!(!verify_with_id(&pk, id, b"tampered", &sig));
    }

    #[test]
    fn wrong_pubkey_rejected() {
        let d_a =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let d_b =
            U256::from_be_hex("0000000000000000000000000000000000000000000000000000000000000007");
        let key_a = Sm2PrivateKey::new(d_a).expect("valid");
        let key_b = Sm2PrivateKey::new(d_b).expect("valid");
        let pk_b = Sm2PublicKey::from_point(key_b.public_key());
        let id = b"ALICE123@YAHOO.COM";
        let msg = b"hello world";
        let sig = sign_with_id(&key_a, id, msg, &mut OsRng).expect("sign");
        // sig is under key_a; verifying under key_b's public must fail.
        assert!(!verify_with_id(&pk_b, id, msg, &sig));
    }

    #[test]
    fn malformed_der_rejected() {
        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key = Sm2PrivateKey::new(d).expect("valid");
        let pk = Sm2PublicKey::from_point(key.public_key());
        // Garbage signature bytes.
        assert!(!verify_with_id(&pk, b"id", b"msg", &[0u8; 8]));
        assert!(!verify_with_id(&pk, b"id", b"msg", &[]));
    }
}
