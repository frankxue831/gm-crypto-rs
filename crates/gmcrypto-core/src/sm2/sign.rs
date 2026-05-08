//! SM2 sign and verify (GB/T 32918.2-2017).

use crate::sm2::curve::{b, PMod, GX_HEX, GY_HEX};
use crate::sm2::public_key::Sm2PublicKey;
use crate::sm3::{Sm3, DIGEST_SIZE};
use crypto_bigint::modular::ConstMontyParams;
use crypto_bigint::U256;

/// Default signer ID per GM/T 0009: 16 ASCII bytes "1234567812345678".
pub const DEFAULT_SIGNER_ID: &[u8; 16] = b"1234567812345678";

/// Compute `Z_A`: `SM3(ENTL_A || ID_A || a || b || x_G || y_G || x_A || y_A)`.
///
/// `ENTL_A` is the 16-bit big-endian bit-length of `ID_A`.
///
/// # Panics
///
/// Panics if the public key point is not finite (at infinity).
#[must_use]
pub fn compute_z(public: &Sm2PublicKey, id: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut h = Sm3::new();

    // ENTL_A: 16-bit BE bit-length of ID.
    #[allow(clippy::cast_possible_truncation)]
    let entl: u16 = (id.len() as u16).wrapping_mul(8);
    h.update(&entl.to_be_bytes());
    h.update(id);

    // a ≡ -3 (mod p), encoded as 32 BE bytes of (p - 3).
    let three = U256::from_u64(3);
    let p_minus_three = PMod::MODULUS.get().wrapping_sub(&three);
    h.update(&p_minus_three.to_be_bytes());

    // b
    h.update(&b().retrieve().to_be_bytes());

    // (x_G, y_G)
    h.update(&U256::from_be_hex(GX_HEX).to_be_bytes());
    h.update(&U256::from_be_hex(GY_HEX).to_be_bytes());

    // (x_A, y_A)
    let (px, py) = public.point().to_affine().expect("public key is finite");
    h.update(&px.retrieve().to_be_bytes());
    h.update(&py.retrieve().to_be_bytes());

    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::private_key::Sm2PrivateKey;

    /// GB/T 32918.2 Appendix A.2: `Z_A` for ID="ALICE123@YAHOO.COM" and the
    /// sample private key D. Expected:
    /// 26db4bc1839bd22e97e1dab667ec5e0a730d5e16521398b4435c576a93afd7ed.
    #[test]
    fn z_appendix_a2() {
        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key = Sm2PrivateKey::new(d).expect("valid scalar");
        let public = Sm2PublicKey::from_point(key.public_key());
        let z = compute_z(&public, b"ALICE123@YAHOO.COM");

        #[allow(clippy::format_collect)]
        let z_hex: alloc::string::String =
            z.iter().map(|byte| alloc::format!("{byte:02x}")).collect();
        assert_eq!(
            z_hex,
            "26db4bc1839bd22e97e1dab667ec5e0a730d5e16521398b4435c576a93afd7ed"
        );
    }
}
