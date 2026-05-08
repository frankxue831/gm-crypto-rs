//! SM2 curve parameters (GB/T 32918.5-2017 §10.1).
//!
//! Short Weierstrass over GF(p): y^2 = x^3 + a*x + b (mod p).
//! Cofactor 1, prime order n. Note `a ≡ -3 (mod p)`, which enables
//! Renes-Costello-Batina's a=-3 specialized complete-addition formulas.

use crypto_bigint::{impl_modulus, U256};

// p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
impl_modulus!(
    PMod,
    U256,
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
);

// n = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
impl_modulus!(
    NMod,
    U256,
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
);

/// Base field GF(p): elements of arithmetic in the curve equation.
pub type Fp = crypto_bigint::modular::ConstMontyForm<PMod, { U256::LIMBS }>;

/// Scalar field GF(n): elements of arithmetic on private keys and signature
/// scalars. n is the curve order.
pub type Fn = crypto_bigint::modular::ConstMontyForm<NMod, { U256::LIMBS }>;

/// Curve constant `b` (the constant term of y^2 = x^3 + a*x + b).
pub(crate) const B_HEX: &str = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";

/// Generator x coordinate.
#[allow(dead_code)]
pub(crate) const GX_HEX: &str = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";

/// Generator y coordinate.
#[allow(dead_code)]
pub(crate) const GY_HEX: &str = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";

/// Curve param `b` as a `Fp`.
#[must_use]
#[allow(clippy::missing_const_for_fn)]
pub fn b() -> Fp {
    Fp::new(&U256::from_be_hex(B_HEX))
}

/// `3 * b` as a `Fp`. RCB formulas use this constant.
#[must_use]
pub fn b3() -> Fp {
    let b = b();
    b + b + b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::modular::ConstMontyParams;

    #[test]
    fn moduli_are_correct_size() {
        assert_eq!(PMod::MODULUS.bits(), 256);
        assert_eq!(NMod::MODULUS.bits(), 256);
    }

    #[test]
    fn b_is_not_zero() {
        let b = b();
        assert_ne!(b.retrieve(), U256::ZERO);
    }

    #[test]
    fn b3_equals_3b() {
        let b = b();
        let b3 = b3();
        assert_eq!(b3.retrieve(), (b + b + b).retrieve());
    }
}
