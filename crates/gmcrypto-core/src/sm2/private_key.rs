//! SM2 private keys.

use crate::sm2::curve::{Fn, NMod};
use crate::sm2::point::ProjectivePoint;
use crate::sm2::scalar_mul::mul_g;
use crypto_bigint::modular::ConstMontyParams;
use crypto_bigint::U256;
use subtle::{Choice, ConstantTimeEq, ConstantTimeLess, CtOption};

/// SM2 private key: scalar `d ∈ [1, n-2]` together with the cached public
/// key `d·G`.
///
/// # Constant-time contract
///
/// `Sm2PrivateKey::new` is constant-time-designed: the range check uses
/// `subtle::ConstantTimeLess` / `ConstantTimeEq`, and out-of-range inputs
/// produce a uniform `CtOption::none()` rather than a distinguishable
/// error. The cached public key is computed once with `mul_g`.
///
/// # Zeroization
///
/// This type is marked for future zeroization support (no-`unsafe` Rust
/// constraint prevents current implementation). The public key component
/// is left intact (it is not secret).
#[derive(Clone)]
pub struct Sm2PrivateKey {
    #[allow(dead_code)]
    d: Fn,
    public: ProjectivePoint,
}

impl Sm2PrivateKey {
    /// Construct from a 256-bit scalar. Returns `CtOption::none()` if `d`
    /// is outside `[1, n-2]`. Constant-time.
    #[must_use]
    pub fn new(d: U256) -> CtOption<Self> {
        let n = NMod::MODULUS.get();
        let n_minus_one = n.wrapping_sub(&U256::ONE);
        let in_range_low: Choice = !d.ct_eq(&U256::ZERO);
        let in_range_high: Choice = d.ct_lt(&n_minus_one);
        let valid = in_range_low & in_range_high;

        let d_fn = Fn::new(&d);
        let public = mul_g(&d_fn);
        let key = Self { d: d_fn, public };
        CtOption::new(key, valid)
    }

    /// Internal scalar, for sign/verify primitives.
    #[allow(dead_code)]
    pub(crate) const fn scalar(&self) -> &Fn {
        &self.d
    }

    /// The public key `d·G`.
    #[must_use]
    pub const fn public_key(&self) -> ProjectivePoint {
        self.public
    }
}

impl core::fmt::Debug for Sm2PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Sm2PrivateKey { d: <redacted>, public: <pub> }")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GB/T 32918.2 sample D constructs cleanly and yields the sample P.
    #[test]
    fn gbt32918_sample_d_constructs() {
        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key = Sm2PrivateKey::new(d).expect("D in [1, n-2]");
        let (x, _y) = key.public_key().to_affine().expect("public is finite");
        assert_eq!(
            x.retrieve(),
            U256::from_be_hex("09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020")
        );
    }

    #[test]
    fn d_zero_rejected() {
        let key = Sm2PrivateKey::new(U256::ZERO);
        assert!(bool::from(key.is_none()));
    }

    #[test]
    fn d_n_minus_one_rejected() {
        let n = NMod::MODULUS.get();
        let n_minus_one = n.wrapping_sub(&U256::ONE);
        let key = Sm2PrivateKey::new(n_minus_one);
        assert!(bool::from(key.is_none()));
    }

    #[test]
    fn d_one_accepted() {
        let key = Sm2PrivateKey::new(U256::ONE);
        assert!(bool::from(key.is_some()));
    }
}
