//! SM2 private keys.

use crate::sm2::curve::Fn;
use crate::sm2::point::ProjectivePoint;
use crate::sm2::scalar_mul::mul_g;
use crypto_bigint::U256;
use subtle::{Choice, ConstantTimeEq, ConstantTimeLess, CtOption};
use zeroize::ZeroizeOnDrop;

/// SM2 private key: scalar `d ∈ [1, n-2]` together with the cached public
/// key `d·G`.
///
/// # Construction
///
/// Two always-on public constructors:
///
/// - [`Sm2PrivateKey::from_bytes_be`] — **recommended.** Takes a
///   32-byte big-endian scalar slice; the caller never has to name
///   `crypto_bigint::U256`.
/// - [`Sm2PrivateKey::from_scalar`] (gated behind the
///   `crypto-bigint-scalar` feature flag) — takes a
///   `crypto_bigint::U256` directly, for callers already carrying
///   that dependency.
///
/// Both perform the same constant-time `[1, n-2]` range check (uses
/// `subtle::ConstantTimeLess` / `ConstantTimeEq`); out-of-range
/// inputs produce a uniform `CtOption::none()` rather than a
/// distinguishable error. The cached public key is computed once with
/// `mul_g`.
///
/// # v0.5 W5 migration
///
/// Prior to v0.5 the constructor was `Sm2PrivateKey::new(d: U256)`
/// (always-on, no feature flag). v0.5 renames it to `from_scalar`
/// **and** gates it behind `crypto-bigint-scalar` per Q5.17 in
/// `docs/v0.5-scope.md`. Migration:
///
/// ```text
/// // Before v0.5:
/// let key = Sm2PrivateKey::new(d_u256).unwrap();
/// // After v0.5 (option 1 — no crypto_bigint exposure):
/// let key = Sm2PrivateKey::from_bytes_be(&d_u256.to_be_bytes()).unwrap();
/// // After v0.5 (option 2 — enable feature, rename):
/// let key = Sm2PrivateKey::from_scalar(d_u256).unwrap();
/// ```
///
/// The serializer `to_sec1_be(&self) -> [u8; 32]` (v0.3+,
/// `#[doc(hidden)] pub`, not-SemVer) is replaced by the always-on
/// public [`Sm2PrivateKey::to_bytes_be`] in v0.5.
///
/// # Zeroization
///
/// The inner scalar is zeroized when the key is dropped. The public key
/// component is left intact (it is not secret). `ConstMontyForm` is
/// `zeroize::DefaultIsZeroes`, which gives it a blanket `Zeroize` impl;
/// the `ZeroizeOnDrop` derive then wires up safe-Rust drop-time wipe.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Sm2PrivateKey {
    d: Fn,
    #[zeroize(skip)]
    public: ProjectivePoint,
}

impl Sm2PrivateKey {
    /// Construct from a 256-bit scalar (`crypto_bigint::U256`).
    /// Returns `CtOption::none()` if `d` is outside `[1, n-2]`.
    /// Constant-time.
    ///
    /// Gated behind the `crypto-bigint-scalar` feature flag (v0.5 W5
    /// Q5.17). Callers who don't want to name `crypto_bigint::U256`
    /// should prefer [`Sm2PrivateKey::from_bytes_be`]; the two
    /// perform the same constant-time `[1, n-2]` range check.
    #[cfg(feature = "crypto-bigint-scalar")]
    #[must_use]
    pub fn from_scalar(d: U256) -> CtOption<Self> {
        Self::from_scalar_inner(d)
    }

    /// Construct from a 32-byte big-endian scalar.
    ///
    /// **Recommended public constructor.** Callers don't need to
    /// name `crypto_bigint::U256` and the SDK keeps its `crypto-bigint`
    /// transitive-dep major version a private implementation detail.
    /// Same constant-time `[1, n-2]` range check as [`Self::from_scalar`].
    ///
    /// Returns `CtOption::none()` for any out-of-range input
    /// (`d == 0`, `d == n - 1`, or `d > n - 1`).
    #[must_use]
    pub fn from_bytes_be(bytes: &[u8; 32]) -> CtOption<Self> {
        let d = U256::from_be_slice(bytes);
        Self::from_scalar_inner(d)
    }

    /// Big-endian 32-byte serialization of the secret scalar.
    ///
    /// **Caller must zeroize the returned `[u8; 32]` after use** —
    /// the buffer contains the plaintext private scalar and the SDK
    /// cannot enforce zeroization on a stack-owned array.
    ///
    /// v0.5 W5 promotes this method from the v0.3 `#[doc(hidden)] pub
    /// fn to_sec1_be(&self)` posture (not-SemVer; pkcs8-internal use
    /// only) to a SemVer-stable public method with the new name
    /// `to_bytes_be`. The body is unchanged.
    #[must_use]
    pub fn to_bytes_be(&self) -> [u8; 32] {
        self.d.retrieve().to_be_bytes().into()
    }

    /// In-crate `from_scalar` body. Always-on (used by tests, pkcs8,
    /// sec1, and the two public constructors). The public
    /// `from_scalar` is feature-gated; this internal helper is not.
    pub(crate) fn from_scalar_inner(d: U256) -> CtOption<Self> {
        let n = *Fn::MODULUS.as_ref();
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
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("D in [1, n-2]");
        let (x, _y) = key.public_key().to_affine().expect("public is finite");
        assert_eq!(
            x.retrieve(),
            U256::from_be_hex("09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020")
        );
    }

    #[test]
    fn d_zero_rejected() {
        let key = Sm2PrivateKey::from_scalar_inner(U256::ZERO);
        assert!(bool::from(key.is_none()));
    }

    #[test]
    fn d_n_minus_one_rejected() {
        let n = *Fn::MODULUS.as_ref();
        let n_minus_one = n.wrapping_sub(&U256::ONE);
        let key = Sm2PrivateKey::from_scalar_inner(n_minus_one);
        assert!(bool::from(key.is_none()));
    }

    #[test]
    fn d_one_accepted() {
        let key = Sm2PrivateKey::from_scalar_inner(U256::ONE);
        assert!(bool::from(key.is_some()));
    }

    /// `from_bytes_be` round-trips a valid scalar.
    #[test]
    fn from_bytes_be_round_trip() {
        let bytes: [u8; 32] = [
            0x39, 0x45, 0x20, 0x8F, 0x7B, 0x21, 0x44, 0xB1, 0x3F, 0x36, 0xE3, 0x8A, 0xC6, 0xD3,
            0x9F, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xB5, 0x1A, 0x42, 0xFB, 0x81, 0xEF,
            0x4D, 0xF7, 0xC5, 0xB8,
        ];
        let key = Sm2PrivateKey::from_bytes_be(&bytes).expect("valid scalar");
        assert_eq!(key.to_bytes_be(), bytes);
    }

    /// `from_bytes_be` rejects out-of-range scalars (zero).
    #[test]
    fn from_bytes_be_rejects_zero() {
        let bytes = [0u8; 32];
        let key = Sm2PrivateKey::from_bytes_be(&bytes);
        assert!(bool::from(key.is_none()));
    }

    /// `from_bytes_be` rejects `d == n - 1`.
    #[test]
    fn from_bytes_be_rejects_n_minus_one() {
        let n = *Fn::MODULUS.as_ref();
        let n_minus_one = n.wrapping_sub(&U256::ONE);
        let bytes: [u8; 32] = n_minus_one.to_be_bytes().into();
        let key = Sm2PrivateKey::from_bytes_be(&bytes);
        assert!(bool::from(key.is_none()));
    }
}
