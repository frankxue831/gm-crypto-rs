//! SM2 private keys.

use crate::sm2::curve::Fn;
use crate::sm2::point::ProjectivePoint;
use crate::sm2::scalar_mul::mul_g;
use crate::sm2::sign::sample_scalar_in_range;
use crypto_bigint::U256;
use rand_core::TryCryptoRng;
use subtle::{Choice, ConstantTimeEq, ConstantTimeLess, CtOption};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SM2 private key: scalar `d ∈ [1, n-2]` together with the cached public
/// key `d·G`.
///
/// # Construction
///
/// Three public constructors:
///
/// - [`Sm2PrivateKey::generate`] — **recommended for new keys.** Samples
///   a fresh key `d ∈ [1, n-2]` from a caller-supplied
///   [`rand_core::TryCryptoRng`] using a fixed-budget constant-time sampler.
/// - [`Sm2PrivateKey::from_bytes_be`] — **recommended for importing bytes.**
///   Takes a 32-byte big-endian scalar slice; the caller never has to name
///   `crypto_bigint::U256`.
/// - `Sm2PrivateKey::from_scalar` (gated behind the
///   `crypto-bigint-scalar` feature flag) — takes a
///   `crypto_bigint::U256` directly, for callers already carrying
///   that dependency.
///
/// Both import constructors perform the same constant-time `[1, n-2]`
/// range check (uses `subtle::ConstantTimeLess` / `ConstantTimeEq`);
/// out-of-range inputs produce a uniform `CtOption::none()` rather than a
/// distinguishable error. The cached public key is computed once with
/// `mul_g`.
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
    /// Generate a fresh SM2 private key (`d ∈ [1, n-2]` per GB/T 32918.1)
    /// from `rng`.
    ///
    /// Samples up to 4 candidate 256-bit scalars unconditionally in constant
    /// time via masked selection, rejecting `0`, `n - 1`, and values `>= n`,
    /// then computes the cached public key `d·G`.
    ///
    /// # Constant-time contract
    ///
    /// Always draws a fixed budget of 4 candidate 32-byte blocks from `rng`
    /// (unless `rng` errors, which is a public condition) and always
    /// computes `d·G` before collapsing the validity mask, avoiding
    /// secret-dependent branches or early exits on valid candidates.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Failed`] if `rng` fails to fill bytes or if
    /// all 4 draws fall outside `[1, n-2]` (probability `≈ 2^-128` for a
    /// uniform CSPRNG). Both cases collapse to the same opaque variant per
    /// the failure-mode invariant.
    ///
    /// # RNG bound
    ///
    /// `R: TryCryptoRng` is the **fallible** `rand_core` cryptographic-RNG
    /// trait. An RNG error never panics; it collapses cleanly to
    /// [`crate::Error::Failed`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use getrandom::SysRng;
    /// use gmcrypto_core::sm2::Sm2PrivateKey;
    ///
    /// # fn main() -> Result<(), gmcrypto_core::Error> {
    /// let key = Sm2PrivateKey::generate(&mut SysRng)?;
    /// let public = key.public_key();
    /// assert_eq!(public.to_sec1_uncompressed().len(), 65);
    /// # Ok(()) }
    /// ```
    pub fn generate<R: TryCryptoRng>(rng: &mut R) -> Result<Self, crate::Error> {
        let n_minus_one = Fn::MODULUS.as_ref().wrapping_sub(&U256::ONE);
        let (mut d, sample_ok) =
            sample_scalar_in_range(rng, &n_minus_one).ok_or(crate::Error::Failed)?;
        // Compute `d·G` unconditionally before collapsing `sample_ok` so
        // budget exhaustion (secret-derived) never leaks via a skipped
        // scalar multiplication. On exhaustion `d` is the dummy scalar 1
        // (valid for `mul_g`), and `key` drops below, wiping `key.d` via
        // `ZeroizeOnDrop`.
        let public = mul_g(&d);
        let key = Self { d, public };
        // Scrub the local `Copy` scalar binding unconditionally on both paths.
        d.zeroize();
        if !bool::from(sample_ok) {
            return Err(crate::Error::Failed);
        }
        Ok(key)
    }

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
    /// Same constant-time `[1, n-2]` range check as `Self::from_scalar`.
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
    pub const fn public_key(&self) -> crate::sm2::Sm2PublicKey {
        crate::sm2::Sm2PublicKey::from_point(self.public)
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
        let (x, _y) = key
            .public_key()
            .point()
            .to_affine()
            .expect("public is finite");
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

    #[derive(Debug)]
    struct MockRngError;

    impl core::fmt::Display for MockRngError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("mock RNG failure")
        }
    }

    impl core::error::Error for MockRngError {}

    struct ScriptedRng {
        steps: [Result<U256, ()>; crate::sm2::sign::NONCE_SAMPLE_BUDGET],
        calls: usize,
        bytes_consumed: usize,
    }

    impl ScriptedRng {
        const fn from_values(values: [U256; crate::sm2::sign::NONCE_SAMPLE_BUDGET]) -> Self {
            Self {
                steps: [Ok(values[0]), Ok(values[1]), Ok(values[2]), Ok(values[3])],
                calls: 0,
                bytes_consumed: 0,
            }
        }

        const fn from_steps(
            steps: [Result<U256, ()>; crate::sm2::sign::NONCE_SAMPLE_BUDGET],
        ) -> Self {
            Self {
                steps,
                calls: 0,
                bytes_consumed: 0,
            }
        }
    }

    impl rand_core::TryRng for ScriptedRng {
        type Error = MockRngError;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(MockRngError)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(MockRngError)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            assert_eq!(dst.len(), 32);
            let idx = self.calls;
            self.calls += 1;
            self.bytes_consumed += dst.len();
            match self.steps[idx] {
                Ok(v) => {
                    dst.copy_from_slice(&v.to_be_bytes());
                    Ok(())
                }
                Err(()) => Err(MockRngError),
            }
        }
    }

    impl rand_core::TryCryptoRng for ScriptedRng {}

    #[test]
    fn generate_with_sysrng_round_trips_sign_and_encrypt() {
        let mut rng = getrandom::SysRng;
        let key = Sm2PrivateKey::generate(&mut rng).expect("SysRng keygen succeeds");
        let mut raw = key.to_bytes_be();
        let d = U256::from_be_slice(&raw);
        let n_minus_one = Fn::MODULUS.as_ref().wrapping_sub(&U256::ONE);
        assert_ne!(d, U256::ZERO);
        assert!(d < n_minus_one);

        let reimported = Sm2PrivateKey::from_bytes_be(&raw).expect("valid generated scalar");
        raw.zeroize();
        assert_eq!(
            reimported.public_key().to_sec1_uncompressed(),
            key.public_key().to_sec1_uncompressed()
        );

        let msg = b"sm2 keygen round-trip";
        let sig = crate::sm2::sign_with_id(&key, crate::sm2::DEFAULT_SIGNER_ID, msg, &mut rng)
            .expect("sign succeeds");
        assert!(crate::sm2::verify_with_id(
            &key.public_key(),
            crate::sm2::DEFAULT_SIGNER_ID,
            msg,
            &sig
        ));

        let ct = crate::sm2::encrypt(&key.public_key(), msg, &mut rng).expect("encrypt succeeds");
        let pt = crate::sm2::decrypt(&key, &ct).expect("decrypt succeeds");
        assert_eq!(pt, msg);
    }

    #[test]
    fn generate_skips_zero_and_selects_second_draw() {
        let mut rng = ScriptedRng::from_values([
            U256::ZERO,
            U256::from_u64(42),
            U256::from_u64(99),
            U256::from_u64(7),
        ]);
        let key = Sm2PrivateKey::generate(&mut rng).expect("second draw valid");
        let expected_d = U256::from_u64(42);
        let expected_pub = Sm2PrivateKey::from_scalar_inner(expected_d)
            .expect("valid")
            .public_key();
        assert_eq!(U256::from_be_slice(&key.to_bytes_be()), expected_d);
        assert_eq!(
            key.public_key().to_sec1_uncompressed(),
            expected_pub.to_sec1_uncompressed()
        );
        assert_eq!(rng.calls, crate::sm2::sign::NONCE_SAMPLE_BUDGET);
        assert_eq!(rng.bytes_consumed, 128);
    }

    #[test]
    fn generate_rejects_n_minus_one_and_selects_second_draw() {
        let n_minus_one = Fn::MODULUS.as_ref().wrapping_sub(&U256::ONE);
        let mut rng = ScriptedRng::from_values([
            n_minus_one,
            U256::from_u64(0x1234),
            U256::from_u64(5),
            U256::from_u64(6),
        ]);
        let key = Sm2PrivateKey::generate(&mut rng).expect("second draw valid");
        let expected_d = U256::from_u64(0x1234);
        assert_eq!(U256::from_be_slice(&key.to_bytes_be()), expected_d);
        assert_eq!(rng.calls, crate::sm2::sign::NONCE_SAMPLE_BUDGET);
        assert_eq!(rng.bytes_consumed, 128);
    }

    #[test]
    fn generate_rejects_out_of_range_and_accepts_upper_boundary_n_minus_two() {
        let n = *Fn::MODULUS.as_ref();
        let n_minus_two = n.wrapping_sub(&U256::from_u64(2));
        let all_ff = U256::from_be_slice(&[0xFFu8; 32]);

        let mut rng_n = ScriptedRng::from_values([n, n_minus_two, U256::ONE, U256::from_u64(3)]);
        let key_n = Sm2PrivateKey::generate(&mut rng_n).expect("n - 2 accepted");
        assert_eq!(U256::from_be_slice(&key_n.to_bytes_be()), n_minus_two);
        assert_eq!(rng_n.calls, crate::sm2::sign::NONCE_SAMPLE_BUDGET);
        assert_eq!(rng_n.bytes_consumed, 128);

        let mut rng_max =
            ScriptedRng::from_values([all_ff, n_minus_two, U256::ONE, U256::from_u64(3)]);
        let key_max = Sm2PrivateKey::generate(&mut rng_max).expect("n - 2 accepted");
        assert_eq!(U256::from_be_slice(&key_max.to_bytes_be()), n_minus_two);
        assert_eq!(rng_max.calls, crate::sm2::sign::NONCE_SAMPLE_BUDGET);
        assert_eq!(rng_max.bytes_consumed, 128);

        let mut rng_one =
            ScriptedRng::from_values([U256::ZERO, all_ff, U256::ONE, U256::from_u64(5)]);
        let key_one = Sm2PrivateKey::generate(&mut rng_one).expect("1 accepted");
        assert_eq!(U256::from_be_slice(&key_one.to_bytes_be()), U256::ONE);
        assert_eq!(rng_one.calls, crate::sm2::sign::NONCE_SAMPLE_BUDGET);
        assert_eq!(rng_one.bytes_consumed, 128);
    }

    #[test]
    fn generate_all_four_draws_invalid_returns_failed() {
        let n = *Fn::MODULUS.as_ref();
        let n_minus_one = n.wrapping_sub(&U256::ONE);
        let all_ff = U256::from_be_slice(&[0xFFu8; 32]);
        let mut rng = ScriptedRng::from_values([U256::ZERO, n_minus_one, n, all_ff]);
        let err = Sm2PrivateKey::generate(&mut rng).unwrap_err();
        assert_eq!(err, crate::Error::Failed);
        assert_eq!(rng.calls, crate::sm2::sign::NONCE_SAMPLE_BUDGET);
        assert_eq!(rng.bytes_consumed, 128);
    }

    #[test]
    fn generate_first_draw_valid_still_consumes_all_four_draws() {
        let valid_d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let mut rng = ScriptedRng::from_values([
            valid_d,
            U256::from_u64(2),
            U256::from_u64(3),
            U256::from_u64(4),
        ]);
        let key = Sm2PrivateKey::generate(&mut rng).expect("first draw valid");
        assert_eq!(U256::from_be_slice(&key.to_bytes_be()), valid_d);
        assert_eq!(rng.calls, crate::sm2::sign::NONCE_SAMPLE_BUDGET);
        assert_eq!(rng.bytes_consumed, 128);
    }

    #[test]
    fn generate_rng_error_on_attempt_1_returns_failed() {
        let mut rng =
            ScriptedRng::from_steps([Err(()), Ok(U256::ONE), Ok(U256::ONE), Ok(U256::ONE)]);
        let err = Sm2PrivateKey::generate(&mut rng).unwrap_err();
        assert_eq!(err, crate::Error::Failed);
        assert_eq!(rng.calls, 1);
    }

    #[test]
    fn generate_rng_error_on_attempt_3_returns_failed() {
        let mut rng = ScriptedRng::from_steps([
            Ok(U256::from_u64(7)),
            Ok(U256::from_u64(8)),
            Err(()),
            Ok(U256::from_u64(9)),
        ]);
        let err = Sm2PrivateKey::generate(&mut rng).unwrap_err();
        assert_eq!(err, crate::Error::Failed);
        assert_eq!(rng.calls, 3);
    }
}
