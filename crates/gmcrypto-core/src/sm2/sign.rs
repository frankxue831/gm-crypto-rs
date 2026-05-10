//! SM2 sign and verify (GB/T 32918.2-2017).

use crate::asn1::sig::encode_sig;
use crate::sm2::curve::{Fn, Fp, GX_HEX, GY_HEX, b};
use crate::sm2::private_key::Sm2PrivateKey;
use crate::sm2::public_key::Sm2PublicKey;
use crate::sm2::scalar_mul::mul_g;
use crate::sm3::{DIGEST_SIZE, Sm3};
use alloc::vec::Vec;
use crypto_bigint::U256;
use rand_core::{CryptoRng, Rng};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess, CtOption};

/// Default signer ID per GM/T 0009: 16 ASCII bytes "1234567812345678".
pub const DEFAULT_SIGNER_ID: &[u8; 16] = b"1234567812345678";

/// Maximum signer-ID length in bytes.
///
/// Per GM/T 0009, the `Z_A` computation prepends `ENTL_A`, the ID's
/// bit-length encoded as a 16-bit big-endian field. The byte length
/// must therefore satisfy `id.len() * 8 ≤ u16::MAX`, i.e.
/// `id.len() ≤ 8191`. Inputs above this would silently wrap to a
/// non-spec `ENTL_A` in earlier code paths; sign / verify now reject
/// such inputs at the API boundary.
pub const MAX_ID_LEN: usize = (u16::MAX as usize) / 8;

/// Compute `Z_A`: `SM3(ENTL_A || ID_A || a || b || x_G || y_G || x_A || y_A)`.
///
/// `ENTL_A` is the 16-bit big-endian bit-length of `ID_A`.
///
/// # Panics
///
/// Panics if the public key point is not finite (at infinity), or if
/// `id.len() > MAX_ID_LEN` (8191 bytes — the largest length whose
/// bit-count fits in `u16`). API-level callers (`sign_with_id`,
/// `verify_with_id`) reject over-length IDs before reaching this
/// function, so the assertion only fires on direct misuse.
#[must_use]
pub fn compute_z(public: &Sm2PublicKey, id: &[u8]) -> [u8; DIGEST_SIZE] {
    assert!(
        id.len() <= MAX_ID_LEN,
        "id.len() exceeds MAX_ID_LEN — ENTL_A would silently wrap"
    );
    let mut h = Sm3::new();

    // ENTL_A: 16-bit BE bit-length of ID. The above assertion guarantees
    // the multiplication does not overflow `u16`.
    #[allow(clippy::cast_possible_truncation)]
    let entl: u16 = (id.len() as u16) * 8;
    h.update(&entl.to_be_bytes());
    h.update(id);

    // a ≡ -3 (mod p), encoded as 32 BE bytes of (p - 3).
    let three = U256::from_u64(3);
    let p_minus_three = Fp::MODULUS.as_ref().wrapping_sub(&three);
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

/// Fixed-K signing retry budget. v0.1 = 2.
pub(crate) const SIGN_RETRY_BUDGET: usize = 2;

/// Sign error: single uninformative variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    /// The retry budget was exhausted. Effectively unreachable with a uniform CSPRNG.
    Failed,
}

/// Sign `message` with `id` under `key`.
///
/// Returns a DER-encoded `SEQUENCE { r, s }` signature, or
/// `SignError::Failed` if the `SIGN_RETRY_BUDGET` was exhausted
/// (probability ~9·2^-512 with a uniform CSPRNG).
///
/// # Constant-time contract
///
/// Unconditionally runs `SIGN_RETRY_BUDGET` iterations regardless of
/// which (if any) iteration produced a valid signature.
///
/// # Errors
///
/// Returns `SignError::Failed` if `id.len() > MAX_ID_LEN` (the
/// `ENTL_A` field is 16-bit) or if every retry in the budget produced
/// an invalid candidate (`r == 0`, `r + k == n`, or `s == 0`). Failure
/// modes are deliberately collapsed to one variant per the
/// failure-mode-invariant policy; see `SECURITY.md`.
pub fn sign_with_id<R: CryptoRng + Rng>(
    key: &Sm2PrivateKey,
    id: &[u8],
    message: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, SignError> {
    let (r, s) = sign_raw_with_id(key, id, message, rng)?;
    Ok(encode_sig(&r, &s))
}

/// Sign and return the raw `(r, s)` scalar pair *without* DER encoding.
///
/// This is the constant-time-relevant work in [`sign_with_id`]: it runs
/// the masked-select retry loop and produces a valid `(r, s)`. The DER
/// encoding step in [`sign_with_id`] is variable-time on `(r, s)` (which
/// is public output), so timing-leak detection harnesses should target
/// this function instead of [`sign_with_id`] to test the crypto path in
/// isolation.
///
/// Hidden from rustdoc; this surface is provided for the dudect harness
/// and is not covered by the v0.1 SemVer stability promise. Use
/// [`sign_with_id`] in application code.
///
/// # Errors
///
/// Same as [`sign_with_id`]: returns `SignError::Failed` only if every
/// retry produced an invalid candidate (`r == 0`, `r + k == n`, or
/// `s == 0`).
#[doc(hidden)]
pub fn sign_raw_with_id<R: CryptoRng + Rng>(
    key: &Sm2PrivateKey,
    id: &[u8],
    message: &[u8],
    rng: &mut R,
) -> Result<(U256, U256), SignError> {
    if id.len() > MAX_ID_LEN {
        return Err(SignError::Failed);
    }
    let public = Sm2PublicKey::from_point(key.public_key());
    let z = compute_z(&public, id);

    let e_bytes = {
        let mut h = Sm3::new();
        h.update(&z);
        h.update(message);
        h.finalize()
    };
    let e_scalar = Fn::new(&U256::from_be_slice(&e_bytes));

    let mut chosen: CtOption<RsPair> = CtOption::new(RsPair::default(), Choice::from(0));
    for _ in 0..SIGN_RETRY_BUDGET {
        let candidate = try_sign_once(key, &e_scalar, rng);
        chosen = ct_or_else(chosen, candidate);
    }

    let pair: Option<RsPair> = chosen.into();
    let pair = pair.ok_or(SignError::Failed)?;
    Ok((pair.r, pair.s))
}

#[derive(Clone, Copy, Debug, Default)]
struct RsPair {
    r: U256,
    s: U256,
}

impl ConditionallySelectable for RsPair {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            r: U256::conditional_select(&a.r, &b.r, choice),
            s: U256::conditional_select(&a.s, &b.s, choice),
        }
    }
}

#[allow(clippy::similar_names, clippy::many_single_char_names)]
fn try_sign_once<R: CryptoRng + Rng>(key: &Sm2PrivateKey, e: &Fn, rng: &mut R) -> CtOption<RsPair> {
    let k = sample_nonzero_scalar(rng);
    let kg = mul_g(&k);
    let (x1, _y1) = kg.to_affine().expect("k·G is finite for k != 0");

    let x1_in_n = Fn::new(&x1.retrieve());
    let r = *e + x1_in_n;

    let r_u = r.retrieve();
    let r_plus_k = (r + k).retrieve();
    let r_zero: Choice = r_u.ct_eq(&U256::ZERO);
    let rk_zero: Choice = r_plus_k.ct_eq(&U256::ZERO);
    let bad_r = r_zero | rk_zero;

    let d = key.scalar();
    let one = Fn::new(&U256::ONE);
    let one_plus_d = one + *d;
    let one_plus_d_inv = one_plus_d.invert();
    let rd = r * *d;
    let k_minus_rd = k - rd;

    let inv_unwrapped: Fn = one_plus_d_inv.unwrap_or(Fn::new(&U256::ONE));
    let inv_ok: Choice = one_plus_d_inv.is_some().into();

    let s = inv_unwrapped * k_minus_rd;
    let s_u = s.retrieve();
    let s_zero: Choice = s_u.ct_eq(&U256::ZERO);

    let valid = !bad_r & !s_zero & inv_ok;
    CtOption::new(RsPair { r: r_u, s: s_u }, valid)
}

pub(crate) fn sample_nonzero_scalar<R: CryptoRng + Rng>(rng: &mut R) -> Fn {
    let n = *Fn::MODULUS.as_ref();
    loop {
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let candidate = U256::from_be_slice(&buf);
        let valid = !candidate.ct_eq(&U256::ZERO) & candidate.ct_lt(&n);
        if bool::from(valid) {
            return Fn::new(&candidate);
        }
    }
}

fn ct_or_else<T: ConditionallySelectable + Default>(a: CtOption<T>, b: CtOption<T>) -> CtOption<T> {
    let a_some = a.is_some();
    let b_some = b.is_some();
    let a_val = a.unwrap_or_else(T::default);
    let b_val = b.unwrap_or_else(T::default);
    let chosen = T::conditional_select(&b_val, &a_val, a_some);
    let some = a_some | b_some;
    CtOption::new(chosen, some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::private_key::Sm2PrivateKey;
    use core::convert::Infallible;
    use getrandom::SysRng;
    use rand_core::{TryCryptoRng, TryRng, UnwrapErr};

    struct SequenceRng {
        values: [U256; 2],
        index: usize,
    }

    impl TryRng for SequenceRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            assert_eq!(dst.len(), 32);
            let value = self.values[self.index];
            self.index += 1;
            dst.copy_from_slice(&value.to_be_bytes());
            Ok(())
        }
    }

    impl TryCryptoRng for SequenceRng {}

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

    /// Sign rejects IDs above `MAX_ID_LEN`. Earlier code paths silently
    /// wrapped the `ENTL_A` field via `wrapping_mul(8)`; the API now
    /// rejects at the boundary.
    #[test]
    fn sign_over_long_id_rejected() {
        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key = Sm2PrivateKey::new(d).expect("valid scalar");
        let too_long = alloc::vec![0u8; MAX_ID_LEN + 1];
        let mut rng = UnwrapErr(SysRng);
        let result = sign_with_id(&key, &too_long, b"msg", &mut rng);
        assert_eq!(result, Err(SignError::Failed));
    }

    #[test]
    fn sample_nonzero_scalar_rejects_candidates_above_order() {
        let n_plus_one = Fn::MODULUS.as_ref().wrapping_add(&U256::ONE);
        let mut rng = SequenceRng {
            values: [n_plus_one, U256::from_u64(2)],
            index: 0,
        };

        let sampled = sample_nonzero_scalar(&mut rng).retrieve();

        assert_eq!(sampled, U256::from_u64(2));
        assert_eq!(rng.index, 2);
    }
}

#[cfg(test)]
mod sign_tests {
    use super::*;
    use core::convert::Infallible;
    use rand_core::{TryCryptoRng, TryRng};

    /// Test-only RNG that always returns the same fixed scalar `k` from
    /// `fill_bytes`. The KAT only depends on the FIRST `fill_bytes` call.
    struct FixedScalarRng {
        k_bytes: [u8; 32],
    }
    impl FixedScalarRng {
        fn new(k_hex: &str) -> Self {
            let k = U256::from_be_hex(k_hex);
            Self {
                k_bytes: k.to_be_bytes().into(),
            }
        }
    }
    impl TryRng for FixedScalarRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            assert_eq!(dst.len(), 32);
            dst.copy_from_slice(&self.k_bytes);
            Ok(())
        }
    }

    impl TryCryptoRng for FixedScalarRng {}

    /// GB/T 32918.2 Appendix A.2 — fixed-k vector.
    /// D = 0x3945208F7B...
    /// k = 0x59276E27D506861A16680F3AD9C02DCFBFBF904F533DA0AC2EE1C9A45B58FF85
    /// Expected r = 0x88348A09A3E324C4FE946843123E40C175468F3E36481885844A144D2167EA4C
    /// Expected s = 0x0AD2CE552FD33EAB792E5A2805E0504D014C96135F8E03891087132ABB24D48D
    /// ID = "ALICE123@YAHOO.COM", message = "message digest"
    #[test]
    fn gbt32918_appendix_a2_fixed_k() {
        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key = Sm2PrivateKey::new(d).expect("valid scalar");
        let id = b"ALICE123@YAHOO.COM";
        let message = b"message digest";
        let mut rng =
            FixedScalarRng::new("59276E27D506861A16680F3AD9C02DCFBFBF904F533DA0AC2EE1C9A45B58FF85");
        let der = sign_with_id(&key, id, message, &mut rng).expect("sign succeeds");
        let (r, s) = crate::asn1::sig::decode_sig(&der).expect("our own DER decodes");
        assert_eq!(
            r,
            U256::from_be_hex("88348A09A3E324C4FE946843123E40C175468F3E36481885844A144D2167EA4C"),
            "r mismatch"
        );
        assert_eq!(
            s,
            U256::from_be_hex("0AD2CE552FD33EAB792E5A2805E0504D014C96135F8E03891087132ABB24D48D"),
            "s mismatch"
        );
    }
}
