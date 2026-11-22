//! SM2 sign and verify (GB/T 32918.2-2016).

use crate::asn1::sig::encode_sig;
use crate::sm2::curve::{Fn, Fp, GX_HEX, GY_HEX, b};
use crate::sm2::private_key::Sm2PrivateKey;
use crate::sm2::public_key::Sm2PublicKey;
use crate::sm2::scalar_mul::mul_g;
use crate::sm3::{DIGEST_SIZE, Sm3};
use alloc::vec::Vec;
use crypto_bigint::U256;
use rand_core::TryCryptoRng;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess, CtOption};
use zeroize::Zeroize;

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
/// bit-count fits in `u16`). API-level callers (`Sm2Hasher::new`,
/// `sign_with_id`, `verify_with_id`) reject over-length IDs before
/// reaching this function, so the assertion only fires on direct misuse.
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

/// Precomputed GB/T 32918.2 SM2 signing digest `e = SM3(Z_A || M)`.
///
/// Produce this type via [`Sm2Hasher`] whenever the message bytes can be
/// hashed locally, or wrap an externally computed `SM3(Z_A || M)` via
/// [`Sm2Digest::from_precomputed_z_hash`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sm2Digest([u8; DIGEST_SIZE]);

impl Sm2Digest {
    /// Return the 32-byte digest `e = SM3(Z_A || M)`.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wrap an externally precomputed GB/T 32918.2 digest `e = SM3(Z_A || M)`.
    ///
    /// # Security warning
    ///
    /// `e` **MUST** be `SM3(Z_A || M)` where `Z_A` is computed via [`compute_z`]
    /// per GB/T 32918.2 — **never** a raw `SM3(M)` hash. Omitting `Z_A` breaks
    /// GB/T 32918.2 signer-identity and public-key binding and produces
    /// non-interoperable signatures.
    ///
    /// Prefer [`Sm2Hasher`] whenever the message can be streamed locally; use
    /// this constructor only at protocol or hardware boundaries that already
    /// supply `SM3(Z_A || M)`.
    #[must_use]
    pub const fn from_precomputed_z_hash(e: [u8; 32]) -> Self {
        Self(e)
    }
}

/// Streaming GB/T 32918.2 `e = SM3(Z_A || M)` hasher for SM2 signing and
/// verification.
///
/// Construct with [`Sm2Hasher::new`] or [`Sm2Hasher::new_default_id`], feed
/// message chunks with [`Sm2Hasher::update`], and finish with
/// [`Sm2Hasher::finalize`] to obtain an [`Sm2Digest`] for [`sign_digest`] or
/// [`crate::sm2::verify_digest`].
///
/// Chunking does not affect the output: streaming `M` in any partition
/// produces the exact same [`Sm2Digest`] as single-shot `SM3(Z_A || M)`.
///
/// # Zeroization
///
/// Best-effort field-layer zeroization: `Sm2Hasher` wraps an inner [`Sm3`],
/// whose [`Drop`] impl scrubs its internal compression state and input
/// buffer on early drop and after [`Sm2Hasher::finalize`] consumes `self`.
/// Following [`crate::hmac::HmacSm3`], `Sm2Hasher` intentionally has no
/// outer `Drop` or `ZeroizeOnDrop` impl so `finalize(self)` can move
/// `self.inner` into [`Sm3::finalize`]. The returned [`Sm2Digest`] is
/// public and is not wiped.
#[derive(Clone, Debug)]
pub struct Sm2Hasher {
    inner: Sm3,
}

impl Sm2Hasher {
    /// Create a streaming SM2 hasher bound to `(public, id)`.
    ///
    /// Computes `Z_A` via [`compute_z`] and absorbs it into
    /// the internal [`Sm3`] state so subsequent [`update`](Self::update)
    /// calls stream message bytes directly into `SM3(Z_A || M)`.
    ///
    /// Returns `None` without panicking if `public` is the point at infinity
    /// or if `id.len() >` [`MAX_ID_LEN`] (8191 bytes). Any public key from
    /// [`Sm2PrivateKey::public_key`] or [`Sm2PublicKey::from_sec1_bytes`]
    /// with `id.len() <= MAX_ID_LEN` returns `Some`.
    #[must_use]
    pub fn new(public: &Sm2PublicKey, id: &[u8]) -> Option<Self> {
        if bool::from(public.point().is_identity()) || id.len() > MAX_ID_LEN {
            return None;
        }
        let z = compute_z(public, id);
        let mut inner = Sm3::new();
        inner.update(&z);
        Some(Self { inner })
    }

    /// Create a streaming SM2 hasher bound to `(public, DEFAULT_SIGNER_ID)`.
    ///
    /// Equivalent to `Self::new(public, DEFAULT_SIGNER_ID)`. Returns `None`
    /// without panicking if `public` is the point at infinity; any public
    /// key from [`Sm2PrivateKey::public_key`] or
    /// [`Sm2PublicKey::from_sec1_bytes`] returns `Some`.
    #[must_use]
    pub fn new_default_id(public: &Sm2PublicKey) -> Option<Self> {
        Self::new(public, DEFAULT_SIGNER_ID)
    }

    /// Absorb message bytes into `SM3(Z_A || M)`.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Consume the hasher and produce the finalized [`Sm2Digest`].
    #[must_use]
    pub fn finalize(self) -> Sm2Digest {
        Sm2Digest(self.inner.finalize())
    }
}

/// Fixed-K signing retry budget. v0.1 = 2.
pub(crate) const SIGN_RETRY_BUDGET: usize = 2;

/// Sign `digest` (`e = SM3(Z_A || M)`) under `key`.
///
/// Typically paired with [`Sm2Hasher`] when streaming a large message or
/// computing the GB/T 32918.2 digest incrementally before signing.
///
/// Returns a DER-encoded `SEQUENCE { r, s }` signature, or
/// [`crate::Error::Failed`] if the `SIGN_RETRY_BUDGET` was exhausted
/// (probability ~9·2^-512 with a uniform CSPRNG).
///
/// # Security warning
///
/// `sign_digest` accepts a precomputed [`Sm2Digest`] and **cannot verify**
/// that `digest` was computed using the `Z_A` derived from `key.public_key()`
/// and the intended signer ID (especially if constructed via
/// [`Sm2Digest::from_precomputed_z_hash`]). Passing a raw `SM3(M)` hash or a
/// digest bound to a different public key produces signatures that fail
/// standard GB/T 32918.2 verification under `(key.public_key(), id)`.
///
/// # Constant-time contract
///
/// Unconditionally runs `SIGN_RETRY_BUDGET` iterations regardless of
/// which (if any) iteration produced a valid signature.
///
/// # Errors
///
/// Returns [`crate::Error::Failed`] if the supplied RNG fails (its
/// `try_fill_bytes` errored — the failure is collapsed to `Failed`,
/// never propagated as a panic), or if every retry in the budget
/// produced an invalid candidate (`r == 0`,
/// `r + k == n`, or `s == 0`). Failure modes are deliberately collapsed
/// to one variant per the failure-mode-invariant policy; see
/// `SECURITY.md`.
pub fn sign_digest<R: TryCryptoRng>(
    key: &Sm2PrivateKey,
    digest: &Sm2Digest,
    rng: &mut R,
) -> Result<Vec<u8>, crate::Error> {
    let (r, s) = sign_raw_digest(key, digest.as_bytes(), rng)?;
    Ok(encode_sig(
        &crate::u256_to_be32(&r),
        &crate::u256_to_be32(&s),
    ))
}

/// Sign `message` with `id` under `key`.
///
/// Returns a DER-encoded `SEQUENCE { r, s }` signature, or
/// [`crate::Error::Failed`] if the `SIGN_RETRY_BUDGET` was exhausted
/// (probability ~9·2^-512 with a uniform CSPRNG).
///
/// # Constant-time contract
///
/// Unconditionally runs `SIGN_RETRY_BUDGET` iterations regardless of
/// which (if any) iteration produced a valid signature.
///
/// # Errors
///
/// Returns [`crate::Error::Failed`] if `id.len() > MAX_ID_LEN` (the
/// `ENTL_A` field is 16-bit), if the supplied RNG fails (its
/// `try_fill_bytes` errored — the failure is collapsed to `Failed`,
/// never propagated as a panic), or if every retry in the budget
/// produced an invalid candidate (`r == 0`,
/// `r + k == n`, or `s == 0`). Failure modes are deliberately collapsed
/// to one variant per the failure-mode-invariant policy; see
/// `SECURITY.md`.
///
/// # RNG bound
///
/// `R: TryCryptoRng` is the **fallible** `rand_core` cryptographic-RNG
/// trait. This is a deliberate ecosystem coupling: `rand_core` is the
/// interop point for RNGs, and the fallible bound gives a defined,
/// no-panic path when the RNG fails (the error collapses to `Failed`).
pub fn sign_with_id<R: TryCryptoRng>(
    key: &Sm2PrivateKey,
    id: &[u8],
    message: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, crate::Error> {
    let (r, s) = sign_raw_with_id(key, id, message, rng)?;
    // `sign_raw_with_id` stays `U256`-typed (it is `#[doc(hidden)]`, dudect-only);
    // the public `encode_sig` boundary takes 32-byte big-endian scalars (v0.22).
    Ok(encode_sig(
        &crate::u256_to_be32(&r),
        &crate::u256_to_be32(&s),
    ))
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
/// **Not part of the public API — not covered by SemVer.** This surface is
/// provided solely for the in-repo dudect timing-leak harness; it is
/// `#[doc(hidden)]` (hidden from rustdoc) and may change or be removed in any
/// release, including patch releases, without notice. Application code must use
/// [`sign_with_id`].
///
/// # Errors
///
/// Same as [`sign_with_id`]: returns [`crate::Error::Failed`] if the
/// RNG fails or if every retry produced an invalid candidate (`r == 0`,
/// `r + k == n`, or `s == 0`).
#[doc(hidden)]
pub fn sign_raw_with_id<R: TryCryptoRng>(
    key: &Sm2PrivateKey,
    id: &[u8],
    message: &[u8],
    rng: &mut R,
) -> Result<(U256, U256), crate::Error> {
    if id.len() > MAX_ID_LEN {
        return Err(crate::Error::Failed);
    }
    let public = key.public_key();
    let z = compute_z(&public, id);

    let e_bytes = {
        let mut h = Sm3::new();
        h.update(&z);
        h.update(message);
        h.finalize()
    };
    sign_raw_digest(key, &e_bytes, rng)
}

pub(crate) fn sign_raw_digest<R: TryCryptoRng>(
    key: &Sm2PrivateKey,
    e_bytes: &[u8; DIGEST_SIZE],
    rng: &mut R,
) -> Result<(U256, U256), crate::Error> {
    let e_scalar = Fn::new(&U256::from_be_slice(e_bytes));

    let mut chosen: CtOption<RsPair> = CtOption::new(RsPair::default(), Choice::from(0));
    for _ in 0..SIGN_RETRY_BUDGET {
        // `None` == an RNG failure (public, not secret-derived). Short-circuit
        // to `Failed` so a transient RNG error is never masked by a later
        // retry succeeding — honoring the A-3 / FFI no-panic-RNG contract
        // (the RNG must produce entropy on every attempt). Candidate
        // invalidity (`r`/`s`/exhaustion) stays a masked `CtOption`, not a
        // branch.
        let Some(candidate) = try_sign_once(key, &e_scalar, rng) else {
            return Err(crate::Error::Failed);
        };
        chosen = ct_or_else(chosen, candidate);
    }

    let pair: Option<RsPair> = chosen.into();
    let pair = pair.ok_or(crate::Error::Failed)?;
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

/// Returns `None` on RNG failure (a *public* condition the caller short-
/// circuits to `Failed`); `Some(CtOption)` otherwise, where the `CtOption`
/// is the masked candidate signature (invalid if `r`/`s` rejected or the
/// nonce sampler exhausted its budget).
#[allow(clippy::similar_names, clippy::many_single_char_names)]
fn try_sign_once<R: TryCryptoRng>(
    key: &Sm2PrivateKey,
    e: &Fn,
    rng: &mut R,
) -> Option<CtOption<RsPair>> {
    // RNG FAILURE is public (not secret-derived): the `?` propagates it as
    // `None` so the caller fails the whole operation. Budget EXHAUSTION, by
    // contrast, IS secret-derived (it depends on the random nonce bytes), so
    // the sampler returns it as the `sample_ok` Choice rather than as `None`:
    // on exhaustion `k` is a dummy (1) and the FULL signing computation still
    // runs in constant time, with the result masked out by folding
    // `sample_ok` into `valid` below. No branch on the exhaustion bit.
    let (mut k, sample_ok) = sample_nonzero_scalar(rng)?;
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
    let mut one_plus_d = one + *d;
    let one_plus_d_inv = one_plus_d.invert();
    let mut rd = r * *d;
    let mut k_minus_rd = k - rd;

    let mut inv_unwrapped: Fn = one_plus_d_inv.unwrap_or(Fn::new(&U256::ONE));
    let inv_ok: Choice = one_plus_d_inv.is_some().into();

    let mut s = inv_unwrapped * k_minus_rd;
    let s_u = s.retrieve();
    let s_zero: Choice = s_u.ct_eq(&U256::ZERO);

    // Fold the sampler's `sample_ok` in: on budget exhaustion the dummy `k`
    // produced an (r, s) that must be rejected without a branch.
    let valid = !bad_r & !s_zero & inv_ok & sample_ok;
    let out = CtOption::new(RsPair { r: r_u, s: s_u }, valid);

    // B-4 (v0.23): wipe the secret-derived scalar intermediates. `Fn`
    // (`ConstMontyForm`) implements `zeroize::DefaultIsZeroes` under
    // crypto-bigint's `zeroize` feature (enabled in the workspace
    // `Cargo.toml`), giving a real `.zeroize()` on the Montgomery
    // representation. The nonce `k`, `1 + d` (which reveals `d`
    // additively), the inverse `(1+d)^-1`, `r·d`, `k − r·d`, and `s` are
    // all functions of the secret `k`/`d`; a nonce leak alone permits
    // private-key recovery from `(r, s)`. The public outputs `r_u`/`s_u`
    // (already in `out`) are deliberately NOT wiped. (The `subtle::CtOption`
    // `one_plus_d_inv` is `Copy` and holds the same inverse value as the
    // wiped `inv_unwrapped`; subtle exposes no `zeroize` on `CtOption`, so
    // that duplicate bit-pattern falls under the documented best-effort
    // stack-zeroization posture — see `SECURITY.md`.)
    k.zeroize();
    one_plus_d.zeroize();
    inv_unwrapped.zeroize();
    rd.zeroize();
    k_minus_rd.zeroize();
    s.zeroize();

    Some(out)
}

/// Fixed-budget constant-time scalar sampler in `[1, upper_exclusive - 1]`.
/// When `upper_exclusive == n` (where `n ≈ 2^256 − 2^224`), per-draw reject
/// probability is `≈ 2^-32`, so a 4-draw budget exhausts (all draws invalid)
/// with probability `≈ 2^-128`.
///
/// Returns:
/// - `None` **only** on RNG failure — a *public* (not secret-derived)
///   condition the caller may branch on (it collapses to `Failed`).
/// - `Some((k, sample_ok))` otherwise, where `sample_ok` is a constant-time
///   [`Choice`] that is set iff a valid draw was found. On exhaustion
///   (`sample_ok == 0`) `k` is a **dummy** scalar (1, a valid curve scalar
///   that cannot panic `mul_g`); the caller folds `sample_ok` into its own
///   validity mask instead of branching on the exhaustion bit (which IS
///   secret-derived). The loop always runs `NONCE_SAMPLE_BUDGET` iterations
///   and the first valid draw is kept by masked select — no `if`/`bool` on
///   secret-derived bytes.
pub(crate) const NONCE_SAMPLE_BUDGET: usize = 4;

pub(crate) fn sample_scalar_in_range<R: TryCryptoRng>(
    rng: &mut R,
    upper_exclusive: &U256,
) -> Option<(Fn, Choice)> {
    let mut chosen = U256::ONE;
    let mut found = Choice::from(0u8);
    for _ in 0..NONCE_SAMPLE_BUDGET {
        let mut buf = [0u8; 32];
        // RNG failure is NOT secret-derived: collapsing it to None here is
        // a public-path early return (becomes Error::Failed upstream). Wipe
        // both this draw's buffer AND any already-selected `chosen` scalar
        // (an earlier valid draw) before bailing.
        if rng.try_fill_bytes(&mut buf).is_err() {
            buf.zeroize();
            chosen.zeroize();
            return None;
        }
        let mut candidate = U256::from_be_slice(&buf);
        let valid = !candidate.ct_eq(&U256::ZERO) & candidate.ct_lt(upper_exclusive);
        let take = valid & !found; // keep the FIRST valid draw
        chosen.conditional_assign(&candidate, take);
        found |= valid;
        candidate.zeroize();
        buf.zeroize();
    }
    // Always return the (possibly dummy) scalar + the CT validity bit;
    // budget exhaustion is folded into the caller's mask, never branched.
    let k = Fn::new(&chosen);
    chosen.zeroize();
    Some((k, found))
}

/// Fixed-budget constant-time nonzero-scalar sampler (`[1, n-1]`).
pub(crate) fn sample_nonzero_scalar<R: TryCryptoRng>(rng: &mut R) -> Option<(Fn, Choice)> {
    sample_scalar_in_range(rng, Fn::MODULUS.as_ref())
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
    use rand_core::{TryCryptoRng, TryRng};

    struct SequenceRng {
        values: [U256; NONCE_SAMPLE_BUDGET],
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
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid scalar");
        let public = key.public_key();
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
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid scalar");
        let too_long = alloc::vec![0u8; MAX_ID_LEN + 1];
        let mut rng = SysRng;
        let result = sign_with_id(&key, &too_long, b"msg", &mut rng);
        assert_eq!(result, Err(crate::Error::Failed));
    }

    /// The fixed-budget masked sampler keeps the FIRST valid draw and
    /// rejects an out-of-range (`>= n`) first candidate via masked
    /// select. v0.23 (B-7): the sampler runs the full
    /// `NONCE_SAMPLE_BUDGET` regardless of which draw was valid (no
    /// data-dependent loop count), so the RNG is consumed exactly
    /// `NONCE_SAMPLE_BUDGET` times.
    #[test]
    fn sample_nonzero_scalar_rejects_candidates_above_order() {
        let n_plus_one = Fn::MODULUS.as_ref().wrapping_add(&U256::ONE);
        // First draw is out-of-range (rejected); second is the valid
        // value 2 (kept); the remaining draws are also valid but must
        // NOT displace the first-valid representative.
        let mut rng = SequenceRng {
            values: [
                n_plus_one,
                U256::from_u64(2),
                U256::from_u64(7),
                U256::from_u64(9),
            ],
            index: 0,
        };

        let (k, sample_ok) = sample_nonzero_scalar(&mut rng).expect("rng ok");
        assert!(bool::from(sample_ok), "a valid draw was found");
        assert_eq!(k.retrieve(), U256::from_u64(2), "first valid draw is kept");
        assert_eq!(
            rng.index, NONCE_SAMPLE_BUDGET,
            "fixed-budget sampler consumes exactly NONCE_SAMPLE_BUDGET draws"
        );
    }

    /// All-invalid draws exhaust the budget → `Some((dummy, sample_ok=0))`
    /// (NOT `None`, which is reserved for RNG failure). The exhaustion bit
    /// is folded into the caller's CT validity mask, never branched.
    /// Uses `n` itself (rejected by `< n`) for every draw.
    #[test]
    fn sample_nonzero_scalar_exhausts_budget_to_invalid_choice() {
        let n = *Fn::MODULUS.as_ref();
        let mut rng = SequenceRng {
            values: [n; NONCE_SAMPLE_BUDGET],
            index: 0,
        };
        let (_dummy, sample_ok) = sample_nonzero_scalar(&mut rng).expect("rng ok");
        assert!(!bool::from(sample_ok), "exhaustion yields sample_ok == 0");
        assert_eq!(rng.index, NONCE_SAMPLE_BUDGET);
    }

    /// An erroring RNG collapses to `None` (the no-panic RNG-failure
    /// path).
    #[test]
    fn sample_nonzero_scalar_rng_error_is_none() {
        struct ErrRng;
        impl TryRng for ErrRng {
            type Error = core::fmt::Error;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Err(core::fmt::Error)
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Err(core::fmt::Error)
            }
            fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), Self::Error> {
                Err(core::fmt::Error)
            }
        }
        impl TryCryptoRng for ErrRng {}
        assert!(sample_nonzero_scalar(&mut ErrRng).is_none());
    }

    /// `sample_nonzero_scalar` samples `[1, n-1]` while
    /// `sample_scalar_in_range(rng, &(n - 1))` samples `[1, n-2]` and
    /// rejects `n - 1`.
    #[test]
    fn sample_nonzero_scalar_vs_sample_scalar_in_range_upper_bound() {
        let n = *Fn::MODULUS.as_ref();
        let n_minus_one = n.wrapping_sub(&U256::ONE);
        let n_minus_two = n_minus_one.wrapping_sub(&U256::ONE);
        let values = [
            n_minus_one,
            n_minus_two,
            U256::from_u64(3),
            U256::from_u64(4),
        ];

        let mut rng_nonce = SequenceRng { values, index: 0 };
        let (k_nonce, ok_nonce) = sample_nonzero_scalar(&mut rng_nonce).expect("rng ok");
        assert!(bool::from(ok_nonce));
        assert_eq!(k_nonce.retrieve(), n_minus_one);
        assert_eq!(rng_nonce.index, NONCE_SAMPLE_BUDGET);

        let mut rng_range = SequenceRng { values, index: 0 };
        let (k_range, ok_range) =
            sample_scalar_in_range(&mut rng_range, &n_minus_one).expect("rng ok");
        assert!(bool::from(ok_range));
        assert_eq!(k_range.retrieve(), n_minus_two);
        assert_eq!(rng_range.index, NONCE_SAMPLE_BUDGET);
    }

    /// Streaming `Sm2Hasher` across arbitrary chunk sizes (0-byte, 1-byte,
    /// 63/64/65-byte boundaries, large multi-KB message) matches manual
    /// `SM3(compute_z || M)` and cross-verifies between `sign_digest`/
    /// `verify_digest` and `sign_with_id`/`verify_with_id`.
    #[test]
    fn sm2_hasher_chunking_and_cross_verify() {
        use crate::sm2::verify::{verify_digest, verify_with_id};

        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid scalar");
        let pk = key.public_key();
        let id = b"ALICE123@YAHOO.COM";
        let z = compute_z(&pk, id);

        let mut rng = SysRng;
        for len in [0usize, 1, 63, 64, 65, 128, 5000] {
            let mut msg = alloc::vec![0u8; len];
            for (idx, byte) in msg.iter_mut().enumerate() {
                *byte = u8::try_from((idx.wrapping_mul(31) ^ (idx >> 8)) % 251)
                    .expect("mod 251 fits in u8");
            }

            let expected_e = {
                let mut sm3 = Sm3::new();
                sm3.update(&z);
                sm3.update(&msg);
                sm3.finalize()
            };

            // One-shot update (plus empty updates around it).
            let mut single = Sm2Hasher::new(&pk, id).expect("valid pk/id");
            single.update(&[]);
            single.update(&msg);
            single.update(&[]);
            let single_digest = single.finalize();
            assert_eq!(single_digest.as_bytes(), &expected_e, "len={len}");

            // Cross-verify `sign_digest` -> `verify_digest` & `verify_with_id`,
            // and `sign_with_id` -> `verify_digest`.
            let sig_from_digest = sign_digest(&key, &single_digest, &mut rng).expect("sign_digest");
            assert!(verify_digest(&pk, &single_digest, &sig_from_digest));
            assert!(verify_with_id(&pk, id, &msg, &sig_from_digest));

            let sig_from_id = sign_with_id(&key, id, &msg, &mut rng).expect("sign_with_id");
            assert!(verify_digest(&pk, &single_digest, &sig_from_id));

            // Arbitrary chunk splits.
            for chunk_size in [1usize, 7, 31, 63, 64, 65, 127, 128, 129, 1024] {
                if len > 256 && chunk_size == 1 {
                    // Skip 5000 1-byte iterations to keep test fast while still
                    // exercising 1-byte chunking up to 128 bytes.
                    continue;
                }
                let mut h = Sm2Hasher::new(&pk, id).expect("valid pk/id");
                for chunk in msg.chunks(chunk_size) {
                    h.update(&[]);
                    h.update(chunk);
                }
                let digest = h.finalize();
                assert_eq!(digest, single_digest, "len={len}, chunk={chunk_size}");
            }
        }

        // `new_default_id` matches `new(..., DEFAULT_SIGNER_ID)` and `Clone`
        // forks independently mid-stream.
        let mut h_default = Sm2Hasher::new_default_id(&pk).expect("valid pk");
        let mut h_explicit = Sm2Hasher::new(&pk, DEFAULT_SIGNER_ID).expect("valid pk");
        h_default.update(b"part1-");
        let mut h_fork = h_default.clone();
        h_default.update(b"part2");
        h_fork.update(b"other");
        h_explicit.update(b"part1-part2");
        let expected_default = h_explicit.finalize();
        assert_eq!(h_default.finalize(), expected_default);
        assert_ne!(h_fork.finalize(), expected_default);
    }

    /// `Sm2Hasher::new` and `Sm2Hasher::new_default_id` return `None` without
    /// panicking on over-long IDs (`MAX_ID_LEN + 1`) and identity public keys.
    #[test]
    fn sm2_hasher_rejects_invalid_inputs_no_panic() {
        use crate::sm2::point::ProjectivePoint;

        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid scalar");
        let pk = key.public_key();

        let too_long = alloc::vec![0x5Au8; MAX_ID_LEN + 1];
        assert!(Sm2Hasher::new(&pk, &too_long).is_none());

        // Exact boundary `MAX_ID_LEN` succeeds and matches `compute_z` + `Sm3`.
        let max_id = alloc::vec![0x5Au8; MAX_ID_LEN];
        let mut h_max = Sm2Hasher::new(&pk, &max_id).expect("MAX_ID_LEN accepted");
        h_max.update(b"boundary");
        let expected_max = {
            let z = compute_z(&pk, &max_id);
            let mut sm3 = Sm3::new();
            sm3.update(&z);
            sm3.update(b"boundary");
            sm3.finalize()
        };
        assert_eq!(h_max.finalize().as_bytes(), &expected_max);

        // Identity public key rejected cleanly by both `new` and `new_default_id`.
        let identity = Sm2PublicKey::from_point(ProjectivePoint::identity());
        assert!(Sm2Hasher::new(&identity, b"id").is_none());
        assert!(Sm2Hasher::new(&identity, DEFAULT_SIGNER_ID).is_none());
        assert!(Sm2Hasher::new_default_id(&identity).is_none());
    }

    /// `Sm2Digest::from_precomputed_z_hash` round-trips with `Sm2Hasher::finalize`.
    #[test]
    fn sm2_digest_from_precomputed_z_hash_round_trip() {
        use crate::sm2::verify::verify_digest;

        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid scalar");
        let pk = key.public_key();

        let mut h = Sm2Hasher::new_default_id(&pk).expect("valid pk");
        h.update(b"precomputed round-trip");
        let streamed = h.finalize();

        let raw: [u8; 32] = *streamed.as_bytes();
        let wrapped = Sm2Digest::from_precomputed_z_hash(raw);
        assert_eq!(wrapped, streamed);
        assert_eq!(wrapped.as_bytes(), &raw);

        let mut rng = SysRng;
        let sig = sign_digest(&key, &wrapped, &mut rng).expect("sign_digest");
        assert!(verify_digest(&pk, &streamed, &sig));
    }

    /// `sign_digest` returns `Err(Error::Failed)` without panicking when the
    /// RNG fails or exhausts the nonce-sampling budget.
    #[test]
    fn sign_digest_rng_error_and_exhaustion() {
        struct ErrRng;
        impl TryRng for ErrRng {
            type Error = core::fmt::Error;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Err(core::fmt::Error)
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Err(core::fmt::Error)
            }
            fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), Self::Error> {
                Err(core::fmt::Error)
            }
        }
        impl TryCryptoRng for ErrRng {}

        struct ExhaustRng {
            invalid: [u8; 32],
        }
        impl TryRng for ExhaustRng {
            type Error = Infallible;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(0)
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(0)
            }
            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
                assert_eq!(dst.len(), 32);
                dst.copy_from_slice(&self.invalid);
                Ok(())
            }
        }
        impl TryCryptoRng for ExhaustRng {}

        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid scalar");
        let mut h = Sm2Hasher::new_default_id(&key.public_key()).expect("valid pk");
        h.update(b"rng failure");
        let digest = h.finalize();

        assert_eq!(
            sign_digest(&key, &digest, &mut ErrRng),
            Err(crate::Error::Failed)
        );

        let n = *Fn::MODULUS.as_ref();
        let mut exhaust_rng = ExhaustRng {
            invalid: crate::u256_to_be32(&n),
        };
        assert_eq!(
            sign_digest(&key, &digest, &mut exhaust_rng),
            Err(crate::Error::Failed)
        );
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
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid scalar");
        let id = b"ALICE123@YAHOO.COM";
        let message = b"message digest";
        let mut rng =
            FixedScalarRng::new("59276E27D506861A16680F3AD9C02DCFBFBF904F533DA0AC2EE1C9A45B58FF85");
        let der = sign_with_id(&key, id, message, &mut rng).expect("sign succeeds");
        let (r, s) = crate::asn1::sig::decode_sig(&der).expect("our own DER decodes");
        assert_eq!(
            r,
            crate::u256_to_be32(&U256::from_be_hex(
                "88348A09A3E324C4FE946843123E40C175468F3E36481885844A144D2167EA4C"
            )),
            "r mismatch"
        );
        assert_eq!(
            s,
            crate::u256_to_be32(&U256::from_be_hex(
                "0AD2CE552FD33EAB792E5A2805E0504D014C96135F8E03891087132ABB24D48D"
            )),
            "s mismatch"
        );
    }

    /// GB/T 32918.2 Appendix A.2 fixed-k KAT: streamed `Sm2Hasher` +
    /// `sign_digest` produces a byte-identical DER signature to `sign_with_id`
    /// under the same RNG stream, and verifies under both `verify_digest` and
    /// `verify_with_id`.
    #[test]
    fn gbt32918_appendix_a2_fixed_k_digest_matches_sign_with_id() {
        use crate::sm2::verify::{verify_digest, verify_with_id};

        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid scalar");
        let pk = key.public_key();
        let id = b"ALICE123@YAHOO.COM";
        let message = b"message digest";
        let k_hex = "59276E27D506861A16680F3AD9C02DCFBFBF904F533DA0AC2EE1C9A45B58FF85";

        let mut hasher = Sm2Hasher::new(&pk, id).expect("valid pk/id");
        hasher.update(b"message ");
        hasher.update(b"digest");
        let digest = hasher.finalize();

        let mut rng_digest = FixedScalarRng::new(k_hex);
        let mut rng_with_id = FixedScalarRng::new(k_hex);
        let der_digest = sign_digest(&key, &digest, &mut rng_digest).expect("sign_digest succeeds");
        let der_with_id =
            sign_with_id(&key, id, message, &mut rng_with_id).expect("sign_with_id succeeds");

        assert_eq!(der_digest, der_with_id);

        let (r, s) = crate::asn1::sig::decode_sig(&der_digest).expect("our own DER decodes");
        assert_eq!(
            r,
            crate::u256_to_be32(&U256::from_be_hex(
                "88348A09A3E324C4FE946843123E40C175468F3E36481885844A144D2167EA4C"
            )),
            "r mismatch"
        );
        assert_eq!(
            s,
            crate::u256_to_be32(&U256::from_be_hex(
                "0AD2CE552FD33EAB792E5A2805E0504D014C96135F8E03891087132ABB24D48D"
            )),
            "s mismatch"
        );

        assert!(verify_digest(&pk, &digest, &der_digest));
        assert!(verify_with_id(&pk, id, message, &der_digest));
    }
}
