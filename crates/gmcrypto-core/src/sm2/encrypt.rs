//! SM2 public-key encryption (GB/T 32918.4-2017 §6).
//!
//! # Algorithm
//!
//! ```text
//! Input:  recipient public key P_B, plaintext M
//! Output: ciphertext (C1 = kG, C3 = SM3(x2 || M || y2), C2 = M XOR KDF(x2 || y2, |M|))
//!
//! 1. Pick random k in [1, n-1]
//! 2. C1 = kG = (x1, y1)
//! 3. (x2, y2) = k * P_B
//! 4. t = KDF(x2 || y2, |M| in bits)
//! 5. If t is all zeros, retry from step 1 (negligible probability for non-empty M)
//! 6. C2 = M XOR t
//! 7. C3 = SM3(x2 || M || y2)
//! 8. Output GM/T 0009 DER encoding of (x1, y1, C3, C2)
//! ```
//!
//! # KDF (GB/T 32918.4 §5.4.3)
//!
//! SM3-based counter-mode key-derivation:
//!
//! ```text
//! KDF(Z, klen):
//!   ct = 1
//!   while output length < klen:
//!     output ||= SM3(Z || ct.to_be_bytes())
//!     ct += 1
//!   return output truncated to klen bits
//! ```
//!
//! v0.2 places this KDF inside `sm2::encrypt` rather than the top-level
//! `gmcrypto_core::kdf` module. `kdf.rs` is reserved for PBKDF2.
//!
//! # Failure-mode invariant
//!
//! [`encrypt`] returns `Result<Vec<u8>, crate::Error>` with a single
//! `Failed` variant — collapses every retry-budget-exhausted, identity-
//! point, or KDF-zero outcome to one uninformative shape. With a
//! [`CryptoRng`], the cumulative-failure probability is `≤ 2^-512` per
//! call across all plaintext lengths (1-byte through arbitrary), per
//! the [`ENCRYPT_RETRY_BUDGET`] table — i.e. never observed in
//! practice.
//!
//! # Constant-time stance
//!
//! Encrypt operates on the recipient's **public key** and a freshly
//! sampled `k`; no caller-controlled secret is touched. The only
//! secret-derived intermediates are `(x2, y2) = kP_B` and the KDF
//! output, both of which are wiped before return. v0.2's dudect
//! harness covers the secret-touching path on the **decrypt** side
//! (`ct_sm2_decrypt`); a `ct_sm2_encrypt` target is optional and
//! deferred until v0.3.

use crate::asn1::ciphertext::{Sm2Ciphertext, encode};
use crate::sm2::curve::{Fn, Fp, b};
use crate::sm2::point::ProjectivePoint;
use crate::sm2::public_key::Sm2PublicKey;
use crate::sm2::scalar_mul::{mul_g, mul_var};
use crate::sm2::sign::sample_nonzero_scalar;
use crate::sm3::{DIGEST_SIZE, Sm3};
use alloc::vec::Vec;
use crypto_bigint::U256;
use rand_core::{CryptoRng, Rng};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Retry budget for the KDF-zero rejection step.
///
/// **Per-iteration KDF-zero probability is length-dependent**, not the
/// asymptotic `2^-256` figure that v0.2's first cut assumed. For a
/// plaintext of `L` bytes the KDF output is `L` bytes long and
/// `P(all-zero) = 2^(-8·L)`. For very short plaintexts the per-call
/// probability is non-negligible:
///
/// | `|M|` (bytes) | per-iteration P(zero) | budget=4 P(fail) | budget=64 P(fail) |
/// |---:|---:|---:|---:|
/// | 1  | `2^-8`   | `2^-32`  | `2^-512`  |
/// | 2  | `2^-16`  | `2^-64`  | `2^-1024` |
/// | 4  | `2^-32`  | `2^-128` | `2^-2048` |
/// | 32 | `2^-256` | `2^-1024`| `2^-16384`|
///
/// A budget of 64 makes the cumulative failure probability negligible
/// at any plaintext length while keeping the loop bounded for liveness
/// under degenerate RNGs. GB/T 32918.4 specifies the retry as
/// indefinite; the 64-step bound is a defense-in-depth ceiling, never
/// reached in practice with a uniform CSPRNG.
const ENCRYPT_RETRY_BUDGET: usize = 64;

/// Encrypt `plaintext` to recipient `public`, returning a GM/T 0009
/// DER-encoded ciphertext.
///
/// `rng` must be a [`CryptoRng`]. With a CSPRNG, encrypt failure
/// probability is `≤ 2^-512` for any plaintext length — see the
/// [`ENCRYPT_RETRY_BUDGET`] table for the per-length math.
///
/// # Errors
///
/// Returns [`crate::Error::Failed`] if the recipient public key is the
/// identity point (a malicious caller could construct one via
/// [`Sm2PublicKey::from_point`]) or if every retry produced an
/// all-zeros KDF output.
pub fn encrypt<R: CryptoRng + Rng>(
    public: &Sm2PublicKey,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, crate::Error> {
    if bool::from(public.point().is_identity()) {
        return Err(crate::Error::Failed);
    }
    for _ in 0..ENCRYPT_RETRY_BUDGET {
        let k = sample_nonzero_scalar(rng);
        if let Some(ct) = try_encrypt_once(public, plaintext, &k) {
            return Ok(encode(&ct));
        }
    }
    Err(crate::Error::Failed)
}

/// Single encrypt attempt. Returns `None` when the KDF output is
/// all-zeros (caller retries with a fresh `k`).
fn try_encrypt_once(public: &Sm2PublicKey, plaintext: &[u8], k: &Fn) -> Option<Sm2Ciphertext> {
    // C1 = kG; (x1, y1) = affine(C1)
    let c1 = mul_g(k);
    let (x1, y1) = c1.to_affine()?;

    // (x2, y2) = k * P_B; affine
    let kp = mul_var(k, &public.point());
    let (x2, y2) = kp.to_affine()?;

    // Z = x2 || y2 (64 bytes), the KDF input.
    let mut z = [0u8; 64];
    z[..32].copy_from_slice(&x2.retrieve().to_be_bytes());
    z[32..].copy_from_slice(&y2.retrieve().to_be_bytes());

    // t = KDF(Z, |plaintext|)
    let mut t = alloc::vec![0u8; plaintext.len()];
    kdf(&z, &mut t);

    // KDF-zero rejection: spec requires retry on all-zeros KDF output.
    // Vacuously satisfied for empty plaintext (no output bytes to check).
    if !plaintext.is_empty() && all_zero_ct(&t) {
        // Wipe the all-zero buffer (defensive; it carries no secret
        // since it's all zeros, but the KDF input Z is secret-derived).
        z.zeroize();
        t.zeroize();
        return None;
    }

    // C2 = M XOR t (in place, reusing the t buffer).
    for (i, byte) in plaintext.iter().enumerate() {
        t[i] ^= byte;
    }
    let c2 = t; // rename: it now holds C2.

    // C3 = SM3(x2 || M || y2)
    let mut h = Sm3::new();
    h.update(&z[..32]);
    h.update(plaintext);
    h.update(&z[32..]);
    let c3 = h.finalize();

    // Wipe the secret-derived (x2 || y2) buffer.
    z.zeroize();

    Some(Sm2Ciphertext {
        x: x1.retrieve(),
        y: y1.retrieve(),
        hash: c3,
        ciphertext: c2,
    })
}

/// SM3 counter-mode KDF per GB/T 32918.4 §5.4.3.
///
/// Writes `output.len()` bytes of derived material into `output` from
/// the input `z`. `output` may be any length, including empty (in
/// which case the function is a no-op).
///
/// Visible to `sm2::decrypt` via `pub(super)`; not part of the public
/// API and not SemVer-stable.
pub(super) fn kdf(z: &[u8], output: &mut [u8]) {
    let mut counter: u32 = 1;
    let mut written = 0;
    while written < output.len() {
        let mut h = Sm3::new();
        h.update(z);
        h.update(&counter.to_be_bytes());
        let digest = h.finalize();
        let block_remaining = output.len() - written;
        let copy_len = block_remaining.min(DIGEST_SIZE);
        output[written..written + copy_len].copy_from_slice(&digest[..copy_len]);
        written += copy_len;
        counter += 1;
    }
}

/// Constant-time all-zero test: `acc |= byte` over the whole buffer,
/// then check `acc == 0`. The final equality is on a non-secret
/// summary value (the OR of all bytes), so the bool result is the
/// only timing signal — and that signal is the "is the KDF output
/// all-zero?" question, which is itself an explicit spec-mandated
/// branch (the retry).
fn all_zero_ct(buf: &[u8]) -> bool {
    let mut acc: u8 = 0;
    for b in buf {
        acc |= b;
    }
    bool::from(acc.ct_eq(&0u8))
}

/// Validate that `(x, y)` lies on the SM2 curve `y² ≡ x³ - 3x + b
/// (mod p)`. Defense against invalid-curve attacks on `decrypt` —
/// without this check, an attacker submitting `C1` on a different
/// curve could leak bits of the recipient's private key via
/// `d_B * C1`.
///
/// Visible to the rest of the crate (W2's `spki` / `sec1` reuse it
/// at the import boundary). Not part of the public API.
pub(crate) fn point_on_curve(x: &Fp, y: &Fp) -> bool {
    let three = Fp::new(&U256::from_u64(3));
    let lhs = *y * *y;
    let rhs = (*x) * (*x) * (*x) - three * (*x) + b();
    bool::from(lhs.retrieve().ct_eq(&rhs.retrieve()))
}

/// Construct a [`ProjectivePoint`] from validated affine `(x, y)`
/// coordinates. Visible to the rest of the crate (W2's `spki` / `sec1`
/// reuse it after `point_on_curve`); not part of the public API.
pub(crate) const fn projective_from_affine(x: Fp, y: Fp) -> ProjectivePoint {
    ProjectivePoint {
        x,
        y,
        z: Fp::new(&U256::ONE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::private_key::Sm2PrivateKey;
    use core::convert::Infallible;
    use rand_core::{TryCryptoRng, TryRng};

    /// Test-only RNG that emits a fixed 32-byte value on every
    /// `fill_bytes` call. Used to drive `encrypt` with a known `k` for
    /// KAT-style tests.
    struct FixedScalarRng {
        bytes: [u8; 32],
    }

    impl FixedScalarRng {
        const fn new(bytes: [u8; 32]) -> Self {
            Self { bytes }
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
            dst.copy_from_slice(&self.bytes);
            Ok(())
        }
    }

    impl TryCryptoRng for FixedScalarRng {}

    /// Build a deterministic 64-byte test `Z` for the KDF cross-checks.
    /// Content doesn't matter — the goal is exact-length, reproducible bytes.
    fn synthetic_z() -> [u8; 64] {
        let mut z = [0u8; 64];
        for (i, b) in z.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            {
                *b = (i as u8).wrapping_mul(7);
            }
        }
        z
    }

    /// Single-block KDF cross-check: 32-byte output equals
    /// `SM3(z || 0x00000001)`.
    #[test]
    fn kdf_single_block_matches_manual_sm3() {
        let z = synthetic_z();
        let mut out = [0u8; 32];
        kdf(&z, &mut out);

        let mut h = Sm3::new();
        h.update(&z);
        h.update(&1u32.to_be_bytes());
        let expected = h.finalize();
        assert_eq!(out, expected);
    }

    /// Two-block KDF cross-check: 40 bytes spans two SM3 invocations
    /// with `ct = 1` then `ct = 2`.
    #[test]
    fn kdf_two_block_matches_manual_sm3() {
        let z = synthetic_z();
        let mut out = [0u8; 40];
        kdf(&z, &mut out);

        let mut h1 = Sm3::new();
        h1.update(&z);
        h1.update(&1u32.to_be_bytes());
        let block1 = h1.finalize();
        let mut h2 = Sm3::new();
        h2.update(&z);
        h2.update(&2u32.to_be_bytes());
        let block2 = h2.finalize();

        assert_eq!(&out[..32], &block1);
        assert_eq!(&out[32..40], &block2[..8]);
    }

    /// Empty-output KDF is a no-op.
    #[test]
    fn kdf_empty_output_is_noop() {
        let z = b"whatever";
        let mut out: [u8; 0] = [];
        kdf(z, &mut out);
        // (no assertion needed — just verifying it doesn't panic and
        // returns a 0-length output)
    }

    /// `point_on_curve` accepts the SM2 generator `G`.
    #[test]
    fn point_on_curve_accepts_generator() {
        let g = ProjectivePoint::generator();
        let (gx, gy) = g.to_affine().expect("G is finite");
        assert!(point_on_curve(&gx, &gy));
    }

    /// `point_on_curve` rejects an arbitrary off-curve point.
    #[test]
    fn point_on_curve_rejects_off_curve() {
        // `(1, 1)` is almost certainly not on SM2 (overwhelmingly
        // likely false; cross-checking the on-curve guard is the
        // point of the test).
        let x = Fp::new(&U256::ONE);
        let y = Fp::new(&U256::ONE);
        assert!(!point_on_curve(&x, &y));
    }

    /// Encrypt rejects an identity-point public key. (Same-style
    /// hardening as `verify_with_id`'s identity-rejection from v0.1.)
    #[test]
    fn encrypt_rejects_identity_pubkey() {
        let pk = Sm2PublicKey::from_point(ProjectivePoint::identity());
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        assert_eq!(
            encrypt(&pk, b"any plaintext", &mut rng),
            Err(crate::Error::Failed)
        );
    }

    /// Fixed-`k` smoke test: encrypt with a deterministic RNG produces
    /// a deterministic ciphertext (round-trip is in `sm2::decrypt`'s
    /// tests).
    #[test]
    fn encrypt_with_fixed_k_is_deterministic() {
        let d =
            U256::from_be_hex("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid d");
        let pk = Sm2PublicKey::from_point(key.public_key());
        let k_bytes =
            U256::from_be_hex("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F")
                .to_be_bytes();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&k_bytes);
        let mut rng_a = rand_core::UnwrapErr(FixedScalarRng::new(bytes));
        let mut rng_b = rand_core::UnwrapErr(FixedScalarRng::new(bytes));
        let der_a = encrypt(&pk, b"encryption standard", &mut rng_a).expect("encrypt a");
        let der_b = encrypt(&pk, b"encryption standard", &mut rng_b).expect("encrypt b");
        assert_eq!(der_a, der_b, "fixed-k encrypt must be deterministic");
    }
}
