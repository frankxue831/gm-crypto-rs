//! SM2 key exchange — GM/T 0003.3 (≡ GB/T 32918.3-2016) with key confirmation.
//!
//! Two role state-machines, `Sm2KxInitiator` and `Sm2KxResponder`. Pure-core;
//! reuses the SM2 curve arithmetic, the masked ephemeral sampler, the SM3 KDF,
//! `compute_z`, and the SEC1 point validation. Confidentiality of the agreed
//! key relies on the caller keeping each ephemeral single-use (the typestate
//! enforces it).

extern crate alloc;

use crate::Error;
use crate::sm2::curve::Fn;
use crate::sm2::encrypt::KDF_MAX_OUTPUT;
use crate::sm2::point::ProjectivePoint;
use crate::sm2::scalar_mul::mul_g;
use crate::sm2::sign::{MAX_ID_LEN, compute_z, sample_nonzero_scalar};
use crate::sm2::{Sm2PrivateKey, Sm2PublicKey};
use alloc::vec::Vec;
use crypto_bigint::U256;
use rand_core::TryCryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

type Result<T> = core::result::Result<T, Error>;

/// On-wire ephemeral point `R` (SEC1 uncompressed `04 ‖ X(32) ‖ Y(32)`).
///
/// Caller-constructible from raw peer bytes; validation (tag, range,
/// on-curve, non-identity) is deferred to the step that consumes the
/// peer's point (`respond` / `confirm`), which collapses any invalid
/// encoding to [`Error::Failed`].
#[derive(Clone)]
pub struct Sm2KxEphemeralPoint([u8; 65]);

impl Sm2KxEphemeralPoint {
    /// The on-wire bytes (`04 ‖ X ‖ Y`).
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 65] {
        self.0
    }

    /// Wrap peer-supplied bytes. No validation here — the consuming
    /// step validates and collapses failures to [`Error::Failed`].
    #[must_use]
    pub const fn from_bytes(b: &[u8; 65]) -> Self {
        Self(*b)
    }
}

/// Agreed shared key (`klen` bytes). Zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct Sm2SharedKey(Vec<u8>);

impl Sm2SharedKey {
    /// The agreed key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// 32-byte SM3 key-confirmation tag (`S_A` / `S_B`).
#[derive(Clone)]
pub struct Sm2KxConfirm([u8; 32]);

impl Sm2KxConfirm {
    /// The tag bytes.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Wrap peer-supplied tag bytes (compared constant-time later).
    #[must_use]
    pub const fn from_bytes(b: &[u8; 32]) -> Self {
        Self(*b)
    }
}

/// Shared parameter validation for both role constructors: `klen`
/// bounds (non-zero, under the KDF `u32`-counter ceiling), `id`
/// lengths (the `ENTL` field is 16-bit), and a non-identity peer
/// static key (`compute_z` requires a finite point; an identity peer
/// collapses to `Failed` instead of panicking). All public inputs —
/// branching here is not secret-dependent.
fn validate_params(
    p_peer: &Sm2PublicKey,
    id_a: &[u8],
    id_b: &[u8],
    klen: usize,
) -> Result<()> {
    let klen64 = u64::try_from(klen).map_err(|_| Error::Failed)?;
    if klen == 0
        || klen64 > KDF_MAX_OUTPUT
        || id_a.len() > MAX_ID_LEN
        || id_b.len() > MAX_ID_LEN
        || bool::from(p_peer.point().is_identity())
    {
        return Err(Error::Failed);
    }
    Ok(())
}

/// Key-exchange initiator (party A), freshly constructed.
///
/// State machine: `Sm2KxInitiator` → [`Sm2KxInitiator::produce_ephemeral`]
/// → `Sm2KxInitiatorWaiting` → `confirm` → `(Sm2SharedKey, Sm2KxConfirm)`.
/// Each step consumes `self`, so an ephemeral cannot be reused and the
/// key is unreachable before confirmation.
pub struct Sm2KxInitiator {
    d: Sm2PrivateKey,
    p_peer: ProjectivePoint,
    z_a: [u8; 32],
    z_b: [u8; 32],
    klen: usize,
}

impl Sm2KxInitiator {
    /// Build an initiator from the local static key `d_a`, the peer's
    /// static public key `p_b`, both identity strings, and the desired
    /// key length in bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if `klen` is zero or above the KDF output
    /// ceiling, an `id` exceeds `MAX_ID_LEN`, or `p_b` is the identity.
    pub fn new(
        d_a: &Sm2PrivateKey,
        p_b: &Sm2PublicKey,
        id_a: &[u8],
        id_b: &[u8],
        klen: usize,
    ) -> Result<Self> {
        validate_params(p_b, id_a, id_b, klen)?;
        Ok(Self {
            d: d_a.clone(),
            p_peer: p_b.point(),
            z_a: compute_z(&d_a.public_key(), id_a),
            z_b: compute_z(p_b, id_b),
            klen,
        })
    }
}

/// Ephemeral secret scalar `r`, wiped on drop.
///
/// The drop-wipe lives on this inner wrapper, NOT on the waiting-state
/// structs that hold it: the consuming steps (`confirm`/`finish`) take
/// `self` by value and move fields out, which Rust forbids on a type
/// with `Drop` — the same reason `Sm3` drop-wipes its state instead of
/// `HmacSm3` (whose `finalize(self)` moves fields out).
struct EphScalar(Fn);

impl Drop for EphScalar {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Sample the ephemeral secret `r ∈ [1, n−1]` and compute `R = [r]G`.
///
/// One call into the existing fixed-budget (4-draw) constant-time
/// masked sampler — it already implements the first-valid masked
/// select, so no retry wrapper here (S3). On budget exhaustion
/// (probability ≈ 2^-128) the dummy scalar still walks the full point
/// computation and the failure surfaces only at the public `Result`
/// boundary, mirroring `sign.rs`'s masked posture. RNG failure (a
/// public condition) → `Failed`.
fn sample_ephemeral<R: TryCryptoRng>(rng: &mut R) -> Result<(Fn, [u8; 65])> {
    let (r, sample_ok) = sample_nonzero_scalar(rng).ok_or(Error::Failed)?;
    let r_point = mul_g(&r);
    let (x, y) = r_point.to_affine().ok_or(Error::Failed)?;
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&crate::u256_to_be32(&x.retrieve()));
    sec1[33..65].copy_from_slice(&crate::u256_to_be32(&y.retrieve()));
    if !bool::from(sample_ok) {
        return Err(Error::Failed);
    }
    Ok((r, sec1))
}

/// Initiator after `R_A` has been produced; awaiting the responder's
/// `(R_B, S_B)`.
pub struct Sm2KxInitiatorWaiting {
    inner: Sm2KxInitiator,
    r_eph: EphScalar,
    r_point_bytes: [u8; 65],
}

impl Sm2KxInitiator {
    /// Sample the ephemeral `r_A`, compute `R_A = [r_A]G`, and advance
    /// to the waiting state. Consumes `self` so the ephemeral is
    /// single-use.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if the RNG fails or the sampler exhausts its
    /// fixed budget (probability ≈ 2^-128).
    pub fn produce_ephemeral<R: TryCryptoRng>(
        self,
        rng: &mut R,
    ) -> Result<(Sm2KxEphemeralPoint, Sm2KxInitiatorWaiting)> {
        let (r, r_bytes) = sample_ephemeral(rng)?;
        Ok((
            Sm2KxEphemeralPoint(r_bytes),
            Sm2KxInitiatorWaiting {
                inner: self,
                r_eph: EphScalar(r),
                r_point_bytes: r_bytes,
            },
        ))
    }
}

/// Key-exchange responder (party B), freshly constructed.
///
/// State machine: `Sm2KxResponder` → `respond` →
/// `Sm2KxResponderWaiting` → `finish` → `Sm2SharedKey`.
pub struct Sm2KxResponder {
    d: Sm2PrivateKey,
    p_peer: ProjectivePoint,
    z_a: [u8; 32],
    z_b: [u8; 32],
    klen: usize,
}

impl Sm2KxResponder {
    /// Build a responder from the local static key `d_b`, the peer's
    /// static public key `p_a`, both identity strings, and the desired
    /// key length in bytes.
    ///
    /// The KDF/tag input order is fixed by role, not by locality:
    /// `Z_A ‖ Z_B` always — here `Z_A` comes from the *peer* (`p_a`,
    /// `id_a`) and `Z_B` from the local key.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] under the same conditions as
    /// [`Sm2KxInitiator::new`].
    pub fn new(
        d_b: &Sm2PrivateKey,
        p_a: &Sm2PublicKey,
        id_a: &[u8],
        id_b: &[u8],
        klen: usize,
    ) -> Result<Self> {
        validate_params(p_a, id_a, id_b, klen)?;
        Ok(Self {
            d: d_b.clone(),
            p_peer: p_a.point(),
            z_a: compute_z(p_a, id_a),
            z_b: compute_z(&d_b.public_key(), id_b),
            klen,
        })
    }
}

/// avf(x) = 2^127 + (x mod 2^127), per GB/T 32918.3 (w = 127 for SM2).
/// `x_be` is the affine x-coordinate of R as a 32-byte big-endian integer.
/// Constant-time: pure bit masking, no branch on `x`. The result is
/// < 2^128 < n, so `Fn::new` is an identity reduction.
fn avf(x_be: &[u8; 32]) -> Fn {
    let mut buf = [0u8; 32];
    // Keep the low 127 bits: bytes 17..32 in full (120 bits) + low 7 bits
    // of byte 16; then force bit 127 set.
    buf[17..32].copy_from_slice(&x_be[17..32]);
    buf[16] = (x_be[16] & 0x7F) | 0x80;
    Fn::new(&U256::from_be_slice(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::U256;

    /// Test-only fixed-bytes RNG (inline, per the repo's `FixedScalarRng`
    /// idiom — `#[cfg(test)]` helpers are module-private, S10).
    pub(super) struct FixedRng(pub [u8; 32]);

    impl rand_core::TryRng for FixedRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
            Ok(0)
        }
        fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
            Ok(0)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
            assert_eq!(dst.len(), 32);
            dst.copy_from_slice(&self.0);
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for FixedRng {}

    #[test]
    fn produce_ephemeral_yields_on_curve_point() {
        use crate::sm2::Sm2PrivateKey;
        let d = Sm2PrivateKey::from_bytes_be(&[2u8; 32]).unwrap();
        let p = d.public_key();
        let init = Sm2KxInitiator::new(&d, &p, b"a", b"b", 16).unwrap();
        let mut rng = FixedRng([7u8; 32]);
        let (r_a, _waiting) = init.produce_ephemeral(&mut rng).unwrap();
        // from_sec1_bytes validates tag/range/on-curve/non-identity.
        assert!(Sm2PublicKey::from_sec1_bytes(&r_a.to_bytes()).is_some());
    }

    #[test]
    fn avf_sets_bit_127_and_masks_low_127() {
        // x = all-ones → x̄ = 2^127 + (2^127 - 1) = 2^128 - 1 (low 128 bits set).
        let x = [0xFFu8; 32];
        let got = avf(&x).retrieve();
        let expect = U256::from_be_hex(
            "00000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        );
        assert_eq!(got, expect);
    }

    #[test]
    fn initiator_new_rejects_overlong_id() {
        use crate::sm2::{Sm2PrivateKey, sign::MAX_ID_LEN};
        let d = Sm2PrivateKey::from_bytes_be(&[1u8; 32]).unwrap();
        let p = d.public_key();
        let too_long = alloc::vec![0u8; MAX_ID_LEN + 1];
        assert!(Sm2KxInitiator::new(&d, &p, &too_long, b"b", 16).is_err());
        assert!(Sm2KxInitiator::new(&d, &p, b"a", &too_long, 16).is_err());
        assert!(Sm2KxInitiator::new(&d, &p, b"a", b"b", 16).is_ok());
        assert!(Sm2KxResponder::new(&d, &p, &too_long, b"b", 16).is_err());
        assert!(Sm2KxResponder::new(&d, &p, b"a", b"b", 16).is_ok());
    }

    #[test]
    fn new_rejects_bad_klen() {
        use crate::sm2::Sm2PrivateKey;
        let d = Sm2PrivateKey::from_bytes_be(&[1u8; 32]).unwrap();
        let p = d.public_key();
        // klen == 0 → Failed.
        assert!(Sm2KxInitiator::new(&d, &p, b"a", b"b", 0).is_err());
        assert!(Sm2KxResponder::new(&d, &p, b"a", b"b", 0).is_err());
        // klen above the KDF u32-counter ceiling → Failed (S1).
        let over = usize::try_from(32u64 * ((1u64 << 32) - 1) + 1).unwrap();
        assert!(Sm2KxInitiator::new(&d, &p, b"a", b"b", over).is_err());
    }

    #[test]
    fn new_rejects_identity_peer_pubkey() {
        use crate::sm2::{Sm2PrivateKey, Sm2PublicKey};
        use crate::sm2::point::ProjectivePoint;
        let d = Sm2PrivateKey::from_bytes_be(&[1u8; 32]).unwrap();
        let identity = Sm2PublicKey::from_point(ProjectivePoint::identity());
        // An identity peer static key must collapse to Failed, not panic
        // in compute_z (S2).
        assert!(Sm2KxInitiator::new(&d, &identity, b"a", b"b", 16).is_err());
        assert!(Sm2KxResponder::new(&d, &identity, b"a", b"b", 16).is_err());
    }

    #[test]
    fn avf_zero_input_yields_exactly_bit_127() {
        // x = 0 → x̄ = 2^127 (only the forced bit set).
        let x = [0u8; 32];
        let got = avf(&x).retrieve();
        let expect = U256::from_be_hex(
            "0000000000000000000000000000000080000000000000000000000000000000",
        );
        assert_eq!(got, expect);
    }
}
