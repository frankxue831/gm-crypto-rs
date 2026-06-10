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
use crate::sm2::encrypt::{KDF_MAX_OUTPUT, kdf};
use crate::sm2::point::ProjectivePoint;
use crate::sm2::scalar_mul::{mul_g, mul_var};
use crate::sm2::sign::{MAX_ID_LEN, compute_z, sample_nonzero_scalar};
use crate::sm2::{Sm2PrivateKey, Sm2PublicKey};
use crate::sm3::Sm3;
use alloc::vec::Vec;
use crypto_bigint::U256;
use rand_core::TryCryptoRng;
use subtle::{Choice, ConstantTimeEq};
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
fn validate_params(p_peer: &Sm2PublicKey, id_a: &[u8], id_b: &[u8], klen: usize) -> Result<()> {
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

/// Split a SEC1 uncompressed point into its 32-byte X / Y halves.
fn split_xy(sec1: &[u8; 65]) -> ([u8; 32], [u8; 32]) {
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&sec1[1..33]);
    y.copy_from_slice(&sec1[33..65]);
    (x, y)
}

/// Confirmation-tag hash, GB/T 32918.3 §6.1 steps A8/B7:
///
/// `inner = SM3(x_U ‖ Z_A ‖ Z_B ‖ x1 ‖ y1 ‖ x2 ‖ y2)`
/// `S     = SM3(prefix ‖ y_U ‖ inner)`; prefix `0x02` → `S_B`, `0x03` → `S_A`.
///
/// `(x1, y1)` are **always** `R_A`'s coordinates and `(x2, y2)` always
/// `R_B`'s, for both roles (fixed by role, not locality — M3).
#[allow(clippy::too_many_arguments)]
fn s_tag(
    prefix: u8,
    yu: &[u8; 32],
    xu: &[u8; 32],
    za: &[u8; 32],
    zb: &[u8; 32],
    x1: &[u8; 32],
    y1: &[u8; 32],
    x2: &[u8; 32],
    y2: &[u8; 32],
) -> [u8; 32] {
    let mut hi = Sm3::new();
    for part in [xu, za, zb, x1, y1, x2, y2] {
        hi.update(part);
    }
    let inner = hi.finalize();
    let mut ho = Sm3::new();
    ho.update(&[prefix]);
    ho.update(yu);
    ho.update(&inner);
    ho.finalize()
}

/// Compute the agreed key bytes + `(x_U, y_U)` (big-endian) for the
/// S-tag hashes.
///
/// `d` = local static secret, `r_eph` = local ephemeral secret,
/// `r_local_x` = the LOCAL `R`'s affine x-coordinate (avf input),
/// `peer_r` = the peer's SEC1 `R`, `p_peer` = the peer's static point.
/// The KDF input order is **always** `x_U ‖ y_U ‖ Z_A ‖ Z_B` for both
/// roles (Z order is fixed by role, not locality — M3).
///
/// Returns `Failed` on an invalid peer `R` (bad tag/range/off-curve/
/// identity — `from_sec1_bytes` is the invalid-curve defense), an
/// identity `U`, or an all-zero `K` (deliberate hardening, scope doc
/// Q1.7). The secret intermediates `t`, the local `(x̄·r)` product,
/// and the KDF input buffer are wiped before returning (M2); the
/// returned `x_U`/`y_U` copies are the *caller's* wipe obligation
/// (after S-tag hashing).
#[allow(clippy::too_many_arguments)]
fn shared_secret(
    d: &Fn,
    r_eph: &Fn,
    r_local_x: &[u8; 32],
    peer_r: &[u8; 65],
    p_peer: &ProjectivePoint,
    z_a: &[u8; 32],
    z_b: &[u8; 32],
    klen: usize,
) -> Result<(Vec<u8>, [u8; 32], [u8; 32])> {
    // Validate + parse peer R: length/tag/coordinate-range/on-curve/
    // non-identity all enforced by `from_sec1_bytes` (public input —
    // branching is not secret-dependent).
    let peer_pub = Sm2PublicKey::from_sec1_bytes(peer_r).ok_or(Error::Failed)?;
    let peer_point = peer_pub.point();
    let mut peer_x = [0u8; 32];
    peer_x.copy_from_slice(&peer_r[1..33]);

    let x_bar_local = avf(r_local_x); // x̄ of LOCAL R
    let x_bar_peer = avf(&peer_x); // x̄ of PEER R

    // t = (d + x̄_local · r_eph) mod n     (h = 1 for SM2)
    let mut xr = x_bar_local * *r_eph;
    let mut t = *d + xr;
    // U = [t]( P_peer + [x̄_peer] R_peer )
    let sum = p_peer.add(&mul_var(&x_bar_peer, &peer_point));
    let u = mul_var(&t, &sum);
    // M2: t = d + x̄·r reveals d given the (public-after-send) R, so
    // wipe it (and the x̄·r product) as soon as U is computed.
    t.zeroize();
    xr.zeroize();

    let (mut xu, mut yu) = u.to_affine().ok_or(Error::Failed)?; // None == U = O
    let xu_b = crate::u256_to_be32(&xu.retrieve());
    let yu_b = crate::u256_to_be32(&yu.retrieve());
    xu.zeroize();
    yu.zeroize();

    // K = KDF(x_U ‖ y_U ‖ Z_A ‖ Z_B, klen); reject all-zero K.
    let mut kin = Vec::with_capacity(128);
    kin.extend_from_slice(&xu_b);
    kin.extend_from_slice(&yu_b);
    kin.extend_from_slice(z_a);
    kin.extend_from_slice(z_b);
    let mut key = alloc::vec![0u8; klen];
    kdf(&kin, &mut key);
    kin.zeroize();
    let mut allzero = Choice::from(1u8);
    for b in &key {
        allzero &= b.ct_eq(&0u8);
    }
    if bool::from(allzero) {
        return Err(Error::Failed);
    }
    Ok((key, xu_b, yu_b))
}

impl Sm2KxInitiatorWaiting {
    /// Receive the responder's `(R_B, S_B)`: derive `K`, verify `S_B`
    /// constant-time, and emit `S_A`. Consumes `self`.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] on an invalid `R_B`, an identity `U`, an
    /// all-zero `K`, or an `S_B` mismatch (indistinguishable by
    /// design).
    pub fn confirm(
        self,
        r_b: &Sm2KxEphemeralPoint,
        s_b: &Sm2KxConfirm,
    ) -> Result<(Sm2SharedKey, Sm2KxConfirm)> {
        let Self {
            inner,
            r_eph,
            r_point_bytes,
        } = self;
        let mut local_x = [0u8; 32];
        local_x.copy_from_slice(&r_point_bytes[1..33]);
        let (key, mut xu_b, mut yu_b) = shared_secret(
            inner.d.scalar(),
            &r_eph.0,
            &local_x,
            &r_b.0,
            &inner.p_peer,
            &inner.z_a,
            &inner.z_b,
            inner.klen,
        )?;
        // Wrap K immediately: every return path below (including the
        // tag-mismatch reject) zeroizes it on drop.
        let key = Sm2SharedKey(key);

        // S-tag coordinates are fixed by role: (x1,y1) = R_A (local
        // here), (x2,y2) = R_B (peer here) — M3.
        let (x1, y1) = split_xy(&r_point_bytes);
        let (x2, y2) = split_xy(&r_b.0);
        let expected_s_b = s_tag(
            0x02, &yu_b, &xu_b, &inner.z_a, &inner.z_b, &x1, &y1, &x2, &y2,
        );
        let ok = expected_s_b[..].ct_eq(&s_b.0[..]);
        if !bool::from(ok) {
            xu_b.zeroize();
            yu_b.zeroize();
            return Err(Error::Failed);
        }
        let s_a = Sm2KxConfirm(s_tag(
            0x03, &yu_b, &xu_b, &inner.z_a, &inner.z_b, &x1, &y1, &x2, &y2,
        ));
        // M2: x_U/y_U wiped only after the S-tag hashing consumed them.
        xu_b.zeroize();
        yu_b.zeroize();
        Ok((key, s_a))
    }
}

/// Responder after `(R_B, S_B)` were sent; holds `K` (zeroize-on-drop)
/// until the initiator's `S_A` verifies.
pub struct Sm2KxResponderWaiting {
    key: Sm2SharedKey,
    expected_s_a: [u8; 32],
}

impl Sm2KxResponder {
    /// Receive the initiator's `R_A`: sample `r_B`, derive `K`, emit
    /// `(R_B, S_B)`, and hold `K` until [`Sm2KxResponderWaiting::finish`]
    /// verifies the initiator's `S_A`. Consumes `self`.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] on RNG failure, an invalid `R_A`, an identity
    /// `V`, or an all-zero `K` (indistinguishable by design).
    pub fn respond<R: TryCryptoRng>(
        self,
        r_a: &Sm2KxEphemeralPoint,
        rng: &mut R,
    ) -> Result<(Sm2KxEphemeralPoint, Sm2KxConfirm, Sm2KxResponderWaiting)> {
        let (r, rb_bytes) = sample_ephemeral(rng)?;
        let r_eph = EphScalar(r);
        let mut local_x = [0u8; 32];
        local_x.copy_from_slice(&rb_bytes[1..33]);
        let (key, mut xu_b, mut yu_b) = shared_secret(
            self.d.scalar(),
            &r_eph.0,
            &local_x,
            &r_a.0,
            &self.p_peer,
            &self.z_a,
            &self.z_b,
            self.klen,
        )?;
        // S-tag coordinates are fixed by role: (x1,y1) = R_A (peer
        // here), (x2,y2) = R_B (local here) — M3.
        let (x1, y1) = split_xy(&r_a.0);
        let (x2, y2) = split_xy(&rb_bytes);
        let s_b = Sm2KxConfirm(s_tag(
            0x02, &yu_b, &xu_b, &self.z_a, &self.z_b, &x1, &y1, &x2, &y2,
        ));
        let expected_s_a = s_tag(0x03, &yu_b, &xu_b, &self.z_a, &self.z_b, &x1, &y1, &x2, &y2);
        // M2: x_U/y_U wiped only after the S-tag hashing consumed them.
        xu_b.zeroize();
        yu_b.zeroize();
        Ok((
            Sm2KxEphemeralPoint(rb_bytes),
            s_b,
            Sm2KxResponderWaiting {
                key: Sm2SharedKey(key),
                expected_s_a,
            },
        ))
    }
}

impl Sm2KxResponderWaiting {
    /// Verify the initiator's `S_A` (constant-time); only then release
    /// `K`. Consumes `self`.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] on an `S_A` mismatch.
    pub fn finish(self, s_a: &Sm2KxConfirm) -> Result<Sm2SharedKey> {
        let ok = self.expected_s_a[..].ct_eq(&s_a.0[..]);
        if !bool::from(ok) {
            // `self.key` drops here → zeroized.
            return Err(Error::Failed);
        }
        Ok(self.key)
    }
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
    fn s_tag_prefixes_differ_and_deterministic() {
        let z = [1u8; 32];
        let xu = [2u8; 32];
        let yu = [3u8; 32];
        let r = [4u8; 32];
        let sb = s_tag(0x02, &yu, &xu, &z, &z, &r, &r, &r, &r);
        let sa = s_tag(0x03, &yu, &xu, &z, &z, &r, &r, &r, &r);
        assert_ne!(sb, sa, "domain-separation prefix must change the tag");
        assert_eq!(
            sb,
            s_tag(0x02, &yu, &xu, &z, &z, &r, &r, &r, &r),
            "deterministic"
        );
    }

    #[test]
    fn confirm_rejects_tampered_s_b() {
        use crate::sm2::Sm2PrivateKey;
        let da = Sm2PrivateKey::from_bytes_be(&[5u8; 32]).unwrap();
        let db = Sm2PrivateKey::from_bytes_be(&[6u8; 32]).unwrap();
        let (pa, pb) = (da.public_key(), db.public_key());
        let init = Sm2KxInitiator::new(&da, &pb, b"a", b"b", 16).unwrap();
        let (ra, iw) = init.produce_ephemeral(&mut FixedRng([11u8; 32])).unwrap();
        let resp = Sm2KxResponder::new(&db, &pa, b"a", b"b", 16).unwrap();
        let (rb, sb, _rw) = resp.respond(&ra, &mut FixedRng([12u8; 32])).unwrap();
        let mut bad = sb.to_bytes();
        bad[0] ^= 1;
        let sb_bad = Sm2KxConfirm::from_bytes(&bad);
        assert!(iw.confirm(&rb, &sb_bad).is_err(), "tampered S_B accepted");
    }

    #[test]
    fn finish_rejects_tampered_s_a() {
        use crate::sm2::Sm2PrivateKey;
        let da = Sm2PrivateKey::from_bytes_be(&[7u8; 32]).unwrap();
        let db = Sm2PrivateKey::from_bytes_be(&[8u8; 32]).unwrap();
        let (pa, pb) = (da.public_key(), db.public_key());
        let init = Sm2KxInitiator::new(&da, &pb, b"a", b"b", 16).unwrap();
        let (ra, iw) = init.produce_ephemeral(&mut FixedRng([13u8; 32])).unwrap();
        let resp = Sm2KxResponder::new(&db, &pa, b"a", b"b", 16).unwrap();
        let (rb, sb, rw) = resp.respond(&ra, &mut FixedRng([14u8; 32])).unwrap();
        let (_k_a, sa) = iw.confirm(&rb, &sb).unwrap();
        let mut bad = sa.to_bytes();
        bad[31] ^= 0x80;
        let sa_bad = Sm2KxConfirm::from_bytes(&bad);
        assert!(rw.finish(&sa_bad).is_err(), "tampered S_A accepted");
    }

    #[test]
    fn round_trip_shared_key_matches() {
        use crate::sm2::Sm2PrivateKey;
        let da = Sm2PrivateKey::from_bytes_be(&[3u8; 32]).unwrap();
        let db = Sm2PrivateKey::from_bytes_be(&[4u8; 32]).unwrap();
        let (pa, pb) = (da.public_key(), db.public_key());
        let mut rng_a = FixedRng([9u8; 32]);
        let mut rng_b = FixedRng([10u8; 32]);

        let init = Sm2KxInitiator::new(&da, &pb, b"a", b"b", 32).unwrap();
        let (ra, init_w) = init.produce_ephemeral(&mut rng_a).unwrap();

        let resp = Sm2KxResponder::new(&db, &pa, b"a", b"b", 32).unwrap();
        let (rb, sb, resp_w) = resp.respond(&ra, &mut rng_b).unwrap();

        let (k_a, sa) = init_w.confirm(&rb, &sb).unwrap();
        let k_b = resp_w.finish(&sa).unwrap();
        assert_eq!(k_a.as_bytes(), k_b.as_bytes());
        assert_eq!(k_a.as_bytes().len(), 32);
        // K must not be all-zero (the degenerate-KDF reject would fire).
        assert!(k_a.as_bytes().iter().any(|&b| b != 0));
    }

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
        let expect =
            U256::from_be_hex("00000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
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
        use crate::sm2::point::ProjectivePoint;
        use crate::sm2::{Sm2PrivateKey, Sm2PublicKey};
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
        let expect =
            U256::from_be_hex("0000000000000000000000000000000080000000000000000000000000000000");
        assert_eq!(got, expect);
    }
}
