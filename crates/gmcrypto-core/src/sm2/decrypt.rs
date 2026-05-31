//! SM2 public-key decryption (GB/T 32918.4-2017 §7).
//!
//! # Algorithm
//!
//! ```text
//! Input:  recipient private key d_B, GM/T 0009 DER ciphertext blob
//! Output: plaintext M
//!
//! 1. Decode DER → (x1, y1, C3, C2)
//! 2. Construct C1 = (x1, y1); reject if not on the SM2 curve
//! 3. (x2, y2) = d_B * C1
//! 4. t = KDF(x2 || y2, |C2|)
//! 5. If t is all zeros, abort
//! 6. M = C2 XOR t
//! 7. u = SM3(x2 || M || y2)
//! 8. If u != C3 (constant-time compare), abort
//! 9. Output M
//! ```
//!
//! # Failure-mode invariant
//!
//! Every failure mode collapses to a single
//! [`crate::Error::Failed`] return — malformed DER, off-curve `C1`,
//! identity `C1`, all-zero KDF, MAC mismatch. No distinguishing
//! variants per the project's failure-mode invariant. SECURITY.md
//! has the full rationale.
//!
//! # Constant-time stance
//!
//! Decrypt operates on the recipient's secret `d_B`. The
//! constant-time-relevant work happens via:
//!
//! - `mul_var(d_B, C1)`: covered by v0.1's `ct_mul_var` harness target
//!   plus the W0 direct-invert diagnostics.
//! - `to_affine` after `mul_var`: covered by W0's `ct_fp_invert`.
//! - KDF (counter-mode SM3): SM3 itself is data-independent in timing.
//! - `M = C2 XOR t`: byte-wise XOR loop, branchless.
//! - MAC compare: `subtle::ConstantTimeEq` on the 32-byte digest.
//! - **All-zero KDF detection: non-branching.** A naïve early-return
//!   on KDF-zero would gift a chosen-ciphertext attacker a timing
//!   oracle for short C2: P(KDF zero) ≈ 2^(-8·|C2|), so a 1-byte C2
//!   trips the branch ~1/256 of the time, and the early-return path
//!   skips the XOR/SM3/MAC work — observably faster than a
//!   normal MAC failure. The implementation folds the all-zero
//!   detection into a `subtle::Choice` and combines it with the
//!   `mac_ok` result via `&` so both classes of failure collapse to
//!   identical control flow.
//!
//! v0.2 adds [`crate::sm4::Sm4Cipher`] for envelope encryption (use
//! SM2 to wrap an SM4 key, then SM4-CBC with HMAC-SM3 for bulk data
//! and integrity). v0.2's dudect harness adds `ct_sm2_decrypt` (W2
//! chunk 3) — class-split by `d_B`, fixed ciphertext.
//!
//! # Invalid-curve attack
//!
//! Without the on-curve check on `C1`, an attacker could submit a
//! point on a different curve sharing the same `x` coordinate as a
//! point on SM2; multiplying by the secret `d_B` then leaks bits of
//! `d_B` via the small-order subgroup of the rogue curve. The
//! [`crate::sm2::encrypt::point_on_curve`] check is the standard
//! defense.

use crate::asn1::ciphertext::decode;
use crate::sm2::curve::Fp;
use crate::sm2::encrypt::{KDF_MAX_OUTPUT, kdf, point_on_curve, projective_from_affine};
use crate::sm2::private_key::Sm2PrivateKey;
use crate::sm2::scalar_mul::mul_var;
use crate::sm3::Sm3;
use alloc::vec::Vec;
use crypto_bigint::U256;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

/// Decrypt a GM/T 0009 DER-encoded ciphertext under recipient private
/// key `private`.
///
/// Returns `Ok(plaintext)` on success, [`crate::Error::Failed`] on any
/// failure.
///
/// # Errors
///
/// See module-doc — every failure mode collapses to one variant.
pub fn decrypt(private: &Sm2PrivateKey, ciphertext_der: &[u8]) -> Result<Vec<u8>, crate::Error> {
    // 1. DER decode. (Returns None on malformed input — single failure
    //    bucket here; we collapse to Failed.)
    let parsed = decode(ciphertext_der).ok_or(crate::Error::Failed)?;

    // 2. Construct C1 from (x1, y1). Reject off-curve.
    //    v0.22: `parsed.{x,y}` are 32-byte big-endian (was `U256`); reconstruct
    //    the field elements. `Fp::new` reduces mod p as before, and the
    //    on-curve check below is the unchanged invalid-curve-attack defense
    //    (the `[u8; 32]` fields are NOT inherently canonical — a caller can
    //    build an arbitrary `Sm2Ciphertext`, so this guard stays here).
    let x1 = Fp::new(&U256::from_be_slice(&parsed.x));
    let y1 = Fp::new(&U256::from_be_slice(&parsed.y));
    if !point_on_curve(&x1, &y1) {
        return Err(crate::Error::Failed);
    }
    let c1 = projective_from_affine(x1, y1);
    if bool::from(c1.is_identity()) {
        return Err(crate::Error::Failed);
    }

    // 3. (x2, y2) = d_B * C1
    let kp = mul_var(private.scalar(), &c1);
    let (x2, y2) = kp.to_affine().ok_or(crate::Error::Failed)?;

    // 4. KDF(x2 || y2, |C2|)
    // B-5 (v0.23): guard the C2 length against the SM2 KDF `u32`
    // counter-wrap ceiling before deriving any key material (symmetric
    // with `encrypt`'s guard). Unreachable at sane sizes (≈137 GB).
    if parsed.ciphertext.len() as u64 > KDF_MAX_OUTPUT {
        return Err(crate::Error::Failed);
    }
    let mut z = [0u8; 64];
    z[..32].copy_from_slice(&x2.retrieve().to_be_bytes());
    z[32..].copy_from_slice(&y2.retrieve().to_be_bytes());

    let mut t = alloc::vec![0u8; parsed.ciphertext.len()];
    kdf(&z, &mut t);

    // 5. KDF-zero detection — *non-branching*. We MUST NOT early-return
    //    here: a chosen-ciphertext attacker who can submit a short C2
    //    (e.g. 1 byte) hits an all-zero KDF output with probability
    //    `≈ 2^(-8 * |C2|)`, and an early-return that skips the
    //    XOR/SM3/MAC work would distinguish the secret-derived
    //    predicate "d_B*C1 produced all-zero KDF" from an ordinary
    //    MAC failure. Both outcomes must collapse to identical control
    //    flow per the failure-mode invariant. The empty-C2 case is
    //    explicitly excluded (vacuous all-zero on an empty buffer).
    let nonempty: Choice = u8::from(!parsed.ciphertext.is_empty()).into();
    let kdf_zero = nonempty & ct_all_zero(&t);

    // 6. M = C2 XOR t (in place — t becomes M).
    for (i, byte) in parsed.ciphertext.iter().enumerate() {
        t[i] ^= byte;
    }
    // Rename for clarity: the buffer now holds (would-be) plaintext.
    let mut plaintext = t;

    // 7. u = SM3(x2 || M || y2) — computed unconditionally regardless
    //    of `kdf_zero` so timing is identical on both branches.
    let mut h = Sm3::new();
    h.update(&z[..32]);
    h.update(&plaintext);
    h.update(&z[32..]);
    let u = h.finalize();

    // 8. Combine the constant-time KDF-zero detection with the MAC
    //    compare into a single `Choice`. Using `&` on `Choice` (defined
    //    via `BitAnd<Choice>`) preserves the constant-time contract.
    let mac_ok = u.ct_eq(&parsed.hash);
    let valid = mac_ok & !kdf_zero;

    // Wipe the secret-derived (x2 || y2) buffer regardless of outcome.
    z.zeroize();

    if !bool::from(valid) {
        // Wipe the would-be plaintext — the caller never sees it.
        plaintext.zeroize();
        return Err(crate::Error::Failed);
    }

    Ok(plaintext)
}

/// Constant-time all-zero scan returning a [`Choice`]. The bitwise OR
/// fold gives a single 8-bit summary value that reveals only whether
/// the buffer is all-zero — itself the mandated KDF-zero predicate
/// — and never short-circuits.
fn ct_all_zero(buf: &[u8]) -> Choice {
    let mut acc: u8 = 0;
    for b in buf {
        acc |= b;
    }
    acc.ct_eq(&0u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::ciphertext::{Sm2Ciphertext, encode};
    use crate::sm2::encrypt::encrypt;
    use crate::sm2::private_key::Sm2PrivateKey;
    use crypto_bigint::U256;
    use getrandom::SysRng;

    /// End-to-end round-trip with a random nonce: encrypt → decrypt
    /// → recover plaintext.
    #[test]
    fn round_trip_random_nonce() {
        let d =
            U256::from_be_hex("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid d");
        let pk = key.public_key();
        let plaintext = b"encryption standard";
        let mut rng = SysRng;
        let der = encrypt(&pk, plaintext, &mut rng).expect("encrypt");
        let recovered = decrypt(&key, &der).expect("decrypt");
        assert_eq!(recovered.as_slice(), plaintext);
    }

    /// Boundary-length round-trip across empty / 1 / 31 / 32 / 33 /
    /// 64 / 65 byte plaintexts. Empty exercises the vacuous
    /// KDF-zero check; 32 sits exactly on a KDF-block boundary; 33
    /// crosses into the second KDF block.
    #[test]
    fn round_trip_boundary_lengths() {
        let d =
            U256::from_be_hex("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid d");
        let pk = key.public_key();
        let mut rng = SysRng;

        for len in [0usize, 1, 31, 32, 33, 64, 65, 128] {
            let plaintext: Vec<u8> = (0..len)
                .map(|i| {
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        (i as u8).wrapping_mul(7)
                    }
                })
                .collect();
            let der = encrypt(&pk, &plaintext, &mut rng).expect("encrypt");
            let recovered = decrypt(&key, &der).expect("decrypt");
            assert_eq!(recovered, plaintext, "round-trip mismatch at len={len}");
        }
    }

    /// Decrypt rejects garbage / malformed DER.
    #[test]
    fn rejects_malformed_der() {
        let d =
            U256::from_be_hex("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid d");
        assert_eq!(decrypt(&key, &[]), Err(crate::Error::Failed));
        assert_eq!(decrypt(&key, b"not DER"), Err(crate::Error::Failed));
        assert_eq!(
            decrypt(&key, &[0x30, 0x05, 0xff, 0xff, 0xff]),
            Err(crate::Error::Failed)
        );
    }

    /// Decrypt rejects ciphertext with `C1` not on the SM2 curve.
    /// (Constructed by hand-building `Sm2Ciphertext` with arbitrary
    /// off-curve `(x, y)`.)
    #[test]
    fn rejects_off_curve_c1() {
        let d =
            U256::from_be_hex("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid d");
        let off_curve = Sm2Ciphertext {
            x: crate::u256_to_be32(&U256::from_u64(1)),
            y: crate::u256_to_be32(&U256::from_u64(1)), // (1, 1) is not on SM2
            hash: [0u8; 32],
            ciphertext: alloc::vec![0u8; 16],
        };
        let der = encode(&off_curve);
        assert_eq!(decrypt(&key, &der), Err(crate::Error::Failed));
    }

    /// Decrypt rejects ciphertext where `C3` (the MAC) doesn't match
    /// the recomputed hash. Mutate one byte of `C3` after a valid
    /// encrypt and verify decrypt fails.
    #[test]
    fn rejects_mac_mismatch() {
        let d =
            U256::from_be_hex("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid d");
        let pk = key.public_key();
        let mut rng = SysRng;
        let der = encrypt(&pk, b"encryption standard", &mut rng).expect("encrypt");

        // Decode → mutate hash → re-encode → decrypt should fail.
        let mut parsed = decode(&der).expect("decode our own DER");
        parsed.hash[0] ^= 0x01;
        let tampered = encode(&parsed);
        assert_eq!(decrypt(&key, &tampered), Err(crate::Error::Failed));
    }

    /// Decrypt under the WRONG private key fails (MAC won't match).
    #[test]
    fn rejects_wrong_private_key() {
        let d_a =
            U256::from_be_hex("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");
        let d_b =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key_a = Sm2PrivateKey::from_scalar_inner(d_a).expect("valid d_a");
        let key_b = Sm2PrivateKey::from_scalar_inner(d_b).expect("valid d_b");
        let pk_a = key_a.public_key();
        let mut rng = SysRng;
        let der = encrypt(&pk_a, b"top secret", &mut rng).expect("encrypt to A");
        // Decrypt with B's key — must fail.
        assert_eq!(decrypt(&key_b, &der), Err(crate::Error::Failed));
    }

    /// Decrypt rejects ciphertext where `C2` has been mutated (one
    /// byte XOR'd) — both the resulting plaintext bit AND the MAC
    /// will be inconsistent.
    #[test]
    fn rejects_tampered_c2() {
        let d =
            U256::from_be_hex("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid d");
        let pk = key.public_key();
        let mut rng = SysRng;
        let der = encrypt(&pk, b"some plaintext data", &mut rng).expect("encrypt");

        let mut parsed = decode(&der).expect("decode our own DER");
        parsed.ciphertext[0] ^= 0xff;
        let tampered = encode(&parsed);
        assert_eq!(decrypt(&key, &tampered), Err(crate::Error::Failed));
    }

    /// Functional regression test for the constant-time KDF-zero
    /// handling. Forge a ciphertext where `C2` is `[0x00; n]` for
    /// small `n`; on decryption the random-looking `KDF(d_B*C1, n)`
    /// won't be all-zero (the attacker can't choose `KDF` output
    /// without knowing `d_B*C1`), so the path must collapse to
    /// `Failed` via the MAC-mismatch arm rather than via an
    /// early-return KDF-zero branch. The pre-fix decoder would have
    /// taken the early return whenever the KDF *did* hit all-zero
    /// (~1/256 of attempts for a 1-byte C2), exposing a chosen-
    /// ciphertext timing oracle. We can't reliably hit the
    /// all-zero KDF output here without grinding `C1`, but this
    /// test does verify the rewrite still rejects forged short
    /// ciphertexts cleanly across many attempts and that no panic
    /// or `Ok` result slips through.
    ///
    /// Companion: see `crates/gmcrypto-core/src/sm2/decrypt.rs`
    /// step 5 comment for the timing-oracle rationale.
    #[test]
    fn rejects_forged_short_ciphertext() {
        let d =
            U256::from_be_hex("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid d");
        let pk = key.public_key();
        let mut rng = SysRng;

        // Encrypt many distinct 1-byte messages so we exercise lots
        // of `(C1, KDF)` pairs, then for each tamper `C3` to force
        // the path through the new branchless KDF-zero detection +
        // MAC compare. None should panic or return `Ok`.
        for round in 0..32u8 {
            let plaintext = [round];
            let der = encrypt(&pk, &plaintext, &mut rng).expect("encrypt 1-byte");
            let mut parsed = decode(&der).expect("decode our own DER");
            parsed.hash[0] ^= 0x01;
            let tampered = encode(&parsed);
            assert_eq!(
                decrypt(&key, &tampered),
                Err(crate::Error::Failed),
                "forged 1-byte ciphertext on round {round} must fail"
            );
        }
    }

    /// Empty plaintext round-trip is supported: `KDF(_, 0)` writes
    /// zero bytes, the all-zero check is vacuously suppressed via
    /// the `nonempty` Choice mask, and `SM3(x2 || empty || y2)`
    /// is the MAC. Companion to `round_trip_boundary_lengths` —
    /// kept independent so a regression on the empty-suppression
    /// behavior surfaces here distinctly.
    #[test]
    fn round_trip_empty_plaintext() {
        let d =
            U256::from_be_hex("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid d");
        let pk = key.public_key();
        let mut rng = SysRng;
        let der = encrypt(&pk, b"", &mut rng).expect("encrypt empty");
        let recovered = decrypt(&key, &der).expect("decrypt empty");
        assert!(recovered.is_empty(), "empty plaintext round-trip");
    }
}
