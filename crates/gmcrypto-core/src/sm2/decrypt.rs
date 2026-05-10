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
//! [`DecryptError::Failed`] return — malformed DER, off-curve `C1`,
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
use crate::sm2::encrypt::{kdf, point_on_curve, projective_from_affine};
use crate::sm2::private_key::Sm2PrivateKey;
use crate::sm2::scalar_mul::mul_var;
use crate::sm3::Sm3;
use alloc::vec::Vec;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Decrypt failure — single uninformative variant per the project's
/// failure-mode invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptError {
    /// Catch-all decryption failure: malformed DER, off-curve `C1`,
    /// identity `C1`, all-zero KDF, or MAC mismatch — never
    /// distinguished.
    Failed,
}

/// Decrypt a GM/T 0009 DER-encoded ciphertext under recipient private
/// key `private`.
///
/// Returns `Ok(plaintext)` on success, [`DecryptError::Failed`] on any
/// failure.
///
/// # Errors
///
/// See module-doc — every failure mode collapses to one variant.
pub fn decrypt(private: &Sm2PrivateKey, ciphertext_der: &[u8]) -> Result<Vec<u8>, DecryptError> {
    // 1. DER decode. (Returns None on malformed input — single failure
    //    bucket here; we collapse to Failed.)
    let parsed = decode(ciphertext_der).ok_or(DecryptError::Failed)?;

    // 2. Construct C1 from (x1, y1). Reject off-curve.
    let x1 = Fp::new(&parsed.x);
    let y1 = Fp::new(&parsed.y);
    if !point_on_curve(&x1, &y1) {
        return Err(DecryptError::Failed);
    }
    let c1 = projective_from_affine(x1, y1);
    if bool::from(c1.is_identity()) {
        return Err(DecryptError::Failed);
    }

    // 3. (x2, y2) = d_B * C1
    let kp = mul_var(private.scalar(), &c1);
    let (x2, y2) = kp.to_affine().ok_or(DecryptError::Failed)?;

    // 4. KDF(x2 || y2, |C2|)
    let mut z = [0u8; 64];
    z[..32].copy_from_slice(&x2.retrieve().to_be_bytes());
    z[32..].copy_from_slice(&y2.retrieve().to_be_bytes());

    let mut t = alloc::vec![0u8; parsed.ciphertext.len()];
    kdf(&z, &mut t);

    // 5. KDF-zero check (vacuously satisfied for empty C2).
    if !parsed.ciphertext.is_empty() && all_zero(&t) {
        z.zeroize();
        t.zeroize();
        return Err(DecryptError::Failed);
    }

    // 6. M = C2 XOR t (in place — t becomes M).
    for (i, byte) in parsed.ciphertext.iter().enumerate() {
        t[i] ^= byte;
    }
    // Rename for clarity: the buffer now holds plaintext.
    let mut plaintext = t;

    // 7. u = SM3(x2 || M || y2)
    let mut h = Sm3::new();
    h.update(&z[..32]);
    h.update(&plaintext);
    h.update(&z[32..]);
    let u = h.finalize();

    // 8. Constant-time MAC compare.
    let mac_ok = u.ct_eq(&parsed.hash);

    // Wipe the secret-derived (x2 || y2) buffer regardless of outcome.
    z.zeroize();

    if !bool::from(mac_ok) {
        // Wipe the would-be plaintext — the caller never sees it.
        plaintext.zeroize();
        return Err(DecryptError::Failed);
    }

    Ok(plaintext)
}

/// Constant-time all-zero scan. Same shape as the encrypt-side helper
/// but local to keep the module self-contained.
fn all_zero(buf: &[u8]) -> bool {
    let mut acc: u8 = 0;
    for b in buf {
        acc |= b;
    }
    bool::from(acc.ct_eq(&0u8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::ciphertext::{Sm2Ciphertext, encode};
    use crate::sm2::encrypt::encrypt;
    use crate::sm2::private_key::Sm2PrivateKey;
    use crate::sm2::public_key::Sm2PublicKey;
    use crypto_bigint::U256;
    use getrandom::SysRng;
    use rand_core::UnwrapErr;

    /// End-to-end round-trip with a random nonce: encrypt → decrypt
    /// → recover plaintext.
    #[test]
    fn round_trip_random_nonce() {
        let d =
            U256::from_be_hex("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");
        let key = Sm2PrivateKey::new(d).expect("valid d");
        let pk = Sm2PublicKey::from_point(key.public_key());
        let plaintext = b"encryption standard";
        let mut rng = UnwrapErr(SysRng);
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
        let key = Sm2PrivateKey::new(d).expect("valid d");
        let pk = Sm2PublicKey::from_point(key.public_key());
        let mut rng = UnwrapErr(SysRng);

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
        let key = Sm2PrivateKey::new(d).expect("valid d");
        assert_eq!(decrypt(&key, &[]), Err(DecryptError::Failed));
        assert_eq!(decrypt(&key, b"not DER"), Err(DecryptError::Failed));
        assert_eq!(
            decrypt(&key, &[0x30, 0x05, 0xff, 0xff, 0xff]),
            Err(DecryptError::Failed)
        );
    }

    /// Decrypt rejects ciphertext with `C1` not on the SM2 curve.
    /// (Constructed by hand-building `Sm2Ciphertext` with arbitrary
    /// off-curve `(x, y)`.)
    #[test]
    fn rejects_off_curve_c1() {
        let d =
            U256::from_be_hex("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");
        let key = Sm2PrivateKey::new(d).expect("valid d");
        let off_curve = Sm2Ciphertext {
            x: U256::from_u64(1),
            y: U256::from_u64(1), // (1, 1) is not on SM2
            hash: [0u8; 32],
            ciphertext: alloc::vec![0u8; 16],
        };
        let der = encode(&off_curve);
        assert_eq!(decrypt(&key, &der), Err(DecryptError::Failed));
    }

    /// Decrypt rejects ciphertext where `C3` (the MAC) doesn't match
    /// the recomputed hash. Mutate one byte of `C3` after a valid
    /// encrypt and verify decrypt fails.
    #[test]
    fn rejects_mac_mismatch() {
        let d =
            U256::from_be_hex("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");
        let key = Sm2PrivateKey::new(d).expect("valid d");
        let pk = Sm2PublicKey::from_point(key.public_key());
        let mut rng = UnwrapErr(SysRng);
        let der = encrypt(&pk, b"encryption standard", &mut rng).expect("encrypt");

        // Decode → mutate hash → re-encode → decrypt should fail.
        let mut parsed = decode(&der).expect("decode our own DER");
        parsed.hash[0] ^= 0x01;
        let tampered = encode(&parsed);
        assert_eq!(decrypt(&key, &tampered), Err(DecryptError::Failed));
    }

    /// Decrypt under the WRONG private key fails (MAC won't match).
    #[test]
    fn rejects_wrong_private_key() {
        let d_a =
            U256::from_be_hex("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");
        let d_b =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key_a = Sm2PrivateKey::new(d_a).expect("valid d_a");
        let key_b = Sm2PrivateKey::new(d_b).expect("valid d_b");
        let pk_a = Sm2PublicKey::from_point(key_a.public_key());
        let mut rng = UnwrapErr(SysRng);
        let der = encrypt(&pk_a, b"top secret", &mut rng).expect("encrypt to A");
        // Decrypt with B's key — must fail.
        assert_eq!(decrypt(&key_b, &der), Err(DecryptError::Failed));
    }

    /// Decrypt rejects ciphertext where `C2` has been mutated (one
    /// byte XOR'd) — both the resulting plaintext bit AND the MAC
    /// will be inconsistent.
    #[test]
    fn rejects_tampered_c2() {
        let d =
            U256::from_be_hex("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");
        let key = Sm2PrivateKey::new(d).expect("valid d");
        let pk = Sm2PublicKey::from_point(key.public_key());
        let mut rng = UnwrapErr(SysRng);
        let der = encrypt(&pk, b"some plaintext data", &mut rng).expect("encrypt");

        let mut parsed = decode(&der).expect("decode our own DER");
        parsed.ciphertext[0] ^= 0xff;
        let tampered = encode(&parsed);
        assert_eq!(decrypt(&key, &tampered), Err(DecryptError::Failed));
    }
}
