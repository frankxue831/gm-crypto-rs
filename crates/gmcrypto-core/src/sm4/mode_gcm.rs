//! SM4 in GCM mode (Galois/Counter Mode) per NIST SP 800-38D, with
//! the underlying block cipher swapped from AES to SM4 per GM/T 0009
//! / RFC 8998.
//!
//! # Authenticated encryption with associated data (AEAD)
//!
//! SM4-GCM is an **authenticated** stream-cipher mode. Output of
//! [`encrypt`] is a `(ciphertext, tag)` pair; [`decrypt`] returns
//! `Some(plaintext)` only when the tag verifies, `None` otherwise.
//! Callers needing integrity should use this in preference to bare
//! [`super::mode_ctr`].
//!
//! # Nonce contract
//!
//! Per NIST SP 800-38D §8.2: SM4-GCM nonces must be **unique-per-key**.
//! Caller-supplied; this module does not generate nonces. Reusing a
//! `(key, nonce)` pair across two distinct plaintexts is *catastrophic*:
//! it reveals `plaintext1 ⊕ plaintext2` (the standard two-time pad
//! attack on stream ciphers) **and** leaks the GCM hash subkey `H`,
//! which enables existential forgery against the authentication tag
//! across the entire `(key, nonce)`-reused stream.
//!
//! The 96-bit (12-byte) nonce length is the "canonical" GCM nonce per
//! NIST §8.2.1 and is what most callers should use. Other lengths are
//! also accepted (per §8.2.2; non-12-byte nonces invoke an extra
//! GHASH round to derive `J0`) but introduce a small additional
//! collision risk vs. the canonical 12-byte path. v0.8 W2 implements
//! both paths for spec compliance and gmssl 3.1.1 interop.
//!
//! # Tag length
//!
//! v0.8 W2 ships only the 128-bit (16-byte) tag length. Shorter tags
//! (per NIST §5.2.1.2) are out of scope for v0.8; tag-truncation
//! amounts to extra bookkeeping with no algorithmic novelty, and the
//! shortened form (e.g. 32 bits, 64 bits) is more vulnerable to
//! existential forgery — restricting to 128-bit tags is the safer
//! default. A future v0.9+ may add tag-length parameterization
//! alongside the streaming-AEAD work.
//!
//! # Failure mode invariant
//!
//! [`decrypt`] returns `Option<Vec<u8>>`. `None` covers all failure
//! paths uniformly:
//!
//! - Tag mismatch.
//!
//! No distinguishing variants per the workspace failure-mode
//! invariant (`CLAUDE.md` "Hard constraints"). [`decrypt`] verifies
//! the tag *before* running CTR decryption, so no plaintext buffer
//! ever materializes on the failure path — no zeroize required.
//!
//! # API
//!
//! ```rust
//! # #[cfg(feature = "sm4-aead")] {
//! use gmcrypto_core::sm4::{KEY_SIZE, mode_gcm};
//!
//! let key: [u8; KEY_SIZE] = [0x42; KEY_SIZE];
//! let nonce: [u8; 12] = [0x01; 12];                  // 12-byte canonical nonce
//! let aad: &[u8] = b"additional authenticated data";
//! let plaintext = b"hello world";
//!
//! let (ciphertext, tag) = mode_gcm::encrypt(&key, &nonce, aad, plaintext);
//! assert_eq!(ciphertext.len(), plaintext.len());
//!
//! let recovered = mode_gcm::decrypt(&key, &nonce, aad, &ciphertext, &tag);
//! assert_eq!(recovered.as_deref(), Some(plaintext.as_slice()));
//!
//! // A tampered tag fails verification.
//! let mut bad_tag = tag;
//! bad_tag[0] ^= 0x01;
//! assert!(mode_gcm::decrypt(&key, &nonce, aad, &ciphertext, &bad_tag).is_none());
//! # }
//! ```

use alloc::vec;
use alloc::vec::Vec;

use subtle::ConstantTimeEq;

use super::cipher::{BLOCK_SIZE, KEY_SIZE, Sm4Cipher};

/// Tag length in bytes. v0.8 W2 fixes this at 128 bits; future
/// versions may parameterize.
pub const TAG_SIZE: usize = 16;

/// Encrypt `plaintext` under `(key, nonce)` with `aad` authenticated
/// but not encrypted. Returns `(ciphertext, tag)` where
/// `ciphertext.len() == plaintext.len()` and `tag.len() == 16`.
///
/// See the module-level docstring for the nonce-uniqueness contract.
#[must_use]
pub fn encrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; TAG_SIZE]) {
    let cipher = Sm4Cipher::new(key);

    // §6.3: H = SM4_E(key, 0^128). The GCM hash subkey.
    let mut h_block = [0u8; BLOCK_SIZE];
    cipher.encrypt_block(&mut h_block);

    // §7.1: J0 derivation from the nonce.
    let j0 = derive_j0(&h_block, nonce);

    // §7.1 step 5: C = GCTR_K(inc32(J0), P).
    let mut ciphertext = vec![0u8; plaintext.len()];
    gctr(&cipher, &inc32(&j0), plaintext, &mut ciphertext);

    // §7.1 step 6: S = GHASH(H, A || 0^v || C || 0^u || [len_A]_64 || [len_C]_64).
    let s = ghash_a_c_lens(&h_block, aad, &ciphertext);

    // §7.1 step 7: T = MSB_128(GCTR_K(J0, S)).
    let mut tag = [0u8; TAG_SIZE];
    gctr(&cipher, &j0, &s, &mut tag);

    (ciphertext, tag)
}

/// Decrypt `ciphertext` under `(key, nonce)` with `aad` authenticated.
///
/// Returns `Some(plaintext)` if the tag verifies, `None` otherwise.
/// CTR decryption is deferred until **after** tag verification so a
/// failure-path plaintext is never materialized — no zeroize needed
/// because no decrypted bytes ever exist on the `None` path.
#[must_use]
pub fn decrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_SIZE],
) -> Option<Vec<u8>> {
    let cipher = Sm4Cipher::new(key);

    let mut h_block = [0u8; BLOCK_SIZE];
    cipher.encrypt_block(&mut h_block);

    let j0 = derive_j0(&h_block, nonce);

    // Recompute the expected tag *before* doing CTR decryption so we
    // can constant-time-compare and avoid emitting a partially-
    // decrypted plaintext to the caller.
    let s = ghash_a_c_lens(&h_block, aad, ciphertext);
    let mut expected_tag = [0u8; TAG_SIZE];
    gctr(&cipher, &j0, &s, &mut expected_tag);

    // §7.2 step 5: constant-time tag compare.
    if expected_tag.ct_eq(tag).unwrap_u8() != 1 {
        return None;
    }

    // Tag verified — proceed to CTR decryption. (If we ever switch
    // to decrypt-before-tag-check for streaming purposes, the
    // plaintext buffer would need Zeroize on the failure path.)
    let mut plaintext = vec![0u8; ciphertext.len()];
    gctr(&cipher, &inc32(&j0), ciphertext, &mut plaintext);

    Some(plaintext)
}

// ============================================================
// GCM internals
// ============================================================

/// `inc32` of a 128-bit block: increment the rightmost 32 bits as an
/// unsigned big-endian integer, leaving the leftmost 96 bits alone.
/// Per NIST SP 800-38D §6.2.
const fn inc32(b: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut out = *b;
    let mut counter = u32::from_be_bytes([out[12], out[13], out[14], out[15]]);
    counter = counter.wrapping_add(1);
    let bytes = counter.to_be_bytes();
    out[12] = bytes[0];
    out[13] = bytes[1];
    out[14] = bytes[2];
    out[15] = bytes[3];
    out
}

/// GCTR (NIST SP 800-38D §6.5): a CTR-mode stream cipher over the
/// supplied initial counter block `icb`. Output buffer `out` must be
/// the same length as `input`.
///
/// Calls into [`Sm4Cipher::encrypt_blocks`] (v0.7 W1 batch API) for
/// the keystream generation so SIMD fanout under `sm4-bitsliced-simd`
/// rides automatically.
fn gctr(cipher: &Sm4Cipher, icb: &[u8; BLOCK_SIZE], input: &[u8], out: &mut [u8]) {
    debug_assert_eq!(out.len(), input.len());
    if input.is_empty() {
        return;
    }

    let block_count = input.len().div_ceil(BLOCK_SIZE);

    // Generate the keystream by encrypting (icb, inc32(icb),
    // inc32(inc32(icb)), ...).
    let mut keystream: Vec<[u8; BLOCK_SIZE]> = Vec::with_capacity(block_count);
    let mut cb = *icb;
    for _ in 0..block_count {
        keystream.push(cb);
        cb = inc32(&cb);
    }
    cipher.encrypt_blocks(&mut keystream);

    // XOR keystream with input.
    for (i, &b) in input.iter().enumerate() {
        let block_idx = i / BLOCK_SIZE;
        let lane = i % BLOCK_SIZE;
        out[i] = b ^ keystream[block_idx][lane];
    }
}

/// Compute `J0` per NIST SP 800-38D §7.1 step 2.
///
/// - If `nonce.len() == 12`: `J0 = nonce || 0x00000001`.
/// - Else: `J0 = GHASH(H, nonce || 0^s || [nonce_len_bits]_64)` where
///   `s` is the zero-pad length that brings `nonce || 0^s` to a
///   multiple of 128 bits.
fn derive_j0(h_block: &[u8; BLOCK_SIZE], nonce: &[u8]) -> [u8; BLOCK_SIZE] {
    if nonce.len() == 12 {
        let mut j0 = [0u8; BLOCK_SIZE];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 0x01;
        return j0;
    }

    // Non-12-byte nonce path: GHASH chain over (nonce ‖ zero-pad ‖
    // [nonce_bit_length]_be_64). The trailing 64-bit length encoding
    // is placed in the high half of the final 128-bit block (per the
    // spec: the structure is `nonce ‖ 0^s ‖ 0^64 ‖ [len(IV)]_64`).
    let nonce_bit_len = u64::try_from(nonce.len())
        .unwrap_or(u64::MAX)
        .saturating_mul(8);
    let mut padded = Vec::with_capacity(nonce.len() + BLOCK_SIZE + BLOCK_SIZE);
    padded.extend_from_slice(nonce);
    // Pad nonce to next 128-bit boundary.
    while padded.len() % BLOCK_SIZE != 0 {
        padded.push(0);
    }
    // Append a full zero block followed by the 64-bit length, OR — per
    // the §7.1 spec — append zeros + [0]_64 + [len_bits]_64. Total: a
    // 128-bit trailing block with high 64 = 0, low 64 = len_bits_be.
    padded.extend_from_slice(&[0u8; 8]);
    padded.extend_from_slice(&nonce_bit_len.to_be_bytes());

    ghash(h_block, &padded)
}

/// GHASH chain over `A ‖ 0^v ‖ C ‖ 0^u ‖ [len_A]_64 ‖ [len_C]_64` per
/// NIST SP 800-38D §6.4.
fn ghash_a_c_lens(h_block: &[u8; BLOCK_SIZE], aad: &[u8], ct: &[u8]) -> [u8; BLOCK_SIZE] {
    let mut buf = Vec::with_capacity(aad.len() + BLOCK_SIZE + ct.len() + BLOCK_SIZE + BLOCK_SIZE);
    buf.extend_from_slice(aad);
    while buf.len() % BLOCK_SIZE != 0 {
        buf.push(0);
    }
    let aad_end = buf.len();
    buf.extend_from_slice(ct);
    while buf.len() % BLOCK_SIZE != 0 {
        buf.push(0);
    }
    debug_assert_eq!((buf.len() - aad_end) % BLOCK_SIZE, 0);

    // Trailing 128-bit block: [len_A_bits]_64 ‖ [len_C_bits]_64.
    let aad_bits = u64::try_from(aad.len())
        .unwrap_or(u64::MAX)
        .saturating_mul(8);
    let ct_bits = u64::try_from(ct.len())
        .unwrap_or(u64::MAX)
        .saturating_mul(8);
    buf.extend_from_slice(&aad_bits.to_be_bytes());
    buf.extend_from_slice(&ct_bits.to_be_bytes());

    ghash(h_block, &buf)
}

/// `Y_0 = 0`; for each 128-bit block `X_i` of `data`: `Y_i = (Y_{i-1}
/// ⊕ X_i) · H`. Returns `Y_m` where `m = data.len() / 16`.
///
/// `data.len()` MUST be a multiple of 16 — callers pad explicitly
/// before invoking. Routes the `·H` step through
/// [`gmcrypto_simd::ghash::ghash_mul`] (W1) so the GHASH multiplication
/// rides CLMUL on `x86_64` / PMULL on `aarch64` when available.
fn ghash(h_block: &[u8; BLOCK_SIZE], data: &[u8]) -> [u8; BLOCK_SIZE] {
    debug_assert_eq!(data.len() % BLOCK_SIZE, 0);
    let mut y = [0u8; BLOCK_SIZE];
    let mut i = 0;
    while i < data.len() {
        let mut xored = [0u8; BLOCK_SIZE];
        for k in 0..BLOCK_SIZE {
            xored[k] = y[k] ^ data[i + k];
        }
        y = gmcrypto_simd::ghash::ghash_mul(h_block, &xored);
        i += BLOCK_SIZE;
    }
    y
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    const NONCE_12: [u8; 12] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    ];

    #[test]
    fn round_trip_canonical_nonce() {
        let aad = b"associated data";
        let plaintext = b"v0.8 W2 SM4-GCM round-trip smoke test";
        let (ct, tag) = encrypt(&KEY, &NONCE_12, aad, plaintext);
        let recovered = decrypt(&KEY, &NONCE_12, aad, &ct, &tag).expect("tag verifies");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let aad = b"aad-only message";
        let (ct, tag) = encrypt(&KEY, &NONCE_12, aad, &[]);
        assert!(ct.is_empty());
        let recovered = decrypt(&KEY, &NONCE_12, aad, &ct, &tag).expect("tag verifies");
        assert_eq!(recovered, &[] as &[u8]);
    }

    #[test]
    fn round_trip_empty_aad() {
        let plaintext = b"hello GCM, no AAD";
        let (ct, tag) = encrypt(&KEY, &NONCE_12, &[], plaintext);
        let recovered = decrypt(&KEY, &NONCE_12, &[], &ct, &tag).expect("tag verifies");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn round_trip_non_12_byte_nonce() {
        let nonce: [u8; 7] = [0x42u8; 7];
        let aad = b"aad";
        let plaintext = b"short-nonce SM4-GCM";
        let (ct, tag) = encrypt(&KEY, &nonce, aad, plaintext);
        let recovered = decrypt(&KEY, &nonce, aad, &ct, &tag).expect("tag verifies");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn tampered_tag_fails() {
        let aad = b"x";
        let plaintext = b"original";
        let (ct, mut tag) = encrypt(&KEY, &NONCE_12, aad, plaintext);
        tag[0] ^= 0x01;
        assert!(decrypt(&KEY, &NONCE_12, aad, &ct, &tag).is_none());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let aad = b"x";
        let plaintext = b"original";
        let (mut ct, tag) = encrypt(&KEY, &NONCE_12, aad, plaintext);
        if !ct.is_empty() {
            ct[0] ^= 0x01;
        }
        assert!(decrypt(&KEY, &NONCE_12, aad, &ct, &tag).is_none());
    }

    #[test]
    fn tampered_aad_fails() {
        let aad = b"correct-aad";
        let plaintext = b"original";
        let (ct, tag) = encrypt(&KEY, &NONCE_12, aad, plaintext);
        assert!(decrypt(&KEY, &NONCE_12, b"wrong-aad", &ct, &tag).is_none());
    }
}
