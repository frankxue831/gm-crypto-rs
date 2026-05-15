//! SM4 in CCM mode (Counter with CBC-MAC) per NIST SP 800-38C and
//! RFC 3610, with the underlying block cipher swapped from AES to
//! SM4 per GM/T 0009 (OID `1.2.156.10197.1.104.9`).
//!
//! # Authenticated encryption with associated data (AEAD)
//!
//! SM4-CCM is an authenticated AEAD mode. Unlike GCM (which composes
//! CTR with GHASH), CCM composes CTR with CBC-MAC under the same
//! block cipher — no separate hash subkey, no GHASH primitive.
//!
//! Compared to [`super::mode_gcm`], CCM:
//!
//! - Uses the same SM4 cipher for both confidentiality and
//!   authentication (no GHASH), so the algorithm reads only from the
//!   existing block cipher path.
//! - Requires the caller to commit to plaintext length up front (the
//!   length is encoded in the first CBC-MAC block) — incompatible
//!   with streaming. v0.8 ships single-shot only.
//! - Parameterizes tag length (4/6/8/10/12/14/16 bytes per RFC 3610).
//!
//! # Nonce contract
//!
//! Per NIST SP 800-38C §5.1: SM4-CCM nonces must be **unique-per-key**.
//! Caller-supplied; this module does not generate nonces. Reusing a
//! `(key, nonce)` pair is catastrophic — same warning as
//! [`super::mode_gcm`].
//!
//! Nonce length must be in `[7, 13]` bytes; the remaining
//! `15 - nonce.len()` bytes of the 16-byte CCM block hold the
//! payload-length field, which limits maximum plaintext size to
//! `2^(8 * (15 - nonce.len()))` bytes. The most common configurations:
//!
//! | `nonce.len()` | Max plaintext bytes |
//! |---|---|
//! | 7  | 2^64 (effectively unbounded) |
//! | 12 | 2^24 ≈ 16 MiB |
//! | 13 | 2^16 = 65 535 bytes |
//!
//! 13-byte nonces are common in IEEE 802.15.4 / Zigbee / TLS-CCM
//! profiles; 12-byte nonces match the SM4-GCM canonical shape and are
//! a reasonable default for new applications.
//!
//! # Tag length
//!
//! Caller-specified, one of `{4, 6, 8, 10, 12, 14, 16}`. Shorter tags
//! reduce ciphertext expansion at the cost of weaker forgery
//! resistance (`2^(8 * tag_len)` work for a single forgery; the
//! standard advisory is `tag_len >= 8`). v0.8 W3 surfaces all seven
//! permitted lengths; callers are responsible for choosing a value
//! appropriate to their threat model.
//!
//! # Failure mode invariant
//!
//! Both [`encrypt`] and [`decrypt`] return `Option<Vec<u8>>`. `None`
//! covers all failure paths uniformly:
//!
//! - Invalid nonce length (outside `[7, 13]`).
//! - Invalid tag length (not in `{4, 6, 8, 10, 12, 14, 16}`).
//! - AAD length too large to encode in CCM's length-prefix
//!   (≥ `2^64` bytes — a hypothetical bound that's never hit on
//!   practical inputs).
//! - Plaintext length too large for the chosen nonce length.
//! - On `decrypt` only: tag mismatch.
//! - On `decrypt` only: ciphertext-with-tag input shorter than
//!   `tag_len` bytes.
//!
//! No distinguishing variants per the workspace failure-mode
//! invariant (`CLAUDE.md` "Hard constraints").
//!
//! # KAT sourcing
//!
//! gmssl 3.1.1 does not ship `sm4 -ccm`. KAT vectors for this module
//! come from OpenSSL 3.x EVP `SM4-CCM` (vendor-neutral GB/T 0009 OID
//! `1.2.156.10197.1.104.9`). See [`docs/v0.8-ccm-kat-sourcing.md`] for
//! the sourcing rationale and reference-oracle C harness.
//!
//! # API
//!
//! ```rust
//! # #[cfg(feature = "sm4-aead")] {
//! use gmcrypto_core::sm4::{KEY_SIZE, mode_ccm};
//!
//! let key: [u8; KEY_SIZE] = [0x42; KEY_SIZE];
//! let nonce: &[u8] = &[0x01; 12];   // 12-byte nonce
//! let aad = b"associated data";
//! let plaintext = b"hello world";
//! let tag_len = 16;
//!
//! let ct_with_tag = mode_ccm::encrypt(&key, nonce, aad, plaintext, tag_len)
//!     .expect("inputs valid");
//! assert_eq!(ct_with_tag.len(), plaintext.len() + tag_len);
//!
//! let recovered = mode_ccm::decrypt(&key, nonce, aad, &ct_with_tag, tag_len);
//! assert_eq!(recovered.as_deref(), Some(plaintext.as_slice()));
//! # }
//! ```

// The CCM control bytes (flags, q, q-1, length encodings) are
// constrained by the validation gates to small ranges (q ∈ 2..=9,
// tag_len/2 ∈ 1..=8, etc.). Suppressing the per-site truncation
// warnings keeps the algorithmic flow readable; the casts are
// invariant-guarded.
#![allow(clippy::cast_possible_truncation)]

use alloc::vec;
use alloc::vec::Vec;

use subtle::ConstantTimeEq;

use super::cipher::{BLOCK_SIZE, KEY_SIZE, Sm4Cipher};

/// Valid CCM tag lengths in bytes per RFC 3610 §2.1.
const VALID_TAG_LENS: [usize; 7] = [4, 6, 8, 10, 12, 14, 16];

/// Valid CCM nonce lengths in bytes per RFC 3610 §2.1.
const MIN_NONCE_LEN: usize = 7;
const MAX_NONCE_LEN: usize = 13;

/// Encrypt `plaintext` under `(key, nonce)` with `aad` authenticated,
/// producing `ciphertext ‖ tag` in a single output buffer.
///
/// Returns `None` if any of the input-validation gates fail (see the
/// module docstring for the full list).
#[must_use]
pub fn encrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> Option<Vec<u8>> {
    validate_params(nonce, plaintext.len(), aad.len(), tag_len)?;

    let cipher = Sm4Cipher::new(key);
    let q = 15 - nonce.len();

    // Step 1: build the formatted authentication data (B0 || aad-formatted || PT-padded).
    let b0 = build_b0(nonce, plaintext.len(), !aad.is_empty(), tag_len, q);
    let mut auth = Vec::with_capacity(BLOCK_SIZE);
    auth.extend_from_slice(&b0);
    if !aad.is_empty() {
        format_aad_into(&mut auth, aad);
    }
    let plaintext_offset = auth.len();
    auth.extend_from_slice(plaintext);
    while auth.len() % BLOCK_SIZE != 0 {
        auth.push(0);
    }
    let _ = plaintext_offset; // documenting the layout; unused.

    // Step 2: CBC-MAC chain over `auth` to obtain the raw 16-byte tag T.
    let t = cbc_mac(&cipher, &auth);

    // Step 3: CTR encryption with A_0 = (q-1 flags) || nonce || 0_q_bytes.
    // The keystream block for counter i is SM4_E(key, A_i), where A_i
    // increments the trailing q-byte counter. The encrypted A_0 is
    // XOR'd into the leading tag_len bytes of T to produce the final
    // tag.
    let mut a0 = [0u8; BLOCK_SIZE];
    a0[0] = (q - 1) as u8; // Adata bit is 0 in A_i blocks (only in B_i blocks).
    a0[1..=nonce.len()].copy_from_slice(nonce);
    // Bytes [1 + nonce_len..16] = counter, starts at 0.

    let mut s0 = a0;
    cipher.encrypt_block(&mut s0);

    // Tag: take first tag_len bytes of (s0 XOR t).
    let mut tag = [0u8; 16];
    for i in 0..tag_len {
        tag[i] = s0[i] ^ t[i];
    }

    // CTR encryption starts at counter 1 (A_1 has trailing bytes = 1).
    let mut ct = vec![0u8; plaintext.len()];
    ccm_ctr_xor(&cipher, &a0, plaintext, &mut ct);

    // Output: ciphertext || tag_len bytes of tag.
    let mut output = Vec::with_capacity(ct.len() + tag_len);
    output.extend_from_slice(&ct);
    output.extend_from_slice(&tag[..tag_len]);
    Some(output)
}

/// Decrypt `ciphertext_with_tag` (≡ `ciphertext ‖ tag`) under
/// `(key, nonce)` with `aad` authenticated. Returns `Some(plaintext)`
/// on tag verification, `None` otherwise.
///
/// CCM's CBC-MAC pass requires the plaintext to compute the
/// authentication tag, so the CTR decryption must happen before tag
/// verification (unlike SM4-GCM, where verify-before-decrypt is
/// possible because GHASH operates on ciphertext bytes). The
/// tentative plaintext buffer is dropped on the failure path; the
/// `None` return never exposes it.
#[must_use]
pub fn decrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
    tag_len: usize,
) -> Option<Vec<u8>> {
    if !VALID_TAG_LENS.contains(&tag_len) {
        return None;
    }
    if ciphertext_with_tag.len() < tag_len {
        return None;
    }
    let split = ciphertext_with_tag.len() - tag_len;
    let ct = &ciphertext_with_tag[..split];
    let wire_tag = &ciphertext_with_tag[split..];

    validate_params(nonce, ct.len(), aad.len(), tag_len)?;

    let cipher = Sm4Cipher::new(key);
    let q = 15 - nonce.len();

    // Step 1: CTR-decrypt the ciphertext into a tentative plaintext.
    // We need the plaintext to recompute the MAC, so unlike GCM we
    // can't verify-before-decrypt purely. However, we still don't
    // *return* the plaintext until the tag verifies — and the local
    // buffer is dropped on the failure path (Rust's drop discipline
    // handles it; no explicit zeroize needed for a stack-Vec).
    let mut a0 = [0u8; BLOCK_SIZE];
    a0[0] = (q - 1) as u8;
    a0[1..=nonce.len()].copy_from_slice(nonce);

    let mut tentative_pt = vec![0u8; ct.len()];
    ccm_ctr_xor(&cipher, &a0, ct, &mut tentative_pt);

    // Step 2: recompute the MAC over the tentative plaintext.
    let b0 = build_b0(nonce, tentative_pt.len(), !aad.is_empty(), tag_len, q);
    let mut auth = Vec::with_capacity(BLOCK_SIZE);
    auth.extend_from_slice(&b0);
    if !aad.is_empty() {
        format_aad_into(&mut auth, aad);
    }
    auth.extend_from_slice(&tentative_pt);
    while auth.len() % BLOCK_SIZE != 0 {
        auth.push(0);
    }
    let t = cbc_mac(&cipher, &auth);

    // Step 3: compute the expected tag bytes.
    let mut s0 = a0;
    cipher.encrypt_block(&mut s0);
    let mut expected_tag = [0u8; 16];
    for i in 0..tag_len {
        expected_tag[i] = s0[i] ^ t[i];
    }

    // Step 4: constant-time compare against wire tag.
    if expected_tag[..tag_len].ct_eq(wire_tag).unwrap_u8() != 1 {
        return None;
    }

    Some(tentative_pt)
}

// ============================================================
// CCM internals
// ============================================================

/// Validate caller-supplied parameters per RFC 3610 §2.1.
fn validate_params(nonce: &[u8], pt_len: usize, aad_len: usize, tag_len: usize) -> Option<()> {
    if !VALID_TAG_LENS.contains(&tag_len) {
        return None;
    }
    if nonce.len() < MIN_NONCE_LEN || nonce.len() > MAX_NONCE_LEN {
        return None;
    }
    let q = 15 - nonce.len();
    // Plaintext length must fit in q bytes.
    if q < 8 {
        let max_pt: u64 = (1u64 << (8 * q)) - 1;
        if (pt_len as u64) > max_pt {
            return None;
        }
    }
    // AAD length encoding limits: spec allows up to 2^64-1 via the
    // 8-byte FFFF prefix, which exceeds practical input sizes. We
    // accept anything `usize` allows (validated transitively by the
    // length-prefix encoder).
    let _ = aad_len;
    Some(())
}

/// Construct the first authentication block `B0` per RFC 3610 §2.2.
fn build_b0(
    nonce: &[u8],
    pt_len: usize,
    has_aad: bool,
    tag_len: usize,
    q: usize,
) -> [u8; BLOCK_SIZE] {
    let mut b0 = [0u8; BLOCK_SIZE];
    // Flags byte: reserved(1)=0 || Adata(1) || ((t-2)/2)(3 bits) || (q-1)(3 bits)
    let adata_bit: u8 = if has_aad { 0x40 } else { 0 };
    let t_field: u8 = (((tag_len - 2) / 2) as u8) << 3;
    let q_field: u8 = (q - 1) as u8;
    b0[0] = adata_bit | t_field | q_field;
    b0[1..=nonce.len()].copy_from_slice(nonce);
    // Encode pt_len as q-byte big-endian integer.
    let pt_len_bytes = (pt_len as u64).to_be_bytes(); // 8 bytes BE
    // Copy the low q bytes into positions [16 - q .. 16].
    let start = 16 - q;
    if q <= 8 {
        b0[start..16].copy_from_slice(&pt_len_bytes[8 - q..8]);
    } else {
        // q > 8 should be unreachable since nonce.len() >= 7 forces q <= 8.
        debug_assert!(q <= 8);
    }
    b0
}

/// Append the formatted AAD to `out` per RFC 3610 §2.2 (zero-padded
/// to a block boundary).
fn format_aad_into(out: &mut Vec<u8>, aad: &[u8]) {
    // Length-prefix encoding per the spec:
    let alen = aad.len();
    if alen < 0xFF00 {
        // 2-byte BE length prefix.
        let l = alen as u16;
        out.extend_from_slice(&l.to_be_bytes());
    } else if alen <= 0xFFFF_FFFF {
        // 0xFFFE + 4-byte BE length prefix.
        out.push(0xFF);
        out.push(0xFE);
        out.extend_from_slice(&(alen as u32).to_be_bytes());
    } else {
        // 0xFFFF + 8-byte BE length prefix. usize on 64-bit hosts can
        // hit this; on 32-bit hosts it's unreachable.
        out.push(0xFF);
        out.push(0xFF);
        out.extend_from_slice(&(alen as u64).to_be_bytes());
    }
    out.extend_from_slice(aad);
    while out.len() % BLOCK_SIZE != 0 {
        out.push(0);
    }
}

/// CBC-MAC chain over `data` (must be block-aligned) under the
/// supplied cipher. Each round: `T = SM4_E(key, T XOR data_block)`.
fn cbc_mac(cipher: &Sm4Cipher, data: &[u8]) -> [u8; BLOCK_SIZE] {
    debug_assert_eq!(data.len() % BLOCK_SIZE, 0);
    let mut t = [0u8; BLOCK_SIZE];
    let mut i = 0;
    while i < data.len() {
        for k in 0..BLOCK_SIZE {
            t[k] ^= data[i + k];
        }
        cipher.encrypt_block(&mut t);
        i += BLOCK_SIZE;
    }
    t
}

/// CCM CTR-mode XOR: keystream is `SM4_E(key, A_i)` for `i = 1, 2,
/// ...` where `A_i` increments the trailing `q` bytes of `a0`.
fn ccm_ctr_xor(cipher: &Sm4Cipher, a0: &[u8; BLOCK_SIZE], input: &[u8], output: &mut [u8]) {
    debug_assert_eq!(input.len(), output.len());
    if input.is_empty() {
        return;
    }
    let block_count = input.len().div_ceil(BLOCK_SIZE);
    let nonce_part_end = a0[0] as usize; // q - 1 = byte index where counter starts - 1
    let q = (nonce_part_end + 1) as u32; // q is 15 - nonce.len()
    let counter_start_idx = 16 - q as usize;

    // Build A_1 .. A_block_count.
    let mut keystream: Vec<[u8; BLOCK_SIZE]> = Vec::with_capacity(block_count);
    for i in 1..=block_count {
        let mut a_i = *a0;
        // Encode i as q-byte BE into the trailing slot.
        let i_bytes = (i as u64).to_be_bytes();
        a_i[counter_start_idx..16].copy_from_slice(&i_bytes[8 - q as usize..8]);
        keystream.push(a_i);
    }
    cipher.encrypt_blocks(&mut keystream);

    for j in 0..input.len() {
        let block_idx = j / BLOCK_SIZE;
        let lane = j % BLOCK_SIZE;
        output[j] = input[j] ^ keystream[block_idx][lane];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    #[test]
    fn round_trip_canonical() {
        let nonce = [0x00u8; 12];
        let aad = b"associated data";
        let pt = b"v0.8 W3 SM4-CCM smoke";
        let ct = encrypt(&KEY, &nonce, aad, pt, 16).expect("valid params");
        let recovered = decrypt(&KEY, &nonce, aad, &ct, 16).expect("tag verifies");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn round_trip_short_tag() {
        let nonce = [0x00u8; 12];
        for &tag_len in &[4, 6, 8, 10, 12, 14, 16] {
            let pt = b"varying tag length";
            let ct = encrypt(&KEY, &nonce, b"aad", pt, tag_len).expect("valid params");
            assert_eq!(ct.len(), pt.len() + tag_len);
            let recovered = decrypt(&KEY, &nonce, b"aad", &ct, tag_len).expect("tag verifies");
            assert_eq!(recovered, pt);
        }
    }

    #[test]
    fn round_trip_nonce_length_sweep() {
        for nonce_len in 7..=13 {
            let nonce = vec![0x42u8; nonce_len];
            let ct = encrypt(&KEY, &nonce, b"x", b"hi", 16).expect("valid params");
            let recovered = decrypt(&KEY, &nonce, b"x", &ct, 16).expect("tag verifies");
            assert_eq!(recovered, b"hi");
        }
    }

    #[test]
    fn round_trip_empty_pt() {
        let nonce = [0x42u8; 12];
        let ct = encrypt(&KEY, &nonce, b"aad", &[], 16).expect("valid params");
        assert_eq!(ct.len(), 16);
        let recovered = decrypt(&KEY, &nonce, b"aad", &ct, 16).expect("tag verifies");
        assert!(recovered.is_empty());
    }

    #[test]
    fn round_trip_empty_aad() {
        let nonce = [0x42u8; 12];
        let pt = b"hello";
        let ct = encrypt(&KEY, &nonce, &[], pt, 16).expect("valid params");
        let recovered = decrypt(&KEY, &nonce, &[], &ct, 16).expect("tag verifies");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn tampered_tag_fails() {
        let nonce = [0x42u8; 12];
        let mut ct = encrypt(&KEY, &nonce, b"aad", b"hello", 16).expect("valid params");
        let len = ct.len();
        ct[len - 1] ^= 0x01;
        assert!(decrypt(&KEY, &nonce, b"aad", &ct, 16).is_none());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let nonce = [0x42u8; 12];
        let mut ct = encrypt(&KEY, &nonce, b"aad", b"hello", 16).expect("valid params");
        ct[0] ^= 0x01;
        assert!(decrypt(&KEY, &nonce, b"aad", &ct, 16).is_none());
    }

    #[test]
    fn tampered_aad_fails() {
        let nonce = [0x42u8; 12];
        let ct = encrypt(&KEY, &nonce, b"correct-aad", b"hello", 16).expect("valid params");
        assert!(decrypt(&KEY, &nonce, b"wrong-aad", &ct, 16).is_none());
    }

    #[test]
    fn invalid_nonce_length_rejected() {
        assert!(encrypt(&KEY, &[0u8; 6], &[], &[], 16).is_none());
        assert!(encrypt(&KEY, &[0u8; 14], &[], &[], 16).is_none());
        assert!(decrypt(&KEY, &[0u8; 6], &[], &[0u8; 16], 16).is_none());
    }

    #[test]
    fn invalid_tag_length_rejected() {
        let nonce = [0x42u8; 12];
        for tag_len in [0usize, 3, 5, 7, 9, 11, 13, 15, 17, 32] {
            assert!(
                encrypt(&KEY, &nonce, &[], &[], tag_len).is_none(),
                "encrypt accepted invalid tag_len={tag_len}",
            );
        }
    }

    #[test]
    fn ct_with_tag_shorter_than_tag_len_rejected() {
        let nonce = [0x42u8; 12];
        // Decrypt with tag_len=16 but only 8 bytes of input → None.
        assert!(decrypt(&KEY, &nonce, b"aad", &[0u8; 8], 16).is_none());
    }
}
