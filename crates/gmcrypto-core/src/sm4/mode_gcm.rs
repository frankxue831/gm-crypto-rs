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
//! [`encrypt`] / [`decrypt`] use the full 128-bit (16-byte) tag — the
//! safest default. v0.9 W1 adds caller-chosen tag lengths via the
//! [`GcmTagLen`] newtype and the [`encrypt_with_tag_len`] /
//! [`decrypt_with_tag_len`] variants (NIST SP 800-38D §5.2.1.2
//! permits `{4, 8, 12, 13, 14, 15, 16}` bytes; the truncated tag is
//! `MSB_t(full_tag)`). Shorter tags reduce ciphertext expansion at
//! the cost of weaker forgery resistance — prefer 16 bytes unless a
//! protocol mandates a shorter tag.
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
//! # Throughput
//!
//! GCM encrypt is CTR plus GHASH. Forged decrypt is GHASH-then-reject
//! and does not take the serial SM4 path, so `sm4-bitsliced-simd` does
//! not accelerate it. Measured 1 MiB figures for `sm4-aead` /
//! `sm4-aead,sm4-bitsliced` / `sm4-aead,sm4-bitsliced-simd` are in
//! CHANGELOG Unreleased (issue #163).
//!
//! # API
//!
//! ```rust
//! # #[cfg(feature = "sm4-aead")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use gmcrypto_core::sm4::{KEY_SIZE, mode_gcm};
//!
//! let key: [u8; KEY_SIZE] = [0x42; KEY_SIZE];
//! let nonce: [u8; 12] = [0x01; 12];                  // 12-byte canonical nonce
//! let aad: &[u8] = b"additional authenticated data";
//! let plaintext = b"hello world";
//!
//! let (ciphertext, tag) = mode_gcm::encrypt(&key, &nonce, aad, plaintext)
//!     .ok_or("plaintext past the GCM counter ceiling")?;
//! assert_eq!(ciphertext.len(), plaintext.len());
//!
//! let recovered = mode_gcm::decrypt(&key, &nonce, aad, &ciphertext, &tag)
//!     .ok_or("authentication failed")?;
//! assert_eq!(recovered, plaintext);
//!
//! // A tampered tag fails verification — with the same opaque `None`.
//! let mut bad_tag = tag;
//! bad_tag[0] ^= 0x01;
//! assert!(mode_gcm::decrypt(&key, &nonce, aad, &ciphertext, &bad_tag).is_none());
//! # Ok(()) }
//! # #[cfg(not(feature = "sm4-aead"))] fn main() {}
//! ```

use alloc::vec;
use alloc::vec::Vec;

use subtle::ConstantTimeEq;

use super::cipher::{BLOCK_SIZE, KEY_SIZE, Sm4Cipher};

/// Full GCM tag length in bytes (128 bits). [`encrypt`] / [`decrypt`]
/// always use this; [`GcmTagLen`] selects a (possibly shorter)
/// truncated length for [`encrypt_with_tag_len`] /
/// [`decrypt_with_tag_len`].
pub const TAG_SIZE: usize = 16;

/// NIST SP 800-38D §5.2.1.1 plaintext ceiling, in bytes:
/// `2^39 − 256` bits = `2^36 − 32` bytes. Past this limit the 32-bit
/// GCTR counter wraps and keystream is reused — catastrophic. The
/// single-shot [`encrypt`] / [`encrypt_with_tag_len`] reject inputs
/// above this (mirroring the streaming poison in
/// [`super::gcm_streaming`]); [`decrypt`] / [`decrypt_with_tag_len`]
/// reject over-ceiling ciphertexts symmetrically. Mirrors
/// `gcm_streaming.rs`'s `GCM_MAX_PT_BYTES`.
pub(crate) const GCM_MAX_PT_BYTES: u64 = (1u64 << 36) - 32;

/// A validated GCM authentication-tag length, in bytes.
///
/// Per NIST SP 800-38D §5.2.1.2 the permitted tag lengths are
/// `{4, 8, 12, 13, 14, 15, 16}` bytes (32, 64, 96, 104, 112, 120,
/// 128 bits). Construct via [`GcmTagLen::new`]; an out-of-range
/// length yields `None` (single failure mode — no distinguishing
/// variant per the workspace invariant).
///
/// Shorter tags reduce ciphertext expansion at the cost of weaker
/// forgery resistance (`2^(8·tag_len)` work per forgery attempt).
/// 16 bytes is the safest default; lengths below 12 should be used
/// only when a protocol mandates them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcmTagLen(usize);

impl GcmTagLen {
    /// Construct from a byte length. Returns `Some` only for the
    /// NIST-permitted set `{4, 8, 12, 13, 14, 15, 16}`.
    #[must_use]
    pub const fn new(bytes: usize) -> Option<Self> {
        match bytes {
            4 | 8 | 12 | 13 | 14 | 15 | 16 => Some(Self(bytes)),
            _ => None,
        }
    }

    /// The validated length in bytes.
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0
    }
}

/// Encrypt `plaintext` under `(key, nonce)` with `aad` authenticated
/// but not encrypted. Returns `Some((ciphertext, tag))` where
/// `ciphertext.len() == plaintext.len()` and `tag.len() == 16`.
///
/// Returns `None` when `plaintext.len() > 2^36 − 32` bytes
/// ([`GCM_MAX_PT_BYTES`]): past that limit the 32-bit GCTR counter
/// wraps and keystream is reused (NIST SP 800-38D §5.2.1.1). This is a
/// length-range reject, not a failure-mode distinction; it mirrors the
/// streaming-encryptor poison. The bound is unreachable at sane sizes
/// (a single ~68 GB in-memory buffer).
///
/// See the module-level docstring for the nonce-uniqueness contract.
#[must_use]
pub fn encrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Option<(Vec<u8>, [u8; TAG_SIZE])> {
    if plaintext.len() as u64 > GCM_MAX_PT_BYTES {
        return None;
    }
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

    Some((ciphertext, tag))
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
    if ciphertext.len() as u64 > GCM_MAX_PT_BYTES {
        return None;
    }
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

/// Encrypt with a caller-chosen authentication-tag length.
///
/// Identical to [`encrypt`] except the returned tag is the first
/// `tag_len.as_usize()` bytes of the full 128-bit tag (NIST SP
/// 800-38D §5.2.1.2 truncation: `T = MSB_t(full_tag)`). The
/// ciphertext is byte-identical to [`encrypt`]'s — only the tag
/// length changes.
///
/// Returns `None` for the same `> 2^36 − 32`-byte plaintext ceiling as
/// [`encrypt`] ([`GCM_MAX_PT_BYTES`]).
#[must_use]
pub fn encrypt_with_tag_len(
    key: &[u8; KEY_SIZE],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: GcmTagLen,
) -> Option<(Vec<u8>, Vec<u8>)> {
    if plaintext.len() as u64 > GCM_MAX_PT_BYTES {
        return None;
    }
    let (ciphertext, full_tag) = encrypt(key, nonce, aad, plaintext)?;
    let tag = full_tag[..tag_len.as_usize()].to_vec();
    Some((ciphertext, tag))
}

/// Decrypt where the authentication tag may be shorter than 128 bits.
///
/// The tag length is inferred from `tag.len()` and validated against
/// the NIST-permitted set. `Some(plaintext)` only when the truncated
/// recomputed tag constant-time-equals `tag`; `None` on any failure
/// (tag mismatch, invalid tag length). Single `None` per the
/// failure-mode invariant. As with [`decrypt`], CTR decryption is
/// deferred until after tag verification so no failure-path plaintext
/// is materialized.
#[must_use]
pub fn decrypt_with_tag_len(
    key: &[u8; KEY_SIZE],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Option<Vec<u8>> {
    if ciphertext.len() as u64 > GCM_MAX_PT_BYTES {
        return None;
    }
    let tag_len = GcmTagLen::new(tag.len())?;
    let t = tag_len.as_usize();

    let cipher = Sm4Cipher::new(key);
    let mut h_block = [0u8; BLOCK_SIZE];
    cipher.encrypt_block(&mut h_block);
    let j0 = derive_j0(&h_block, nonce);

    let s = ghash_a_c_lens(&h_block, aad, ciphertext);
    let mut expected_full = [0u8; TAG_SIZE];
    gctr(&cipher, &j0, &s, &mut expected_full);

    // Constant-time compare over the first `t` bytes only. `t` is a
    // public (non-secret) length, so indexing `expected_full[..t]` is
    // not a secret-dependent access; `ct_eq` keeps the byte comparison
    // itself constant-time.
    if expected_full[..t].ct_eq(tag).unwrap_u8() != 1 {
        return None;
    }

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
///
/// `pub(super)` (v0.9 W2): reused by [`super::gcm_streaming`] for the
/// incremental GCTR counter advance.
pub(super) const fn inc32(b: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
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
///
/// `pub(super)` (v0.9 simplify pass): reused by
/// [`super::gcm_streaming::Sm4GcmDecryptor`] so the buffered-decrypt
/// path runs this same canonical (SIMD-fanned) GCTR rather than a
/// hand-rolled per-block loop.
pub(super) fn gctr(cipher: &Sm4Cipher, icb: &[u8; BLOCK_SIZE], input: &[u8], out: &mut [u8]) {
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
///
/// `pub(super)` (v0.9 W2): reused by [`super::gcm_streaming`] to derive
/// the pre-counter block at constructor time.
pub(super) fn derive_j0(h_block: &[u8; BLOCK_SIZE], nonce: &[u8]) -> [u8; BLOCK_SIZE] {
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

#[cfg(feature = "aead-traits")]
mod aead_impl {
    //! v1.11 — `RustCrypto` `aead` 0.6 trait fit for SM4-GCM (Q11.1–Q11.9).
    //!
    //! [`Sm4Gcm`] is a **thin wrapper**: every method delegates to the inherent
    //! [`encrypt`](super::encrypt) / [`decrypt`](super::decrypt) above and adds
    //! no cryptography. That is load-bearing, not incidental — it is why this
    //! surface needs no dudect target of its own (the measured bodies behind
    //! `ct_sm4_gcm_decrypt` are byte-identical on this path).
    //!
    //! **The trait set is not a free choice.** `aead` 0.6 blanket-implements
    //! `Aead` for every `AeadInOut`, so a direct `impl Aead for Sm4Gcm` cannot
    //! compile — it would conflict. `AeadInOut` is the entry point; the
    //! `Vec`-returning `Aead` and the `Buffer`-based in-place methods come
    //! free. (`AeadInPlace` is deprecated in 0.6 and deliberately not
    //! implemented.)
    //!
    //! **Profile (Q11.3):** fixed 12-byte nonce, 16-byte postfix tag — the
    //! canonical safe shape, and what RFC 8998 and TLS use. Truncated tags
    //! ([`GcmTagLen`](super::GcmTagLen)) and arbitrary-length nonces stay
    //! reachable through the inherent functions; the trait types are not the
    //! place to expose them.
    //!
    //! **Costs, stated plainly.** The struct holds key bytes, so each call runs
    //! a fresh SM4 key schedule; and because the underlying functions allocate,
    //! so do the methods named "in place". Throughput-sensitive callers should
    //! use the inherent API. Both costs buy the wrapper thinness above.
    //!
    //! **Why the `copy_from_slice` calls below cannot panic.** They rely on an
    //! invariant of `InOutBuf` rather than of this module: the type carries a
    //! single `len` and its checked constructor rejects unequal halves
    //! (`InOutBuf::new -> Result<_, NotEqualError>`), so `get_in().len()` and
    //! `get_out().len()` are always equal — a caller cannot hand us mismatched
    //! halves even deliberately. Since the underlying functions return output
    //! exactly as long as their input, the copy lengths always agree. If a
    //! future `inout` major version ever relaxed that, these copies would need
    //! explicit length checks.

    use aead::array::Array;
    use aead::consts::{U12, U16};
    use aead::inout::InOutBuf;
    use aead::{AeadCore, AeadInOut, Error, KeyInit, KeySizeUser, Nonce, Result, Tag, TagPosition};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use super::{KEY_SIZE, TAG_SIZE, decrypt, encrypt};

    const _: () = assert!(KEY_SIZE == 16, "Sm4Gcm declares KeySize = U16");
    const _: () = assert!(TAG_SIZE == 16, "Sm4Gcm declares TagSize = U16");

    /// SM4-GCM as a `RustCrypto` [`aead`] cipher: 128-bit key, 96-bit nonce,
    /// 128-bit postfix tag.
    ///
    /// Wire format from [`Aead::encrypt`](aead::Aead::encrypt) is
    /// `ciphertext ‖ tag`, byte-identical to
    /// [`mode_gcm::encrypt`](super::encrypt).
    ///
    /// The `(key, nonce)` pair must never repeat — nonce reuse under one key
    /// breaks GCM catastrophically, revealing plaintext XORs and leaking the
    /// authentication subkey. This type does not and cannot enforce that;
    /// choosing nonces is the caller's contract.
    #[derive(Clone, Zeroize, ZeroizeOnDrop)]
    pub struct Sm4Gcm {
        key: [u8; KEY_SIZE],
    }

    impl KeySizeUser for Sm4Gcm {
        type KeySize = U16;
    }

    impl KeyInit for Sm4Gcm {
        fn new(key: &aead::Key<Self>) -> Self {
            let mut k = [0u8; KEY_SIZE];
            k.copy_from_slice(key.as_slice());
            Self { key: k }
        }
    }

    impl AeadCore for Sm4Gcm {
        type NonceSize = U12;
        type TagSize = U16;
        const TAG_POSITION: TagPosition = TagPosition::Postfix;
    }

    impl AeadInOut for Sm4Gcm {
        fn encrypt_inout_detached(
            &self,
            nonce: &Nonce<Self>,
            associated_data: &[u8],
            mut buffer: InOutBuf<'_, '_, u8>,
        ) -> Result<Tag<Self>> {
            // `encrypt` already returns the detached (ct, tag) shape, so there
            // is nothing to split. Its `None` (the 2^36−32-byte ceiling)
            // becomes the one opaque error, like every other failure.
            let (ct, tag) = encrypt(
                &self.key,
                nonce.as_slice(),
                associated_data,
                buffer.get_in(),
            )
            .ok_or(Error)?;
            buffer.get_out().copy_from_slice(&ct);
            Ok(Array(tag))
        }

        fn decrypt_inout_detached(
            &self,
            nonce: &Nonce<Self>,
            associated_data: &[u8],
            mut buffer: InOutBuf<'_, '_, u8>,
            tag: &Tag<Self>,
        ) -> Result<()> {
            let tag_arr: [u8; TAG_SIZE] = (*tag).into();
            // GCM verifies before releasing plaintext, so on failure nothing
            // was decrypted and the out-half stays untouched.
            let mut pt = decrypt(
                &self.key,
                nonce.as_slice(),
                associated_data,
                buffer.get_in(),
                &tag_arr,
            )
            .ok_or(Error)?;
            buffer.get_out().copy_from_slice(&pt);
            // The inherent API hands this Vec to the caller; here it is purely
            // transient, and dropping a Vec frees without scrubbing.
            pt.zeroize();
            Ok(())
        }
    }
}

#[cfg(feature = "aead-traits")]
pub use aead_impl::Sm4Gcm;

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
        let (ct, tag) = encrypt(&KEY, &NONCE_12, aad, plaintext).expect("under ceiling");
        let recovered = decrypt(&KEY, &NONCE_12, aad, &ct, &tag).expect("tag verifies");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let aad = b"aad-only message";
        let (ct, tag) = encrypt(&KEY, &NONCE_12, aad, &[]).expect("under ceiling");
        assert!(ct.is_empty());
        let recovered = decrypt(&KEY, &NONCE_12, aad, &ct, &tag).expect("tag verifies");
        assert_eq!(recovered, &[] as &[u8]);
    }

    #[test]
    fn round_trip_empty_aad() {
        let plaintext = b"hello GCM, no AAD";
        let (ct, tag) = encrypt(&KEY, &NONCE_12, &[], plaintext).expect("under ceiling");
        let recovered = decrypt(&KEY, &NONCE_12, &[], &ct, &tag).expect("tag verifies");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn round_trip_non_12_byte_nonce() {
        let nonce: [u8; 7] = [0x42u8; 7];
        let aad = b"aad";
        let plaintext = b"short-nonce SM4-GCM";
        let (ct, tag) = encrypt(&KEY, &nonce, aad, plaintext).expect("under ceiling");
        let recovered = decrypt(&KEY, &nonce, aad, &ct, &tag).expect("tag verifies");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn tampered_tag_fails() {
        let aad = b"x";
        let plaintext = b"original";
        let (ct, mut tag) = encrypt(&KEY, &NONCE_12, aad, plaintext).expect("under ceiling");
        tag[0] ^= 0x01;
        assert!(decrypt(&KEY, &NONCE_12, aad, &ct, &tag).is_none());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let aad = b"x";
        let plaintext = b"original";
        let (mut ct, tag) = encrypt(&KEY, &NONCE_12, aad, plaintext).expect("under ceiling");
        if !ct.is_empty() {
            ct[0] ^= 0x01;
        }
        assert!(decrypt(&KEY, &NONCE_12, aad, &ct, &tag).is_none());
    }

    #[test]
    fn tampered_aad_fails() {
        let aad = b"correct-aad";
        let plaintext = b"original";
        let (ct, tag) = encrypt(&KEY, &NONCE_12, aad, plaintext).expect("under ceiling");
        assert!(decrypt(&KEY, &NONCE_12, b"wrong-aad", &ct, &tag).is_none());
    }

    // ---- v0.9 W1: tag-length parameterization ----

    #[test]
    fn gcm_tag_len_accepts_valid_lengths() {
        for &n in &[4usize, 8, 12, 13, 14, 15, 16] {
            assert_eq!(GcmTagLen::new(n).map(GcmTagLen::as_usize), Some(n));
        }
    }

    #[test]
    fn gcm_tag_len_rejects_invalid_lengths() {
        for &n in &[0usize, 1, 2, 3, 5, 6, 7, 9, 10, 11, 17, 32] {
            assert!(GcmTagLen::new(n).is_none(), "len {n} must be rejected");
        }
    }

    #[test]
    fn tag_len_truncation_matches_full_tag_prefix() {
        let aad = b"hdr";
        let pt = b"truncate me to a short tag";
        let (ct_full, tag_full) = encrypt(&KEY, &NONCE_12, aad, pt).expect("under ceiling");
        for &n in &[4usize, 8, 12, 13, 14, 15, 16] {
            let tl = GcmTagLen::new(n).unwrap();
            let (ct_t, tag_t) =
                encrypt_with_tag_len(&KEY, &NONCE_12, aad, pt, tl).expect("under ceiling");
            assert_eq!(ct_t, ct_full, "ciphertext invariant under tag_len {n}");
            assert_eq!(tag_t.as_slice(), &tag_full[..n], "tag = MSB_n(full) at {n}");
        }
    }

    #[test]
    fn tag_len_round_trip() {
        let aad = b"hdr";
        let pt = b"round trip under every tag length";
        for &n in &[4usize, 8, 12, 13, 14, 15, 16] {
            let tl = GcmTagLen::new(n).unwrap();
            let (ct, tag) =
                encrypt_with_tag_len(&KEY, &NONCE_12, aad, pt, tl).expect("under ceiling");
            let got = decrypt_with_tag_len(&KEY, &NONCE_12, aad, &ct, &tag);
            assert_eq!(
                got.as_deref(),
                Some(pt.as_slice()),
                "round trip at tag_len {n}"
            );
        }
    }

    #[test]
    fn tag_len_decrypt_rejects_bad_tag_and_bad_len() {
        let aad = b"hdr";
        let pt = b"reject me";
        let tl = GcmTagLen::new(12).unwrap();
        let (ct, mut tag) =
            encrypt_with_tag_len(&KEY, &NONCE_12, aad, pt, tl).expect("under ceiling");
        tag[0] ^= 0x01;
        assert!(decrypt_with_tag_len(&KEY, &NONCE_12, aad, &ct, &tag).is_none());
        // Wrong-length tag (not in the valid set) → None.
        assert!(decrypt_with_tag_len(&KEY, &NONCE_12, aad, &ct, &tag[..5]).is_none());
    }

    #[test]
    fn gcm_max_pt_bytes_matches_spec() {
        // NIST SP 800-38D §5.2.1.1: 2^39 − 256 bits = 2^36 − 32 bytes.
        // Pinned identical to the streaming-encryptor ceiling so the
        // single-shot and streaming poison agree.
        assert_eq!(GCM_MAX_PT_BYTES, (1u64 << 36) - 32);
        assert_eq!(GCM_MAX_PT_BYTES, 68_719_476_704);
    }

    #[test]
    fn tag_len_full_16_matches_plain_decrypt() {
        // encrypt_with_tag_len(16) tag must verify through the plain
        // fixed-16 decrypt path too (cross-API consistency).
        let aad = b"hdr";
        let pt = b"cross-API consistency";
        let tl = GcmTagLen::new(16).unwrap();
        let (ct, tag) = encrypt_with_tag_len(&KEY, &NONCE_12, aad, pt, tl).expect("under ceiling");
        let tag16: [u8; TAG_SIZE] = tag.as_slice().try_into().unwrap();
        assert_eq!(
            decrypt(&KEY, &NONCE_12, aad, &ct, &tag16).as_deref(),
            Some(pt.as_slice()),
        );
    }
}
