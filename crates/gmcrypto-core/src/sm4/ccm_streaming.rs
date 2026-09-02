//! Length-committed streaming SM4-CCM (v1.12).
//!
//! Stateful counterpart to [`super::mode_ccm`]'s single-shot
//! [`encrypt`] / [`decrypt`]. The two directions are asymmetric, and the
//! names are chosen to say exactly what each one is:
//!
//! - [`Sm4CcmEncryptor`] is **length-committed streaming**: the caller
//!   declares the plaintext length at construction, because CCM encodes it
//!   in the first CBC-MAC block `B0` (RFC 3610 §2.2). In exchange, each
//!   [`update`](Sm4CcmEncryptor::update) emits its chunk's ciphertext
//!   immediately — the CBC-MAC and the CTR keystream both advance chunk by
//!   chunk — with `O(chunk)` memory.
//! - [`Sm4CcmDecryptor`] is **incremental-input buffered**, never
//!   "streaming": CCM authenticates the *plaintext*, so no MAC work can
//!   start until the length is known, which for a stream is EOF. It buffers
//!   ciphertext and does all its work in
//!   [`finalize_verify`](Sm4CcmDecryptor::finalize_verify), releasing the
//!   plaintext only after the tag verifies (commit-on-verify). Memory is
//!   `O(message)`, bounded by the nonce's payload ceiling (for a 7-byte
//!   nonce, q = 8, the ceiling is 2^64 − 1 and the latch is not a practical
//!   memory bound).
//!
//! # Why this exists despite the v0.15 objection
//!
//! `docs/v0.15-scope.md` (Q15.11) rejected an "incremental-input" CCM API
//! because, for an *unknown*-length plaintext, it could only buffer and had
//! no memory story. That holds. The length-committed encryptor is the design
//! that objection did not evaluate: once the length is declared, nothing in
//! CCM prevents streaming encryption. The decryptor exists for API parity
//! with [`super::Sm4GcmDecryptor`] and is labelled as what it is.
//!
//! # Contract
//!
//! - AAD is supplied at construction only (it is the message header).
//! - Encryptor: an `update` that would exceed the committed length emits
//!   nothing and **poisons** the encryptor; `finalize` returns `None` if
//!   poisoned or **under-fed**. A partial stream is never tag-authenticated.
//!   (Stricter than [`super::Sm4GcmEncryptor`], which still returns a tag
//!   after poison.)
//! - Decryptor: `update` never fails; it latches once the buffer would pass
//!   `2^(8q) − 1` bytes (`q = 15 − nonce.len()`), and `finalize_verify`
//!   then returns `None`. The tag's length selects the tag length.
//! - Every failure is the single `None` (workspace failure-mode invariant).
//! - Nonce uniqueness per key is the caller's responsibility, as for every
//!   mode in this crate. A `(key, nonce)` pair also fixes `B0`, so two
//!   encryptors on the same pair with different lengths are a nonce reuse.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "sm4-aead")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use gmcrypto_core::sm4::{KEY_SIZE, Sm4CcmDecryptor, Sm4CcmEncryptor};
//!
//! let key: [u8; KEY_SIZE] = [0x42; KEY_SIZE];
//! let nonce = [0x01u8; 12];
//! let aad = b"header";
//! let frame = b"a payload whose length the header already told us";
//!
//! // Commit to the length, then stream.
//! let mut enc = Sm4CcmEncryptor::new(&key, &nonce, aad, frame.len(), 16)
//!     .ok_or("nonce or tag length outside RFC 3610 §2.1")?;
//! let mut ct = Vec::new();
//! for chunk in frame.chunks(7) {
//!     ct.extend_from_slice(&enc.update(chunk).ok_or("over-fed")?);
//! }
//! let tag = enc.finalize().ok_or("under-fed")?;
//!
//! // Buffer, then verify-and-release.
//! let mut dec = Sm4CcmDecryptor::new(&key, &nonce, aad).ok_or("bad nonce length")?;
//! for chunk in ct.chunks(5) {
//!     dec.update(chunk);
//! }
//! let recovered = dec.finalize_verify(&tag).ok_or("authentication failed")?;
//! assert_eq!(recovered, frame);
//! # Ok(()) }
//! # #[cfg(not(feature = "sm4-aead"))] fn main() {}
//! ```
//!
//! [`encrypt`]: super::mode_ccm::encrypt
//! [`decrypt`]: super::mode_ccm::decrypt

use alloc::vec;
use alloc::vec::Vec;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::cipher::{BLOCK_SIZE, KEY_SIZE, Sm4Cipher};
use super::mode_ccm::{
    MAX_NONCE_LEN, MIN_NONCE_LEN, VALID_TAG_LENS, build_a0, build_b0, counter_block,
    decrypt_with_cipher, format_aad_into, payload_ceiling, validate_params,
};

/// Length-committed, output-streaming SM4-CCM encryptor.
///
/// The caller commits to the exact plaintext length at construction
/// (CCM encodes it in the first CBC-MAC block `B0`, RFC 3610 §2.2); in
/// exchange every [`update`](Self::update) emits its chunk's ciphertext
/// immediately with `O(chunk)` memory. AAD is supplied at construction
/// only. [`finalize`](Self::finalize) emits the tag — or `None` if the
/// stream was under-fed or poisoned. See the module docstring for the
/// contract and the divergence from [`super::Sm4GcmEncryptor`].
///
/// Holds plaintext-derived state across calls (the CBC-MAC partial block,
/// the running MAC, leftover keystream) and the SM4 key schedule; all of
/// it is zeroized on drop (best-effort — stack copies and register spills
/// are outside what `zeroize` reaches).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Sm4CcmEncryptor {
    cipher: Sm4Cipher,
    a0: [u8; BLOCK_SIZE],
    /// Running CBC-MAC value `T`.
    mac: [u8; BLOCK_SIZE],
    /// Plaintext bytes not yet folded into `mac` (< one block).
    mac_block: [u8; BLOCK_SIZE],
    mac_block_len: usize,
    /// Leftover keystream from the last partial-block CTR step.
    ks: [u8; BLOCK_SIZE],
    ks_pos: usize,
    /// Index of the next CTR block to generate (`A_1` is the first).
    next_block: u64,
    declared_len: u64,
    fed_len: u64,
    tag_len: usize,
    poisoned: bool,
}

impl Sm4CcmEncryptor {
    /// Construct from key, nonce, the full AAD, the committed plaintext
    /// length, and the tag length.
    ///
    /// Returns `None` if the nonce length is outside `[7, 13]`, `tag_len`
    /// is not one of `{4, 6, 8, 10, 12, 14, 16}`, or `plaintext_len` does
    /// not fit the nonce's `q = 15 − nonce.len()`-byte length field — the
    /// same gate as [`super::mode_ccm::encrypt`]. Formats and folds
    /// `B0 ‖ format(aad)` here (an `O(aad)` allocation that is dropped
    /// before returning); the streaming phase is `O(chunk)`.
    ///
    /// **Nonce uniqueness is the caller's contract.** A `(key, nonce)` pair
    /// also fixes `B0`, so two encryptors on the same pair with different
    /// `plaintext_len` are still a nonce reuse.
    #[must_use]
    pub fn new(
        key: &[u8; KEY_SIZE],
        nonce: &[u8],
        aad: &[u8],
        plaintext_len: usize,
        tag_len: usize,
    ) -> Option<Self> {
        validate_params(nonce, plaintext_len, aad.len(), tag_len)?;
        let declared_len = u64::try_from(plaintext_len).ok()?;
        let cipher = Sm4Cipher::new(key);
        let q = 15 - nonce.len();

        // Fold the fixed prefix `B0 ‖ format(aad)` into the CBC-MAC now.
        // `format_aad_into` zero-pads to a block boundary, and B0 is one
        // block, so the prefix is block-aligned.
        let mut prefix = Vec::with_capacity(2 * BLOCK_SIZE);
        prefix.extend_from_slice(&build_b0(nonce, plaintext_len, !aad.is_empty(), tag_len, q));
        if !aad.is_empty() {
            format_aad_into(&mut prefix, aad);
        }
        let mut mac = [0u8; BLOCK_SIZE];
        for block in prefix.chunks_exact(BLOCK_SIZE) {
            for (m, &b) in mac.iter_mut().zip(block) {
                *m ^= b;
            }
            cipher.encrypt_block(&mut mac);
        }

        Some(Self {
            a0: build_a0(nonce),
            cipher,
            mac,
            mac_block: [0u8; BLOCK_SIZE],
            mac_block_len: 0,
            ks: [0u8; BLOCK_SIZE],
            ks_pos: BLOCK_SIZE, // no leftover keystream yet
            next_block: 1,
            declared_len,
            fed_len: 0,
            tag_len,
            poisoned: false,
        })
    }

    /// Encrypt `chunk`, returning its ciphertext (same length).
    ///
    /// Returns `None` — emitting nothing and **poisoning** the encryptor so
    /// every later call also returns `None` — if the cumulative plaintext
    /// would exceed the committed `plaintext_len`. Ciphertext already
    /// emitted is not retracted, but no tag will authenticate it.
    /// `update(&[])` is a no-op returning an empty `Vec`.
    #[must_use]
    pub fn update(&mut self, chunk: &[u8]) -> Option<Vec<u8>> {
        if self.poisoned {
            return None;
        }
        // checked_add on u64: a wrapping usize add on a 32-bit target could
        // miss the bound and then run the q-byte counter past its field.
        let new_len = u64::try_from(chunk.len())
            .ok()
            .and_then(|c| self.fed_len.checked_add(c))
            .filter(|&n| n <= self.declared_len);
        let Some(new_len) = new_len else {
            self.poisoned = true;
            return None;
        };

        let mut out = vec![0u8; chunk.len()];
        let mut i = 0;

        // 1. Drain leftover keystream from a previous partial-block call.
        while i < chunk.len() && self.ks_pos < BLOCK_SIZE {
            out[i] = chunk[i] ^ self.ks[self.ks_pos];
            self.ks_pos += 1;
            i += 1;
        }

        // 2. Whole blocks: batch the keystream through `encrypt_blocks` so
        //    bulk chunks keep the SIMD fanout under `sm4-bitsliced-simd`
        //    (the single-shot's path). Byte-identical to per-block.
        let whole = (chunk.len() - i) / BLOCK_SIZE;
        if whole > 0 {
            let first = self.next_block;
            let mut blocks: Vec<[u8; BLOCK_SIZE]> = (0..whole)
                .map(|k| counter_block(&self.a0, first + u64::try_from(k).unwrap_or(u64::MAX)))
                .collect();
            self.cipher.encrypt_blocks(&mut blocks);
            for (k, ks_block) in blocks.iter().enumerate() {
                let base = i + k * BLOCK_SIZE;
                for lane in 0..BLOCK_SIZE {
                    out[base + lane] = chunk[base + lane] ^ ks_block[lane];
                }
            }
            blocks.iter_mut().zeroize();
            self.next_block += u64::try_from(whole).unwrap_or(u64::MAX);
            i += whole * BLOCK_SIZE;
        }

        // 3. Tail (< one block): one keystream block, consume what is
        //    needed, keep the rest as leftover.
        if i < chunk.len() {
            self.ks = counter_block(&self.a0, self.next_block);
            self.cipher.encrypt_block(&mut self.ks);
            self.next_block += 1;
            self.ks_pos = 0;
            while i < chunk.len() {
                out[i] = chunk[i] ^ self.ks[self.ks_pos];
                self.ks_pos += 1;
                i += 1;
            }
        }

        // 4. CBC-MAC absorbs the *plaintext* (CCM authenticates plaintext).
        self.mac_absorb(chunk);
        self.fed_len = new_len;
        Some(out)
    }

    /// Finish and return the `tag_len`-byte tag.
    ///
    /// Returns `None` if the encryptor is poisoned or **under-fed**
    /// (`fed != plaintext_len`): the length in `B0` is a commitment, and a
    /// tag over a shorter message than the one committed to would be a tag
    /// over a message the caller never sent. This is deliberately stricter
    /// than [`super::Sm4GcmEncryptor::finalize`], which still returns a
    /// tag after a poisoned `update`.
    #[must_use]
    pub fn finalize(mut self) -> Option<Vec<u8>> {
        if self.poisoned || self.fed_len != self.declared_len {
            return None;
        }
        // Zero-pad and fold any partial plaintext block. The unused tail
        // of `mac_block` is already zero (reset after every fold).
        if self.mac_block_len != 0 {
            self.mac_fold();
        }
        let mut s0 = self.a0;
        self.cipher.encrypt_block(&mut s0);
        let tag: Vec<u8> = s0
            .iter()
            .zip(&self.mac)
            .take(self.tag_len)
            .map(|(s, t)| s ^ t)
            .collect();
        s0.zeroize();
        Some(tag)
    }

    fn mac_absorb(&mut self, data: &[u8]) {
        for &b in data {
            self.mac_block[self.mac_block_len] = b;
            self.mac_block_len += 1;
            if self.mac_block_len == BLOCK_SIZE {
                self.mac_fold();
            }
        }
    }

    fn mac_fold(&mut self) {
        for (m, &b) in self.mac.iter_mut().zip(&self.mac_block) {
            *m ^= b;
        }
        self.cipher.encrypt_block(&mut self.mac);
        self.mac_block = [0u8; BLOCK_SIZE];
        self.mac_block_len = 0;
    }
}

/// Incremental-input, output-**buffered** SM4-CCM decryptor (commit-on-verify).
///
/// Not a streaming type: CCM's CBC-MAC runs over the plaintext and needs
/// the total length in `B0`, which for a stream is known only at EOF, so
/// all work happens in [`finalize_verify`](Self::finalize_verify) and the
/// ciphertext is buffered until then — `O(message)` memory, the same
/// shape as [`super::Sm4GcmDecryptor`]. The buffer is latched at the
/// nonce's payload ceiling (`2^(8q) − 1`, e.g. 65 535 bytes for a 13-byte
/// nonce; for a 7-byte nonce, q = 8, the ceiling is 2^64 − 1 and the latch
/// is not a practical memory bound) so a misbehaving peer cannot make it
/// grow without bound.
///
/// This type is a thin wrapper over the single-shot decrypt body and adds
/// no cryptography — which is what lets it share the single-shot's dudect
/// coverage. Holds the SM4 key schedule (zeroized on drop by that field);
/// its other state — nonce, AAD, ciphertext — is not secret.
pub struct Sm4CcmDecryptor {
    cipher: Sm4Cipher,
    nonce: [u8; MAX_NONCE_LEN],
    nonce_len: usize,
    aad: Vec<u8>,
    buf: Vec<u8>,
    ceiling: u64,
    overflowed: bool,
}

impl Sm4CcmDecryptor {
    /// Construct from key, nonce, and the full AAD (retained until
    /// [`finalize_verify`](Self::finalize_verify) — the MAC cannot consume
    /// it before the length is known). Returns `None` if the nonce length
    /// is outside `[7, 13]`.
    #[must_use]
    pub fn new(key: &[u8; KEY_SIZE], nonce: &[u8], aad: &[u8]) -> Option<Self> {
        if nonce.len() < MIN_NONCE_LEN || nonce.len() > MAX_NONCE_LEN {
            return None;
        }
        let mut n = [0u8; MAX_NONCE_LEN];
        n[..nonce.len()].copy_from_slice(nonce);
        Some(Self {
            cipher: Sm4Cipher::new(key),
            nonce: n,
            nonce_len: nonce.len(),
            aad: aad.to_vec(),
            buf: Vec::new(),
            ceiling: payload_ceiling(15 - nonce.len()),
            overflowed: false,
        })
    }

    /// Buffer `chunk` of ciphertext. Emits nothing (commit-on-verify).
    /// Once the buffered length would exceed the nonce's payload ceiling
    /// the overflow is latched, further chunks are dropped, and
    /// [`finalize_verify`](Self::finalize_verify) returns `None`.
    pub fn update(&mut self, chunk: &[u8]) {
        if self.overflowed {
            return;
        }
        let within_ceiling = u64::try_from(self.buf.len())
            .ok()
            .zip(u64::try_from(chunk.len()).ok())
            .and_then(|(cur, c)| cur.checked_add(c))
            .is_some_and(|n| n <= self.ceiling);
        if !within_ceiling {
            self.overflowed = true;
            return;
        }
        self.buf.extend_from_slice(chunk);
    }

    /// Verify `tag` (its length selects the tag length, validated against
    /// RFC 3610 §2.1) and, on success, return the plaintext. `None` on tag
    /// mismatch, invalid tag length, or a latched overflow — single failure
    /// mode. No plaintext survives the failure path.
    #[must_use]
    pub fn finalize_verify(self, tag: &[u8]) -> Option<Vec<u8>> {
        if self.overflowed || !VALID_TAG_LENS.contains(&tag.len()) {
            return None;
        }
        decrypt_with_cipher(
            &self.cipher,
            &self.nonce[..self.nonce_len],
            &self.aad,
            &self.buf,
            tag,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm4::mode_ccm;

    const KEY: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    const NONCE_12: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

    #[allow(clippy::cast_possible_truncation)]
    fn make_payload(len: usize) -> Vec<u8> {
        (0..len as u32).map(|i| (i ^ (i >> 3)) as u8).collect()
    }

    /// Drive `pt` through a fresh encryptor in fixed `chunk`-byte pieces and
    /// return `ct ‖ tag` (the single-shot output shape).
    fn stream_encrypt(
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
        tag_len: usize,
        chunk: usize,
    ) -> Vec<u8> {
        let mut enc =
            Sm4CcmEncryptor::new(&KEY, nonce, aad, pt.len(), tag_len).expect("valid params");
        let mut out = Vec::new();
        let mut off = 0;
        while off < pt.len() {
            let take = chunk.min(pt.len() - off);
            out.extend_from_slice(
                &enc.update(&pt[off..off + take])
                    .expect("within declared length"),
            );
            off += take;
        }
        out.extend_from_slice(&enc.finalize().expect("declared length fed exactly"));
        out
    }

    #[test]
    fn encryptor_chunked_matches_single_shot() {
        let aad = b"associated header";
        let pt = make_payload(200);
        let want = mode_ccm::encrypt(&KEY, &NONCE_12, aad, &pt, 16).expect("valid params");
        for chunk in [1usize, 7, 15, 16, 17, 31, 32, 33, 100, pt.len()] {
            let got = stream_encrypt(&NONCE_12, aad, &pt, 16, chunk);
            assert_eq!(got, want, "ct||tag divergence at chunk {chunk}");
        }
    }

    #[test]
    fn encryptor_every_tag_length_matches_single_shot() {
        let pt = make_payload(45);
        for &tag_len in &VALID_TAG_LENS {
            let want =
                mode_ccm::encrypt(&KEY, &NONCE_12, b"aad", &pt, tag_len).expect("valid params");
            let got = stream_encrypt(&NONCE_12, b"aad", &pt, tag_len, 13);
            assert_eq!(got, want, "tag_len {tag_len}");
            assert_eq!(got.len(), pt.len() + tag_len);
        }
    }

    #[test]
    fn encryptor_every_nonce_length_matches_single_shot() {
        let pt = make_payload(70);
        for nonce_len in MIN_NONCE_LEN..=MAX_NONCE_LEN {
            let nonce = vec![0x42u8; nonce_len];
            let want = mode_ccm::encrypt(&KEY, &nonce, b"x", &pt, 16).expect("valid params");
            let got = stream_encrypt(&nonce, b"x", &pt, 16, 9);
            assert_eq!(got, want, "nonce_len {nonce_len}");
        }
    }

    #[test]
    fn encryptor_empty_aad_and_zero_length_plaintext() {
        let want_no_aad = mode_ccm::encrypt(&KEY, &NONCE_12, &[], b"hello", 16).expect("valid");
        assert_eq!(stream_encrypt(&NONCE_12, &[], b"hello", 16, 2), want_no_aad);

        let want_empty = mode_ccm::encrypt(&KEY, &NONCE_12, b"aad", &[], 16).expect("valid");
        let enc = Sm4CcmEncryptor::new(&KEY, &NONCE_12, b"aad", 0, 16).expect("valid");
        let tag = enc.finalize().expect("zero declared, zero fed");
        assert_eq!(tag, want_empty);
    }

    #[test]
    fn encryptor_empty_updates_are_noops() {
        let pt = b"payload";
        let want = mode_ccm::encrypt(&KEY, &NONCE_12, b"a", pt, 16).expect("valid");
        let mut enc = Sm4CcmEncryptor::new(&KEY, &NONCE_12, b"a", pt.len(), 16).expect("valid");
        assert_eq!(enc.update(&[]).unwrap().len(), 0);
        let mut got = enc.update(pt).unwrap();
        assert_eq!(enc.update(&[]).unwrap().len(), 0);
        got.extend_from_slice(&enc.finalize().unwrap());
        assert_eq!(got, want);
    }

    #[test]
    fn encryptor_over_feed_emits_nothing_poisons_and_finalize_is_none() {
        let mut enc = Sm4CcmEncryptor::new(&KEY, &NONCE_12, b"a", 10, 16).expect("valid");
        assert_eq!(enc.update(&[0u8; 6]).unwrap().len(), 6);
        // 6 + 5 > 10: the whole chunk is rejected, nothing emitted.
        assert!(enc.update(&[0u8; 5]).is_none());
        // Poisoned: even a chunk that would have fit is refused.
        assert!(enc.update(&[0u8; 1]).is_none());
        assert!(enc.update(&[]).is_none());
        assert!(enc.finalize().is_none());
    }

    #[test]
    fn encryptor_under_feed_finalize_is_none() {
        let mut enc = Sm4CcmEncryptor::new(&KEY, &NONCE_12, b"a", 10, 16).expect("valid");
        assert_eq!(enc.update(&[0u8; 9]).unwrap().len(), 9);
        assert!(enc.finalize().is_none());
    }

    #[test]
    fn encryptor_new_rejects_invalid_parameters() {
        assert!(
            Sm4CcmEncryptor::new(&KEY, &[0u8; 6], b"", 0, 16).is_none(),
            "nonce too short"
        );
        assert!(
            Sm4CcmEncryptor::new(&KEY, &[0u8; 14], b"", 0, 16).is_none(),
            "nonce too long"
        );
        for tag_len in [0usize, 3, 5, 7, 9, 11, 13, 15, 17, 32] {
            assert!(
                Sm4CcmEncryptor::new(&KEY, &NONCE_12, b"", 0, tag_len).is_none(),
                "tag_len {tag_len}"
            );
        }
        // 13-byte nonce → q = 2 → ceiling 65 535.
        assert!(Sm4CcmEncryptor::new(&KEY, &[0u8; 13], b"", 65_535, 16).is_some());
        assert!(Sm4CcmEncryptor::new(&KEY, &[0u8; 13], b"", 65_536, 16).is_none());
    }

    /// Feed `ct` through a fresh decryptor in `chunk`-byte pieces and verify.
    fn stream_decrypt(
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        tag: &[u8],
        chunk: usize,
    ) -> Option<Vec<u8>> {
        let mut dec = Sm4CcmDecryptor::new(&KEY, nonce, aad).expect("valid nonce");
        let mut off = 0;
        while off < ct.len() {
            let take = chunk.min(ct.len() - off);
            dec.update(&ct[off..off + take]);
            off += take;
        }
        dec.finalize_verify(tag)
    }

    #[test]
    fn decryptor_chunked_matches_single_shot() {
        let aad = b"associated header";
        let pt = make_payload(200);
        let ct_with_tag = mode_ccm::encrypt(&KEY, &NONCE_12, aad, &pt, 16).expect("valid");
        let (ct, tag) = ct_with_tag.split_at(ct_with_tag.len() - 16);
        for chunk in [1usize, 7, 15, 16, 17, 31, 32, 33, 100, ct.len()] {
            assert_eq!(
                stream_decrypt(&NONCE_12, aad, ct, tag, chunk).as_deref(),
                Some(pt.as_slice()),
                "divergence at chunk {chunk}"
            );
        }
    }

    #[test]
    fn decryptor_every_tag_length_verifies() {
        let pt = make_payload(33);
        for &tag_len in &VALID_TAG_LENS {
            let ct_with_tag =
                mode_ccm::encrypt(&KEY, &NONCE_12, b"aad", &pt, tag_len).expect("valid");
            let (ct, tag) = ct_with_tag.split_at(ct_with_tag.len() - tag_len);
            assert_eq!(
                stream_decrypt(&NONCE_12, b"aad", ct, tag, 5).as_deref(),
                Some(pt.as_slice())
            );
        }
    }

    #[test]
    fn decryptor_rejects_tampered_tag_and_ciphertext_and_aad() {
        let pt = b"tamper target";
        let ct_with_tag = mode_ccm::encrypt(&KEY, &NONCE_12, b"h", pt, 16).expect("valid");
        let (ct, tag) = ct_with_tag.split_at(ct_with_tag.len() - 16);

        let mut bad_tag = tag.to_vec();
        bad_tag[0] ^= 0x01;
        assert!(stream_decrypt(&NONCE_12, b"h", ct, &bad_tag, 4).is_none());

        let mut bad_ct = ct.to_vec();
        bad_ct[0] ^= 0x01;
        assert!(stream_decrypt(&NONCE_12, b"h", &bad_ct, tag, 4).is_none());

        assert!(stream_decrypt(&NONCE_12, b"wrong", ct, tag, 4).is_none());
    }

    #[test]
    fn decryptor_rejects_invalid_tag_length() {
        let ct_with_tag = mode_ccm::encrypt(&KEY, &NONCE_12, b"h", b"x", 16).expect("valid");
        let (ct, tag) = ct_with_tag.split_at(ct_with_tag.len() - 16);
        for bad_len in [0usize, 3, 5, 7, 9, 11, 13, 15] {
            assert!(
                stream_decrypt(&NONCE_12, b"h", ct, &tag[..bad_len], 4).is_none(),
                "tag len {bad_len}"
            );
        }
    }

    #[test]
    fn decryptor_new_rejects_invalid_nonce_length() {
        assert!(Sm4CcmDecryptor::new(&KEY, &[0u8; 6], b"").is_none());
        assert!(Sm4CcmDecryptor::new(&KEY, &[0u8; 14], b"").is_none());
        assert!(Sm4CcmDecryptor::new(&KEY, &[0u8; 7], b"").is_some());
        assert!(Sm4CcmDecryptor::new(&KEY, &[0u8; 13], b"").is_some());
    }

    #[test]
    fn decryptor_latches_past_the_q_ceiling() {
        // 13-byte nonce → q = 2 → ceiling 65 535 bytes.
        let nonce = [0x42u8; 13];
        let at_ceiling = vec![0u8; 65_535];
        let mut dec = Sm4CcmDecryptor::new(&KEY, &nonce, b"").expect("valid nonce");
        dec.update(&at_ceiling);
        dec.update(&[0u8; 1]); // 65 536 > ceiling → latch
        assert!(dec.finalize_verify(&[0u8; 16]).is_none());

        // Exactly at the ceiling is accepted by the latch (and then fails
        // only on the tag, which is the single-shot's decision).
        let mut dec = Sm4CcmDecryptor::new(&KEY, &nonce, b"").expect("valid nonce");
        dec.update(&at_ceiling);
        assert!(dec.finalize_verify(&[0u8; 16]).is_none()); // garbage tag
    }

    #[test]
    fn decryptor_empty_updates_then_verify() {
        let ct_with_tag = mode_ccm::encrypt(&KEY, &NONCE_12, b"a", &[], 16).expect("valid");
        let mut dec = Sm4CcmDecryptor::new(&KEY, &NONCE_12, b"a").expect("valid nonce");
        dec.update(&[]);
        dec.update(&[]);
        assert_eq!(dec.finalize_verify(&ct_with_tag).as_deref(), Some(&[][..]));
    }

    #[test]
    fn round_trip_through_streaming_both_directions() {
        let aad = b"end to end";
        let pt = make_payload(137);
        let mut enc = Sm4CcmEncryptor::new(&KEY, &NONCE_12, aad, pt.len(), 12).expect("valid");
        let mut ct = Vec::new();
        for c in pt.chunks(13) {
            ct.extend_from_slice(&enc.update(c).unwrap());
        }
        let tag = enc.finalize().unwrap();
        assert_eq!(tag.len(), 12);

        let mut dec = Sm4CcmDecryptor::new(&KEY, &NONCE_12, aad).expect("valid nonce");
        for c in ct.chunks(11) {
            dec.update(c);
        }
        assert_eq!(dec.finalize_verify(&tag).as_deref(), Some(pt.as_slice()));
    }
}
