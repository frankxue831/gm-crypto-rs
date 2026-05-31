//! Incremental-input buffered SM4-GCM (v0.9 W2).
//!
//! Stateful counterpart to [`super::mode_gcm`]'s single-shot
//! [`encrypt`] / [`decrypt`]. The term is **"incremental-input
//! buffered"** — deliberately NOT "streaming" — because the two
//! directions are asymmetric:
//!
//! - The **encryptor** ([`Sm4GcmEncryptor`]) is output-streaming:
//!   each [`update`](Sm4GcmEncryptor::update) emits the ciphertext for
//!   that chunk immediately and folds it into the running GHASH.
//!   Memory is `O(chunk)`.
//! - The **decryptor** ([`Sm4GcmDecryptor`]) is input-incremental but
//!   output-BUFFERED: it accumulates the whole ciphertext, and
//!   [`finalize_verify`](Sm4GcmDecryptor::finalize_verify) releases
//!   the plaintext only after the tag verifies (commit-on-verify).
//!   Memory is `O(message)`.
//!
//! This asymmetry is inherent to AEAD decryption: releasing plaintext
//! before the tag check would hand an attacker a chosen-ciphertext
//! distinguisher. The encryptor has no such constraint — its output
//! is already committed to the tag via the running GHASH.
//!
//! AAD is supplied at construction (it is the message *header*, known
//! up-front); only the payload is fed incrementally. A differential
//! KAT proves arbitrary input chunking reproduces the single-shot
//! [`super::mode_gcm::encrypt`] / [`super::mode_gcm::decrypt`] output
//! byte-for-byte.
//!
//! # Length ceiling
//!
//! NIST SP 800-38D §5.2.1.1 caps GCM plaintext at `2^39 − 256` bits =
//! `2^36 − 32` bytes (past which the 32-bit GCTR counter would wrap).
//! Both types track the running payload length and refuse to exceed
//! it — the encryptor returns `None` from `update` (and is poisoned
//! thereafter); the decryptor latches an overflow flag and returns
//! `None` from `finalize_verify`. Single failure mode per the
//! workspace invariant.
//!
//! [`encrypt`]: super::mode_gcm::encrypt
//! [`decrypt`]: super::mode_gcm::decrypt

use alloc::vec;
use alloc::vec::Vec;

use subtle::ConstantTimeEq;

use super::cipher::{BLOCK_SIZE, KEY_SIZE, Sm4Cipher};
use super::mode_gcm::{GcmTagLen, TAG_SIZE, derive_j0, gctr, inc32};

/// NIST SP 800-38D §5.2.1.1 plaintext ceiling, in bytes:
/// `2^39 − 256` bits = `2^36 − 32` bytes.
const GCM_MAX_PT_BYTES: u64 = (1u64 << 36) - 32;

/// Running GHASH accumulator over `A ‖ 0^v ‖ C ‖ 0^u` followed by the
/// trailing length block `[len_A]_64 ‖ [len_C]_64`.
///
/// Folds whole 128-bit blocks as bytes arrive; [`pad_to_block`] closes
/// a domain (end of AAD, end of CT) by zero-padding and folding any
/// partial block. Equivalent to [`super::mode_gcm`]'s single-shot
/// `ghash_a_c_lens` but driven incrementally.
///
/// [`pad_to_block`]: GhashAcc::pad_to_block
struct GhashAcc {
    h: [u8; BLOCK_SIZE],
    y: [u8; BLOCK_SIZE],
    block: [u8; BLOCK_SIZE],
    block_len: usize,
}

impl GhashAcc {
    const fn new(h: &[u8; BLOCK_SIZE]) -> Self {
        Self {
            h: *h,
            y: [0u8; BLOCK_SIZE],
            block: [0u8; BLOCK_SIZE],
            block_len: 0,
        }
    }

    /// Fold the running `y` with the current full 128-bit `block`,
    /// then reset the block buffer.
    fn fold(&mut self) {
        let mut xored = [0u8; BLOCK_SIZE];
        for ((x, &yk), &bk) in xored.iter_mut().zip(&self.y).zip(&self.block) {
            *x = yk ^ bk;
        }
        self.y = gmcrypto_simd::ghash::ghash_mul(&self.h, &xored);
        self.block = [0u8; BLOCK_SIZE];
        self.block_len = 0;
    }

    /// Absorb arbitrary bytes, folding whole blocks as they complete.
    fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.block[self.block_len] = b;
            self.block_len += 1;
            if self.block_len == BLOCK_SIZE {
                self.fold();
            }
        }
    }

    /// Zero-pad and fold any partial block at a domain boundary. The
    /// unused tail of `block` is already zero (reset after each fold,
    /// and `update` only writes `block[..block_len]`).
    fn pad_to_block(&mut self) {
        if self.block_len != 0 {
            self.fold();
        }
    }

    /// Test-only: finish without appending the length block.
    #[cfg(test)]
    fn finish_no_lengths(mut self) -> [u8; BLOCK_SIZE] {
        self.pad_to_block();
        self.y
    }

    /// Close the final (CT) domain, append `[aad_bits]_64 ‖ [ct_bits]_64`,
    /// and return the final `Y`.
    fn finish_with_lengths(mut self, aad_len: u64, ct_len: u64) -> [u8; BLOCK_SIZE] {
        self.pad_to_block();
        let mut lb = [0u8; BLOCK_SIZE];
        lb[..8].copy_from_slice(&aad_len.saturating_mul(8).to_be_bytes());
        lb[8..].copy_from_slice(&ct_len.saturating_mul(8).to_be_bytes());
        self.block = lb;
        self.block_len = BLOCK_SIZE;
        self.fold();
        self.y
    }
}

/// One-block GCTR used for tag derivation: `out = E_K(icb) ⊕ s`,
/// truncated to `out.len()`. Local to streaming so we don't widen
/// [`super::mode_gcm`]'s multi-block `gctr`.
fn gctr_block(cipher: &Sm4Cipher, icb: &[u8; BLOCK_SIZE], s: &[u8; BLOCK_SIZE], out: &mut [u8]) {
    let mut ks = *icb;
    cipher.encrypt_block(&mut ks);
    for (i, o) in out.iter_mut().enumerate() {
        *o = s[i] ^ ks[i];
    }
}

/// Shared GCM setup for both streaming directions: build the cipher,
/// derive the hash subkey `H = E_K(0^128)` and pre-counter block `J0`,
/// seed a [`GhashAcc`] with the (closed) AAD domain, and capture the
/// AAD length. Identical to the prologue of [`super::mode_gcm::encrypt`].
fn init_gcm(
    key: &[u8; KEY_SIZE],
    nonce: &[u8],
    aad: &[u8],
) -> (Sm4Cipher, [u8; BLOCK_SIZE], GhashAcc, u64) {
    let cipher = Sm4Cipher::new(key);
    let mut h = [0u8; BLOCK_SIZE];
    cipher.encrypt_block(&mut h);
    let j0 = derive_j0(&h, nonce);

    debug_assert!(
        u64::try_from(aad.len()).is_ok(),
        "AAD length exceeds u64 — unreachable on real hardware",
    );
    let aad_len = u64::try_from(aad.len()).unwrap_or(u64::MAX);

    let mut ghash = GhashAcc::new(&h);
    ghash.update(aad);
    ghash.pad_to_block(); // close the AAD domain

    (cipher, j0, ghash, aad_len)
}

/// Incremental-input, output-streaming SM4-GCM encryptor.
///
/// AAD is supplied at construction. Each [`update`](Self::update)
/// emits the ciphertext for its chunk; [`finalize`](Self::finalize)
/// emits the 128-bit tag (or [`finalize_with_tag_len`] for a
/// truncated tag). See the module docstring for the
/// encryptor/decryptor asymmetry.
///
/// [`finalize_with_tag_len`]: Self::finalize_with_tag_len
pub struct Sm4GcmEncryptor {
    cipher: Sm4Cipher,
    j0: [u8; BLOCK_SIZE],
    counter: [u8; BLOCK_SIZE],
    ks: [u8; BLOCK_SIZE],
    ks_pos: usize,
    ghash: GhashAcc,
    aad_len: u64,
    ct_len: u64,
    poisoned: bool,
}

impl Sm4GcmEncryptor {
    /// Construct from key, nonce, and the full AAD (the message
    /// header, known up-front).
    ///
    /// See [`super::mode_gcm`]'s docstring for the nonce-uniqueness
    /// contract — it applies identically here.
    #[must_use]
    pub fn new(key: &[u8; KEY_SIZE], nonce: &[u8], aad: &[u8]) -> Self {
        let (cipher, j0, ghash, aad_len) = init_gcm(key, nonce, aad);
        Self {
            cipher,
            j0,
            counter: inc32(&j0),
            ks: [0u8; BLOCK_SIZE],
            ks_pos: BLOCK_SIZE, // no leftover keystream yet
            ghash,
            aad_len,
            ct_len: 0,
            poisoned: false,
        }
    }

    /// Encrypt `chunk`, returning its ciphertext.
    ///
    /// Returns `None` once the cumulative plaintext would exceed the
    /// GCM ceiling (`2^36 − 32` bytes); the encryptor is poisoned
    /// thereafter and every subsequent call returns `None`. Do not
    /// call [`finalize`](Self::finalize) after a `None` — the emitted
    /// ciphertext stream is incomplete.
    #[must_use]
    pub fn update(&mut self, chunk: &[u8]) -> Option<Vec<u8>> {
        if self.poisoned {
            return None;
        }
        let new_len = self.ct_len.checked_add(u64::try_from(chunk.len()).ok()?)?;
        if new_len > GCM_MAX_PT_BYTES {
            self.poisoned = true;
            return None;
        }

        let mut out = vec![0u8; chunk.len()];
        let mut i = 0;

        // Drain leftover keystream from a previous partial-block call.
        while i < chunk.len() && self.ks_pos < BLOCK_SIZE {
            out[i] = chunk[i] ^ self.ks[self.ks_pos];
            self.ks_pos += 1;
            i += 1;
        }

        // Full blocks via fresh keystream.
        while chunk.len() - i >= BLOCK_SIZE {
            self.ks = self.counter;
            self.cipher.encrypt_block(&mut self.ks);
            self.counter = inc32(&self.counter);
            for lane in 0..BLOCK_SIZE {
                out[i + lane] = chunk[i + lane] ^ self.ks[lane];
            }
            i += BLOCK_SIZE;
        }

        // Tail (< one block): generate a block, consume what's needed,
        // save the rest as leftover.
        if i < chunk.len() {
            self.ks = self.counter;
            self.cipher.encrypt_block(&mut self.ks);
            self.counter = inc32(&self.counter);
            self.ks_pos = 0;
            while i < chunk.len() {
                out[i] = chunk[i] ^ self.ks[self.ks_pos];
                self.ks_pos += 1;
                i += 1;
            }
        }

        self.ghash.update(&out);
        self.ct_len = new_len;
        Some(out)
    }

    /// Finish and emit the full 128-bit tag.
    #[must_use]
    pub fn finalize(self) -> [u8; TAG_SIZE] {
        let s = self.ghash.finish_with_lengths(self.aad_len, self.ct_len);
        let mut tag = [0u8; TAG_SIZE];
        gctr_block(&self.cipher, &self.j0, &s, &mut tag);
        tag
    }

    /// Finish and emit a truncated tag of `tag_len` bytes
    /// (`MSB_t(full_tag)` per NIST SP 800-38D §5.2.1.2).
    #[must_use]
    pub fn finalize_with_tag_len(self, tag_len: GcmTagLen) -> Vec<u8> {
        let full = self.finalize();
        full[..tag_len.as_usize()].to_vec()
    }
}

/// Incremental-input, output-BUFFERED SM4-GCM decryptor.
///
/// AAD is supplied at construction; ciphertext is fed via
/// [`update`](Self::update) and buffered internally.
/// [`finalize_verify`](Self::finalize_verify) constant-time-compares
/// the tag and releases the plaintext only on success (commit-on-
/// verify). Memory is `O(message)`. See the module docstring for the
/// asymmetry rationale.
pub struct Sm4GcmDecryptor {
    cipher: Sm4Cipher,
    j0: [u8; BLOCK_SIZE],
    ghash: GhashAcc,
    ct_buf: Vec<u8>,
    aad_len: u64,
    overflowed: bool,
}

impl Sm4GcmDecryptor {
    /// Construct from key, nonce, and the full AAD.
    #[must_use]
    pub fn new(key: &[u8; KEY_SIZE], nonce: &[u8], aad: &[u8]) -> Self {
        let (cipher, j0, ghash, aad_len) = init_gcm(key, nonce, aad);
        Self {
            cipher,
            j0,
            ghash,
            ct_buf: Vec::new(),
            aad_len,
            overflowed: false,
        }
    }

    /// Buffer `chunk` of ciphertext and fold it into the running
    /// GHASH. No plaintext is produced here (commit-on-verify).
    pub fn update(&mut self, chunk: &[u8]) {
        if self.overflowed {
            return;
        }
        // Running CT length must stay under the GCM ceiling. Mirrors the
        // encryptor's checked-add guard; on a 64-bit target the
        // `try_from`s never fail, but the checked path keeps the guard
        // portable.
        let within_ceiling = u64::try_from(self.ct_buf.len())
            .ok()
            .zip(u64::try_from(chunk.len()).ok())
            .and_then(|(cur, c)| cur.checked_add(c))
            .is_some_and(|n| n <= GCM_MAX_PT_BYTES);
        if !within_ceiling {
            self.overflowed = true;
            return;
        }
        self.ghash.update(chunk);
        self.ct_buf.extend_from_slice(chunk);
    }

    /// Verify `tag` (its length determines the tag length, validated
    /// against the NIST-permitted set) and, on success, return the
    /// decrypted plaintext.
    ///
    /// Returns `None` on tag mismatch, invalid tag length, or
    /// length-ceiling overflow — single failure mode. No plaintext is
    /// produced on the failure path (commit-on-verify), so no
    /// failure-path buffer needs zeroizing.
    #[must_use]
    pub fn finalize_verify(self, tag: &[u8]) -> Option<Vec<u8>> {
        if self.overflowed {
            return None;
        }
        let _ = GcmTagLen::new(tag.len())?;
        let ct_len = u64::try_from(self.ct_buf.len()).ok()?;
        let s = self.ghash.finish_with_lengths(self.aad_len, ct_len);
        let mut expected_full = [0u8; TAG_SIZE];
        gctr_block(&self.cipher, &self.j0, &s, &mut expected_full);

        // `tag.len()` is a public quantity, so slicing the recomputed
        // tag is not a secret-dependent index; `ct_eq` keeps the byte
        // comparison constant-time.
        if expected_full[..tag.len()].ct_eq(tag).unwrap_u8() != 1 {
            return None;
        }

        // Tag verified — produce the plaintext via the same canonical
        // GCTR (from inc32(J0)) the single-shot decrypt uses, so the
        // buffered path rides the v0.7 batch API / SIMD fanout instead
        // of a hand-rolled per-block loop.
        let mut pt = vec![0u8; self.ct_buf.len()];
        gctr(&self.cipher, &inc32(&self.j0), &self.ct_buf, &mut pt);
        Some(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm4::mode_gcm;

    const KEY: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    const NONCE_12: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

    #[allow(clippy::cast_possible_truncation)]
    fn make_payload(len: usize) -> Vec<u8> {
        (0..len as u32).map(|i| (i ^ (i >> 3)) as u8).collect()
    }

    #[test]
    fn ghash_incremental_single_zero_block_is_zero() {
        let h = [
            0x66u8, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let mut g = GhashAcc::new(&h);
        g.update(&[0u8; 16]);
        assert_eq!(g.finish_no_lengths(), [0u8; 16]);
    }

    #[test]
    fn encryptor_chunked_matches_single_shot() {
        let aad = b"associated header";
        let pt = make_payload(200);
        let (ref_ct, ref_tag) =
            mode_gcm::encrypt(&KEY, &NONCE_12, aad, &pt).expect("under ceiling");

        for chunk in [1usize, 7, 15, 16, 17, 31, 32, 33, 100, pt.len().max(1)] {
            let mut enc = Sm4GcmEncryptor::new(&KEY, &NONCE_12, aad);
            let mut ct = Vec::new();
            let mut off = 0;
            while off < pt.len() {
                let take = chunk.min(pt.len() - off);
                ct.extend_from_slice(&enc.update(&pt[off..off + take]).expect("under ceiling"));
                off += take;
            }
            let tag = enc.finalize();
            assert_eq!(ct, ref_ct, "ct divergence at chunk {chunk}");
            assert_eq!(tag, ref_tag, "tag divergence at chunk {chunk}");
        }
    }

    #[test]
    fn encryptor_tag_len_matches_single_shot_truncation() {
        let aad = b"h";
        let pt = b"tag-len finalize path";
        let (_, full) = mode_gcm::encrypt(&KEY, &NONCE_12, aad, pt).expect("under ceiling");
        let mut enc = Sm4GcmEncryptor::new(&KEY, &NONCE_12, aad);
        let _ = enc.update(pt).unwrap();
        let tag = enc.finalize_with_tag_len(GcmTagLen::new(12).unwrap());
        assert_eq!(tag.as_slice(), &full[..12]);
    }

    #[test]
    fn encryptor_empty_updates_are_noops() {
        let mut enc = Sm4GcmEncryptor::new(&KEY, &NONCE_12, b"a");
        assert_eq!(enc.update(&[]).unwrap().len(), 0);
        assert_eq!(enc.update(&[]).unwrap().len(), 0);
        let _ = enc.finalize();
    }

    #[test]
    fn decryptor_chunked_matches_single_shot() {
        let aad = b"associated header";
        let pt = make_payload(200);
        let (ct, tag) = mode_gcm::encrypt(&KEY, &NONCE_12, aad, &pt).expect("under ceiling");

        for chunk in [1usize, 7, 15, 16, 17, 31, 32, 33, 100, ct.len().max(1)] {
            let mut dec = Sm4GcmDecryptor::new(&KEY, &NONCE_12, aad);
            let mut off = 0;
            while off < ct.len() {
                let take = chunk.min(ct.len() - off);
                dec.update(&ct[off..off + take]);
                off += take;
            }
            let got = dec.finalize_verify(&tag);
            assert_eq!(
                got.as_deref(),
                Some(pt.as_slice()),
                "divergence at chunk {chunk}"
            );
        }
    }

    #[test]
    fn decryptor_rejects_tampered_tag() {
        let aad = b"h";
        let pt = b"tamper target";
        let (ct, mut tag) = mode_gcm::encrypt(&KEY, &NONCE_12, aad, pt).expect("under ceiling");
        tag[0] ^= 0x01;
        let mut dec = Sm4GcmDecryptor::new(&KEY, &NONCE_12, aad);
        dec.update(&ct);
        assert!(dec.finalize_verify(&tag).is_none());
    }

    #[test]
    fn decryptor_rejects_invalid_tag_length() {
        let aad = b"h";
        let pt = b"bad tag length";
        let (ct, tag) = mode_gcm::encrypt(&KEY, &NONCE_12, aad, pt).expect("under ceiling");
        let mut dec = Sm4GcmDecryptor::new(&KEY, &NONCE_12, aad);
        dec.update(&ct);
        // 5 is not in {4,8,12,13,14,15,16}.
        assert!(dec.finalize_verify(&tag[..5]).is_none());
    }

    #[test]
    fn decryptor_supports_truncated_tag() {
        let aad = b"h";
        let pt = b"short tag decrypt";
        let mut enc = Sm4GcmEncryptor::new(&KEY, &NONCE_12, aad);
        let ct = enc.update(pt).unwrap();
        let tag12 = enc.finalize_with_tag_len(GcmTagLen::new(12).unwrap());
        let mut dec = Sm4GcmDecryptor::new(&KEY, &NONCE_12, aad);
        dec.update(&ct);
        assert_eq!(dec.finalize_verify(&tag12).as_deref(), Some(pt.as_slice()));
    }

    #[test]
    fn decryptor_empty_then_verify() {
        let (ct, tag) = mode_gcm::encrypt(&KEY, &NONCE_12, b"a", &[]).expect("under ceiling");
        let mut dec = Sm4GcmDecryptor::new(&KEY, &NONCE_12, b"a");
        dec.update(&[]);
        dec.update(&ct);
        assert_eq!(dec.finalize_verify(&tag).as_deref(), Some(&[][..]));
    }

    #[test]
    fn round_trip_through_streaming_both_directions() {
        let aad = b"end to end";
        let pt = make_payload(137);
        let mut enc = Sm4GcmEncryptor::new(&KEY, &NONCE_12, aad);
        let mut ct = Vec::new();
        for c in pt.chunks(13) {
            ct.extend_from_slice(&enc.update(c).unwrap());
        }
        let tag = enc.finalize();

        let mut dec = Sm4GcmDecryptor::new(&KEY, &NONCE_12, aad);
        for c in ct.chunks(11) {
            dec.update(c);
        }
        assert_eq!(dec.finalize_verify(&tag).as_deref(), Some(pt.as_slice()));
    }

    #[test]
    fn streaming_matches_single_shot_with_non_12_byte_nonce() {
        let nonce: [u8; 7] = [0x42; 7];
        let aad = b"short nonce";
        let pt = make_payload(80);
        let (ref_ct, ref_tag) = mode_gcm::encrypt(&KEY, &nonce, aad, &pt).expect("under ceiling");

        let mut enc = Sm4GcmEncryptor::new(&KEY, &nonce, aad);
        let mut ct = Vec::new();
        for c in pt.chunks(16) {
            ct.extend_from_slice(&enc.update(c).unwrap());
        }
        assert_eq!(ct, ref_ct);
        assert_eq!(enc.finalize(), ref_tag);
    }
}
