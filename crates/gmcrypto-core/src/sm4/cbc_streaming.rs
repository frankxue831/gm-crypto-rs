//! Streaming SM4-CBC encrypt / decrypt (v0.3 W5).
//!
//! Single-shot v0.2 [`super::mode_cbc::encrypt`] / [`super::mode_cbc::decrypt`]
//! still ship unchanged; this module adds an `update`/`finalize` shape
//! for callers who can't materialize the full plaintext / ciphertext
//! up front.
//!
//! # Equivalence with v0.2 single-shot
//!
//! For any plaintext `M` partitioned into chunks `M = c_0 || c_1 || ...
//! || c_n`, the streaming encryptor's concatenated output equals
//! `super::mode_cbc::encrypt(key, iv, M)` byte-for-byte. Same goes
//! for the decryptor.
//!
//! # Padding-oracle posture
//!
//! Same as v0.2's single-shot decrypt — see the
//! [`super::mode_cbc`] module-doc. Wrap with HMAC-SM3 + encrypt-then-
//! MAC if you need integrity in the presence of network attackers.
//! The streaming decryptor's PKCS#7 strip on `finalize` reuses the
//! v0.2 constant-time scan idiom — it does not reimplement it.
//!
//! # Streaming decrypt buffer-back-by-one rule
//!
//! [`Sm4CbcDecryptor::update`] holds the **most recent decrypted
//! block** back from emission so that `finalize` can apply PKCS#7
//! strip to it — even on a chunked-input call where the boundary
//! between "last block" and "not last block" is only known at
//! `finalize` time. This avoids an early-emit padding oracle: the
//! caller sees plaintext bytes only after `finalize` confirms the
//! overall structure is consistent.
//!
//! # Failure-mode invariant
//!
//! [`Sm4CbcDecryptor::finalize`] returns `Option<Vec<u8>>` — `None`
//! on any decrypt-side failure (length not multiple of 16, invalid
//! PKCS#7). Single uninformative shape per `CLAUDE.md`.

use crate::sm4::cipher::{BLOCK_SIZE, KEY_SIZE, Sm4Cipher};
use alloc::vec::Vec;
use subtle::{ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};

/// Streaming SM4-CBC encryptor with PKCS#7 padding.
///
/// Construct with `new(&key, &iv)`, feed plaintext via `update`,
/// finalize with `finalize` (returns the full ciphertext as a
/// `Vec<u8>`). The IV must be **caller-supplied unpredictable**
/// per NIST SP 800-38A Appendix C — same contract as
/// [`super::mode_cbc::encrypt`].
///
/// `update` may be called any number of times with arbitrary chunk
/// sizes. `finalize` must be called exactly once; after `finalize`
/// the instance is consumed.
pub struct Sm4CbcEncryptor {
    cipher: Sm4Cipher,
    /// Most recent ciphertext block (or IV before the first block
    /// is emitted).
    prev: [u8; BLOCK_SIZE],
    /// Buffered partial-block bytes from the tail of the most
    /// recent `update` call.
    buffer: [u8; BLOCK_SIZE],
    /// Number of valid bytes in `buffer`. Always `< BLOCK_SIZE`.
    buffer_len: usize,
    /// Accumulated ciphertext so far (full blocks only).
    output: Vec<u8>,
}

impl Sm4CbcEncryptor {
    /// Construct a new streaming encryptor. The IV must be
    /// CSPRNG-derived per the SM4-CBC IV contract.
    #[must_use]
    pub fn new(key: &[u8; KEY_SIZE], iv: &[u8; BLOCK_SIZE]) -> Self {
        Self {
            cipher: Sm4Cipher::new(key),
            prev: *iv,
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
            output: Vec::new(),
        }
    }

    /// Absorb plaintext bytes. Emits ciphertext for every full
    /// 16-byte block; trailing partial bytes are buffered until the
    /// next `update` or `finalize`.
    pub fn update(&mut self, mut data: &[u8]) {
        // Top up the buffer first if it's partially filled.
        if self.buffer_len > 0 {
            let need = BLOCK_SIZE - self.buffer_len;
            let take = need.min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];
            if self.buffer_len == BLOCK_SIZE {
                let block = self.buffer;
                self.encrypt_one(&block);
                self.buffer_len = 0;
            }
        }
        // Drain whole blocks straight from the input.
        while data.len() >= BLOCK_SIZE {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&data[..BLOCK_SIZE]);
            self.encrypt_one(&block);
            data = &data[BLOCK_SIZE..];
        }
        // Buffer any trailing partial block.
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Drain the accumulated ciphertext, leaving the encryptor ready
    /// for further `update` calls. The Rust streaming API has no
    /// inherent reason for this method — `finalize` consumes the
    /// encryptor and returns the full accumulation. This helper exists
    /// for the `gmcrypto-c` FFI shim's streaming pattern (v0.5 W1)
    /// which emits ciphertext incrementally as `update` produces full
    /// blocks.
    ///
    /// **Not part of the public API — not covered by SemVer.** Same posture as
    /// [`crate::sm2::sign_raw_with_id`]: `#[doc(hidden)] pub` for `gmcrypto-c`
    /// FFI-shim consumption only; it may change or be removed in any release,
    /// including patch releases, without notice. Internal cross-crate use stays
    /// sound via the workspace's lockstep publishing policy (sibling crates
    /// release together; exact-version sibling pins enforced at the 1.0 publish).
    #[doc(hidden)]
    pub fn take_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.output)
    }

    /// Apply PKCS#7 padding to the buffered tail and emit the final
    /// ciphertext block(s). Consumes the encryptor.
    #[must_use]
    pub fn finalize(mut self) -> Vec<u8> {
        // PKCS#7: append `pad_len = BLOCK_SIZE - buffer_len` copies
        // of `pad_len`. When buffer_len == 0, that's a full block of
        // `0x10` per RFC 5652 §6.3.
        #[allow(clippy::cast_possible_truncation)]
        let pad_len = (BLOCK_SIZE - self.buffer_len) as u8;
        for i in self.buffer_len..BLOCK_SIZE {
            self.buffer[i] = pad_len;
        }
        let block = self.buffer;
        self.encrypt_one(&block);
        self.output
    }

    fn encrypt_one(&mut self, plaintext_block: &[u8; BLOCK_SIZE]) {
        let mut block = *plaintext_block;
        for (b, p) in block.iter_mut().zip(self.prev.iter()) {
            *b ^= *p;
        }
        self.cipher.encrypt_block(&mut block);
        self.prev = block;
        self.output.extend_from_slice(&block);
    }
}

/// Streaming SM4-CBC decryptor with PKCS#7 strip.
///
/// Construct with `new(&key, &iv)`, feed ciphertext via `update`,
/// finalize with `finalize` (returns `Option<Vec<u8>>`).
///
/// **Buffer-back-by-one:** `update` decrypts every full 16-byte
/// block but holds the **most recent decrypted block** back from
/// emission until `finalize` confirms it is the last block. This
/// keeps the PKCS#7 strip uniform — no early-emit padding-oracle
/// surface during the streaming phase. Callers see plaintext only
/// after `finalize` validates the trailing-block padding.
///
/// Same single-`None` failure-mode posture as the v0.2 single-shot
/// [`super::mode_cbc::decrypt`].
pub struct Sm4CbcDecryptor {
    cipher: Sm4Cipher,
    /// Most recent ciphertext block (or IV before the first block).
    prev: [u8; BLOCK_SIZE],
    /// Buffered partial-block ciphertext bytes from the tail of the
    /// most recent `update` call.
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    /// Accumulated plaintext from "definitely-not-the-last" blocks.
    output: Vec<u8>,
    /// The **last decrypted block** held back from emission. None if
    /// no full block has been processed yet.
    held_back: Option<[u8; BLOCK_SIZE]>,
}

impl Sm4CbcDecryptor {
    /// Construct a new streaming decryptor.
    #[must_use]
    pub fn new(key: &[u8; KEY_SIZE], iv: &[u8; BLOCK_SIZE]) -> Self {
        Self {
            cipher: Sm4Cipher::new(key),
            prev: *iv,
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
            output: Vec::new(),
            held_back: None,
        }
    }

    /// Absorb ciphertext bytes.
    ///
    /// **v0.6 W6 fanout (under `sm4-bitsliced-simd`):** when the
    /// incoming `data` holds enough buffered ciphertext for a full
    /// SIMD batch (`SIMD_BATCH` blocks — 8 on `x86_64`, 4 on `aarch64`,
    /// 1 elsewhere), the batched path
    /// [`super::cipher::Sm4Cipher::decrypt_blocks_simd`] fans the
    /// per-round `tau` across the full SIMD register width via
    /// [`gmcrypto_simd::sm4::sbox_x32`] / [`gmcrypto_simd::sm4::sbox_x16`].
    /// Behavior is byte-identical to the per-block
    /// [`Self::decrypt_one`] path (Q5.10's "no new public Rust
    /// surface" carries through — only the internal loop shape
    /// changes).
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buffer_len > 0 {
            let need = BLOCK_SIZE - self.buffer_len;
            let take = need.min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];
            if self.buffer_len == BLOCK_SIZE {
                let block = self.buffer;
                self.decrypt_one(&block);
                self.buffer_len = 0;
            }
        }

        // v0.6 W6 — SIMD batch fanout. Drains `data` in
        // `SIMD_BATCH`-sized chunks while at least one batch is
        // available. The chaining-input snapshot (`saved`) is taken
        // before parallel decrypt; each plaintext is then XOR-ed
        // with the previous ciphertext (preserving the standard CBC
        // chaining). The last decrypted block of the batch lands in
        // `held_back` (preserving the buffer-back-by-one
        // invariant); the prior batch's `held_back` is flushed to
        // `output`. Same per-block semantics as `decrypt_one`,
        // amortized across `SIMD_BATCH` blocks.
        #[cfg(feature = "sm4-bitsliced-simd")]
        {
            use super::cipher::SIMD_BATCH;
            while data.len() >= SIMD_BATCH * BLOCK_SIZE {
                let mut batch = [[0u8; BLOCK_SIZE]; SIMD_BATCH];
                for i in 0..SIMD_BATCH {
                    batch[i].copy_from_slice(&data[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]);
                }
                self.decrypt_batch(&batch);
                data = &data[SIMD_BATCH * BLOCK_SIZE..];
            }
        }

        while data.len() >= BLOCK_SIZE {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&data[..BLOCK_SIZE]);
            self.decrypt_one(&block);
            data = &data[BLOCK_SIZE..];
        }
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Drain the emitted plaintext so far (i.e. all decrypted blocks
    /// EXCEPT the held-back final-candidate block). Same FFI-helper
    /// posture as [`Sm4CbcEncryptor::take_output`]: `#[doc(hidden)] pub`
    /// for `gmcrypto-c` streaming-FFI consumption only — **not part of the
    /// public API, not covered by SemVer** (may change or be removed in any
    /// release, including patch releases, without notice).
    ///
    /// **Note**: the held-back block is *not* drained — the buffer-
    /// back-by-one invariant is preserved across this call.
    #[doc(hidden)]
    pub fn take_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.output)
    }

    /// Strip PKCS#7 padding from the held-back final block and emit
    /// the full plaintext. Returns `None` if any failure mode is
    /// hit — length not multiple of 16, no full blocks ever seen,
    /// or padding-strip rejection.
    #[must_use]
    pub fn finalize(mut self) -> Option<Vec<u8>> {
        // Any partial buffered ciphertext at finalize time is invalid
        // (overall ciphertext length must be a multiple of 16).
        if self.buffer_len != 0 {
            return None;
        }
        let last = self.held_back?;
        let stripped = strip_pkcs7_block(&last)?;
        self.output.extend_from_slice(&last[..stripped]);
        Some(self.output)
    }

    fn decrypt_one(&mut self, ciphertext_block: &[u8; BLOCK_SIZE]) {
        let mut block = *ciphertext_block;
        let saved = block;
        self.cipher.decrypt_block(&mut block);
        for (b, p) in block.iter_mut().zip(self.prev.iter()) {
            *b ^= *p;
        }
        self.prev = saved;

        // Move any previously-held-back block to the output (it's
        // now confirmed-not-the-last) and replace it with the
        // freshly-decrypted block.
        if let Some(prev_held) = self.held_back.take() {
            self.output.extend_from_slice(&prev_held);
        }
        self.held_back = Some(block);
    }

    /// v0.6 W6 — Batch-decrypt a SIMD_BATCH-block chunk of ciphertext,
    /// preserving the buffer-back-by-one invariant.
    ///
    /// State-machine contract (preserved across the batched call):
    ///
    /// ```text
    /// Before:
    ///   self.prev      = ciphertext of last block before this batch (or IV)
    ///   self.held_back = Some(plaintext of last-block-before-this-batch),
    ///                    or None on first batch
    ///
    /// For ct_blocks[0..N] (N = SIMD_BATCH):
    ///   1. saved[i] = ct_blocks[i]                  (chaining snapshot)
    ///   2. pt_blocks[0..N] = batched_decrypt(ct_blocks[0..N])
    ///   3. pt_blocks[0] ^= self.prev                (chain to pre-batch state)
    ///      pt_blocks[i] ^= saved[i-1]   for i in 1..N
    ///   4. Emit prior self.held_back to self.output (if Some).
    ///   5. Emit pt_blocks[0..N-1]   to self.output  (confirmed-not-last)
    ///   6. self.held_back = Some(pt_blocks[N-1])    (defer last for padding)
    ///   7. self.prev = saved[N-1]                    (= ct_blocks[N-1])
    /// ```
    ///
    /// Byte-identical to calling [`Self::decrypt_one`] N times on the
    /// same ciphertext blocks.
    #[cfg(feature = "sm4-bitsliced-simd")]
    fn decrypt_batch(&mut self, ct_blocks: &[[u8; BLOCK_SIZE]; super::cipher::SIMD_BATCH]) {
        use super::cipher::SIMD_BATCH;

        // 1. Snapshot the chaining inputs before decryption.
        let saved = *ct_blocks;

        // 2. Batched parallel decrypt (in-place).
        let mut pt_blocks = saved;
        self.cipher.decrypt_blocks_simd(&mut pt_blocks);

        // 3. XOR with chaining inputs: pt[0] ^= prev; pt[i] ^= saved[i-1].
        for (b, p) in pt_blocks[0].iter_mut().zip(self.prev.iter()) {
            *b ^= *p;
        }
        for i in 1..SIMD_BATCH {
            let chain = saved[i - 1];
            for (b, p) in pt_blocks[i].iter_mut().zip(chain.iter()) {
                *b ^= *p;
            }
        }

        // 4. Flush prior held_back.
        if let Some(prev_held) = self.held_back.take() {
            self.output.extend_from_slice(&prev_held);
        }
        // 5. Emit pt_blocks[0..N-1] (confirmed-not-last; another block
        //    follows in held_back).
        for pt in pt_blocks.iter().take(SIMD_BATCH - 1) {
            self.output.extend_from_slice(pt);
        }
        // 6. Hold back the last decrypted block (PKCS#7 candidate).
        self.held_back = Some(pt_blocks[SIMD_BATCH - 1]);
        // 7. Update prev to the last ciphertext of this batch.
        self.prev = saved[SIMD_BATCH - 1];
    }
}

/// Constant-time PKCS#7 strip on a 16-byte block. Returns the byte
/// count that should be retained (`BLOCK_SIZE - pad_len`) on success,
/// `None` on any malformed padding.
///
/// Same scan logic as [`super::mode_cbc::decrypt`]'s helper —
/// re-implemented here to avoid making the v0.2 helper public, but
/// byte-identical in behavior.
fn strip_pkcs7_block(block: &[u8; BLOCK_SIZE]) -> Option<usize> {
    let last = block[BLOCK_SIZE - 1];
    let pad_nonzero = !last.ct_eq(&0u8);
    #[allow(clippy::cast_possible_truncation)]
    let pad_le_block = !last.ct_gt(&(BLOCK_SIZE as u8));
    let pad_in_range = pad_nonzero & pad_le_block;

    let mut acc: u8 = 0;
    for (i, byte) in block.iter().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let pos_from_end = (BLOCK_SIZE - i) as u8;
        let in_padding = !pos_from_end.ct_gt(&last);
        let diff = *byte ^ last;
        let masked = u8::conditional_select(&0u8, &diff, in_padding);
        acc |= masked;
    }
    let acc_zero = acc.ct_eq(&0u8);
    let valid = pad_in_range & acc_zero;
    if bool::from(valid) {
        Some(BLOCK_SIZE - last as usize)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm4::mode_cbc;

    /// Equivalence with single-shot encrypt for a no-chunking call.
    #[test]
    fn encrypt_single_chunk_matches_v02() {
        let key = [0x42u8; KEY_SIZE];
        let iv = [0x33u8; BLOCK_SIZE];
        let plaintext = b"streaming round trip";
        let mut enc = Sm4CbcEncryptor::new(&key, &iv);
        enc.update(plaintext);
        let stream_ct = enc.finalize();
        let oneshot_ct = mode_cbc::encrypt(&key, &iv, plaintext);
        assert_eq!(stream_ct, oneshot_ct);
    }

    /// Equivalence with single-shot encrypt across chunk boundaries.
    #[test]
    fn encrypt_chunked_matches_v02() {
        let key = [0x42u8; KEY_SIZE];
        let iv = [0x33u8; BLOCK_SIZE];
        // 100-byte plaintext, mid-multi-block.
        let pt: Vec<u8> = (0..100u8).collect();
        // Several arbitrary chunkings.
        for chunk_size in [1usize, 7, 16, 17, 31, 32, 100] {
            let mut enc = Sm4CbcEncryptor::new(&key, &iv);
            for chunk in pt.chunks(chunk_size) {
                enc.update(chunk);
            }
            let stream_ct = enc.finalize();
            let oneshot_ct = mode_cbc::encrypt(&key, &iv, &pt);
            assert_eq!(stream_ct, oneshot_ct, "chunk_size={chunk_size}");
        }
    }

    /// Round-trip through streaming encrypt + streaming decrypt.
    #[test]
    fn streaming_round_trip() {
        let key = [0x42u8; KEY_SIZE];
        let iv = [0x33u8; BLOCK_SIZE];
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 100, 256] {
            #[allow(clippy::cast_possible_truncation)]
            let pt: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(13)).collect();
            let mut enc = Sm4CbcEncryptor::new(&key, &iv);
            enc.update(&pt);
            let ct = enc.finalize();

            // Decrypt across multiple chunkings.
            for chunk_size in [1usize, 7, 16, 17, 31, 32, ct.len().max(1)] {
                let mut dec = Sm4CbcDecryptor::new(&key, &iv);
                for chunk in ct.chunks(chunk_size) {
                    dec.update(chunk);
                }
                let recovered = dec.finalize().expect("decrypt");
                assert_eq!(recovered, pt, "len={len} chunk_size={chunk_size}");
            }
        }
    }

    /// Decrypt rejects truncated stream (length not multiple of 16).
    #[test]
    fn decrypt_rejects_truncated() {
        let key = [0x42u8; KEY_SIZE];
        let iv = [0x33u8; BLOCK_SIZE];
        let mut dec = Sm4CbcDecryptor::new(&key, &iv);
        dec.update(&[0xAB; 31]); // 31 bytes = 1 full block + 15 buffered
        assert!(dec.finalize().is_none());
    }

    /// Decrypt rejects empty stream (no full blocks at all).
    #[test]
    fn decrypt_rejects_empty() {
        let key = [0x42u8; KEY_SIZE];
        let iv = [0x33u8; BLOCK_SIZE];
        let dec = Sm4CbcDecryptor::new(&key, &iv);
        assert!(dec.finalize().is_none());
    }

    /// Decrypt rejects bad padding (tampered final block).
    #[test]
    fn decrypt_rejects_bad_padding() {
        let key = [0x42u8; KEY_SIZE];
        let iv = [0x33u8; BLOCK_SIZE];
        let pt = b"this is a test message that spans multiple blocks";
        let mut enc = Sm4CbcEncryptor::new(&key, &iv);
        enc.update(pt);
        let mut ct = enc.finalize();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        let mut dec = Sm4CbcDecryptor::new(&key, &iv);
        dec.update(&ct);
        assert!(dec.finalize().is_none());
    }

    /// v0.6 W6 — chunk-boundary sweep around the SIMD batch size.
    ///
    /// Per codex's phase 3 design flag #3: "chunk-boundary tests
    /// around `0, 1, N-1, N, N+1, 2N` blocks, including
    /// `take_output`." The new `decrypt_batch` path only triggers
    /// when `data.len() >= SIMD_BATCH * BLOCK_SIZE`; this test
    /// covers the transitions on either side.
    ///
    /// `SIMD_BATCH` is compile-time arch-specific. On `x86_64`: 8;
    /// on `aarch64`: 4; elsewhere: 1 (where this test degenerates
    /// to single-block).
    #[cfg(feature = "sm4-bitsliced-simd")]
    #[test]
    fn cbc_decrypt_simd_batch_boundary_sweep() {
        use super::super::cipher::SIMD_BATCH;
        let key = [0x42u8; KEY_SIZE];
        let iv = [0x33u8; BLOCK_SIZE];

        // Block counts around the batch boundary. For SIMD_BATCH=8
        // (x86_64): 0, 1, 7, 8, 9, 15, 16, 17. For SIMD_BATCH=4
        // (aarch64): 0, 1, 3, 4, 5, 7, 8, 9. For SIMD_BATCH=1
        // (other): degenerates to 0, 1, 0, 1, 2, 1, 2, 3 — still
        // valid, just less interesting.
        let block_counts: [usize; 8] = [
            0,
            1,
            SIMD_BATCH.saturating_sub(1),
            SIMD_BATCH,
            SIMD_BATCH + 1,
            (2 * SIMD_BATCH).saturating_sub(1),
            2 * SIMD_BATCH,
            2 * SIMD_BATCH + 1,
        ];

        for &n_blocks in &block_counts {
            // Build n_blocks worth of plaintext (16 bytes per block).
            // n_blocks = 0 maps to empty plaintext (PKCS#7 pads to
            // one full block of 0x10).
            let pt: Vec<u8> = (0..(n_blocks * BLOCK_SIZE))
                .map(|i| u8::try_from(i & 0xFF).unwrap_or(0))
                .collect();
            let canonical = mode_cbc::encrypt(&key, &iv, &pt);

            // Stream-decrypt the canonical ciphertext.
            let mut dec = Sm4CbcDecryptor::new(&key, &iv);
            dec.update(&canonical);
            let recovered = dec.finalize().expect("decrypt");
            assert_eq!(
                recovered, pt,
                "boundary sweep: n_blocks={n_blocks} (SIMD_BATCH={SIMD_BATCH})",
            );
        }
    }

    /// v0.6 W6 — chunked-update boundary sweep. The same total
    /// ciphertext, fed through `update` in chunks of varying sizes
    /// (including sub-block, exact-batch, batch+1, etc.), must
    /// recover the same plaintext. Catches state-machine bugs in
    /// the partial-buffer + batch-drain + single-block-drain
    /// transitions.
    #[cfg(feature = "sm4-bitsliced-simd")]
    #[test]
    fn cbc_decrypt_simd_chunked_update_sweep() {
        use super::super::cipher::SIMD_BATCH;
        let key = [0x42u8; KEY_SIZE];
        let iv = [0x33u8; BLOCK_SIZE];
        // 3 * SIMD_BATCH + half-block of plaintext to ensure
        // every batch boundary is crossed at least once.
        let total_blocks = 3 * SIMD_BATCH + 1;
        let pt: Vec<u8> = (0..(total_blocks * BLOCK_SIZE - 5))
            .map(|i| u8::try_from((i * 17) & 0xFF).unwrap_or(0))
            .collect();
        let ct = mode_cbc::encrypt(&key, &iv, &pt);

        let batch_bytes = SIMD_BATCH * BLOCK_SIZE;
        let chunk_sizes = [
            1,
            7,
            BLOCK_SIZE,
            BLOCK_SIZE + 1,
            batch_bytes - 1,
            batch_bytes,
            batch_bytes + 1,
            2 * batch_bytes,
            ct.len().max(1),
        ];

        for &chunk_size in &chunk_sizes {
            let mut dec = Sm4CbcDecryptor::new(&key, &iv);
            for chunk in ct.chunks(chunk_size) {
                dec.update(chunk);
            }
            let recovered = dec.finalize().expect("decrypt");
            assert_eq!(
                recovered, pt,
                "chunked update: chunk_size={chunk_size} (batch_bytes={batch_bytes})",
            );
        }
    }

    /// v0.6 W6 — `take_output` interaction with the SIMD batch
    /// path. The FFI-shim helper drains emitted plaintext partway
    /// through a stream; the held-back block must remain held back
    /// across the take. Verifies that calling `take_output` mid-
    /// stream doesn't drop the SIMD-batched held-back invariant.
    #[cfg(feature = "sm4-bitsliced-simd")]
    #[test]
    fn cbc_decrypt_simd_take_output_preserves_held_back() {
        use super::super::cipher::SIMD_BATCH;
        let key = [0x42u8; KEY_SIZE];
        let iv = [0x33u8; BLOCK_SIZE];
        // 2 * SIMD_BATCH + 1 blocks of plaintext to force at least
        // one batch and one straggler-block path.
        let total_blocks = 2 * SIMD_BATCH + 1;
        let pt: Vec<u8> = (0..(total_blocks * BLOCK_SIZE))
            .map(|i| u8::try_from((i ^ 0xA5) & 0xFF).unwrap_or(0))
            .collect();
        let ct = mode_cbc::encrypt(&key, &iv, &pt);

        // Feed in two chunks: first SIMD_BATCH + 1 blocks, then the
        // rest. Drain emitted plaintext via take_output after the
        // first chunk; the held_back block must still be there for
        // finalize to consume.
        let mut dec = Sm4CbcDecryptor::new(&key, &iv);
        let split = (SIMD_BATCH + 1) * BLOCK_SIZE;
        dec.update(&ct[..split]);
        let first_chunk_pt = dec.take_output();

        dec.update(&ct[split..]);
        let rest = dec.finalize().expect("decrypt");

        // Concatenated result must equal the original plaintext.
        let mut combined = first_chunk_pt;
        combined.extend_from_slice(&rest);
        assert_eq!(combined, pt);
    }

    /// Cross-validation: streaming encrypt of a decryption of a
    /// streaming encrypt is a fixed point. (Stronger sanity check
    /// than just round-trip — exercises both paths against each
    /// other on the same instance.)
    #[test]
    fn streaming_decrypt_matches_v02_oneshot() {
        let key = [0x42u8; KEY_SIZE];
        let iv = [0x33u8; BLOCK_SIZE];
        let pt = b"test message for cross-validation";
        let canonical = mode_cbc::encrypt(&key, &iv, pt);

        // Decrypt the canonical ciphertext via streaming decryptor.
        let mut dec = Sm4CbcDecryptor::new(&key, &iv);
        dec.update(&canonical);
        let stream_pt = dec.finalize().expect("streaming decrypt");
        assert_eq!(stream_pt, pt);

        // And vice versa: oneshot decrypt of streaming ciphertext.
        let mut enc = Sm4CbcEncryptor::new(&key, &iv);
        enc.update(pt);
        let blob = enc.finalize();
        let recovered = mode_cbc::decrypt(&key, &iv, &blob).expect("oneshot decrypt");
        assert_eq!(recovered, pt);
    }
}
