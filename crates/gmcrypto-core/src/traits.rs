//! In-crate streaming primitive traits.
//!
//! v0.3 W5 ships a small **in-crate** trait surface — [`Hash`],
//! [`Mac`], [`BlockCipher`] — that the SM3 / HMAC-SM3 / SM4
//! implementations all satisfy. Per Q7.3 / Q7.10, `RustCrypto`
//! trait fit (`digest::Digest`, `digest::Mac`,
//! `cipher::BlockEncrypt`/`BlockDecrypt`) is **deferred to v0.4**
//! behind an opt-in feature flag. v0.3 stays `no_std` +
//! zero-runtime-deps.
//!
//! # Posture
//!
//! These traits exist for ergonomic generic-over-our-types wiring,
//! NOT as bound-on-public-API constraints. Don't take `T: Hash` on
//! a public function — that would be a v1.0 `SemVer` surface.
//! Implementations of these traits on types in this crate are
//! additive; consumers can opt in if they want.
//!
//! # Lifecycle
//!
//! All three traits use the same shape:
//!
//! - `new()` (or `new(key)` for `Mac` / `BlockCipher`) constructs a
//!   fresh instance.
//! - `update(&mut self, &[u8])` absorbs input bytes (where applicable).
//! - `finalize(self) -> Self::Output` consumes the instance and
//!   produces the result (digest, MAC, or ciphertext).
//!
//! `BlockCipher` is shape-different: it operates per-block via
//! `encrypt_block` / `decrypt_block` rather than a streaming
//! update/finalize. Higher-level streaming modes (CBC, CTR) compose
//! on top.

/// A streaming hash function.
pub trait Hash {
    /// The fixed-size digest output.
    type Output;

    /// Construct a fresh hasher.
    #[must_use]
    fn new() -> Self;

    /// Absorb input bytes.
    fn update(&mut self, data: &[u8]);

    /// Consume the hasher and produce the final digest.
    fn finalize(self) -> Self::Output;
}

/// A streaming MAC (message authentication code).
pub trait Mac {
    /// The fixed-size MAC tag output.
    type Output;

    /// Construct a fresh MAC keyed with `key`.
    #[must_use]
    fn new(key: &[u8]) -> Self;

    /// Absorb message bytes.
    fn update(&mut self, data: &[u8]);

    /// Consume the MAC instance and produce the final tag.
    fn finalize(self) -> Self::Output;

    /// Verify a candidate tag against the computed one in
    /// constant-time. Returns `true` on match. Implementations MUST
    /// use a constant-time comparison primitive (e.g.
    /// `subtle::ConstantTimeEq`).
    fn verify(self, expected: &Self::Output) -> bool
    where
        Self: Sized;
}

/// A symmetric block cipher (single-block primitive).
///
/// Higher-level modes (CBC, CTR, GCM) compose on top by chaining
/// `encrypt_block` / `decrypt_block` calls; see
/// [`crate::sm4::mode_cbc`] for the v0.2 single-shot CBC and
/// [`crate::sm4::cbc_streaming`] for the v0.3 W5 streaming
/// `Sm4CbcEncryptor` / `Sm4CbcDecryptor`.
pub trait BlockCipher {
    /// Block size in bytes (e.g. 16 for SM4).
    const BLOCK_SIZE: usize;

    /// Construct a cipher instance from a key.
    #[must_use]
    fn new(key: &[u8]) -> Self;

    /// Encrypt one block in place.
    fn encrypt_block(&self, block: &mut [u8]);

    /// Decrypt one block in place.
    fn decrypt_block(&self, block: &mut [u8]);
}
