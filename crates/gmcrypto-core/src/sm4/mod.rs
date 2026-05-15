//! SM4 block cipher (GB/T 32907-2016) and operating modes.
//!
//! v0.2 ships:
//!
//! - The raw 128-bit block cipher [`cipher::Sm4Cipher`].
//! - SM4-CBC with PKCS#7 padding (single-shot, [`mode_cbc::encrypt`] /
//!   [`mode_cbc::decrypt`]).
//!
//! v0.3 W5 adds streaming wrappers:
//!
//! - [`cbc_streaming::Sm4CbcEncryptor`] / [`cbc_streaming::Sm4CbcDecryptor`].
//!
//! v0.7 W2 adds SM4-CTR (counter mode; unauthenticated stream cipher):
//!
//! - [`mode_ctr::encrypt`] / [`mode_ctr::decrypt`] (single-shot).
//!
//! v0.7 W3 adds the streaming SM4-CTR counterpart:
//!
//! - [`ctr_streaming::Sm4CtrCipher`] (symmetric — serves both directions).
//!
//! See [`cipher`]'s module-doc for the constant-time stance, throughput
//! cost, and KAT sources.

pub mod cbc_streaming;
pub mod cipher;
pub mod ctr_streaming;
pub mod mode_cbc;
pub mod mode_ctr;

// v0.8 W2 — SM4-GCM single-shot AEAD per NIST SP 800-38D + GM/T 0009 /
// RFC 8998. Behind the `sm4-aead` feature flag (additive; zero impact
// on the default-features build). Pulls in `gmcrypto-simd::ghash` for
// the GHASH primitive (v0.8 W1).
#[cfg(feature = "sm4-aead")]
pub mod mode_gcm;

// v0.8 W3 — SM4-CCM single-shot AEAD per NIST SP 800-38C / RFC 3610 +
// GM/T 0009 (OID 1.2.156.10197.1.104.9). Same `sm4-aead` feature flag
// as mode_gcm; pure-Rust CBC-MAC + CTR over the existing
// `Sm4Cipher::encrypt_block(s)` path (no GHASH).
#[cfg(feature = "sm4-aead")]
pub mod mode_ccm;

// v0.4 W3 — Bitsliced (table-less, gate-only) SM4 S-box behind the
// `sm4-bitsliced` feature flag (Q4.9 / Q4.10 / Q4.11 of
// docs/v0.4-scope.md). The module is `pub(crate)` so `cipher.rs`'s
// `tau` can swap to it when the feature is on; not in the public API.
//
// When `sm4-bitsliced-simd` is also enabled, `tau` dispatches into
// `sbox_bitsliced_simd::sbox` instead (which calls the sibling
// crate). The v0.4 W3 module then becomes dead code at the
// non-test build path, but its `tests::bitsliced_matches_table` is
// still useful as an algorithmic correctness gate and as a
// reference for `sbox_bitsliced_simd::tests::simd_sbox_matches_single_block`.
#[cfg(feature = "sm4-bitsliced")]
#[cfg_attr(feature = "sm4-bitsliced-simd", allow(dead_code))]
pub(crate) mod sbox_bitsliced;

// v0.5 W4 — Multi-block SIMD-packed bitsliced SM4 S-box behind the
// `sm4-bitsliced-simd` feature flag (Q5.10–Q5.15 of
// docs/v0.5-scope.md). Phase 1 ships scaffolding only — the module
// delegates transparently to `sbox_bitsliced` so the cfg-dispatch
// path, dudect target, and CI matrix entry land before the AVX2
// (phase 2) / NEON (phase 3) intrinsic implementations.
#[cfg(feature = "sm4-bitsliced-simd")]
pub(crate) mod sbox_bitsliced_simd;

pub use cbc_streaming::{Sm4CbcDecryptor, Sm4CbcEncryptor};
pub use cipher::{BLOCK_SIZE, KEY_SIZE, Sm4Cipher};
pub use ctr_streaming::Sm4CtrCipher;
