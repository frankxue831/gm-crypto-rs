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
//! See [`cipher`]'s module-doc for the constant-time stance, throughput
//! cost, and KAT sources.

pub mod cbc_streaming;
pub mod cipher;
pub mod mode_cbc;

// v0.4 W3 — Bitsliced (table-less, gate-only) SM4 S-box behind the
// `sm4-bitsliced` feature flag (Q4.9 / Q4.10 / Q4.11 of
// docs/v0.4-scope.md). The module is `pub(crate)` so `cipher.rs`'s
// `tau` can swap to it when the feature is on; not in the public API.
#[cfg(feature = "sm4-bitsliced")]
pub(crate) mod sbox_bitsliced;

pub use cbc_streaming::{Sm4CbcDecryptor, Sm4CbcEncryptor};
pub use cipher::{BLOCK_SIZE, KEY_SIZE, Sm4Cipher};
