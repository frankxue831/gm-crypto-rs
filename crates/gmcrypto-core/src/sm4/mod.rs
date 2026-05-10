//! SM4 block cipher (GB/T 32907-2016) and operating modes.
//!
//! v0.2 ships:
//!
//! - The raw 128-bit block cipher [`cipher::Sm4Cipher`].
//! - SM4-CBC with PKCS#7 padding (lands in W1 chunk 2).
//!
//! See [`cipher`]'s module-doc for the constant-time stance, throughput
//! cost, and KAT sources.

pub mod cipher;
pub mod mode_cbc;

pub use cipher::{BLOCK_SIZE, KEY_SIZE, Sm4Cipher};
