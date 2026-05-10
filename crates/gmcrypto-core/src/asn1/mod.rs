//! Minimal ASN.1 DER subset.
//!
//! v0.1 ships only the SM2 signature `SEQUENCE { r INTEGER, s INTEGER }`
//! shape. Full reader/writer lands in v0.3.

pub mod ciphertext;
pub mod sig;

pub use sig::{decode_sig, encode_sig};
