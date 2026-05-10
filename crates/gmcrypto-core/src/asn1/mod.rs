//! Minimal ASN.1 DER subset.
//!
//! v0.3 introduces the reusable [`reader`] / [`writer`] / [`oid`]
//! primitives; [`sig`] and [`ciphertext`] re-implement on top of
//! them while preserving byte-identical accept/reject behaviour
//! against the v0.2 surface.

pub mod ciphertext;
pub mod oid;
pub mod reader;
pub mod sig;
pub mod writer;

pub use sig::{decode_sig, encode_sig};
