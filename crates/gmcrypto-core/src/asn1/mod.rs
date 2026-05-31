//! Minimal ASN.1 DER subset.
//!
//! v0.3 introduces the reusable [`reader`] / [`writer`] / [`oid`]
//! primitives; [`sig`] and [`ciphertext`] re-implement on top of
//! them while preserving byte-identical accept/reject behaviour
//! against the v0.2 surface.

pub mod ciphertext;
// Not public API / not SemVer — low-level DER primitives kept pub for internal cross-module + dev-crate use.
#[doc(hidden)]
pub mod oid;
// Not public API / not SemVer — low-level DER primitives kept pub for internal cross-module + dev-crate use.
#[doc(hidden)]
pub mod reader;
pub mod sig;
// Not public API / not SemVer — low-level DER primitives kept pub for internal cross-module + dev-crate use.
#[doc(hidden)]
pub mod writer;

pub use sig::{decode_sig, encode_sig};
