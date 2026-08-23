//! Minimal ASN.1 DER subset.
//!
//! Hand-rolled, `no_std`, and deliberately small: this crate parses exactly
//! the two structures Chinese-standard SM2 puts on the wire, and nothing
//! else. There is no general-purpose ASN.1 engine here to be pointed at
//! untrusted schemas.
//!
//! The public surface is two codecs:
//!
//! - [`sig`] — the RFC 3279 `SEQUENCE { r INTEGER, s INTEGER }` that
//!   [`sm2::sign_with_id`](crate::sm2::sign_with_id) emits and
//!   [`verify_with_id`](crate::sm2::verify_with_id) consumes.
//! - [`ciphertext`] — the GM/T 0009 SM2 ciphertext
//!   `SEQUENCE { x, y INTEGER, hash OCTET STRING, cipher OCTET STRING }`.
//!
//! **Strict canonical DER, on both sides.** The reader rejects what a
//! permissive parser would wave through: non-minimal length encodings,
//! leading zero padding on an INTEGER, a negative INTEGER where an unsigned
//! value belongs, trailing bytes after the outer SEQUENCE. That strictness
//! is the point — DER malleability is how signature-encoding bugs become
//! consensus bugs, and a parser that accepts two encodings of one value has
//! already lost.
//!
//! Decoding returns `Option`, never a reason. A caller cannot learn *which*
//! rule a malformed input broke, by design; see `SECURITY.md`.
//!
//! Inputs here are public — a signature and a ciphertext are both things an
//! attacker already holds — so no constant-time obligation arises in this
//! module, and none is claimed.

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
