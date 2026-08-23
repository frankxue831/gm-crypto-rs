//! SM2 elliptic curve cryptography (GB/T 32918-2017).
//!
//! SM2 is the Chinese national public-key algorithm: a 256-bit prime-field
//! curve with its own signature and public-key-encryption schemes. It is not
//! ECDSA-on-a-different-curve — both schemes bind a **signer identity** into
//! the hash, so a signature is only meaningful relative to the `id` it was
//! produced under.
//!
//! # What is here
//!
//! | | |
//! |---|---|
//! | [`sign_with_id`] / [`verify_with_id`] | GB/T 32918.2 signature, DER-encoded `(r, s)` |
//! | [`encrypt`](fn@encrypt) / [`decrypt`](fn@decrypt) | GB/T 32918.4 public-key encryption, GM/T 0009 DER `C1‖C3‖C2` |
//! | [`Sm2PrivateKey`] / [`Sm2PublicKey`] | key types; SEC1 and raw-scalar constructors |
//! | [`raw_ciphertext`] | the `C1‖C3‖C2` byte layout, for callers not using DER |
//! | `key_exchange` | GM/T 0003.3 key agreement — behind the `sm2-key-exchange` feature |
//!
//! # The signer ID is part of the signature
//!
//! Both schemes hash a `Z` value derived from the curve parameters, the
//! public key, **and** a caller-supplied identity string. Verify with a
//! different `id` than you signed with and the signature fails — correctly.
//! [`DEFAULT_SIGNER_ID`] is the `"1234567812345678"` from GB/T 32918.2 §10,
//! which is what most interoperating implementations use when the protocol
//! does not specify one. Use it when you have no better answer, not as a
//! placeholder to fill in later: changing it later invalidates every
//! signature already issued.
//!
//! # Randomness is the caller's
//!
//! Signing and encryption both consume a `rand_core::TryCryptoRng`. This
//! crate pulls no RNG into its dependency graph — pick one in your own
//! `Cargo.toml` (`getrandom`'s `SysRng`, an OS-backed CSPRNG, is the usual
//! answer; on `wasm32` you additionally enable its `wasm_js` feature). An
//! RNG failure surfaces as the same opaque [`Error`](crate::Error) as any
//! other failure, never a panic.
//!
//! # Failure is deliberately uninformative
//!
//! [`verify_with_id`] returns `bool`. [`decrypt`](fn@decrypt) returns one
//! [`Error::Failed`](crate::Error::Failed) whether the DER was malformed,
//! `C1` was off-curve, or the `C3` hash did not match — distinguishing them
//! would hand an attacker an oracle. This is a designed property, not a
//! missing feature; see `SECURITY.md`.
//!
//! # Example
//!
//! ```rust
//! use gmcrypto_core::sm2::{
//!     DEFAULT_SIGNER_ID, Sm2PrivateKey, sign_with_id, verify_with_id,
//! };
//! // Any `rand_core::TryCryptoRng`. `getrandom` is not a dependency of this
//! // crate — add it (or another CSPRNG) to your own Cargo.toml.
//! use getrandom::SysRng;
//!
//! // `from_bytes_be` is the recommended constructor: always available, and
//! // it keeps `crypto_bigint::U256` out of your code. It returns a
//! // `CtOption` — rejection of an out-of-range scalar is constant-time.
//! let d = [0x42u8; 32];
//! let key = Sm2PrivateKey::from_bytes_be(&d).expect("0x42..42 is a valid scalar");
//! let public = key.public_key();
//!
//! let sig = sign_with_id(&key, DEFAULT_SIGNER_ID, b"attack at dawn", &mut SysRng)
//!     .expect("signing failed — RNG or an internal invariant");
//!
//! assert!(verify_with_id(&public, DEFAULT_SIGNER_ID, b"attack at dawn", &sig));
//!
//! // A different ID is a different Z, so the same signature no longer verifies.
//! assert!(!verify_with_id(&public, b"other-signer", b"attack at dawn", &sig));
//! ```
//!
//! `Sm2PrivateKey::to_bytes_be` hands back **plaintext secret bytes**; the
//! caller owns zeroizing that `[u8; 32]`.

pub(crate) mod comb_table;
// `curve` is internal low-level SM2 field/scalar arithmetic over `crypto-bigint`
// 0.7 (`Fn`, `Fp`, `NMod`, `PMod`, `b`, `b3`). v0.22 marks the whole module
// `#[doc(hidden)]`: **NOT part of the public API / NOT covered by SemVer — may
// change or be removed in any release** (including under a `crypto-bigint` major
// bump). Rust users use the high-level `sm2` API; C users use `gmcrypto-c`. Kept
// `pub` only so in-repo dev crates (the dudect bench, integration tests, fuzz)
// can reach it cross-crate. Module-level hiding also covers the macro-generated
// `NMod`/`PMod` (which cannot take a per-item attribute). See `docs/v0.22-scope.md`
// §3 Q22.3 + `docs/v1.0-readiness.md` §3.A.
#[doc(hidden)]
pub mod curve;
pub mod decrypt;
pub mod encrypt;
// v1.1 — SM2 key exchange (GM/T 0003.3 ≡ GB/T 32918.3-2016) with key
// confirmation. Opt-in via the `sm2-key-exchange` feature; default builds
// are byte-identical. See docs/v1.1-sm2-key-exchange-design.md.
#[cfg(feature = "sm2-key-exchange")]
pub mod key_exchange;
// `point` (`ProjectivePoint`) is the internal low-level curve point. Same
// posture as `curve`/`scalar_mul` above: `#[doc(hidden)]`, not public API /
// not SemVer-covered, kept `pub` only for in-repo dev crates + cross-module use.
#[doc(hidden)]
pub mod point;
pub mod private_key;
pub mod public_key;
pub mod raw_ciphertext;
// `scalar_mul` (`mul_g`/`mul_var`) takes the `crypto-bigint`-typed `Fn`. Same
// posture as `curve` above: `#[doc(hidden)]`, internal low-level arithmetic, not
// public API / not SemVer-covered, kept `pub` only for in-repo dev crates.
#[doc(hidden)]
pub mod scalar_mul;
pub mod sign;
pub mod verify;

// Re-export of the internal `crypto-bigint`-typed curve types; `#[doc(hidden)]`
// so the re-export does not re-expose them in the public API (see `mod curve`).
#[doc(hidden)]
pub use curve::{Fn, Fp};
pub use decrypt::decrypt;
pub use encrypt::encrypt;
// Re-export of the internal low-level curve point; `#[doc(hidden)]` (see
// `mod point`) — not public API / not SemVer; internal low-level curve point.
#[doc(hidden)]
pub use point::ProjectivePoint;
pub use private_key::Sm2PrivateKey;
pub use public_key::Sm2PublicKey;
// Re-export of the internal low-level scalar-mult fns; `#[doc(hidden)]` (see
// `mod scalar_mul`).
#[doc(hidden)]
pub use scalar_mul::{mul_g, mul_var};
pub use sign::{DEFAULT_SIGNER_ID, compute_z, sign_raw_with_id, sign_with_id};
pub use verify::verify_with_id;

/// SM2 module error — alias for the workspace-wide [`crate::Error`].
///
/// Prior to v0.5 each operation had its own per-module enum
/// (`SignError`, `EncryptError`, `DecryptError`) all with a single
/// `Failed` variant. v0.5 W5 collapses them into one type; migration
/// recipe is `s/SignError/sm2::Error/g`, `s/EncryptError/sm2::Error/g`,
/// `s/DecryptError/sm2::Error/g` (or use the workspace-wide path
/// `gmcrypto_core::Error` directly). The workspace-wide type is
/// `#[non_exhaustive]`, so exhaustive `match` arms must add `_ => ...`.
pub type Error = crate::Error;
