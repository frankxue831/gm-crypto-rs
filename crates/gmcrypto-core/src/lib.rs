//! Constant-time-designed pure-Rust SM2 / SM3 / SM4 primitives.
//!
//! See the workspace `README.md` for scope, threat model, and the honest
//! framing of the in-CI `dudect`-based timing-leak regression harness.
//!
//! # Modules
//!
//! - [`sm2`] — SM2 elliptic-curve sign / verify / encrypt / decrypt
//!   (GB/T 32918). Comb-table fixed-base scalar mult (v0.3 W6).
//! - [`sm3`] — SM3 hash (GB/T 32905) with streaming `new/update/finalize`.
//! - [`sm4`] — SM4 block cipher (GB/T 32907) + CBC mode (single-shot
//!   and v0.3 W5 streaming).
//! - [`hmac`] — HMAC-SM3 (RFC 2104), single-shot + v0.3 W5 streaming.
//! - [`kdf`] — PBKDF2-HMAC-SM3 (RFC 8018 §5.2).
//! - [`asn1`] — strict-canonical DER reader / writer / OID constants
//!   (v0.3 W1); GM/T 0009 SM2 ciphertext SEQUENCE; RFC 3279 SM2
//!   signature SEQUENCE.
//! - [`pem`] — RFC 7468 PEM codec (v0.3 W2; hand-rolled, `no_std`).
//! - [`spki`] — RFC 5280 `SubjectPublicKeyInfo` for SM2 (v0.3 W2).
//! - [`sec1`] — RFC 5915 `ECPrivateKey` + SEC1 uncompressed point (v0.3 W2).
//! - [`pkcs8`] — RFC 5958 `OneAsymmetricKey` + RFC 8018 PBES2 (v0.3 W2).
//! - [`traits`] — in-crate `Hash` / `Mac` / `BlockCipher` traits
//!   (v0.3 W5; RustCrypto-trait fit deferred to v0.4).
//!
//! # Crate features
//!
//! - `default` — `no_std`, `alloc`-only.
//! - `std` — opt-in; reserved for future file-I/O wire-format helpers.

#![no_std]
#![deny(missing_docs)]
#![doc(html_root_url = "https://docs.rs/gmcrypto-core/0.3.0")]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod asn1;
pub mod hmac;
pub mod kdf;
pub mod pem;
pub mod pkcs8;
pub mod sec1;
pub mod sm2;
pub mod sm3;
pub mod sm4;
pub mod spki;
pub mod traits;
