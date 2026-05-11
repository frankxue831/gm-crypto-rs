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
//!   and v0.3 W5 streaming). v0.4 W3 adds an opt-in bitsliced
//!   (table-less, gate-only) S-box behind the `sm4-bitsliced` feature.
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
//!   (v0.3 W5). v0.4 W2 adds RustCrypto-trait fit (`digest::Digest`,
//!   `digest::Mac`, `cipher::BlockEncrypt`/`BlockDecrypt`) behind the
//!   opt-in `digest-traits` / `cipher-traits` features.
//!
//! # Crate features
//!
//! - `default` — `no_std`, `alloc`-only. No optional dependencies.
//! - `std` — opt-in; reserved for future file-I/O wire-format helpers.
//! - `digest-traits` — opt-in (v0.4 W2). Implements `digest::Digest` for
//!   [`sm3::Sm3`] and `digest::Mac` for [`hmac::HmacSm3`]. Pulls
//!   `digest = "0.10"`.
//! - `cipher-traits` — opt-in (v0.4 W2). Implements
//!   `cipher::{BlockEncrypt, BlockDecrypt, BlockSizeUser, KeySizeUser,
//!   KeyInit}` for [`sm4::Sm4Cipher`]. Pulls `cipher = "0.4"`.
//! - `sm4-bitsliced` — opt-in (v0.4 W3). Routes the SM4 S-box through
//!   a bitsliced (table-less, gate-only) Itoh-Tsujii inversion in
//!   GF(2^8). Byte-identical output to the default linear-scan path;
//!   constant-time by construction (no table lookups, no branches on
//!   secret bits).
//!
//! # `wasm32-unknown-unknown`
//!
//! Builds clean as of v0.4 W1. The crate is `no_std + alloc` only and
//! does NOT pull `getrandom`'s `wasm_js` backend or `wasm-bindgen` /
//! `js-sys` into its default dep graph. Wasm callers wire their own
//! `rand_core::Rng` impl — see the workspace `README.md`.

#![no_std]
#![deny(missing_docs)]
#![doc(html_root_url = "https://docs.rs/gmcrypto-core/0.4.0")]

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
