//! Constant-time-designed pure-Rust SM2 / SM3 primitives.
//!
//! See the workspace `README.md` for scope, threat model, and the honest
//! framing of the in-CI `dudect`-based timing-leak regression harness.
//!
//! # Crate features
//!
//! - `default` — `no_std`, `alloc`-only.
//! - `std` — opt-in; reserved for future file-I/O wire-format helpers (v0.3+).

#![no_std]
#![deny(missing_docs)]
#![doc(html_root_url = "https://docs.rs/gmcrypto-core/0.1.0")]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod asn1;
pub mod hmac;
pub mod sm2;
pub mod sm3;
pub mod sm4;
