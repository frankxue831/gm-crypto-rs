//! SIMD backends for `gmcrypto-core` (v0.5 W4 phase 2 / v0.6 W6).
//!
//! This crate quarantines the unavoidable SIMD `unsafe` (AVX2
//! intrinsics on `x86_64`, NEON on `aarch64`) so that
//! `gmcrypto-core` itself can keep `unsafe_code = "forbid"`. The
//! posture mirrors the established [`gmcrypto-c`] precedent (FFI
//! shim with `unsafe_code = "warn"`).
//!
//! The crate exposes a small Rust-internal API surface only (no raw
//! pointers, no C ABI). It is `rlib`-only; the single C-ABI surface
//! for downstream callers remains [`gmcrypto-c`].
//!
//! # v0.5 W4 phase 2 scope
//!
//! - x86_64 AVX2 8-way packed bitsliced SM4 S-box
//!   ([`sm4::sbox_x8::sbox_x8`]), with runtime AVX2 detection via
//!   the `cpufeatures` crate and silent scalar fallback on non-AVX2
//!   CPUs. 8 input bytes occupy the low lanes of the 256-bit
//!   register; the upper 24 lanes are unused.
//!
//! # v0.6 W6 (phase 3) scope
//!
//! - x86_64 AVX2 32-byte full-width packed bitsliced S-box
//!   ([`sm4::sbox_x32::sbox_x32`]). The intended consumer is an
//!   8-block CBC-decrypt batch fanout in `gmcrypto-core` (8 SM4
//!   blocks × 4 `tau` bytes per round = 32 bytes per call, zero
//!   wasted lanes).
//! - aarch64 NEON 16-byte packed bitsliced S-box
//!   ([`sm4::sbox_x16::sbox_x16`]). NEON is the architectural
//!   baseline on aarch64 (Q5.12 / Q6.3 of the v0.5 / v0.6 scope
//!   docs); compile-time gated, no runtime detect.
//!
//! [`gmcrypto-c`]: https://docs.rs/gmcrypto-c

#![no_std]
// v0.5 W4 phase 2 / v0.6 W6 — this crate is the SIMD-intrinsic
// backend (mirroring `gmcrypto-c`'s FFI-shim posture).
// `core::arch::*` intrinsics are all `unsafe fn`, and
// `#[target_feature(enable = "...")] unsafe fn` is the only
// stable-Rust path on MSRV 1.85 to combine runtime CPU dispatch
// with intrinsic calls. Every `unsafe` block / fn declaration
// carries a `// SAFETY:` comment naming the architectural /
// runtime-detect precondition. The Cargo.toml lint
// `unsafe_code = "warn"` documents intent; this crate-level
// `allow` keeps the per-decl noise out of the review surface
// (same pattern as `gmcrypto-c`'s `src/lib.rs`).
// `gmcrypto-core` itself stays `unsafe_code = "forbid"`.
#![allow(unsafe_code)]

pub mod ghash;
pub mod sm4;

mod detect;

pub use detect::{has_avx2, has_pclmulqdq, has_pmull};
pub use ghash::ghash_mul;
