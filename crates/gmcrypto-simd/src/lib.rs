//! SIMD backends for `gmcrypto-core` (v0.5 W4).
//!
//! This crate quarantines the unavoidable SIMD `unsafe` (AVX2
//! intrinsics on `x86_64`, NEON on `aarch64` in W4 phase 3) so that
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
//!   ([`sm4::sbox_x8::sbox_x8`]), with runtime AVX2 detection via the
//!   `cpufeatures` crate and silent scalar fallback on non-AVX2 CPUs.
//! - Scalar fallback path delegates to `gmcrypto-core`'s v0.4 W3
//!   single-block bitslice ([`gmcrypto_core::sm4::sbox_bitsliced::sbox`]),
//!   so the byte-output is identical across AVX2-on / AVX2-off /
//!   non-x86_64 dispatch.
//!
//! # v0.5 W4 phase 3 scope (deferred)
//!
//! - aarch64 NEON 4-way bitsliced S-box (NEON is baseline on
//!   `aarch64` — no runtime detection needed).
//! - `Sm4CbcDecryptor::process_chunk` SIMD fanout per Q5.10 — the
//!   public-API surface that batches 8 (or 4 on NEON) ciphertext
//!   blocks at once. Until phase 3 lands, the phase 2 SIMD path is
//!   exercised with 7 of 8 lanes carrying replicated input.
//!
//! [`gmcrypto-c`]: https://docs.rs/gmcrypto-c

#![no_std]

pub mod sm4;

mod detect;

pub use detect::has_avx2;
