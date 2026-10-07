//! SM4 SIMD backends.
//!
//! v0.5 W4 phase 2 landed the AVX2 8-way packed bitsliced S-box
//! [`sbox_x8::sbox_x8`] — 8 bytes packed into the low lanes of
//! `__m256i` (7 of 8 lanes wasted in the phase-2 `tau` consumer).
//!
//! v0.6 W6 (phase 3) added:
//! - [`sbox_x32::sbox_x32`] — AVX2 32-byte full-width packed S-box,
//!   the throughput-favorable shape for an 8-block CBC-decrypt
//!   batch (8 SM4 blocks × 4 `tau` bytes per round = 32 bytes).
//! - [`sbox_x16::sbox_x16`] — NEON 16-byte packed S-box on
//!   `aarch64` (4 SM4 blocks × 4 `tau` bytes per round = 16 bytes).
//!   Compile-time baseline; no runtime CPU detect.
//!
//! Issue #163 added:
//! - [`sbox_x4::sbox_x4`] — four-byte serial-`tau` adapter. `AArch64`
//!   reuses one NEON x16 invocation; `x86_64` production is four
//!   scalar calls (AVX2 not selected: 10% rule unmeasured);
//!   [`sbox_x8`] is kept as an internal candidate / test surface.
//!
//! v1.16 added:
//! - `gfni` — SM4 S-box as GF2P8AFFINEQB + GF2P8AFFINEINVQB through
//!   the isomorphism to the AES field, behind `sbox_x32_gfni`. Compiled
//!   only on x86_64 with rustc >= 1.89 (`build.rs` emits
//!   `cfg(gmcrypto_simd_gfni)`); its derivation tests run everywhere.
//!
//! The scalar primitives (Boyar-Peralta Itoh-Tsujii gate sequence)
//! live in `scalar` and serve as the fallback path for every SIMD
//! entry point on targets without the relevant intrinsics. The
//! AVX2 byte-parallel primitives live in `avx2` and are shared
//! between [`sbox_x8`] (low-lanes staged) and [`sbox_x32`]
//! (full-width). The NEON byte-parallel primitives live in `neon`.

pub(crate) mod scalar;

#[cfg(target_arch = "x86_64")]
pub(crate) mod avx2;

#[cfg(target_arch = "aarch64")]
pub(crate) mod neon;

// v1.16 — GFNI kernel on x86_64 with rustc >= 1.89 (build.rs cfg); its
// portable derivation tests run on every target.
#[cfg(any(test, all(target_arch = "x86_64", gmcrypto_simd_gfni)))]
pub(crate) mod gfni;

pub mod sbox_x16;
pub mod sbox_x32;
pub mod sbox_x4;
pub mod sbox_x8;
