//! GHASH multiplication in `GF(2^128) / (x^128 + x^7 + x^2 + x + 1)`.
//!
//! NIST SP 800-38D §6.4. The polynomial-multiplication primitive used by
//! SM4-GCM (v0.8 W2) and any other GCM-style AEAD with this reduction
//! polynomial. Hash subkey `H` is secret (derived from the encryption
//! key via the underlying block cipher's encryption of the zero block),
//! so the multiplication must be constant-time over `H`.
//!
//! # Dispatch
//!
//! The public entry point [`ghash_mul`] selects an implementation at
//! runtime based on available CPU features, with silent fallback to
//! the software path:
//!
//! - **x86_64 with PCLMULQDQ + SSE2**: [`clmul::ghash_mul_clmul`]. Single
//!   carryless-multiplication instruction available since Intel Westmere
//!   (2010) / AMD Bulldozer (2011). Detected at runtime via
//!   [`crate::detect::has_pclmulqdq`].
//! - **aarch64 with PMULL (AES extension)**: [`pmull::ghash_mul_pmull`].
//!   ARMv8.0 Crypto Extensions; present on all Apple Silicon and most
//!   modern aarch64 server / mobile chips. Detected at runtime via
//!   [`crate::detect::has_pmull`].
//! - **Otherwise**: [`software::ghash_mul_software`] — constant-time
//!   bit-serial. Slower (~5-10× the hardware paths) but correct.
//!
//! Byte-equivalence between the three paths is verified exhaustively by
//! `tests/ghash_lane_equivalence.rs`.
//!
//! # Constant-time discipline
//!
//! All three paths are constant-time over `H`. The software path uses
//! mask-XOR rather than branches; the hardware paths inherit
//! constant-time guarantees from the underlying single-cycle
//! carryless-multiply instructions. No table lookups, no
//! secret-dependent branches, no `_mm_shuffle_*` against secret indices.

pub mod software;

#[cfg(target_arch = "x86_64")]
pub mod clmul;

#[cfg(target_arch = "aarch64")]
pub mod pmull;

pub use software::ghash_mul_software;

#[cfg(target_arch = "x86_64")]
pub use clmul::ghash_mul_clmul;

#[cfg(target_arch = "aarch64")]
pub use pmull::ghash_mul_pmull;

/// GHASH multiplication: `H · X mod (x^128 + x^7 + x^2 + x + 1)`.
///
/// Selects the fastest available implementation at runtime. See the
/// module docstring for dispatch order. Byte-identical output across
/// every dispatch target.
#[must_use]
#[inline]
pub fn ghash_mul(h: &[u8; 16], x: &[u8; 16]) -> [u8; 16] {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::has_pclmulqdq() {
            // SAFETY: `has_pclmulqdq()` returned `true`, so the running
            // CPU supports the PCLMULQDQ + SSE2 instruction pair that
            // `ghash_mul_clmul` invokes via `core::arch::x86_64`
            // intrinsics. Fixed-size array references cross the unsafe
            // boundary by value; no raw pointers exposed.
            return unsafe { clmul::ghash_mul_clmul(h, x) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if crate::detect::has_pmull() {
            // SAFETY: `has_pmull()` returned `true`, so the running
            // aarch64 CPU exposes the ARMv8.0 Crypto Extensions
            // PMULL64 instruction that `ghash_mul_pmull` invokes via
            // `core::arch::aarch64::vmull_p64`.
            return unsafe { pmull::ghash_mul_pmull(h, x) };
        }
    }
    software::ghash_mul_software(h, x)
}
