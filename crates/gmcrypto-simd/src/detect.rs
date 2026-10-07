//! Runtime CPU feature detection.
//!
//! Uses [`cpufeatures`] for `no_std`-compatible, cached detection of:
//! - x86_64 AVX2 (used by [`crate::sm4::sbox_x8`] / [`crate::sm4::sbox_x32`]).
//! - x86_64 PCLMULQDQ (v0.8 W1; used by `crate::ghash::ghash_mul_clmul`).
//! - aarch64 AES extension a.k.a. PMULL64 (v0.8 W1; used by
//!   `crate::ghash::ghash_mul_pmull`).
//!
//! On targets that don't support a feature, the corresponding getter
//! returns a compile-time `false` constant (the `cpufeatures::new!`
//! macro is a no-op on unsupported architectures).
//!
//! Detection is cached after the first call via an internal
//! `Once`-protected static; the per-call cost is one atomic load
//! plus one branch.

#[cfg(target_arch = "x86_64")]
cpufeatures::new!(cpuid_avx2, "avx2");

#[cfg(target_arch = "x86_64")]
cpufeatures::new!(cpuid_pclmulqdq, "pclmulqdq");

// v1.16 — only on compilers where the `gfni` intrinsics are stable
// (build.rs emits the cfg on rustc >= 1.89).
#[cfg(all(target_arch = "x86_64", gmcrypto_simd_gfni))]
cpufeatures::new!(cpuid_gfni_avx2, "gfni", "avx2");

#[cfg(target_arch = "aarch64")]
cpufeatures::new!(cpuid_aes, "aes");

/// Returns `true` if the host CPU supports AVX2 and the running
/// translation unit may dispatch into AVX2 intrinsics.
///
/// On non-`x86_64` targets this is always `false` (and the
/// AVX2 path is `cfg`-gated out entirely).
#[must_use]
#[inline]
pub fn has_avx2() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        cpuid_avx2::get()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Returns `true` if the host CPU supports GFNI and AVX2 and this build
/// includes the GFNI S-box (rustc >= 1.89; v1.16 Q16.2).
///
/// `cpufeatures` checks GFNI together with OS-enabled AVX-512 register
/// state, so a GFNI CPU without AVX-512 reports `false` and keeps the
/// AVX2 path. Always `false` off `x86_64` or on older compilers.
#[must_use]
#[inline]
pub fn has_gfni_avx2() -> bool {
    #[cfg(all(target_arch = "x86_64", gmcrypto_simd_gfni))]
    {
        cpuid_gfni_avx2::get()
    }
    #[cfg(not(all(target_arch = "x86_64", gmcrypto_simd_gfni)))]
    {
        false
    }
}

/// Returns `true` if the host CPU supports the PCLMULQDQ carryless-
/// multiply instruction (Intel Westmere+ / AMD Bulldozer+, 2010+).
///
/// On non-`x86_64` targets this is always `false`.
#[must_use]
#[inline]
pub fn has_pclmulqdq() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        cpuid_pclmulqdq::get()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Returns `true` if the host aarch64 CPU supports the ARMv8.0 Crypto
/// Extensions PMULL64 instruction (`vmull_p64`).
///
/// The Rust target-feature name for this is `"aes"` (a single feature
/// flag gates AES, PMULL, PMULL2, and PMULL128 on aarch64 per the
/// ARMv8.0 architecture spec). Present on all Apple Silicon and most
/// modern aarch64 server / mobile chips.
///
/// On non-`aarch64` targets this is always `false`.
#[must_use]
#[inline]
pub fn has_pmull() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        cpuid_aes::get()
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}
