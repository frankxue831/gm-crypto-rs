//! Runtime CPU feature detection.
//!
//! Uses [`cpufeatures`] for `no_std`-compatible, cached detection of
//! x86_64 AVX2. On non-x86_64 targets `has_avx2()` is a compile-time
//! `false` constant (the `cpufeatures::new!` macro is a no-op on
//! unsupported architectures).
//!
//! Detection is cached after the first call via an internal
//! `Once`-protected static; the per-call cost is one atomic load
//! plus one branch.

#[cfg(target_arch = "x86_64")]
cpufeatures::new!(cpuid_avx2, "avx2");

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
