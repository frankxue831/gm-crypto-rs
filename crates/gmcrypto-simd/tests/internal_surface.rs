//! v0.21 — existence pins for `gmcrypto-simd`'s internal `#[doc(hidden)]` entry
//! points that `gmcrypto-core` relies on across the crate boundary. This crate
//! has **no stable Rust API** (see `docs/v0.21-scope.md` Q21.5): the items below
//! are `pub` only so core can call them, and are not covered by SemVer for any
//! external consumer. This test guards against a silent removal that would break
//! the core build — it calls each dispatcher once (scalar fallback on any arch
//! without the relevant intrinsic).

#[test]
fn internal_entry_points_exist() {
    // Packed bitsliced S-box dispatchers.
    let _ = gmcrypto_simd::sm4::sbox_x8::sbox_x8(&[0u8; 8]);
    let _ = gmcrypto_simd::sm4::sbox_x16::sbox_x16(&[0u8; 16]);
    let _ = gmcrypto_simd::sm4::sbox_x32::sbox_x32(&[0u8; 32]);

    // GHASH GF(2^128) multiply — the module path and the crate-root re-export.
    let _ = gmcrypto_simd::ghash::ghash_mul(&[0u8; 16], &[0u8; 16]);
    let _ = gmcrypto_simd::ghash_mul(&[0u8; 16], &[0u8; 16]);

    // Cached CPU-feature detectors (defined on all arches; `false` off-arch).
    let _ = gmcrypto_simd::has_avx2();
    let _ = gmcrypto_simd::has_pclmulqdq();
    let _ = gmcrypto_simd::has_pmull();
}
