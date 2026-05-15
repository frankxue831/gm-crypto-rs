//! v0.8 W1 — GHASH Known-Answer Tests.
//!
//! NIST SP 800-38D / GCM-spec-derived `(H, X) → Y` test vectors. The
//! exhaustive cross-path equivalence lives in `ghash_lane_equivalence.rs`;
//! this file pins a small set of triples to specific output bytes so a
//! regression in *all three* dispatch paths simultaneously would still
//! be caught here.
//!
//! ## Provenance
//!
//! The `H` constant used below is `AES_128(0^128) = 66e94bd4ef8a2c3b
//! 884cfa59ca342b2e` — the well-known hash subkey for the all-zero AES
//! key. This is documented in NIST GCM spec Appendix B Test Case 1 and
//! widely cited in AES-GCM implementations.
//!
//! The `X = 0388dace60b6a392f328c2b971b2fe78` constant is the
//! ciphertext block from NIST GCM Test Case 2 (one all-zero plaintext
//! block under K=0, IV=0^96). Its product with `H` is part of the
//! standard AES-GCM tag-computation chain.
//!
//! The expected `Y` value was computed by the software path
//! ([`super::ghash_mul_software`]) on 2026-05-15 and cross-validated
//! against the aarch64 PMULL path. It is independently verifiable by
//! anyone running the v0.8 W2 SM4-GCM end-to-end interop test against
//! gmssl (any algorithmic regression in GHASH would surface as a tag
//! mismatch in that test).

#![allow(unsafe_code, clippy::items_after_statements)]

#[cfg(target_arch = "x86_64")]
use gmcrypto_simd::ghash::ghash_mul_clmul;
#[cfg(target_arch = "aarch64")]
use gmcrypto_simd::ghash::ghash_mul_pmull;
use gmcrypto_simd::ghash::ghash_mul_software;

/// `AES_128(0^128) = 66e94bd4ef8a2c3b884cfa59ca342b2e`.
/// The hash subkey for an all-zero AES key — a canonical NIST GCM
/// reference constant.
const H: [u8; 16] = [
    0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
];

/// NIST GCM Test Case 2 single ciphertext block.
const X: [u8; 16] = [
    0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
];

/// `H · X mod (x^128 + x^7 + x^2 + x + 1)`.
const Y: [u8; 16] = [
    0x5e, 0x2e, 0xc7, 0x46, 0x91, 0x70, 0x62, 0x88, 0x2c, 0x85, 0xb0, 0x68, 0x53, 0x53, 0xde, 0xb7,
];

#[test]
fn ghash_nist_triple_software() {
    assert_eq!(ghash_mul_software(&H, &X), Y);
}

#[test]
fn ghash_nist_triple_dispatch() {
    // Public dispatch entry point on whatever path the host CPU
    // selects (software / CLMUL / PMULL). Equivalent of the software
    // test on a different code path.
    assert_eq!(gmcrypto_simd::ghash_mul(&H, &X), Y);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn ghash_nist_triple_clmul() {
    if !gmcrypto_simd::has_pclmulqdq() {
        eprintln!("skipping: PCLMULQDQ not available on this x86_64 CPU");
        return;
    }
    // SAFETY: has_pclmulqdq() returned true; PCLMULQDQ + SSE2 available.
    let got = unsafe { ghash_mul_clmul(&H, &X) };
    assert_eq!(got, Y);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn ghash_nist_triple_pmull() {
    if !gmcrypto_simd::has_pmull() {
        eprintln!("skipping: PMULL not available on this aarch64 CPU");
        return;
    }
    // SAFETY: has_pmull() returned true; PMULL64 available.
    let got = unsafe { ghash_mul_pmull(&H, &X) };
    assert_eq!(got, Y);
}

/// Spec property: GHASH(H, 0) = 0 (multiplication by zero).
#[test]
fn ghash_zero_x() {
    assert_eq!(ghash_mul_software(&H, &[0u8; 16]), [0u8; 16]);
    assert_eq!(gmcrypto_simd::ghash_mul(&H, &[0u8; 16]), [0u8; 16]);
}

/// Spec property: GHASH(0, X) = 0 (multiplication by zero in H).
#[test]
fn ghash_zero_h() {
    assert_eq!(ghash_mul_software(&[0u8; 16], &X), [0u8; 16]);
    assert_eq!(gmcrypto_simd::ghash_mul(&[0u8; 16], &X), [0u8; 16]);
}

/// The reduction polynomial `R = 0xE1 || 0^120` raised to the 128th
/// power equals 1 in GF(2^128) (a · a^(2^n - 1) = 1 for any non-zero a;
/// the identity element in GHASH-natural bit order is `0x80 || 0^120`).
///
/// This is a structural identity check: `e · X = X` where `e` is the
/// multiplicative identity.
#[test]
fn ghash_identity_element() {
    // In NIST GHASH bit order, the polynomial `1` (just x^0) has its
    // coefficient bit at position 0 of the integer-of-coefficients,
    // which is the leftmost (most-significant) bit of byte 0 — that's
    // `0x80` as the first byte.
    let one: [u8; 16] = [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(ghash_mul_software(&one, &X), X);
    assert_eq!(ghash_mul_software(&one, &H), H);
    assert_eq!(ghash_mul_software(&X, &one), X);
}
