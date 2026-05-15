//! v0.8 W1 — Cross-validate every GHASH dispatch path against the
//! software reference.
//!
//! Lives as an integration test (rather than a unit test) so it can use
//! `std::eprintln!` to silently skip when the host CPU lacks the
//! relevant hardware feature — the test must remain green on any
//! target the workspace is built for, including non-CLMUL x86_64
//! VMs and aarch64 chips without the AES extension.
//!
//! The software path is the correctness reference; the hardware paths
//! are byte-equivalent or the test fails. Inputs span: random samples,
//! known-good NIST/AES-GCM-derived constants, and structural edge
//! cases (zero, all-ones, single-bit-set across every bit position).

#![allow(unsafe_code, clippy::items_after_statements)]

#[cfg(target_arch = "x86_64")]
use gmcrypto_simd::ghash::ghash_mul_clmul;
#[cfg(target_arch = "aarch64")]
use gmcrypto_simd::ghash::ghash_mul_pmull;
use gmcrypto_simd::ghash::ghash_mul_software;

fn fixed_inputs() -> Vec<([u8; 16], [u8; 16])> {
    let mut cases = vec![
        // NIST AES-GCM Test Case 3: H = AES_128(0^128) for K = 00...
        // commonly cited reference value (only the value of H matters
        // here; we're testing the multiplication primitive only).
        (
            [
                0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
                0x2b, 0x2e,
            ],
            [
                0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
                0xfe, 0x78,
            ],
        ),
        ([0u8; 16], [0u8; 16]),
        ([0xFFu8; 16], [0xFFu8; 16]),
        ([0xFFu8; 16], [0x00u8; 16]),
        ([0x00u8; 16], [0xFFu8; 16]),
        // Single-bit-set inputs across degree 0, 7, 8, 64, 120, 127.
        (
            [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        (
            [0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        (
            [0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        (
            [0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0],
        ),
        (
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80],
        ),
        (
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
        ),
    ];

    // Random-walk samples deterministically seeded so the test is
    // reproducible.
    let mut state: u32 = 0xDEAD_BEEF;
    for _ in 0..64 {
        let mut h = [0u8; 16];
        let mut x = [0u8; 16];
        #[allow(clippy::cast_possible_truncation)]
        for i in 0..16 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            h[i] = (state >> 16) as u8;
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            x[i] = (state >> 16) as u8;
        }
        cases.push((h, x));
    }

    cases
}

#[test]
fn software_self_consistency() {
    // Every input pair must produce a stable output across repeated
    // calls (sanity check that the software path has no hidden state).
    for (h, x) in &fixed_inputs() {
        let a = ghash_mul_software(h, x);
        let b = ghash_mul_software(h, x);
        assert_eq!(
            a, b,
            "software path nondeterminism on h={h:02x?} x={x:02x?}"
        );
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn clmul_matches_software() {
    if !gmcrypto_simd::has_pclmulqdq() {
        eprintln!("skipping: PCLMULQDQ not available on this x86_64 CPU");
        return;
    }
    for (h, x) in &fixed_inputs() {
        let expected = ghash_mul_software(h, x);
        // SAFETY: has_pclmulqdq() returned true, so PCLMULQDQ + SSE2
        // are available on this CPU.
        let got = unsafe { ghash_mul_clmul(h, x) };
        assert_eq!(
            got, expected,
            "CLMUL/software mismatch: h={h:02x?} x={x:02x?}",
        );
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn pmull_matches_software() {
    if !gmcrypto_simd::has_pmull() {
        eprintln!("skipping: PMULL not available on this aarch64 CPU");
        return;
    }
    for (h, x) in &fixed_inputs() {
        let expected = ghash_mul_software(h, x);
        // SAFETY: has_pmull() returned true, so PMULL64 (AES extension)
        // is available on this aarch64 CPU.
        let got = unsafe { ghash_mul_pmull(h, x) };
        assert_eq!(
            got, expected,
            "PMULL/software mismatch: h={h:02x?} x={x:02x?}",
        );
    }
}

/// The public dispatch entry point [`gmcrypto_simd::ghash_mul`] must
/// also agree with the software reference.
#[test]
fn dispatch_matches_software() {
    for (h, x) in &fixed_inputs() {
        let expected = ghash_mul_software(h, x);
        let got = gmcrypto_simd::ghash_mul(h, x);
        assert_eq!(
            got, expected,
            "ghash_mul/software mismatch: h={h:02x?} x={x:02x?}",
        );
    }
}
