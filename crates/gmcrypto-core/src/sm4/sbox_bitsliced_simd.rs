//! Multi-block SIMD-packed bitsliced SM4 S-box (v0.5 W4) —
//! **phase 1 scaffolding**.
//!
//! Behind the `sm4-bitsliced-simd` feature flag. Stacks on
//! [`sbox_bitsliced`][super::sbox_bitsliced]'s gate-only S-box circuit
//! but processes 8 (AVX2) / 4 (NEON) blocks in parallel.
//!
//! # Staged rollout
//!
//! v0.5 W4 lands in three PRs (v0.5 release notes will list them
//! together as the W4 milestone):
//!
//! - **Phase 1** (this commit) — feature-flag scaffolding. The module
//!   exists with the public-to-crate `sbox` entry point, but it
//!   transparently delegates to the v0.4 single-block bitslice
//!   ([`super::sbox_bitsliced::sbox`]). Byte-identical output;
//!   identical timing profile. Lets dependent code land
//!   (`tau` dispatch in [`super::cipher`], dudect target slot, CI
//!   matrix entry) without waiting on the architecture-specific
//!   intrinsic work. **No SIMD lanes are used in phase 1.**
//! - **Phase 2** (W4-phase-2 PR) — AVX2 8-way bitsliced S-box on
//!   `x86_64` with runtime CPU detection (`is_x86_feature_detected!
//!   ("avx2")`). Uses the `safe_arch` crate to keep
//!   `unsafe_code = "forbid"` on `gmcrypto-core` (per Q5.11 / scope
//!   doc §"Posture"). Silently falls back to phase 1's delegate on
//!   non-AVX2 CPUs (Q5.13).
//! - **Phase 3** (W4-phase-3 PR) — NEON 4-way bitsliced S-box on
//!   `aarch64` (baseline; no runtime check needed). Plus
//!   `Sm4CbcDecryptor` SIMD fanout per Q5.10 — CBC encryption stays
//!   single-block (block-chain serialization defeats lane packing);
//!   CBC decryption fans out to N-block batches under the feature.
//!
//! The feature-flag name is stable across all three phases. Callers
//! that enable `sm4-bitsliced-simd` in v0.5.0 transparently pick up
//! the AVX2 / NEON fast paths as v0.5.x patch releases land — no
//! source change required.
//!
//! # Phase 1 contract
//!
//! - `sbox(x)` is **byte-identical** to [`super::sbox_bitsliced::sbox`]
//!   for every `x ∈ 0..=255` (the exhaustive equivalence test below
//!   asserts this at compile-time wall-clock).
//! - Constant-time-by-construction (delegates to the v0.4 single-block
//!   gate-only circuit; no table lookups, no branches on secret bits).
//! - No SIMD intrinsics — the v0.5 dudect harness target
//!   `ct_sm4_encrypt_block_bitsliced_simd` measures the same gate
//!   sequence as `ct_sm4_encrypt_block_bitsliced`. Both gate at
//!   `|tau| < 0.20` (Q5.14).
//!
//! # Why ship phase 1 separately
//!
//! Three reasons (in priority order):
//!
//! 1. **Reviewability.** AVX2 bit-transposition + 8-way Boyar-Peralta
//!    gate sequence is ~400-800 LOC of architecture-specific
//!    intrinsics. Landing that on top of unsettled scaffolding (cfg
//!    dispatch, feature flag, CI matrix, dudect target) is hard to
//!    review. Phase 1 commits the scaffolding so phase 2's diff is
//!    purely the SIMD body.
//! 2. **Bisectability.** If a phase-2 regression is found in the
//!    field, `git bisect` lands on the SIMD-body commit, not on a
//!    monolithic W4 mega-commit.
//! 3. **`cargo deny` review surface.** Phase 2 adds the `safe_arch`
//!    runtime dep — that's a `cargo deny check` audit-line by itself.
//!    Better separated from the cryptographic-correctness review.

/// SM4 S-box, SIMD-packed bitsliced (phase 1 — transparent delegate to
/// [`super::sbox_bitsliced::sbox`]).
///
/// In phase 1 this function exists so that
/// [`super::cipher::tau`]'s dispatch can refer to a stable
/// path under `cfg(feature = "sm4-bitsliced-simd")` without churning
/// when phase 2 / phase 3 land. Behaviour is **byte-identical** to
/// the v0.4 single-block bitslice; no SIMD lanes are involved.
///
/// Phase 2 will replace the body with an AVX2 8-way bitsliced path
/// (runtime CPU detection; falls back to this delegate on non-AVX2).
/// Phase 3 will add a NEON 4-way path. The signature stays the same.
//
// `const fn` in phase 1 (pure delegate to a `const fn`). Phase 2's
// AVX2 body cannot be `const fn` (runtime feature detection); the
// signature drops `const` then — non-breaking, the callsites are
// internal.
#[inline]
#[must_use]
pub const fn sbox(x: u8) -> u8 {
    // Phase 1: pure delegate. The point of this module in phase 1 is
    // to anchor the cfg-dispatch path; the gate sequence is the
    // v0.4 single-block bitslice.
    super::sbox_bitsliced::sbox(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustive equivalence test — every input byte runs through
    /// both the SIMD module's `sbox` and the v0.4 single-block
    /// bitslice. Phase 1 ensures the byte-identical contract is
    /// asserted before phase 2 swaps in the AVX2 body.
    ///
    /// On phase 2 / phase 3 this test becomes the lane-correctness
    /// gate: each SIMD lane MUST produce the same byte as the
    /// single-block path for the same input.
    #[test]
    fn simd_sbox_matches_single_block() {
        for i in 0..=255u8 {
            assert_eq!(
                sbox(i),
                super::super::sbox_bitsliced::sbox(i),
                "SIMD-packed S-box must match single-block bitslice at byte {i:#04x}",
            );
        }
    }

    /// Cross-check the SIMD-packed S-box against the GB/T 32907-2016
    /// §6.2 published table. Transitive of `simd_sbox_matches_single_block`
    /// (which delegates to single-block, which already cross-checks the
    /// table) — but kept here so the SIMD module's contract is provable
    /// in isolation when phase 2 / phase 3 introduce real SIMD code.
    #[test]
    fn simd_sbox_matches_published_table() {
        for i in 0..=255u8 {
            assert_eq!(
                sbox(i),
                super::super::cipher::S_BOX[i as usize],
                "SIMD-packed S-box must match GB/T 32907-2016 §6.2 at byte {i:#04x}",
            );
        }
    }
}
