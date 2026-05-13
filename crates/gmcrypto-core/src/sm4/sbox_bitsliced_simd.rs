//! Multi-block SIMD-packed bitsliced SM4 S-box (v0.5 W4).
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
//! - **Phase 1** — feature-flag scaffolding. The module existed with
//!   the public-to-crate `sbox` entry point, but it transparently
//!   delegated to the v0.4 single-block bitslice
//!   ([`super::sbox_bitsliced::sbox`]). Byte-identical output;
//!   identical timing profile. Let dependent code land
//!   (`tau` dispatch in [`super::cipher`], dudect target slot, CI
//!   matrix entry) without waiting on the architecture-specific
//!   intrinsic work. No SIMD lanes were used in phase 1.
//! - **Phase 2** (this commit) — AVX2 8-way packed bitsliced S-box
//!   on `x86_64`, with runtime CPU detection and silent fallback
//!   to single-block bitslice on non-AVX2 hosts. The intrinsics
//!   live in the new sibling crate
//!   [`gmcrypto-simd`](https://docs.rs/gmcrypto-simd) with
//!   `unsafe_code = "warn"` (mirroring the
//!   [`gmcrypto-c`](https://docs.rs/gmcrypto-c) FFI-shim
//!   precedent). `gmcrypto-core` itself stays
//!   `unsafe_code = "forbid"` and `no_std`. Runtime detection uses
//!   `cpufeatures` (`RustCrypto`, `no_std`-compatible, cached) — not
//!   the `std`-only `is_x86_feature_detected!` mentioned in the
//!   v0.5 scope doc Q5.11 (see the Q5.11 addendum in
//!   `docs/v0.5-scope.md`).
//! - **Phase 3** (W4-phase-3 PR) — NEON 4-way bitsliced S-box on
//!   `aarch64` (baseline; no runtime check needed). Plus
//!   `Sm4CbcDecryptor` SIMD fanout per Q5.10 — CBC encryption stays
//!   single-block (block-chain serialization defeats lane packing);
//!   CBC decryption fans out to N-block batches under the feature.
//!   Phase 3 is also where the SIMD lanes finally carry real
//!   parallel data; phase 2's per-`tau` call replicates the single
//!   input across 7 wasted lanes.
//!
//! The feature-flag name is stable across all three phases. Callers
//! that enabled `sm4-bitsliced-simd` in v0.5.0 transparently pick up
//! the AVX2 / NEON fast paths as v0.5.x patch releases land — no
//! source change required.
//!
//! # Phase 2 contract
//!
//! - `sbox(x)` is **byte-identical** to
//!   [`super::sbox_bitsliced::sbox`] for every `x ∈ 0..=255`,
//!   regardless of which dispatch path (AVX2 / scalar) the sibling
//!   crate selects. The sibling carries exhaustive lane-equivalence
//!   tests in `crates/gmcrypto-simd/tests/lane_equivalence.rs`
//!   against the published GB/T 32907-2016 §6.2 S-box table.
//! - Constant-time-by-construction. The sibling's AVX2 path uses
//!   `_mm256_*` intrinsics with publicly-fixed loop counts; no
//!   table lookups, no secret-dependent branches. The dudect target
//!   `ct_sm4_encrypt_block_bitsliced_simd` (gate `|tau| < 0.20`,
//!   Q5.14) measures the SIMD path end-to-end under the
//!   `sm4-bitsliced-simd` feature on CI's AVX2-capable
//!   `ubuntu-24.04` runner.
//!
//! # Phase 2 trade-off
//!
//! Per-`tau`-call dispatch into the sibling's 8-way function with
//! the single input replicated across all 8 lanes — 7 wasted lanes.
//! Throughput is no better than the v0.4 single-block bitslice;
//! sometimes slightly worse on AVX2 hosts (the constant SIMD setup
//! cost is paid per round). Phase 3's `Sm4CbcDecryptor::process_chunk`
//! fanout is where the real throughput win lands.
//!
//! The phase 2 PR's value is review surface + correctness gating
//! (lane-equivalence + dudect target measuring the AVX2 path) +
//! scaffolding for phase 3. Do not benchmark v0.5 W4 phase 2 against
//! v0.4 single-block expecting a speedup — there isn't one until
//! phase 3.

/// SM4 S-box, SIMD-packed bitsliced (phase 2 — dispatches into the
/// `gmcrypto-simd` sibling crate's [`sbox_x8`] entry point).
///
/// On `x86_64` hosts with AVX2, the sibling crate runs an 8-way packed
/// bitsliced S-box; on every other host, the sibling falls back to
/// 8 sequential single-block calls. Byte-identical to the v0.4 W3
/// single-block bitslice in every dispatch path.
///
/// # Per-round dispatch cost
///
/// `gmcrypto_simd::sm4::sbox_x8::sbox_x8` does one cached
/// `cpufeatures` check per call (single atomic load + branch).
/// Phase 3 will widen the call site to amortize this over an 8-block
/// batch via `Sm4CbcDecryptor::process_chunk`; for now (phase 2) the
/// per-`tau` cost is accepted.
///
/// [`sbox_x8`]: gmcrypto_simd::sm4::sbox_x8::sbox_x8
#[inline]
#[must_use]
pub fn sbox(x: u8) -> u8 {
    // 7 wasted lanes — phase 2 trade-off. Phase 3's CBC-decrypt
    // fanout will fill all 8 lanes with real data.
    let input = [x; 8];
    gmcrypto_simd::sm4::sbox_x8::sbox_x8(&input)[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Phase 2 contract: dispatch into the sibling crate produces
    /// the same byte as the v0.4 W3 single-block bitslice for every
    /// input. The sibling's own `tests/lane_equivalence.rs` is the
    /// authoritative correctness test; this is the cross-crate
    /// surface check.
    #[test]
    fn simd_sbox_matches_single_block() {
        for i in 0..=255u8 {
            assert_eq!(
                sbox(i),
                super::super::sbox_bitsliced::sbox(i),
                "SIMD-packed dispatch must match single-block bitslice at byte {i:#04x}",
            );
        }
    }

    /// Cross-check the SIMD dispatch against the published
    /// GB/T 32907-2016 §6.2 table. Transitive of
    /// `simd_sbox_matches_single_block` (the single-block bitslice
    /// already cross-checks the table) — but kept here so the SIMD
    /// dispatch's contract is provable in isolation.
    #[test]
    fn simd_sbox_matches_published_table() {
        for i in 0..=255u8 {
            assert_eq!(
                sbox(i),
                super::super::cipher::S_BOX[i as usize],
                "SIMD-packed dispatch must match GB/T 32907-2016 §6.2 at byte {i:#04x}",
            );
        }
    }
}
