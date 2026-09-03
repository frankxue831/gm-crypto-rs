---
paths:
  - "crates/gmcrypto-simd/**"
  - "crates/gmcrypto-core/src/sm4/sbox_bitsliced*.rs"
---

# SIMD backend and the S-box

`gmcrypto-simd` (AVX2 / NEON + GHASH) is where `unsafe` is quarantined:
`unsafe_code = "warn"`, `core::arch` + `#[target_feature]` on MSRV 1.85,
`// SAFETY:` on every block. Reached only through core's opt-in features
`sm4-bitsliced-simd` or `sm4-aead`.

- Don't replace the default SM4 linear-scan S-box with a LUT. `sm4-bitsliced`
  is opt-in, table-less, byte-identical (`bitsliced_matches_table`). Packed
  SIMD lives here, not by widening `sm4-bitsliced`.
- Don't expose the bitsliced helpers (`gf_mul`, `gf_inv`, `affine_a`)
  publicly.
- Don't add SIMD intrinsics to `gmcrypto-core` — route via this crate.
- Don't promote this crate from rlib to cdylib/staticlib (`gmcrypto-c` is the
  only C ABI), and don't widen its public API (no raw pointers / `extern "C"`
  across the boundary).
- CPU detection is cached in `gmcrypto_simd::detect`. Don't add a
  `cpufeatures` check inside an inner SM4 loop in core, and don't pull
  `cpufeatures` into core.
- The crate has its **own** README (v1.11.2): it outranks `gmcrypto-core` in
  a crates.io `sm4` search, so its page has to say it is an internal backend.
  Don't point `readme` back at `../../README.md`.
- AVX-512 `sbox_x64` is open backlog.
