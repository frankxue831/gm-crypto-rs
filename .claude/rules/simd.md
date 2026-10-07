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
- GFNI S-box (v1.16, `docs/v1.16-scope.md`) replaced the AVX-512
  `sbox_x64` backlog item: `sbox_x32_gfni`, two GFNI instructions at
  AVX2 width, no core batch change; `sbox_x32` selects it where detected
  (about 10x, record above `sbox_x32`), and `sbox_x4` selects
  `sbox_x4_gfni` (128-bit, about 60x, record above `sbox_x4`). A CPU
  model string does not tell you whether GFNI ran: hosted EPYC 9V74 VMs
  differ in whether they expose `gfni`/`avx512f`; read the job's `lscpu`
  Flags. Its code is behind
  `cfg(gmcrypto_simd_gfni)`, which `build.rs` emits only on rustc >= 1.89
  (GFNI stabilized there); keep every GFNI item behind that cfg and
  `target_arch = "x86_64"`, or the 1.85 MSRV build breaks. The derived
  constants in `sm4/gfni.rs` are checked by a portable test; don't
  hand-edit them. `simd-x86-sde` is the only job guaranteed to run the
  GFNI path.
