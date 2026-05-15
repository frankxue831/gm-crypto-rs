# Contributing to gm-crypto-rs

Thanks for your interest. This is a single-maintainer personal project; review
turnaround is best-effort.

## Reporting bugs

File an issue with:
- Rust toolchain version (`rustc --version`).
- OS / arch.
- Minimal reproducible test case.

## Security issues

See [`SECURITY.md`](SECURITY.md) — use GitHub Security Advisories, not public issues.

## Pull requests

Before opening a PR:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check --exclude-dev
```

If you touched anything in `crates/gmcrypto-core/src/sm2/`,
`crates/gmcrypto-core/src/sm4/`, `hmac.rs`, `kdf.rs`, `pkcs8.rs`, or
`benches/`:

```bash
DUDECT_SAMPLES=10000 cargo bench --bench timing_leaks --features crypto-bigint-scalar
```

Verify:
- `negative_control` reports `|tau| > 1.0` (huge — usually 25+).
- `ct_mul_g`, `ct_mul_var`, `ct_sign` each report `|tau| < 0.20`.
- For SM4 work: `ct_sm4_key_schedule`, `ct_sm4_encrypt_block`,
  `ct_sm4_ctr_encrypt` each `|tau| < 0.20`. Under
  `--features sm4-bitsliced-simd`, also
  `ct_sm4_encrypt_block_bitsliced_simd` and
  `ct_sm4_cbc_decrypt_fanout`.
- For HMAC / PBKDF2 / encrypted-PKCS#8 work: `ct_hmac_sm3` and
  `ct_pkcs8_decrypt` each `|tau| < 0.20`.
- For SM2 envelope encryption work: `ct_sm2_decrypt` `|tau| < 0.20`.
- `ct_sign_k_class`, `ct_fn_invert`, `ct_fp_invert` carry target-
  specific gate policy after the 2026-05-12 recalibration —
  telemetry at the PR-smoke 10K budget. See [`SECURITY.md`](SECURITY.md)
  for the canonical per-target table.

PRs that introduce timing-leak regressions in the dudect harness will be
rejected — investigate the source before pushing back on the threshold.
The harness is the gate.

PRs that distinguish failure modes in the verify / DER-decode paths (i.e.
anything that makes errors more "helpful") will be rejected on sight. See
[`SECURITY.md`](SECURITY.md)'s failure-mode-invariant section.

## Coding conventions

- `unsafe_code = "forbid"` workspace-wide.
- All public items get rustdoc.
- Constant-time primitives go through `subtle`, not Rust booleans.
- `#![no_std]` is the baseline; `alloc` is OK; nothing else from `std` without
  a feature flag.
- KAT-driven tests for cryptographic primitives. New algorithms need a
  source-cited reference vector before merge.
