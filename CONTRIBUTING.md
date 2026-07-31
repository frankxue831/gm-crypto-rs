# Contributing to gm-crypto-rs

Thanks for your interest. This is a single-maintainer personal project; review
turnaround is best-effort.

Most of this document is about the constraints on **secret-dependent
cryptographic code**, which are strict on purpose. If you are looking for a
first contribution, start with the next section instead — plenty of useful
work here never touches a secret.

## Good first contributions

Issues labelled [`good first issue`](https://github.com/frankxue831/gm-crypto-rs/labels/good%20first%20issue)
are scoped to avoid the constant-time discipline entirely. Areas that are
safe to touch without triggering the dudect checklist below:

- **Documentation** — `README.md`, `fuzz/README.md`, the `docs/` index, or
  rustdoc on any public item.
- **C examples** — `crates/gmcrypto-c/examples/`. These are doc-only; CI does
  not build them, but they should compile and run before you send them.
- **Known-answer tests** for primitives that already exist, provided you cite
  the published source of the vector (see "Coding conventions").
- **Fuzz targets** for parsing / decoding surfaces — see below.

What to avoid as a first PR: anything under `src/sm2/`, `src/sm4/`, or
`src/tlcp/` that runs on secret material, and anything that changes an error
type. Those are not off-limits, but they carry the review burden described
below.

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

If you changed anything that affects **wire output** (a cipher mode, a codec,
a signature or ciphertext encoding), also run the gmssl cross-validation
suite. It is skipped unless `GMCRYPTO_GMSSL=1` is set — and it *passes* while
skipping, so an unset variable looks identical to a green run:

```bash
GMCRYPTO_GMSSL=1 cargo test --test interop_gmssl --features sm4-aead   # 13 tests
```

This needs **GmSSL v3.2.0** on your `PATH` (`brew install gmssl` currently
gives you exactly that). The suite pins its oracle version and fails with an
`ORACLE DRIFT` message on any other build, because GmSSL renames subcommands
and narrows accepted input ranges between releases. You do not have to run
this: CI's `interop-gmssl` job runs the same suite against a pinned
from-source build.

If you touched anything in `crates/gmcrypto-core/src/sm2/`,
`crates/gmcrypto-core/src/sm4/`, `crates/gmcrypto-core/src/tlcp/`, `sm3.rs`,
`hmac.rs`, `kdf.rs`, `pkcs8.rs`, or `benches/`:

```bash
DUDECT_SAMPLES=10000 cargo bench --bench timing_leaks --features sm4-bitsliced-simd,sm4-aead,sm4-xts,sm2-key-exchange,tlcp,crypto-bigint-scalar
```

That feature string is CI's 4th dudect matrix leg
(`.github/workflows/dudect-pr.yml`) plus `crypto-bigint-scalar` for the bench
itself. Run it as written — under `--features crypto-bigint-scalar` alone,
**8 of the 20 `ct_*` targets compile out entirely** and you will see a green
run that proved nothing about them.

Verify:
- `negative_control` reports `|tau| > 1.0` (huge — usually 25+). It MUST fire
  on every run; that is what proves the harness is wired up.
- `ct_mul_g`, `ct_mul_var`, `ct_sign` each report `|tau| < 0.20`.
- For SM4 work: `ct_sm4_key_schedule`, `ct_sm4_encrypt_block`,
  `ct_sm4_ctr_encrypt` each `|tau| < 0.20`. Under
  `--features sm4-bitsliced-simd`, also
  `ct_sm4_encrypt_block_bitsliced_simd` and
  `ct_sm4_cbc_decrypt_fanout`.
- For PBKDF2 / encrypted-PKCS#8 work: `ct_pkcs8_decrypt` `|tau| < 0.20`.
- For SM2 envelope encryption work: `ct_sm2_decrypt` `|tau| < 0.20`.
- For SM4-GCM / SM4-CCM AEAD work (`--features sm4-aead`):
  `ct_sm4_gcm_decrypt`, `ct_sm4_ccm_decrypt`, and
  `ct_sm4_gcm_decrypt_buffered` each `|tau| < 0.20`.
- For SM4-XTS work (`--features sm4-xts`): `ct_sm4_xts_decrypt` `|tau| < 0.20`.
- For SM2 key-exchange work (`--features sm2-key-exchange`):
  `ct_sm2_key_exchange` `|tau| < 0.20`.
- For TLCP record work (`--features tlcp`): `ct_tlcp_cbc_deprotect`
  `|tau| < 0.20` — the Lucky13 residual guard.
- **Four targets do NOT gate at 0.20** and must not be read as failures at the
  PR-smoke budget: `ct_fn_invert` and `ct_fp_invert` (since the 2026-05-12
  runner recalibration), `ct_sign_k_class` (2026-06-07), and `ct_hmac_sm3`
  (2026-06-17). All four are PR telemetry only, with a nightly
  gross-regression sentinel at `|tau| >= 0.55`. `noise_floor_fn_invert` and
  `noise_floor_fp_invert` are always-on telemetry probes that cannot leak by
  construction — they never gate.
  [`SECURITY.md`](SECURITY.md) carries the canonical per-target table; when
  this list and that table disagree, **that table wins** — please fix this one.

PRs that introduce timing-leak regressions in the dudect harness will be
rejected — investigate the source before pushing back on the threshold.
The harness is the gate.

PRs that distinguish failure modes in the verify / DER-decode paths (i.e.
anything that makes errors more "helpful") will be rejected on sight. See
[`SECURITY.md`](SECURITY.md)'s failure-mode-invariant section.

## Adding a fuzz target

The `fuzz/` crate is its **own workspace** (the parent excludes it), so
`cargo fmt --all` / `cargo clippy --workspace` / `cargo test --workspace` do
not reach it. Target it explicitly, and use the nightly toolchain.

A new target needs edits in **three** places, and missing any one of them
fails quietly rather than loudly:

1. A `[[bin]]` entry in `fuzz/Cargo.toml`.
2. The target name added to `FUZZ_TARGETS` in
   `.github/workflows/fuzz-nightly.yml` — that env var is the single source of
   truth for the nightly sweep. A target absent there still *compiles* (the
   PR-time `fuzz-build.yml` builds everything) but is **never actually
   fuzzed**.
3. At least one curated seed under `fuzz/seeds/<target>/`. libFuzzer treats a
   nonexistent corpus directory as a fatal error and exits before running a
   single input, so a missing seed dir would surface as a spurious `CRASH`.
   A preflight step now fails the nightly with an explicit
   `config drift, NOT a crash` message instead — but the fix is still to add
   the seeds.

Run one locally with **corpus first, seeds second** — libFuzzer writes new
units into the first directory, and the committed seeds must stay curated:

```bash
cargo +nightly fuzz run <target> fuzz/corpus/<target> fuzz/seeds/<target> -- \
    -max_len=16384 -rss_limit_mb=2048 -timeout=25 -max_total_time=60
```

## Coding conventions

- `unsafe_code = "forbid"` on `gmcrypto-core` (non-negotiable). The two
  sibling crates are `"warn"` for unavoidable `unsafe`: `gmcrypto-c`
  (raw-pointer FFI primitives) and `gmcrypto-simd` (SIMD intrinsics +
  `#[target_feature]`). Every `unsafe` block in those two carries a
  `// SAFETY:` comment. Don't add `unsafe` to `gmcrypto-core`.
- All public items get rustdoc.
- Constant-time primitives go through `subtle`, not Rust booleans.
- `#![no_std]` is the baseline; `alloc` is OK; nothing else from `std` without
  a feature flag.
- KAT-driven tests for cryptographic primitives. New algorithms need a
  source-cited reference vector before merge.

## License

The project is dual-licensed under [`LICENSE-APACHE`](LICENSE-APACHE) and
[`LICENSE-MIT`](LICENSE-MIT); a consumer may take either.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project by you, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms or
conditions (inbound = outbound).
