---
paths:
  - "fuzz/**"
  - ".github/workflows/fuzz-*.yml"
---

# Fuzz workspace

`fuzz/` is its **own** workspace (parent `exclude = ["fuzz"]`), nightly-only,
run from the repo root. `cargo fmt --all` / `clippy --workspace` /
`test --workspace` do **not** touch it: `cargo fmt --manifest-path fuzz/Cargo.toml --all`.
`fuzz/Cargo.lock` stays committed (the root `Cargo.lock` is the only
gitignored one).

```bash
cargo +nightly fuzz build
cargo +nightly fuzz build --features simd   # second profile = sm4-bitsliced-simd
cargo +nightly fuzz run fuzz_pem fuzz/corpus/fuzz_pem fuzz/seeds/fuzz_pem -- \
  -max_len=16384 -rss_limit_mb=2048 -timeout=25 -max_total_time=60
```

`cargo fuzz run` **writes** into the first directory: corpus (gitignored)
first, seeds second.

- `FUZZ_TARGETS` in `fuzz-nightly.yml` must name every `fuzz/Cargo.toml`
  `[[bin]]`; every target needs a `fuzz/seeds/<target>/` dir. A target that
  touches SM4 also goes in `FUZZ_SIMD_TARGETS` (the `fuzz-simd` job re-sweeps
  it under the crate's opt-in `simd` feature — don't make that feature
  always-on; additive features would un-fuzz the portable S-box). Update the
  census count in `README.md` / `SECURITY.md` / `fuzz/README.md` when it moves.
- Don't add `fuzz-build.yml` to branch protection while it keeps a `paths:`
  filter.
- SM4 seed layouts are pinned to `arbitrary` 1.4.2 front-consuming order
  (`fuzz/Cargo.lock`). Bumping `arbitrary` ⇒ re-verify + regenerate them.
- `fuzz/Cargo.lock` path-dep entries for the three crates go stale each
  release; refresh with
  `cargo update --manifest-path fuzz/Cargo.toml --offline -p gmcrypto-core -p gmcrypto-simd -p gmcrypto-c`
  in the release-prep PR. A feature task that dirties the lock or reformats an
  untouched target restores it (`git checkout --`), never stages it.
