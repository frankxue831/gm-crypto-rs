# gmcrypto-fuzz — cargo-fuzz harness

`cargo-fuzz` (libFuzzer) coverage over the **untrusted-input decode/decrypt
surface** of `gmcrypto-core`. The invariant under test is the project's
failure-mode invariant on adversarial bytes: **every malformed input collapses
to the single safe `None` / `Error::Failed` (or `false`) return — no panic, no
unbounded allocation, no hang.** See `docs/v0.14-scope.md` for the full design.

This crate is its **own** Cargo workspace (note the empty `[workspace]` table in
`Cargo.toml`) and is **excluded** from the published 3-crate workspace. Its
`libfuzzer-sys` / `arbitrary` deps never enter the published dependency graph.
It is **unpublished** and **nightly-only** — MSRV 1.85 does not apply here.

## Prerequisites (one-time)

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --version 0.13.1   # pinned for reproducibility
```

(Apple clang / a system LLVM provides libFuzzer; no extra step on macOS.)

## Run a target

```bash
# From the repo root (the directory that contains this `fuzz/`):
cargo +nightly fuzz run fuzz_pem fuzz/corpus/fuzz_pem fuzz/seeds/fuzz_pem -- \
    -max_len=16384 -rss_limit_mb=2048 -timeout=25 -max_total_time=60
```

- **Dir order matters.** libFuzzer reads *all* listed corpus dirs but writes new
  coverage-increasing inputs only to the **first** one. So `fuzz/corpus/<target>`
  (gitignored, grown) goes first and `fuzz/seeds/<target>` (committed, curated,
  read-only) goes second — that way the curated seeds are never mutated.
- `fuzz/seeds/<target>/` is a **committed** curated set of valid encodings (+ any
  minimized crash regression inputs) that bootstraps coverage. The runtime-grown
  corpus (`fuzz/corpus/`), build output (`fuzz/target/`), and crash repros
  (`fuzz/artifacts/`) are gitignored.
- A crash writes a reproducer to `fuzz/artifacts/<target>/`. Re-run it with:
  ```bash
  cargo +nightly fuzz run fuzz_pem fuzz/artifacts/fuzz_pem/crash-<hash>
  ```
- Minimize a crash before filing/fixing:
  ```bash
  cargo +nightly fuzz tmin fuzz_pem fuzz/artifacts/fuzz_pem/crash-<hash>
  ```
  A minimized crash input is committed under `fuzz/seeds/<target>/` as a
  permanent regression seed.

## Build all targets (no run)

```bash
cargo +nightly fuzz build
```

## Targets

| Target | Entry point under test |
|---|---|
| `fuzz_pem` | `pem::decode` (RFC 7468 armor + base64) |

(W2 adds the wire-format parsers; W3 adds the SM4 decrypts. See
`docs/v0.14-scope.md` Q14.3 for the full 16-target list.)
