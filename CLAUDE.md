# CLAUDE.md

Pure-Rust SM2/SM3/SM4 SDK. Three-crate workspace, lockstep version, path-deps
pinned **exactly** (`=X.Y.Z`); publish order **simd → core → c**:

- `crates/gmcrypto-core/` — `no_std` crypto core (default-member)
- `crates/gmcrypto-c/` — FFI shim (cdylib + staticlib + cbindgen header)
- `crates/gmcrypto-simd/` — SIMD backend (rlib-only; opt-in via core's
  `sm4-bitsliced-simd` or `sm4-aead`)

Read `README.md`, `SECURITY.md`, `CONTRIBUTING.md` for the user-facing posture.
This file is the constraints an agent will violate by default.
Cycle history: `docs/version-history.md` (do not re-add it here).
Dudect gates: thresholds in `.github/workflows/dudect-*.yml` (inline Python),
target definitions in `crates/gmcrypto-core/benches/timing_leaks.rs`, demotion
record in `docs/v0.5-dudect-recalibration.md`.

Keep this file to facts every session needs. Test for new prose: *would an
agent that never reads it break something?* If not, it is history — file it.

## Release state

| | |
|---|---|
| Workspace version | `1.12.0` (sibling pins `=1.12.0`) — **prepped, not published**: publish simd → core → c from `9ccb262` is the maintainer's call. Gate #1 (`docs/ECOSYSTEM.md` §8) is **done** — PASS against `9ccb262`, `docs/v1.12.0-gate1-evidence.md`; it is owed again only if a PR touches `crates/` or `Cargo.toml` first. A new minor does not always mean crates.io (see Workflow) |
| Live on crates.io | **`1.11.2`** — all three crates, 2026-08-23 from `0de98e2` (tag `v1.11.2`, ED25519-verified). Previous: `1.11.1` 2026-08-22 from `26a49c3` |
| 1.11.2 patch | Presentation only (no non-comment `.rs` line changed since 1.11.1), because crates.io metadata and docs.rs renders are baked into a *published version*: docs.rs feature badges (`#![cfg_attr(docsrs, feature(doc_cfg))]` + `rustdoc-args`), a per-crate `gmcrypto-simd` README (it was rendering the workspace one while outranking `gmcrypto-core` in a crates.io `sm4` search), a `gmcrypto-core` crate-root landing page plus module pages for `sm2`/`sm3`/`kdf`/`asn1`, a README rewritten as a landing page (code at line 17, not 166), crate docs stripped of internal cycle tags, every doctest on `?`, and keyword/description/`homepage` metadata. All six §13 post-publish checks verified on the live pages 2026-08-23. Runbook: `docs/v1.11.2-release-review.md` |
| Dudect runner pool | Hosted `ubuntu-24.04` is heterogeneous (EPYC 7763 / 9V74 / 9V45 / Xeon 8573C / 6973P-C) and composite-window targets read materially higher on some SKUs. Both workflows print `RUNNER-CPU:` beside the verdicts since #172 — **read it before calling a red slot noise.** `ct_sm4_cbc_decrypt_fanout` no-change medians reached 0.2904 on 9V74 (three false reds), so since 2026-09-01 its bound is **0.55 on EPYC 9V74 only** (a `SKU-GATE:` line marks each application), 0.20 everywhere else incl. unknown SKUs (`docs/v0.5-dudect-recalibration.md`, 2026-09-01) |
| crates.io skips | `1.10.0` (non-publishing assurance) and **`1.9.1`** (licence-text patch superseded by 1.11.0). Record: `docs/v1.9.1-release-review.md`. **1.11.0 is the first published release carrying licence text**; 1.9.0 and earlier stay without it |
| Runbook / gate | v1.12: sequence in `docs/v1.12-scope.md` §7; `docs/v1.12.0-gate1-evidence.md` (PASS against `9ccb262`, 2026-09-02); no release-review runbook. Previous: `docs/v1.11.2-release-review.md`, `docs/v1.11.2-gate1-evidence.md` (PASS ×3); `docs/v1.11.1-release-review.md`, `docs/v1.11.1-gate1-evidence.md` (PASS) |

`cargo publish` and the SSH-signed tag are the **maintainer's authenticated
call** — the agent path is branch + PR. The 1.11.0 publish was a recorded
one-off delegation, not a standing grant.

When handing a maintainer a publish command, put the `cd` **inside** the code
block (the app Run button uses the current directory). For `git tag`, **name
the SHA** — `HEAD` may have moved.

### v1.12 — the current release

`sm4::Sm4CcmEncryptor` / `sm4::Sm4CcmDecryptor` (`sm4::ccm_streaming`), behind
the **existing** `sm4-aead` flag — no new feature, no new dep, no C ABI change.
Default build byte-identical. Scope: `docs/v1.12-scope.md`.

Load-bearing, and easy to "fix" wrongly:

- **The encryptor is length-committed by design.** `new` takes `plaintext_len`
  because CCM's `B0` encodes it; that commitment is what makes `O(chunk)`
  streaming possible. An over-feeding `update` emits nothing and poisons;
  `finalize` is `None` on poison **or under-feed** (stricter than
  `Sm4GcmEncryptor` — a partial stream is never tag-authenticated). Don't relax
  either.
- **The decryptor is a pure delegator** over `mode_ccm::decrypt_with_cipher`
  (buffer, latch at `payload_ceiling(q)`, gate `tag.len()`, delegate). That
  thinness is why v1.12 adds **no dudect target**; it is guarded by
  `fuzz_sm4_ccm_streaming_decrypt`. Any cryptographic work inside it (a
  length-declared decryptor, incremental CBC-MAC, CTR before finalize) voids
  the argument and reopens dudect.
- **CCM's counter is `mode_ccm::counter_block`** (`q`-byte big-endian field,
  `q = 15 − nonce.len()`), shared by single-shot and streaming. Never GCM's
  `inc32` — even the 12-byte nonce is `q = 3`.
- Helpers promoted for `ccm_streaming` are `pub(super)` (the `mode_gcm`
  precedent), never `pub` / `pub(crate)`.
- Terminology: encryptor "length-committed streaming"; decryptor
  "incremental-input buffered" — never "streaming".

FFI projection is the v1.13 candidate (v0.9 → v0.10 cadence); the
`Sm4GcmEncryptor` / `GhashAcc` zeroize follow-up is recorded in the scope §6.
The v1.11 `aead-traits` constraints (implement `AeadInOut`, never `Aead`; both
types thin over `mode_gcm`/`mode_ccm`; no XTS fit) still hold — see
`docs/version-history.md`.

## Open backlog

- Still open: AVX-512 `sbox_x64`, streaming-CCM FFI (v1.13 candidate; Rust types landed v1.12), **F21** `ct_sm4_cbc_unpad`
  (v1.10 attempted; composite window is blind — landing it would gate something
  that cannot fail). Record: `docs/v1.10-scope.md` Q10.9.
- **F16 closed** in v1.10 (`interop-gmssl` in `ci.yml`). Pre-1.0 §3.A
  crypto-bigint exposure resolved in v0.22.
- `noise_twin_class_split` is required non-blocking telemetry, **not** a
  relative gate until hosted-runner calibration + injected-leak controls pass.

## Hard constraints (non-negotiable)

- `unsafe_code = "forbid"` on `gmcrypto-core`. Don't add `unsafe`.
  Exceptions (`unsafe_code = "warn"`, `// SAFETY:` on every block):
  `gmcrypto-c` (raw-pointer FFI) and `gmcrypto-simd` (`core::arch` +
  `#[target_feature]` on MSRV 1.85).
- `#![no_std]` + `alloc` only in `crates/gmcrypto-core/src/`. No `std::` paths.
  No generic `std` feature (removed v0.5). A future file helper would be named
  like `std-file-io`. `gmcrypto-c` is `std`-OK.
- **Constant-time on secrets.** Never `==` / `if` / Rust `bool` on a
  secret-derived value. Use `subtle::{Choice, ConditionallySelectable,
  ConstantTimeEq, ConstantTimeLess, CtOption}`. SM2 sign retry is fixed `K=2`.
- **Failure-mode invariant.** `verify_with_id` returns `bool`. Every fallible
  `Result` uses `gmcrypto_core::Error` with a single `Failed` variant (module
  aliases point at the same type). DER decode returns `Option`. PRs that
  distinguish failure modes are rejected — see `SECURITY.md`.
- `Cargo.lock` is gitignored (lib-crate). Don't `git add` it. For `cargo deny`,
  `cargo generate-lockfile` first. Anchor is `/Cargo.lock` (root only) so
  `fuzz/Cargo.lock` stays committed.
- MSRV **1.85**, edition **2024**. Don't use `Integer::is_multiple_of` (1.87).
- `sign_raw_with_id` is `#[doc(hidden)] pub` for dudect only — **not SemVer**.
  Don't expand or publicly expose it.

## Commands

Not `cargo test --all-targets` (runs benches; CI 15-min timeout). `cargo build
--all-targets` is fine. Each opt-in feature gets its **own** clippy pass.
`rustcrypto_aead_traits` is `required-features`-gated — `cargo test --workspace`
never builds it.

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features digest-traits,cipher-traits --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features sm4-bitsliced --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features sm4-aead --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features sm4-xts --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features sm2-key-exchange,crypto-bigint-scalar --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features x509 --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features tlcp --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features tlcp,x509 --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features aead-traits --all-targets -- -D warnings
cargo test -p gmcrypto-core --features aead-traits

cargo deny --exclude-dev check
cargo deny --features gmcrypto-core/digest-traits,gmcrypto-core/cipher-traits,gmcrypto-core/sm4-bitsliced,gmcrypto-core/sm4-bitsliced-simd,gmcrypto-core/sm4-aead,gmcrypto-core/sm4-xts,gmcrypto-core/crypto-bigint-scalar,gmcrypto-core/sm2-key-exchange,gmcrypto-core/x509,gmcrypto-core/tlcp,gmcrypto-core/aead-traits --exclude-dev check

cargo +1.85 build -p gmcrypto-core
cargo +1.85 build -p gmcrypto-core --features digest-traits,cipher-traits,sm4-bitsliced,sm4-bitsliced-simd,sm4-aead,sm4-xts,crypto-bigint-scalar,sm2-key-exchange,x509,tlcp,aead-traits
cargo build -p gmcrypto-core --no-default-features

# wasm32: caller-supplied RNG; these features are pure-core/no_std.
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --no-default-features
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --no-default-features --features sm4-xts,sm2-key-exchange,x509,tlcp,aead-traits
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --no-default-features --features sm4-bitsliced-simd
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --no-default-features --features sm4-aead,sm4-bitsliced-simd

# C ABI: AEAD/XTS FFI is always-on (no --features). regen-header must not drift.
cargo build -p gmcrypto-c --release
cargo build -p gmcrypto-c --features regen-header
git diff --exit-code crates/gmcrypto-c/include/gmcrypto.h
cargo test -p gmcrypto-c
cargo clippy -p gmcrypto-c --all-targets -- -D warnings

# Dudect. Bench needs crypto-bigint-scalar. Gate |tau| (not |t|).
# 4th matrix slot carries AEAD+XTS+KX. Pin: ubuntu-24.04 + rustc 1.95.0.
DUDECT_SAMPLES=10000 cargo bench --bench timing_leaks --features crypto-bigint-scalar
DUDECT_SAMPLES=10000 cargo bench --bench timing_leaks --features sm2-key-exchange,sm4-xts,sm4-aead,sm4-bitsliced-simd,crypto-bigint-scalar

# gmssl interop (pin DEFAULT_GMSSL_VERSION; mismatch gates, oracle infra does not).
GMCRYPTO_GMSSL=1 cargo test --test interop_gmssl
GMCRYPTO_GMSSL=1 cargo test --test interop_gmssl --features sm4-aead

# Fuzz: separate workspace (parent exclude=["fuzz"]). Nightly. Run from repo root.
# cargo fuzz run WRITES into the FIRST dir — corpus (gitignored) first, seeds second.
cargo +nightly fuzz build
cargo +nightly fuzz build --features simd   # second profile = sm4-bitsliced-simd
cargo +nightly fuzz run fuzz_pem fuzz/corpus/fuzz_pem fuzz/seeds/fuzz_pem -- \
  -max_len=16384 -rss_limit_mb=2048 -timeout=25 -max_total_time=60

# docs.rs render (feature badges). Nightly-only: `doc_cfg` is unstable.
# NEVER add --cfg docsrs to api-stability.yml's stable cargo-doc job.
cargo +nightly rustdoc -p gmcrypto-core --all-features -- --cfg docsrs
grep -c 'stab portability' target/doc/gmcrypto_core/index.html

python3 .github/scripts/check_disclosure_boundary.py --self-test
python3 .github/scripts/check_disclosure_boundary.py --worktree
python3 .github/scripts/check_disclosure_boundary.py --range origin/main..HEAD
# P2 lines are advisory (pre-existing gate-evidence docs trip ~9); only P1 blocks.
# Never edit committed evidence docs to silence P2s.
```

## Architecture

```
crates/gmcrypto-core/   no_std primitives (sm2/sm3/sm4, asn1, pkcs8, opt-in
                        x509/tlcp/aead-traits). benches/timing_leaks.rs = dudect
crates/gmcrypto-c/      C ABI; committed include/gmcrypto.h; tests/c_smoke.rs
crates/gmcrypto-simd/   AVX2/NEON + GHASH; unsafe quarantined here
fuzz/                   own workspace; 33 [[bin]]s; seeds committed, corpus not
.github/workflows/      ci / dudect-pr / dudect-nightly / fuzz-* / api-stability
                        / gitleaks / disclosure-boundary
docs/                   scope + version-history + api-baseline; not session scratch
```

`getrandom` is a direct workspace dep (`sys_rng`). `spin` (`once`) is the
no_std comb-table lazy init — not `LazyLock`/`OnceLock` (both `std`).

## Workflow

- Agent path: **branch + PR**. Direct `main` only for trivial time-sensitive
  fixes. WIP skip: `[skip ci]` in the **PR title**.
- CI: five `ci.yml` jobs on `macos-14`; `simd-x86` on `ubuntu-latest`;
  `interop-gmssl` on `ubuntu-24.04`. **Dudect stays on `ubuntu-24.04`** —
  moving it invalidates `|tau|` calibration. No self-hosted runner (RCE on a
  public repo).
- Tags: SSH-signed (`gpg.format = ssh`). Verify `git tag -v vX.Y.Z`. Default
  `git tag` sort is lexicographic (`v1.11.0` < `v1.2.0`) — use
  `--sort=-creatordate` / `--sort=-v:refname` or an exact-name ls-remote.
- Publish (maintainer): simd → core → c; `cd` inside the command; tag a SHA.
- A new minor does **not** always mean crates.io (v0.14 / v1.10 were
  assurance cycles). Don't bump version or publish for a no-crate-change cycle.

## Don't

- Don't add a `Cargo.toml` `authors` field.
- Don't commit session working documents into `docs/` (plans, runbooks, scratch
  with paths/tracker IDs). Working notes live **outside** the repo. Policy:
  `docs/disclosure-boundary.md`.
- Don't cite an absolute local path as KAT/evidence provenance.
- Don't restate the private sibling's file layout in `docs/ECOSYSTEM.md`
  (obligations only; D1). Don't "restore consistency" by copying private
  commands into the charter.
- Don't add per-version scope sections or verbose history rows to `README.md`.
  Per-release narrative → `CHANGELOG.md` + `docs/vX.Y-scope.md` only. README
  is the crates.io landing page.
- Don't grow per-cycle narrative back into `CLAUDE.md`. Prepend history to
  `docs/version-history.md`. Touch this file only where a **live** constraint
  moved (release table, current-cycle subsection **replace** not append,
  commands, Don't/gotcha). `**Earlier — vX.Y —**` does not belong here.
- Don't reduce the SM2 retry-loop iteration count or short-circuit on first
  valid candidate (fixed-K masked-select).
- Don't reference any external "Java prototype" / `gm-crypto-lite-java` repo.
- Don't replace the default SM4 linear-scan S-box with a LUT. `sm4-bitsliced`
  is opt-in, table-less, byte-identical (`bitsliced_matches_table`). Packed
  SIMD lives in `gmcrypto-simd` (`sm4-bitsliced-simd`), not by widening
  `sm4-bitsliced`.
- Don't expose bitsliced helpers (`gf_mul`, `gf_inv`, `affine_a`) publicly.
- Don't generate the SM4-CBC IV inside `mode_cbc::encrypt` (caller-supplied,
  unpredictable).
- Don't make `mode_cbc::decrypt` distinguish failure modes (single `None`).
- Don't add an iteration-count default to `pbkdf2_hmac_sm3`.
- Don't make `pbkdf2_hmac_sm3` allocate the output buffer (caller `&mut [u8]`).
- Don't remove single-shot `hmac_sm3` (streaming `HmacSm3` exists alongside).
- Don't ship `encode_c1c2c3_legacy` (legacy `C1||C2||C3` is decrypt-only).
- Don't change `mul_g`'s public signature (`pub fn mul_g(k: &Fn) -> ProjectivePoint`).
- Don't drop `spin::Once` for "just unsafe and faster" comb-table init.
- Don't make `sm2::decrypt` distinguish failure modes (single `Failed`).
- Don't drop the `point_on_curve` check on `C1` in `sm2::decrypt`.
- Don't expose SM2 `kdf` or `point_on_curve` in the public API. Top-level
  `kdf.rs` is PBKDF2.
- Don't make `pkcs8::decrypt` distinguish wrong-password / malformed-PEM /
  bad-inner (single `Failed`).
- `Sm2PrivateKey::to_bytes_be` returns plaintext secret bytes — **callers
  zeroize** the `[u8; 32]`.
- Don't rename FFI `gmcrypto_sm2_privkey_to_sec1_be` (Rust method is `to_bytes_be`).
- Don't widen `gmcrypto-c` `unsafe_code` from `warn` to `allow`; don't remove
  `// SAFETY:` on any FFI `unsafe` block. Don't relax core's `forbid`.
- Don't add SIMD intrinsics to `gmcrypto-core` — route via `gmcrypto-simd`.
- Don't promote `gmcrypto-simd` from rlib to cdylib/staticlib (`gmcrypto-c`
  is the only C ABI).
- Don't point `gmcrypto-simd`'s `readme` back at `../../README.md` (v1.11.2 gave
  it its own — it outranks `gmcrypto-core` in a crates.io `sm4` search, so its
  page has to say it is an internal backend). Don't add `all-features = true` to
  `gmcrypto-c`'s docs.rs metadata: it would switch on `regen-header` and run
  cbindgen in the docs build.
- Don't widen the `gmcrypto-simd` public API (no raw pointers / extern "C"
  across that boundary).
- Don't add a `cpufeatures` check inside an inner SM4 loop in `gmcrypto-core`
  (cached in `gmcrypto-simd::detect`). Don't pull `cpufeatures` into core.
- Don't make any C ABI entry distinguish failure modes (`GMCRYPTO_FAILED` only).
- Don't add `log`/`tracing`/`defmt` (or any logging/diagnostic output) to the
  shipped crates — the core never logs (SECURITY.md "Logging & observability");
  dev observability lives in tests/benches/workflows only.
- Don't invent a second RNG-callback shape; `CallbackRng` already covers KX /
  record. Don't pull `getrandom`'s `wasm_js` into core's default dep graph
  (wasm callers enable it in *their* `Cargo.toml`).
- Don't implement SM4-XTS per **IEEE 1619**. Target **GB/T 17964-2021**
  (`xts_standard=GB`): `mul_alpha` is bit-reflected (right-shift, `0xE1` into
  byte 0), not IEEE `<<1`/`0x87`.
- Don't branch on the XTS tweak in `mul_alpha` (masked XOR, never `if`).
- Don't add `gmcrypto-simd` (or any dep) to `sm4-xts` (`sm4-xts = []`).
- Don't relax `Key1 == Key2 → None` in `mode_xts` (CT compare; outcome gates).
- Don't let the XTS API generate or reuse tweaks; XTS is confidentiality-only
  (never imply it authenticates).
- XTS sectors: tweak is LE-128 of the sector number, not raw bytes; helper is
  in-place; pre-flight validation so `buf` is untouched on `None`. FFI takes
  `uint64_t` start_sector. **Copy the 32-byte key** into `[u8;32]` before
  reconstructing `&mut buf` (key/buf overlap = `&`/`&mut` UB).
- Don't forget `MATRIX_FEATURES` on the dudect **Parse and gate** step (`env`
  is step-scoped) or feature-conditional `|tau|` gates silently never fire.
- Don't bump dudect `dtolnay/rust-toolchain@1.95.0` or `runs-on: ubuntu-24.04`
  casually (reviewed re-baseline + `docs/v0.5-dudect-recalibration.md`).
- Don't move the dudect multi-run median into `timing_leaks.rs` (loop + median
  live in workflow YAML + inline Python). `required_low`/sentinel gate the
  **median**; `negative_control` gates the **min**; required target measured
  `< N` runs fails (completeness).
- Don't re-promote `ct_fn_invert`/`ct_fp_invert` to `|tau|<=0.20` because a
  calibration looks quiet (telemetry / nightly sentinel `@0.55`). Same for
  `ct_sign_k_class` and `ct_hmac_sm3` (class-split image noise; HMAC has no
  non-composite backstop). `negative_control` must fire every run (`|tau|>1.0`,
  gated on the **min**).
- Don't re-add the v0.19 fix-vs-fix relative gate (falsified). Don't turn
  `noise_twin_class_split` into a relative gate until calibration +
  injected-leak controls pass. See `docs/v0.5-dudect-recalibration.md`.
- Dudect `rust-cache` `shared-key` is `strategy.job-index`, **not**
  `${{ matrix.features }}` (commas break the cache key).
- `Sm4GcmDecryptor` is commit-on-verify and O(message) memory — not a stream.
- TLCP `deprotect_*`: length is computed internally — **never** a deprotect
  parameter (secret post-strip length).
- `verify_chain` / `verify_pair` are structural trust, **not** endpoint auth.
- Don't fold `rustcrypto_aead_traits` into `rustcrypto_traits.rs` (would
  silently unwire that CI leg).
- Fuzz `FUZZ_TARGETS` in `fuzz-nightly.yml` must name every `fuzz/Cargo.toml`
  `[[bin]]`; every target needs a `fuzz/seeds/<target>/` dir. A target that
  touches SM4 also goes in `FUZZ_SIMD_TARGETS` (the `fuzz-simd` job re-sweeps
  it under the fuzz crate's opt-in `simd` feature — don't make that feature
  always-on; additive features would un-fuzz the portable S-box). Don't add
  `fuzz-build.yml` to branch protection while it keeps a `paths:` filter.
- GCM decryptor / TLCP CBC deprotect / X.509 parse: public inputs or already
  covered by existing dudect targets — don't add a target "because the cycle
  touched crypto" without a secret-dependent window.

## Agent gotchas

- **New opt-in feature → seven places; two fail late:** `Cargo.toml` (dep +
  feature), `deny.toml`, `ci.yml` (test / clippy / MSRV / wasm32),
  **`api-stability.yml` cargo-doc feature list** (missing = never doc-checked;
  intra-doc links to cfg-gated items from always-compiled docs become
  `-D warnings` failures — use plain code spans), and a `[[test]]` with
  `required-features` needs its **own** ci.yml leg (`cargo test --workspace`
  will not run it).
- Fuzz crate is a **separate workspace**. `cargo fmt --all` / `clippy
  --workspace` / `test --workspace` do **not** touch it. Fmt:
  `cargo fmt --manifest-path fuzz/Cargo.toml --all`.
- SM4 fuzz seed layouts are pinned to `arbitrary` 1.4.2 front-consuming order
  (`fuzz/Cargo.lock`). Bumping `arbitrary` ⇒ re-verify + regenerate those seeds.
- Workspace version is `[workspace.package].version`; crates inherit
  `version.workspace = true`.
- Integration-test scratch: `env!("CARGO_TARGET_TMPDIR")` (no `tempfile` dep).
- `gmssl sm2keygen -out priv.pem` also prints SPKI to stdout — use `-pubout`.
  `gmssl sm2encrypt` emits GM/T 0009 DER only (no `-binary` in 3.1.1).
- `cargo fmt --all` invalidates the Edit tool's file-state cache — re-Read
  before further edits.
- Codex review prompts ~500 words or they hang; don't paste full files.
- Stacked PRs: merge parents **without** `--delete-branch` or GitHub **closes**
  the child and refuses reopen/retarget. After squash, rebase the child
  `--onto main`. CI on non-`main` bases: `gh workflow run ci.yml --ref <branch>`.
- `pub(crate) const` inside `pub(crate) mod` trips clippy::pub-in-priv — use
  `pub` on inner items.
- `dtolnay/rust-toolchain@master` + `targets:` is flaky; pair with explicit
  `rustup target add wasm32-unknown-unknown --toolchain ${MSRV}`.
- RustCrypto 0.11/0.5: inherent vs trait `finalize`/`encrypt_block` — use UFCS.
  HMAC via `<HmacSm3 as digest::KeyInit>::new_from_slice` (`Mac` no longer
  carries `KeyInit`).
- docs.rs feature badges come from `#![cfg_attr(docsrs, feature(doc_cfg))]` in
  core's `lib.rs`, switched on by `rustdoc-args = ["--cfg", "docsrs"]`. It is
  **inert on stable**, which is what keeps `api-stability.yml`'s `-D warnings`
  `cargo doc` job green — adding `--cfg docsrs` there would make `#![feature]`
  fail to compile. `doc_auto_cfg` was **removed in 1.92** and merged into
  `doc_cfg`; under the merged feature auto-labelling needs no per-item
  `doc(cfg(...))`. Still unstable: a malformed render surfaces only on docs.rs
  after publish, so run the nightly render above before cutting.
- cbindgen 0.27 doesn't recognize `#[unsafe(no_mangle)]` — pin **0.29+**.
- CI `cargo deny`: `taiki-e/install-action@v2` with `cargo-deny@0.20.2` — don't
  switch to `cargo install --locked cargo-deny`.
