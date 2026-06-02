# CI-gate effectiveness review — gm-crypto-rs `1.0.0`

| | |
|---|---|
| **Date** | 2026-06-02 |
| **Commit** | `12e26b4` (`main`, workspace `1.0.0`) |
| **Mission** | Do the existing CI gates effectively protect the project's stated guarantees? Look for bypasses, stale assumptions, missing combinations, flaky gates, unnecessary cost. |
| **Method** | Read-only multi-agent workflow (`ci-gate-effectiveness-review`): 6-lens map → adversarial verify (gap genuine? repo-visible?) → synthesis. 48 agents; 41 findings → 25 confirmed / 14 refuted / 2 uncertain → 12 confirmed + 4 hypotheses + 11 well-protected. **Then independently re-verified the load-bearing line-level claims against `ci.yml`/`deny.toml`/the simd tests + `Error` enum — overriding the workflow in 3 places (see Corrections).** |
| **Scope** | 5 workflows: `ci.yml`, `api-stability.yml`, `dudect-pr.yml`, `dudect-nightly.yml`, `fuzz-nightly.yml` + `deny.toml`. |

**Headline:** crypto-correctness *outputs* and the API/ABI surface are well-gated; the real gaps are **PR-time coverage holes** — the SIMD backend escapes the dudect PR gate, the x86_64 AVX2/CLMUL correctness tests run on no CI host, `sm4-xts` is absent from every per-feature gate, the gmssl byte-identical guarantee runs in no CI job, and the `fuzz/` crate gets no PR-time build.

**This is a static, read-only review of committed config.** No workflow was run; nothing changed.

---

## ▶ ACTION ITEMS (pick up later)

High-value, low-effort CI fixes (none is a code defect):

- [ ] **(High)** Add `crates/gmcrypto-simd/src/**` to `dudect-pr.yml` paths-allowlist (lines 8-14) so SIMD-backend changes trigger the PR timing smoke.
- [ ] **(High)** Decide the gmssl interop story: run it in CI (container/action) **or** explicitly document the 11/11 guarantee as maintainer-verified, not CI-gated (README/SECURITY).
- [ ] **(Med)** Wire `sm4-xts` into every per-feature `ci.yml` gate it's missing from: standalone clippy, wasm build, `cargo-deny` second pass, MSRV opt-in build (commands already documented in CLAUDE.md lines 492/500).
- [ ] **(Med)** Add one ubuntu (x86_64) job running `cargo test -p gmcrypto-simd` (or `--workspace`) so the AVX2/CLMUL lane-equivalence + lane-position + CLMUL-KAT tests actually execute.
- [ ] **(Med)** Add a PR-time `cargo +nightly fuzz build` (build-only) so fuzz targets don't rot until the nightly cron.
- [ ] **(Med)** Add `cargo generate-lockfile` before the first `cargo deny check` (`ci.yml::deny`).
- [ ] **(Low)** Derive `FUZZ_TARGETS` from the file listing (or add a mismatch check) so new targets are auto-swept.

---

## 1 · Confirmed findings (severity-ranked; each cites `workflow.yml::job`)

| Sev | Finding | `workflow::job` | Impact | Recommendation |
|---|---|---|---|---|
| High | **dudect PR gate's paths-allowlist omits `crates/gmcrypto-simd/src/**`** — a timing regression in the SIMD backend (`sbox_x8/x16/x32`, `avx2.rs`, `neon.rs`, `ghash/clmul.rs`, `ghash/pmull.rs`) doesn't trigger the PR smoke test | `dudect-pr.yml::smoke` (paths-allowlist, lines 8-14) | CT regression in the backend ships to `main`; only caught by nightly +≤24h | Add `crates/gmcrypto-simd/src/**` (and `crates/gmcrypto-simd/Cargo.toml`) to the allowlist |
| High | **gmssl 3.1.1 byte-identical interop (11/11) runs in no CI job** — `GMCRYPTO_GMSSL` appears in zero workflows; `tests/interop_gmssl.rs` is never exercised | all workflows (env absent) | The headline "byte-identical / interop 11/11" guarantee is verified only on the maintainer's machine; a wire-encoding regression could merge | Run interop in CI (gmssl container/action) **or** explicitly document it as maintainer-verified, not CI-gated |
| Med | **`sm4-xts` absent from *every* per-feature `ci.yml` gate** — and gets **zero `clippy -D warnings` anywhere** (ci.yml clippy steps omit it; api-stability has no clippy job) | `ci.yml::build` (clippy 148-159, test 115-145), `::wasm32` (318-323), `::deny` (274), `::msrv` (195) | A shipped feature (since v0.12/v0.13) has no dedicated clippy/wasm/deny/MSRV gate; only transitively built+tested via `api-stability.yml::feature-matrix --all-features` + the `docs` job | Add the four documented commands (CLAUDE.md 492/500): standalone `sm4-xts` clippy + wasm build + deny feature + MSRV opt-in build inclusion |
| Med | **x86_64 AVX2/CLMUL correctness tests run on no CI host** *(re-promoted — workflow refuted this unsoundly; see Corrections)* | `ci.yml::build` line 109 `cargo test --workspace` is **macos-14/aarch64-only**; no x86_64 `--workspace`/`-p gmcrypto-simd` job | `gmcrypto-simd`'s exhaustive lane-equivalence + lane-position + CLMUL-KAT tests (incl. `#[cfg(target_arch="x86_64")]` `avx2_*`/`clmul_*` cases) execute nowhere; AVX2 only *compiles* + is exercised indirectly by core KATs | Add one ubuntu (x86_64) job running `cargo test -p gmcrypto-simd` |
| Med | **`fuzz/` (separate workspace) gets no PR-time build** — `cargo {test,clippy,fmt} --workspace` + `cargo-deny` all exclude it; only `fuzz-nightly.yml` (cron/dispatch) touches it | `fuzz-nightly.yml` (no `pull_request` trigger) | A fuzz target that fails to compile after an API reshape (cf. v0.22/v0.23 `decode_sig`/FFI changes) is uncaught until the nightly cron | Add a PR-time `cargo +nightly fuzz build` (build-only, no run) |
| Med | **`cargo-deny` runs without `cargo generate-lockfile`** (Cargo.lock gitignored) | `ci.yml::deny` (262, 274) | Resolves a fresh dep graph each run (non-reproducible); a newly-published advisory/version changes results non-deterministically (deny still runs — resolves in-memory) | Add `cargo generate-lockfile` before the first `cargo deny check` (CLAUDE.md line 470) |
| Med | **Inversion sentinel @0.55 leaves a moderate-leak band** — `ct_fn_invert`/`ct_fp_invert` gate only gross regressions; `[~0.45–0.54]` would pass; PR side is telemetry-only | `dudect-nightly.yml::Parse and gate` (~299-308); `dudect-pr.yml` (telemetry) | A moderate inversion leak evades both gates | Accepted per the documented v0.19-falsification posture; the class-split "noise-twin" (deferred) is the only sound re-promotion path |
| Med | **MSRV job is build-only** (no `cargo test` on 1.85) | `ci.yml::msrv` (192-195) | MSRV behavioral regressions aren't caught until the stable test job | Accepted by design (documented 162-167); optionally `cargo +1.85 test` |
| Med | **`fuzz/` deps (`libfuzzer-sys`, `arbitrary`) unscanned by `cargo-deny`** | `ci.yml::deny` (fuzz/ excluded from the workspace) | Dev-tooling supply chain outside `deny.toml` policy — low risk (unpublished), undocumented | Document the exclusion, or add a `cargo deny` pass over `fuzz/` |
| Low | **`FUZZ_TARGETS` env is hand-maintained** — a new target file isn't auto-swept | `fuzz-nightly.yml` (FUZZ_TARGETS, ~51-56) | A post-1.0 target added without updating the env is silently never fuzzed/covered | Derive from `ls fuzz_targets/*.rs`, or add a mismatch check |

## 2 · Hypotheses (lower confidence / settings-dependent)

| Sev | Finding | `workflow::job` | Why hypothesis |
|---|---|---|---|
| Med | api-stability feature-matrix tests only the two extremes (`--no-default-features` build + `--all-features` test); intermediate/pairwise combos untested *there* | `api-stability.yml::feature-matrix` | Largely **redundant** — `ci.yml::build` runs per-feature + key pair combos; sufficiency depends on which checks are *required* (branch-protection not in repo) |
| High→? | 10K×3 PR vs 100K×5 nightly SNR asymmetry could make the shared `\|tau\|<0.20` gate flaky | `dudect-pr.yml` vs `dudect-nightly.yml` | Empirical claim needing a multi-run distribution study; PR smoke is documented non-authoritative |
| Low | `cargo-fuzz 0.13.1` compiled from source each nightly (no cache) — ~60-90 runner-min/month | `fuzz-nightly.yml::Install pinned cargo-fuzz` | Cost-only; other workflows use `rust-cache`. Add a cache key |
| Low | dudect-nightly matrix leg-cancellation CI-health item | `dudect-nightly.yml` (`cancel-in-progress:false`) | Known/deferred (CLAUDE.md); intentional (don't discard a 100K run); no current breakage |

## 3 · Corrections to the workflow's own output (transparency)

1. **Re-promoted (workflow refuted unsoundly):** "AVX2 x86_64 not tested" was refuted on the grounds that *"`cargo bench` builds all integration tests"* and *"api-stability `--all-features` covers it."* Both wrong: `cargo bench --bench timing_leaks` runs a `gmcrypto-core` **bench**, not `gmcrypto-simd`'s `#[test]`s; and `cargo test -p gmcrypto-core --all-features` does **not** run `gmcrypto-simd`'s own test targets. The dedicated AVX2/CLMUL tests run only via `cargo test --workspace`/`-p gmcrypto-simd`, which exists only on the aarch64 host → they run on no CI host. Confirmed → Medium.
2. **Downgraded + corrected (workflow over-rated HIGH):** "failure-mode invariant unprotected at compile-time" proposed a custom Error-enum-parsing lint. But the **public variant set IS gated**: the enforced `api-stability.yml::public-api` baseline records `pub gmcrypto_core::Error::Failed` (line 280), so adding a public variant = drift = job fails. (`#[non_exhaustive]` means `cargo-semver-checks` alone would *not* catch it — public-api does.) Only the *semantic* oracle-resistance (distinguishing failure modes in control flow without a new variant) is ungated, and that's inherently a review + dudect/fuzz concern, not statically lintable → **Low**, proposed lint largely redundant.
3. **Extended:** the `sm4-xts` gap is broader than the 3 separate mediums the workflow listed — it's absent from per-feature **test** and the **MSRV opt-in build** too, and gets **zero clippy anywhere**. Consolidated into one cluster finding above.

## 4 · Guarantees that ARE well-protected (positive map)

- **Constant-time discipline** (composite targets `ct_mul_g/var`, `ct_sign`, `ct_sm4_*`, `ct_hmac_sm3`, `ct_sm2_decrypt`, `ct_pkcs8_decrypt`) — `dudect-pr.yml::smoke` (10K median @0.20) + `dudect-nightly.yml` (100K) — *modulo* the SIMD-backend PR-trigger gap (High #1).
- **SemVer 1.0 forward contract** — `api-stability.yml::cargo-semver-checks` (enforced, no continue-on-error).
- **Public API drift** (incl. the single `Error::Failed` variant) — `api-stability.yml::public-api` (committed baseline + `git diff --exit-code`, pinned tool+nightly).
- **C ABI + header drift** — `ci.yml::cabi` (65 `c_smoke` tests + cbindgen regen `git diff`).
- **`unsafe_code = forbid`** on `gmcrypto-core` — compile-time enforced by every build job.
- **`no_std` / wasm portability** (default + `sm4-aead`) — `ci.yml::wasm32` + `api-stability.yml::feature-matrix` `--no-default-features`.
- **Supply chain (default + most opt-in features)** — `ci.yml::deny` two-pass — *modulo* the `sm4-xts` + lockfile gaps above.
- **Docs** — `api-stability.yml::docs` (`cargo doc -D warnings`, includes `sm4-xts`).

## 5 · Caveats

- **Read-only static analysis** of committed config — no workflow was run.
- **Settings-dependent items forced to hypothesis:** branch protection / required-status-checks / `paths-ignore` + required-check interaction / stacked-PR-into-non-main behavior / runner availability are **not in the repo** — cannot confirm whether a doc-only PR's skipped `ci.yml` blocks merge, or whether api-stability is a *required* check. These need the GitHub repo settings.
- **"No source-supported gap"** in the scopes covered by the well-protected map — not a claim of perfection, just that no config-level bypass was found there.

---

## Provenance

Generated by a read-only Claude Code dynamic workflow (`ci-gate-effectiveness-review`, run
`wf_ecdeba10-eb9`), with orchestrator re-verification of the line-level claims against `ci.yml`,
`deny.toml`, the `gmcrypto-simd` test cfg-gating, and the `Error` enum. No files edited, nothing
committed/pushed/published/tagged, no CI or settings touched. Working-tree artifact; commit/track at
your discretion (per the branch+PR rule, the agent did not commit it).
