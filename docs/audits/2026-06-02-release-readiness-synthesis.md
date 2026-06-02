# Release-readiness synthesis — gm-crypto-rs `1.0.0`

| | |
|---|---|
| **Date** | 2026-06-02 |
| **Commit** | `12e26b4` (`main`, workspace `1.0.0`; one commit past signed tag `v1.0.0` = `e4de463`) |
| **Question** | Synthesizing the seven prior read-only audits, is gm-crypto-rs `1.0.0` release-ready? GO/NO-GO, blockers, non-blocking cleanup, and which irreversible actions remain maintainer-only. |
| **Method** | Read-only multi-agent synthesis (Claude Code dynamic workflow `v1-release-readiness-synthesis`): 7 parallel extractors (one per audit) → dedupe/cluster with provenance + contradiction map → 9 adversarial adjudicators re-verifying flagged contradictions/unverified-blockers against source+git → ranked synthesis. 19 agents; 42 findings deduped; 9 source-adjudicated; **0 blockers**. (First run hit a transient API socket-drop at the cluster step; resumed from cached extracts.) |
| **Scope** | The 7 inputs in `docs/audits/`: constant-time discipline, fuzz coverage-gaps, API/ABI stability, CI-gate effectiveness, dependency policy, doc↔code↔CI consistency, misuse/footgun. No new broad analysis — fresh source/git reads only to resolve contradictions. |
| **Static vs dynamic** | **Static / source-level only**, offline. No bench executed; no `cargo public-api`/`cbindgen`/`cargo-semver-checks` re-run; no network. The crates.io publish itself is **unverifiable offline**. |

---

## Headline verdict

**🟢 GO-WITH-FOLLOWUP** — ship/keep `1.0.0` as-is; land the cleanup in a backward-compatible `1.0.1`.

**No source-supported blocker in the checked scope.** The *irreversible* 1.0 surface is clean:

- **Constant-time:** *no source-supported timing-leak finding* across ~96 secret-touching sites (refute-by-default; 83/86 automated candidates refuted). Load-bearing invariants positively confirmed — fixed-K=2 masked sign retry, 4-draw constant-time nonce sampler, on-curve-before-mul, `ConstantTimeEq` tag/MAC compares, masked XTS α-doubling, RCB complete addition, `CtOption` inversions, the load-bearing zeroizations. *(Static-only; dudect bench not executed.)*
- **API/SemVer/ABI:** `cargo-public-api` baseline matches source bidirectionally; `#[doc(hidden)]` items correctly absent from the baseline; `crypto-bigint` decoupled from the always-on API (only the opt-in `from_scalar(U256)` residual); `public_key() → Sm2PublicKey`; C header export set 1:1 with FFI symbols (63 == 63). **No SemVer/ABI break is locked into 1.0.**

Every confirmed defect is documentation wording, a runtime-value string, or CI config — **all reversible and fully patchable in a backward-compatible `1.0.1` (none changes a symbol, signature, or wire byte).** Hence GO-WITH-FOLLOWUP, not plain GO.

**Severity profile (42 deduped):** 0 blocker · 0 critical · **3 high** · **11 medium** · **21 low** · 7 info — 34 confirmed / 6 hypothesis / 2 other.

This is *"no source-supported blocker,"* not a proof of absence — see *Honesty caveats*.

---

## Release-state note (read this first)

The repo is **post-tag on `main`**: signed `v1.0.0` tag = `e4de463` (verified Good ED25519 signature), HEAD = `12e26b4` is exactly one commit past it (#86, the `cargo-semver-checks` enforce flip). Workspace is `1.0.0` (`Cargo.toml:24`) with exact `=1.0.0` sibling pins. The bump (#85 / `976bd72`) and the semver-enforce flip (#86) are both merged on-disk.

> ⚠️ **The on-disk state proves:** signed tag + version bump + exact pins + semver-enforce merged.
> **It does NOT prove:** that `cargo publish` actually reached crates.io for all three crates (simd→core→c). The tag message and #86 *assert* "live on crates.io," **but a commit/tag message is not an upload receipt — this is `unverifiable-offline` and is not asserted either way.** A human must confirm crates.io reachability. Several in-repo docs still narrate the publish as *pending* (F5/F6/F7/F8) — those are **stale**, not evidence the publish didn't happen.

---

## 1 · Blockers

**None.** No source-supported blocker in the checked scope. The one genuinely irreversible step — the crates.io publish — is maintainer-only and unverifiable offline; nothing in scope should block or unblock it beyond the maintainer confirming the three crates are live at `=1.0.0`.

---

## 2 · Non-blocking cleanup — confirmed, ranked (all → `1.0.1`)

### 🔴 HIGH (2 confirmed; both doc/CI-patchable, neither a code defect)

| ID | Finding | Citation | Action |
|---|---|---|---|
| **F30** | Raw SM4 single-block ECB API carries **no misuse warning** — looping `encrypt_block` builds ECB with no semantic security. | `Sm4Cipher::{encrypt,decrypt}_block`; C `gmcrypto_sm4_{encrypt,decrypt}_block`; docstring covers CT/throughput/KAT but never "not a mode" | Add a prominent ECB-warning docstring (+ C header); point to `mode_cbc/ctr/gcm/ccm/xts`. Non-breaking. |
| **F15** | `dudect-pr.yml` paths-allowlist **omits `crates/gmcrypto-simd/src/**`** → a SIMD constant-time regression merges and is caught only by nightly (~24 h late). | `dudect-pr.yml` allowlist (core+root only); SIMD: `sbox_x8/x16/x32`, `avx2.rs`, `neon.rs`, `ghash/{clmul,pmull}.rs` | Add `crates/gmcrypto-simd/src/**` to the allowlist. CI-config; addable any time. *(Severity hinges on branch-protection state — unverifiable offline.)* |

### 🟠 MEDIUM (11 confirmed)

| ID | Finding | Citation | Action |
|---|---|---|---|
| **F1** | `SECURITY.md` still declares the line **"pre-1.0 (0.x)"** (future-tense "1.0 commitment") on a shipped+tagged 1.0.0 — misleads in the *dangerous* direction (reader concludes SemVer is **not** enforced). | `SECURITY.md:18` vs `Cargo.toml:24`, `README.md:92,104`, `api-stability.yml:73,96-97` | Rewrite to present-tense "1.0 stable; SemVer enforced". |
| **F2** | `SECURITY.md` `#[doc(hidden)]`/"not SemVer-covered" enumeration **stops at v0.22**; omits the v0.23-hidden surface README/CHANGELOG fully list. | `SECURITY.md:27-30`; `README.md:114-123`; `CHANGELOG.md:86-98` (baseline correct) | Extend the list (`sm2::point`+`ProjectivePoint`, `asn1::{reader,writer,oid}`, `traits::{Hash,Mac,BlockCipher}`, `from_point/point`). |
| **F3** | `gmcrypto_version()` returns hardcoded **`"0.4.0"`** in the 1.0.0 crate (wrong runtime value; header documents the same stale value → no CI drift). | `crates/gmcrypto-c/src/lib.rs:301` (`b"0.4.0\0"`); `Cargo.toml:24`; `gmcrypto.h:140-144` | Derive from `env!("CARGO_PKG_VERSION")`. Value-only; no symbol/wire change. |
| **F11** | README Quick-start **does not compile** against 1.0.0: `Sm2PublicKey::from_point(key.public_key())` is an E0308 (wrong type, `#[doc(hidden)]` ctor). Not a doctest → CI never catches it. | `README.md:631`; `public_key.rs:20-24,70-76`; `private_key.rs:131-135` | Replace with `let public = key.public_key();`; consider a compiled doctest. |
| **F16** | gmssl 3.1.1 **interop 11/11 — the headline wire guarantee — runs in no CI job** (`GMCRYPTO_GMSSL` set nowhere); README + `interop_gmssl.rs:3` falsely imply CI parity. *(ci-gate audit rated high; adjudicated medium — wire bytes maintainer-verified, KAT fixtures still run in CI.)* | `grep .github/workflows → 0 hits`; `interop_gmssl.rs:3,43`; `ci.yml:109`; `README.md:21,515` | Wire gmssl into CI, **or** relabel 11/11 as maintainer-verified + fix the false test comment. |
| **F22** | `rand_core 0.10.x` `TryCryptoRng` bound is in the **always-on public SemVer contract** — undisclosed boundary (accepted Fork-4 coupling; only disclosure is the gap). | public sign/encrypt/decrypt/verify signatures; `Cargo.toml rand_core=0.10.1` | Document that 1.0 is bound to `rand_core 0.10.x` (a 0.11 break ⇒ major). |
| **F23** | `crypto-bigint 0.7.3` always-on transitive coupling — default API names zero crypto-bigint types, but the internal coupling + mitigation are undisclosed. | `Cargo.toml crypto-bigint=0.7.3`; v0.22 doc-hid `Fn/Fp`; opt-in `crypto-bigint-scalar` | Document the internal coupling + the opt-in escape hatch in the stability notes. |
| **F17** | x86_64 AVX2/CLMUL correctness tests **run on no CI host** (only the aarch64 mac runs `--workspace`). | `ci.yml:109` (macos-14 only); `gmcrypto-simd` x86_64 lane/CLMUL tests | Add one ubuntu x86_64 `cargo test -p gmcrypto-simd` job. |
| **F18** | `fuzz/` separate workspace gets **no PR-time build** — an API reshape can break a target uncaught until nightly. | `fuzz-nightly.yml` (no `pull_request`); `--workspace` excludes `fuzz/` | Add PR-time `cargo +nightly fuzz build` (build-only). |
| **F19** | `cargo-deny` runs without `cargo generate-lockfile` (`Cargo.lock` gitignored) → non-reproducible resolution. | `ci.yml::deny`; `CLAUDE.md:470` (documented recipe) | Add `cargo generate-lockfile` before `cargo deny check`. |
| **F31 / F32** | C ABI: pointer/length preconditions not consolidated in `gmcrypto.h` (OOB-read class on misuse); callers not told sign/encrypt are **RNG-fallible**. | `gmcrypto.h`; `sm2/sign.rs:99-104` | Add a module-level C-ABI preconditions block + an "may return `GMCRYPTO_ERR` on RNG failure" note. |

### 🟡 LOW (21 confirmed — grouped; all doc/config staleness)

- **Stale "publish-pending" / release-state narrative** (5): `F5` `docs/v1.0-readiness.md:7-23,251-252` + `F8` row `:47`; `F6` CLAUDE.md header; `F7` `CLAUDE.md:779,122-123` (calls semver-checks "informational/continue-on-error/vs-0.16.0" — both literals false vs `api-stability.yml:73,96-97`).
- **CLAUDE.md CI-drift** (3): `F9` "dudect stays on ubuntu-latest" vs pinned `ubuntu-24.04` (`dudect-pr.yml:36`, `dudect-nightly.yml:45`); `F10` 3-entry vs actual 4-leg dudect matrix; `F14` `sm4-xts` documented in MSRV/wasm32/deny commands those CI jobs don't build.
- **Docs/examples** (4): `F4` `html_root_url` → `0.5.0` on a 1.0 crate (`lib.rs:61`, vestigial); `F12` README RNG examples still wrap `SysRng` in `UnwrapErr` (`README.md:623,633,683,686`); `F13` CHANGELOG `[1.0.0]` dead `### v0.17–v0.23` anchors + fuzz 16→18 unrecorded; `F35` no worked CSPRNG IV/nonce example per mode.
- **Dependency-policy hygiene** (3): `F24` `deny.toml:3-4` comment omits `spin` (entry at `:54` correct); `F25` `deny.toml:19` allow-lists `ISC`+`Unicode-DFS-2016`, neither in the tree; `F26` `digest 0.11`/`cipher 0.5` opt-in couplings lack a pre-1.0 feature caveat.
- **AEAD/XTS ergonomics** (3): `F33` CCM short-tags `{4,6}` no bit-strength floor (advisory `tag_len≥8` present); `F34` XTS C `start_sector u64` cap undocumented; `F36` `GcmTagLen` no short-tag strength table.
- **CT coverage** (1): `F21` constant-time PKCS#7 unpad (`mode_cbc.rs::strip_pkcs7_ct`, `cbc_streaming.rs::strip_pkcs7_block`) has **no dedicated dudect target** — CT in source, gated only indirectly via the cfg-gated SIMD batch path. *(Coverage gap, NOT a confirmed leak.)*

---

## 3 · Confirmed vs. hypotheses (explicit separation)

**Confirmed (31):** all of §2 — each source-verified by ≥1 audit, and the 9 adjudicated items (C-PUBLISH, C-1…C-6, F11, F16) re-checked against source/git this session (F11 verified at the type level; F16 by grepping all 5 workflows for `GMCRYPTO_GMSSL` → zero hits). Plus two info-tier confirmations: `F37` GCM-streaming finalize free-semantics already guarded by the header; `F42` the single-`Failed` public variant set is gated by the public-api baseline (`Error::Failed` at baseline line 280).

**Hypotheses / lower-confidence (7):**
- `F21` (low) — unpad CT-target coverage gap (source is CT; this is target-coverage only).
- `F26` (low) — `digest 0.11`/`cipher 0.5` pre-1.0 opt-in caveat (version-dependent).
- `F28` (info) — `cpufeatures 0.2.x` pre-1.0 transitive dep (reflects the transient resolution tree; isolated by `gmcrypto-simd` `#[doc(hidden)]`).
- `F29` (info) — `wit-bindgen` two-version WASI multiple-versions WARNING (not a deny; native builds unaffected; resolves upstream).
- `F36` (low) — `GcmTagLen` short-tag bit-strength table (enhancement only).
- `F40` sub-items (CG-13/CG-14) — cargo-fuzz recompiled each nightly (cost-only); dudect-nightly leg-cancellation (known/deferred CI-health) — unverified cost/health hypotheses.
- `F41` (low) — api-stability feature-matrix tests only the two extremes + PR(10K×3)-vs-nightly(100K×5) SNR asymmetry — empirical claim not verified; sufficiency hinges on offline-unknowable branch-protection.

**Explicitly NOT defects (accepted postures — per the audit ground rules):** the single-`Failed`/`None`/`GMCRYPTO_ERR` failure-mode invariant; `unsafe_code = forbid` in core; the dudect telemetry/sentinel `@0.55` posture for `ct_fn_invert`/`ct_fp_invert` (the v0.19-falsified fix-vs-fix relative gate must **not** be re-added).

---

## 4 · Irreversible actions — maintainer-only

| Action | Status | Note |
|---|---|---|
| **`cargo publish` simd → core → c at `=1.0.0`** | **`unverifiable-offline`** | The one genuinely irreversible step. On-disk proves tag+bump+pins+semver-flip — **not** the crates.io upload. Tag/#86 messages assert it; a message is not a receipt. **Human must confirm all three crates are live at `=1.0.0`.** Do not assert it landed or didn't. |
| Create/push SSH-signed `v1.0.0` tag | **done** | Verified: `git tag -v v1.0.0` → Good ED25519 signature, tag object `e4de463`. Irreversible (rewriting a signed tag is a force-push hazard). |
| Publish the GitHub Release for `v1.0.0` | `unverifiable-offline` | Remote artifact, not observable from the local clone. |
| Flip `cargo-semver-checks` → enforced (`api-stability.yml`) | **done** | Merged as #86; `api-stability.yml:72-97` runs the enforced gate, no `continue-on-error`. (Reversible CI edit, grouped here as runbook §4-step-7.) |

---

## 5 · Per-dimension verdicts

| Dimension | Verdict | One-line |
|---|---|---|
| Constant-time correctness | **GO** | *No source-supported timing-leak finding* in scope; CT invariants hold. *(Static-only; bench not run.)* |
| API / SemVer / ABI finality | **GO** | Locked surface clean; no break locked into 1.0; defects are doc/value/CI only. |
| Dependency policy / supply chain | **GO** | Minimal, well-governed; only disclosure/comment staleness. |
| Fuzz coverage | **GO** | 18-target baseline verified; coverage-backlog analysis, **zero defects**. |
| Publish mechanics / release state | **GO-WITH-FOLLOWUP** | Tag+bump+pins+semver-flip landed; crates.io publish is the irreversible maintainer step, unverifiable offline; publish-pending docs stale. |
| Honest disclosure / docs truthfulness | **GO-WITH-FOLLOWUP** | Several confirmed consumer-facing doc mismatches (F1/F11/F3/F16); all 1.0.1-patchable. |
| CI gate effectiveness | **GO-WITH-FOLLOWUP** | Every finding is a CI-config gap, never a defect in the published crate. |
| Misuse / footgun ergonomics | **GO-WITH-FOLLOWUP** | Well-guarded overall; lone real gap is the raw-ECB warning (F30). |

---

## 6 · Cross-audit agreements (highest-confidence signals)

- **F1** `SECURITY.md:18` "pre-1.0" staleness — independently source-confirmed by api-abi (M-1) and docs (R-1); both flag the dangerous-direction misread.
- **F3** `gmcrypto_version()=="0.4.0"` — confirmed on-disk by api-abi (M-3), cross-referenced by docs; both agree it is a wrong runtime *value*, not a header/source drift.
- **Stale publish-pending narrative** — flagged by **all five non-fuzz audits** (api-abi, ci-gate, dependency-policy, docs, misuse).
- **F14** `sm4-xts` MSRV/wasm32/deny coverage — same fact framed by docs (M-8) and ci-gate (CG-3).
- **Inversion sentinel `@0.55`** posture — jointly *accepted* by constant-time (CT-1) and ci-gate (CG-7) as the documented v0.19/v0.20 baseline, **not** a defect.
- **`unsafe_code = forbid`** + the single-`Failed` invariant — affirmed across api-abi, dependency-policy, ci-gate with no violation found.

---

## 7 · Honesty caveats / scope limits

1. **Constant-time is static/source-level only** — the dudect bench was **not executed** this session. Empirical CT confidence rests on the existing CI gates + the documented telemetry/sentinel posture, not a fresh run. *"No source-supported finding"* is the correct framing — **not** "no leak."
2. **crates.io publish is unverifiable offline** — on-disk proves the signed tag + bump + pins + merged semver-flip, **not** the upload. Must be human-confirmed; not asserted either way.
3. **GitHub Release + branch-protection / required-check state are not in the repo** — several CI-config severities (esp. F15, F41) hinge on the unverifiable required-gate state.
4. **API↔baseline was a read+grep correspondence** — no `cargo public-api` / `cargo-semver-checks` / `cbindgen` re-run; the `--omit auto-trait-impls` blind spot now relies on the enforced semver gate.
5. **F11 (README compile-break) and F16 (interop) verified at type/grep level**, not actually compiled/run (README is prose-referenced, not a doctest; interop self-skips without `GMCRYPTO_GMSSL`).
6. **Hypothesis-tier dependency findings (F28/F29) reflect the transient resolution tree** at audit time; not re-resolved here.
7. **The fuzz-coverage "severity" axis is priority/value of adding a target, NOT defect severity** — nothing was built or run there.

---

## Bottom line

No source-supported reason to hold `1.0.0`. The single human action that matters is **confirming the crates.io publish actually landed** (simd→core→c at `=1.0.0`); everything else is a clean `1.0.1` doc/value/CI sweep led by **F30** (raw-ECB warning), **F15** (dudect SIMD allowlist), **F11** (README compile break), **F3** (`gmcrypto_version` value), and **F1/F2** (`SECURITY.md` SemVer prose).

---

## Provenance

Generated by a read-only Claude Code dynamic workflow (`v1-release-readiness-synthesis`, run `wf_215e19f8-f31`), synthesizing the seven `docs/audits/2026-06-02-*.md` audits. 19 agents (7 extract + 1 cluster + 9 adjudicate + 1 synthesis); fresh source/git reads were performed **only** to resolve flagged contradictions/unverified blockers. No files edited (beyond creating this artifact), nothing committed/pushed/published/tagged, no CI or secrets touched. This document is a working-tree artifact; commit/track at your discretion (per the branch+PR rule, the agent did not commit it).
