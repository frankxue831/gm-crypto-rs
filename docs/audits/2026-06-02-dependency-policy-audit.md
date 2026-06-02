# Dependency-policy & feature-exposure audit — gm-crypto-rs `1.0.0`

| | |
|---|---|
| **Date** | 2026-06-02 |
| **Commit** | `12e26b4` (`main`, workspace `1.0.0`) |
| **Mission** | Audit dependency policy and feature-gated dependency exposure: core runtime deps, optional digest/cipher trait deps, FFI + getrandom platform surface, SIMD backend deps + unsafe/provenance, cargo-deny allowlist sufficiency, no_std / license / yanked-advisory / supply-chain risk. |
| **Method** | Read-only multi-agent workflow (`dependency-policy-audit`): 6-lens map → adversarial verify (exposure genuine, not opt-in/dev-only/allowlisted-away? + tree-grounded?) → synthesis. 58 agents; 51 findings → 24 confirmed / 27 refuted → 4 confirmed + 3 hypotheses + 11 well-governed. Agents ran read-only `cargo tree`/`metadata` to ground the transitive graph. |

**Headline:** the dependency footprint is **minimal and well-governed** — the default build pulls only 5 runtime deps, the core is RNG-agnostic (`getrandom` is dev-only there), optional deps are properly `dep:`-gated, `unsafe` is quarantined to the two non-core crates, and sources are locked to crates.io. The real items are **pre-1.0 coupling disclosure** and **`deny.toml` documentation/allow-list hygiene** — not enforcement holes. No critical or active security exposure.

**Analysis only** — no deps added/bumped/removed, no manifest/`deny.toml`/source edits, nothing committed. (The read-only `cargo tree` runs wrote only a transient gitignored `Cargo.lock`, not `git add`ed.)

---

## ▶ ACTION ITEMS (pick up later)

All documentation/hygiene; none is a code or security defect:

- [ ] **(Low)** `deny.toml` top comment (lines 3-4) omits `spin` from the stated always-on NORMAL deps — update to "crypto-bigint, subtle, zeroize, rand_core, **and spin**". (Allow-list itself is correct.)
- [ ] **(Low)** Remove (or document-as-reserved) the stale `ISC` + `Unicode-DFS-2016` entries in `[licenses].allow` (line 19) — not encountered in the resolved tree.
- [ ] **(Med, disclosure)** Document the `rand_core 0.10` public-trait coupling as a known SemVer-contract boundary in SECURITY.md/CLAUDE.md (parallel to the `crypto-bigint-scalar` caveat).
- [ ] **(Med, hypothesis)** Add a pre-1.0 caveat to the `digest-traits`/`cipher-traits` feature docstrings (`lib.rs`) mirroring the `crypto-bigint-scalar` escape-hatch note.
- [ ] **(Low, observed)** Consider adding `version = 2` to `deny.toml` — it currently uses the legacy schema; this also enables the `unused-allowed-license` check that would settle the ISC/Unicode-DFS-2016 staleness above. *(Verify behavior with a local `cargo deny check` first.)*

---

## 1 · Confirmed findings (severity-ranked)

Columns per the mission: **dependency path · affected feature/crate · downstream impact · recommended policy change.**

### [HIGH · pre-1.0-exposure] `rand_core 0.10.1` is a public-API trait bound on the always-on path
- **Dependency path:** `gmcrypto-core → rand_core 0.10.1`
- **Affected feature/crate:** `gmcrypto-core` public API (`sign`/`encrypt`/`decrypt`/`verify` take `rand_core::TryCryptoRng`)
- **Downstream impact:** the `TryCryptoRng` bound is baked into the v1.0 SemVer contract; a breaking `rand_core 0.11` cannot be adopted without a gmcrypto-core major bump (or a v1.x update that consumers must track). Deliberate ecosystem-interop coupling, not a vulnerability.
- **Recommended policy change:** document in SECURITY.md/CLAUDE.md that v1.0 is bound to the `rand_core 0.10.x` public trait API; `rand_core 0.11` breaking changes will require a gmcrypto-core update; monitor RustCrypto for `rand_core` 1.0.

### [MEDIUM · pre-1.0-exposure] `crypto-bigint 0.7.3` is an always-on transitive coupling (type hidden)
- **Dependency path:** `gmcrypto-core → crypto-bigint 0.7.3` (always-on)
- **Affected feature/crate:** `gmcrypto-core` (all builds)
- **Downstream impact:** internal SM2 field/scalar arithmetic depends on `crypto-bigint`; a breaking upstream release forces a gmcrypto-core patch despite the 1.0 stable claim. **Mitigated:** the default public API names zero `crypto-bigint` types (v0.22 doc-hid `Fn`/`Fp`); only the opt-in `crypto-bigint-scalar` feature exposes `U256` directly.
- **Recommended policy change:** document the internal coupling + its mitigation (doc-hidden scalar types + opt-in `from_scalar` gate) in the v1.0 stability notes; public consumers are decoupled unless they enable `crypto-bigint-scalar`.

### [LOW · policy-gap] `deny.toml` top comment omits `spin` from the always-on NORMAL deps
- **Dependency path:** `gmcrypto-core → spin 0.10` (always-on, `once` feature only)
- **Affected feature/crate:** `gmcrypto-core`; `deny.toml` documentation
- **Downstream impact:** doc drift only — the comment (lines 3-4) says "ships only crypto-bigint, subtle, zeroize, rand_core" but `spin` is a confirmed always-on NORMAL dep. The allow-list entry is present and correct; only the comment is stale.
- **Recommended policy change:** update the comment to include `spin`.

### [LOW · stale-allowlist] `ISC` + `Unicode-DFS-2016` allow-listed but never encountered
- **Dependency path:** `deny.toml [licenses].allow` (line 19)
- **Affected feature/crate:** policy only (not runtime)
- **Downstream impact:** zero runtime impact; the unused entries are policy cruft (would surface as `license-not-encountered` once the `unused-allowed-license` check is enabled).
- **Recommended policy change:** drop `ISC` + `Unicode-DFS-2016` (keep `Apache-2.0`, `MIT`, `BSD-3-Clause`, `Unicode-3.0`), or annotate them as reserved-for-future. *(See the version=2 note in §3 — this is also the operative resolution of the minor self-inconsistency in the workflow's well-governed map, which elsewhere listed ISC as "used".)*

## 2 · Hypotheses (lower confidence / version-dependent)

| Sev | Finding | Dependency path | Affected feature/crate | Downstream impact | Recommended policy change |
|---|---|---|---|---|---|
| Med | `digest 0.11` / `cipher 0.5` are pre-1.0 opt-in couplings | `gmcrypto-core{digest-traits,cipher-traits} → {digest 0.11, cipher 0.5}` | opt-in `digest-traits` / `cipher-traits` | default build pulls neither; consumers who enable them inherit a 0.x major-bump treadmill (a `digest 0.12`/`cipher 0.6` forces lockstep updates) | Add a pre-1.0 caveat to the feature docstrings in `lib.rs`, mirroring the `crypto-bigint-scalar` note |
| Low | `cpufeatures 0.2.x` is a pre-1.0 transitive runtime dep, target-gated | `gmcrypto-c → gmcrypto-core{sm4-aead} → gmcrypto-simd → cpufeatures 0.2` | opt-in `sm4-bitsliced-simd` / `sm4-aead`; x86_64/aarch64 only | only SIMD-enabled binaries on x86_64/aarch64 carry it; compile-excluded on wasm32 etc. | Note the pre-1.0 status in `gmcrypto-simd/Cargo.toml`; coupling is isolated via `#[doc(hidden)]` |
| Low | `wit-bindgen` appears in two versions on WASI targets | `gmcrypto-c → getrandom 0.4.2 → {wasip3 → wit-bindgen 0.51, wasip2 → wit-bindgen 0.57}` | `gmcrypto-c` on WASI (native builds unaffected) | ~50 KB duplicate on WASI; not a correctness issue (platform-gated); a `multiple-versions` warning artifact | Add a `deny.toml` comment explaining the expected getrandom multi-WASI-backend duplication; resolves naturally upstream |

## 3 · Caveats & cross-checks

- **One internal inconsistency in the workflow output, reconciled:** the well-governed map (#5) called the license allow-list "comprehensive incl. ISC," while confirmed finding #4 says ISC is unused. The **stale-allowlist finding is the operative one** — ISC/Unicode-DFS-2016 are not in the resolved tree.
- **`deny.toml` schema (observed in recon, version-dependent):** the file has **no `version = 2` key**, so cargo-deny runs in legacy-schema mode. Whether `advisories.unmaintained`/`unsound` are gated, and whether `unused-allowed-license` fires for the stale ISC entry, depends on the cargo-deny 0.19 defaults — **confirm with a local `cargo deny check`** before acting. (The well-governed map's claim that "unmaintained/unsound are errors" is not verifiable from the committed config alone.)
- **`sm4-xts` omitted from the CI deny second pass** (cross-ref the CI-gate review, same date): `sm4-xts = []` adds no deps so it's currently benign, but the policy doesn't validate that invariant over time.
- **Resolved-version items** (the two-version `wit-bindgen`, exact `cpufeatures`/`crypto-bigint` patch levels) reflect the transient `cargo tree` resolution at audit time; they shift with upstream releases.

## 4 · Well-governed (sound by design — the positive map)

- **Minimal always-on footprint** — 5 NORMAL deps (`crypto-bigint`, `subtle`, `zeroize`, `rand_core`, `spin`), each load-bearing and allow-listed with rationale; no bloat.
- **RNG-agnostic core** — public APIs take caller-supplied `rand_core::TryCryptoRng`; `getrandom` is **dev-only** in `gmcrypto-core` and a normal dep only in the `gmcrypto-c` FFI shim (which must own RNG sourcing). Clean separation; no `wasm_js`/`wasm-bindgen` pulled into core (Q4.2).
- **Exemplary feature gating** — every optional dep uses `dep:` syntax; default build pulls zero optional deps; CI runs a dual-pass deny (default + all-runtime-opt-in).
- **Workspace member isolation** — `gmcrypto-simd` is rlib-only + `#[doc(hidden)]`; `cpufeatures` target-gated; `cbindgen` build-time-only + `regen-header`-gated + `skip-tree`'d in deny.
- **Unsafe quarantine** — `unsafe_code = forbid` on `gmcrypto-core`; `warn` + `// SAFETY:` on the two non-core crates; SIMD `#[target_feature]` paths guarded by runtime CPU detection.
- **no_std + alloc invariant** — all always-on + optional deps are no_std (`default-features = false` enforced at the workspace level); verified by the wasm32 CI leg.
- **Sources locked** — `[sources] unknown-registry = deny`, `unknown-git = deny`, allow-registry = crates.io; no git deps (except internal `path` members).
- **License posture** — all resolved deps are permissive (Apache-2.0/MIT/BSD-3-Clause/Unicode-3.0); no GPL/LGPL/proprietary; no NOTICE-file obligation.
- **Pre-1.0 couplings are explicit & accepted** — the `crypto-bigint 0.7` / `rand_core 0.10` couplings were a deliberate, documented decision (v1.0-reaudit Fork 4: accept-and-document), not hidden.
- **Advisories** — `yanked = "deny"`, `ignore = []` (no stale suppressions).

---

## Provenance

Generated by a read-only Claude Code dynamic workflow (`dependency-policy-audit`, run
`wf_13e2f9e8-87d`), with orchestrator recon of the three manifests + `deny.toml`. Agents ran
read-only `cargo tree`/`metadata` (transient gitignored `Cargo.lock` only). No files edited, nothing
committed/pushed/published/tagged, no deps changed, no CI touched. Working-tree artifact; commit/track
at your discretion (per the branch+PR rule, the agent did not commit it).
