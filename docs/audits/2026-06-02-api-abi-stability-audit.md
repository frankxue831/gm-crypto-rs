# Public API / C ABI stability audit — gm-crypto-rs `1.0.0`

| | |
|---|---|
| **Date** | 2026-06-02 |
| **Commit** | `12e26b4` (`main`, workspace `1.0.0`) |
| **Question** | Did any accidental public Rust API or C ABI **instability** slip into the shipped `1.0.0` — drift vs the committed baselines, header/export mismatch, feature-gate or `#[doc(hidden)]` leak, or stale SemVer-coverage claims? |
| **Method** | Read-only multi-agent workflow (`audit-v1-api-abi-stability`): recon → 5-area parallel inspection → per-finding adversarial verification (refute-by-default) → dedupe/rank synthesis. 33 agents; 26 candidates raised, every one source-verified → **5 confirmed issues** (3 Med / 2 Low) + 21 confirmed-correct non-findings/context; **0 unresolved hypotheses**. |
| **Scope** | public-api baseline (`gmcrypto-core` + `gmcrypto-simd`) vs source; C header `gmcrypto.h` ⟷ FFI exports; feature-gated API (esp. `crypto-bigint-scalar`); `#[doc(hidden)]` boundary leaks; README / SECURITY / CHANGELOG / `v1.0-readiness` SemVer claims. |
| **Static vs dynamic** | **Static / source-level only.** No `cargo public-api` run, no `cbindgen`/header regen, no feature-matrix / MSRV / wasm builds, no network. Baseline↔source and header↔export equivalences are read+grep correspondences; the crates.io publish itself is **not** verified. |
| **Out of scope** | Cryptographic correctness / constant-time discipline — see the companion `docs/audits/2026-06-02-ct-discipline-audit.md`. This audit makes **no** crypto-correctness claim. |

---

## Headline verdict

**No source-supported public-API or C-ABI instability in the audited scope.** No SemVer/ABI
break, no accidental hard-to-remove public surface, no public-api↔baseline drift, and no
header↔export drift were found. The API freeze itself is clean: the committed `cargo-public-api`
baseline matches the non-doc-hidden source surface bidirectionally, the C header is set-identical
to the FFI exports (63 == 63), and the crypto-bigint-decoupling posture (claims 1–4) holds.

**Every confirmed issue is documentation or runtime-value staleness that survived the
`0.16.0 → 1.0.0` bump** and is now locked into the first stable release — most materially,
`SECURITY.md` still calls the line "pre-1.0 (0.x)" and `gmcrypto_version()` still returns
`"0.4.0"`. All five are doc/value fixes that **do not touch the wire format or the locked API**;
they are safe to correct in a `1.0.1`.

**Severity histogram:** 0 Critical · 0 High · **3 Medium** · **2 Low** · 19 Info / non-findings.

Severity rubric (from the verifier): **Critical** = a SemVer/ABI break 1.0 locks · **High** =
accidental, hard-to-remove public/exported surface · **Medium** = doc/code (or doc/doc) mismatch
that misleads consumers · **Low** = cosmetic / process-narrative prose · **Info** = verified
non-finding or context.

### Scope-framing note (recon contradicted the assumed repo state)

`CLAUDE.md` describes release-prep as in progress on `feat/v1.0-release` with the merge/publish
pending. The repo is in fact **post-tag on `main`**: HEAD `12e26b4` is **one commit past** the
SSH-signed `v1.0.0` tag (`e4de463`), workspace is at `1.0.0`, the bump landed (PR #85 / `976bd72`),
and the post-publish `cargo-semver-checks`-enforced flip already landed (PR #86 — runbook §4
step 7). So **"after v1.0" is literal here**, and several in-repo docs still describe the
pre-publish world — which is exactly where the findings cluster.

---

## 1 · Confirmed issues (ranked by severity)

### 🟠 MEDIUM

**M-1 · `SECURITY.md` still declares the line "pre-1.0 (0.x)" after the 1.0.0 release/tag**
- **File / symbol:** `SECURITY.md:18` — `## API stability & SemVer`
- **Mismatch:** The canonical stability-contract document a security-conscious integrator reads
  opens by declaring the line pre-1.0 and frames the readiness work as "ahead of a `1.0`
  commitment" (future tense), directly contradicting the shipped state. The directional
  contradiction **misleads in the dangerous direction**: a reader concludes SemVer is *not*
  enforced and breakage is permitted — the opposite of the now-enforced forward gate. Last touched
  in v0.23 (`41d1ca9`); not re-synced in release-prep PR #85.
- **Evidence:** `SECURITY.md:18` "The crate line is pre-1.0 (0.x); the **v1.0 readiness audit**
  (v0.21) froze and / CI-guarded the public surface ahead of a `1.0` commitment…" vs.
  `Cargo.toml:24 version = "1.0.0"`; `git tag -l → v1.0.0`; `README.md:92` "The line graduates to
  **1.0 (stable)** with this release."; `README.md:104` "**From 1.0, SemVer is enforced**".

**M-2 · `SECURITY.md`'s "not covered by SemVer" `#[doc(hidden)]` enumeration is stale; omits the entire v0.23-hidden surface**
- **File / symbol:** `SECURITY.md:26-30` — `## API stability & SemVer`
- **Mismatch:** The list stops at v0.22 — only `sm2::sign_raw_with_id`, the two
  `Sm4Cbc{Encryptor,Decryptor}::take_output` drains, and `sm2::curve` / `sm2::scalar_mul` /
  `ProjectivePoint::to_affine`. It omits the v0.23-hidden items that README and CHANGELOG both
  enumerate and source confirms `#[doc(hidden)] pub`: the `sm2::point` module + `ProjectivePoint`
  type + re-export, `Sm2PublicKey::{from_point, point}` + `From<ProjectivePoint>`, the
  `asn1::{reader, writer, oid}` modules, and the in-crate `traits::{Hash, Mac, BlockCipher}`
  module. A reader treating this list as authoritative would **wrongly believe `ProjectivePoint`,
  `asn1::reader/writer/oid`, and `traits` are SemVer-covered.** Doc-only — the items are correctly
  hidden in source and correctly absent from the baseline; partly mitigated by SECURITY.md pointing
  to `docs/v1.0-readiness.md` and by README/CHANGELOG carrying the full list.
- **Evidence:** `SECURITY.md:26-30` (truncated enumeration); grep of SECURITY.md for
  `sm2::point` / `asn1::` / `traits::` / `from_point` → no hit. Source-hidden:
  `sm2/mod.rs:20-21,41-42`; `public_key.rs:20-22,29-31,71-72`; `asn1/mod.rs:10-18`; `lib.rs:76-77`.
  Full sibling lists at `README.md:114-123`, `CHANGELOG.md:86-98`. Baseline grep for
  `point|traits|reader|writer|oid` in `docs/api-baseline/gmcrypto-core.txt` → none.

**M-3 · `gmcrypto_version()` returns hardcoded `"0.4.0"` in the 1.0.0 release crate**
- **File / symbol:** `crates/gmcrypto-c/src/lib.rs:298-306` — `gmcrypto_version`
- **Mismatch:** The FFI version entry point returns the string literal `"0.4.0"` while the crate
  publishes at `1.0.0` (inherited via `version.workspace = true`). It is **not** derived from
  `CARGO_PKG_VERSION` / `env!` (only the literal `b"0.4.0\0"` appears; `build.rs` injects nothing),
  so it will not auto-track future bumps either. **Every 1.0.0 C consumer calling
  `gmcrypto_version()` gets `"0.4.0"`.** Critically this is **not** a header⟷source drift the CI
  `git diff` gate catches — the committed header documents the same stale value and bakes nothing
  into the prototype, so the drift gate stays green. Symbol name + signature are correct and
  stable, so it is **not** a SemVer/ABI break — it is a wrong runtime value.
- **Evidence:** `crates/gmcrypto-c/src/lib.rs:301`
  `const VERSION: &core::ffi::CStr = match core::ffi::CStr::from_bytes_with_nul(b"0.4.0\0") {`.
  `Cargo.toml:24 version = "1.0.0"`; `crates/gmcrypto-c/Cargo.toml:7 version.workspace = true`.
  `crates/gmcrypto-c/include/gmcrypto.h:140-144` doc comment `(e.g. "0.4.0")` + valueless prototype
  (header and source agree → no drift flagged).

### 🟡 LOW

**L-1 · Stale `html_root_url` points docs.rs intra-doc links at 0.5.0 on a 1.0.0 crate**
- **File / symbol:** `crates/gmcrypto-core/src/lib.rs:61` — `#![doc(html_root_url = …)]`
- **Mismatch:** `#![doc(html_root_url = "https://docs.rs/gmcrypto-core/0.5.0")]` while the crate is
  at 1.0.0. Written at bootstrap (`3215fbe`), never updated across the 0.5→1.0 arc; the only
  `html_root_url` in the repo; not in the cargo-public-api baseline, so `api-stability.yml` won't
  flag it. A stale base can mis-target downstream-generated cross-crate intra-doc links, but
  `html_root_url` is largely vestigial post-Rust-1.48 (docs.rs ignores it for its own builds), so
  realistic impact is minimal — hence low, not medium. Ships with the 1.0 publish.
- **Evidence:** `crates/gmcrypto-core/src/lib.rs:61`; `Cargo.toml:24 version = "1.0.0"` via
  `version.workspace = true`. `grep -rn "html_root_url\|0.5.0" docs/api-baseline/` → no match.

**L-2 · `docs/v1.0-readiness.md` status header describes the publish as in-progress on `feat/v1.0-release`**
- **File / symbol:** `docs/v1.0-readiness.md:1-23` (esp. 7-10, 21-23) — top status block
- **Mismatch:** Says the `1.0.0` publish "is now executing via the `feat/v1.0-release` branch (§4)"
  with the `cargo publish` + signed tag "a separate, deliberate step taken later." That process has
  completed and moved on: bump+pins merged to `main` (PR #85 / `976bd72`), `v1.0.0` tagged, `main`
  one commit past the tag with #86 (the post-publish semver-enforce flip = runbook §4 step 7,
  already performed), and `feat/v1.0-release` is superseded. Process-narrative prose only — no
  API/ABI/SemVer/wire claim is misstated and the §4 checklist steps remain procedurally accurate —
  hence low.
- **Evidence:** `docs/v1.0-readiness.md:7-10` ("now executing via the `feat/v1.0-release` branch")
  and `:21-23` ("taken later"). Contradicted by `Cargo.toml:24 version = "1.0.0"`;
  `git rev-list -n 1 v1.0.0 = e4de463`;
  `git log --oneline v1.0.0..HEAD = 12e26b4 "ci: enforce cargo-semver-checks forward gate (post-1.0.0 publish) (#86)"`;
  `git log --oneline -1 -- docs/v1.0-readiness.md = 976bd72` (last written by the now-merged release-prep PR).

---

## 2 · Hypotheses / needs human confirmation

**No code-level hypotheses.** Every dossier entry that reached a verdict was source-confirmed
(`status=confirmed`); there were no `status=uncertain` candidates.

The single residual that genuinely cannot be settled by static analysis is **process, not code**:
whether `cargo publish` (`gmcrypto-simd → gmcrypto-core → gmcrypto-c`) actually executed on
crates.io. On-disk state proves only the signed tag, the `1.0.0` workspace version, and the exact
`=1.0.0` sibling pins; the `v1.0.0` tag *message* asserts "first stable release," but
read-only/no-network access cannot verify the upload. **A human should confirm all three crates
are live on crates.io at 1.0.0 (and that the publish order succeeded)** before treating L-2's
runbook prose as merely stale.

---

## 3 · Verified non-findings (the freeze itself — checked and confirmed correct/intended)

Listed so the reader sees the coverage. These were source-verified as **intended state, not
defects**:

- **Public-API baseline drift (core):** none. The committed `--all-features`
  `docs/api-baseline/gmcrypto-core.txt` (283 lines) matches the non-doc-hidden source surface
  **bidirectionally** — every visible `pub` item present, every baseline line maps to a real source
  item, no accidental new surface, no stale entry.
- **All `#[doc(hidden)] pub` items absent from the baseline:** correct (tool-omission is documented;
  a regeneration reproduces the file), not a stale baseline.
- **crypto-bigint posture — claim (1):** the only crypto-bigint-typed public item is the opt-in,
  default-off `Sm2PrivateKey::from_scalar(U256)` (baseline L68/L98 only); the **default-features**
  surface names **zero** crypto-bigint types.
- **crypto-bigint posture — claim (2):** `Sm2PrivateKey::public_key()` returns `Sm2PublicKey`;
  `ProjectivePoint` appears in **no** visible signature and nowhere in the baseline.
- **`gmcrypto-simd` 1-line baseline:** intended record (whole crate is `#[doc(hidden)] pub`); not
  missing coverage; nothing leaks into the core baseline.
- **C header ⟷ FFI export set:** fully in sync — **63 == 63**, set-identical, both `comm`
  directions empty; 8 consts match name+value, 9 structs map 1:1, the `gmcrypto_rng_callback`
  typedef matches.
- **v0.23 "always-on AEAD/XTS FFI" — claim (3):** confirmed — **zero** `#[cfg(feature)]` gates on
  any export; the C shim drops the forwarding features; the default build compiles all 63 symbols.
- **63-vs-65 export-count "contradiction":** not real — **63** = exported symbols; **65** = the
  `c_smoke` `#[test]` count. Two distinct, correctly-labeled metrics.
- **Other opt-in features** (`sm4-aead` / `sm4-xts` / `sm4-bitsliced` / `-simd` / `digest-traits` /
  `cipher-traits`): introduce no accidental public surface and no crypto-bigint leak; SIMD/bitsliced
  helpers are `pub(crate)`; trait impls live in private modules.
- **crypto-bigint posture — claim (4):** `asn1::{reader,writer,oid}` + `traits` hidden; wire types
  `asn1::{encode,decode}_sig` + `Sm2Ciphertext` public and `[u8;32]`-typed.
- **`public-api` gate's `--omit auto-trait-impls` blind spot:** real but **deliberate, documented,
  and fully compensated** by the now-enforced `cargo-semver-checks` forward gate (#86) — context,
  not a defect.
- **`sign_raw_with_id` exposes `(U256,U256)` and is not feature-gated:** acceptable — correctly
  `#[doc(hidden)]`, honestly labeled "not covered by SemVer," absent from the baseline; public
  `sign_with_id` converts to `[u8;32]` internally, so no visible signature names `U256`.
- **Cosmetic re-export asymmetry** (`sign_raw_with_id` / `take_output` re-export lines lack a
  belt-and-suspenders `#[doc(hidden)]`): the definition-site attribute suffices, proven by baseline
  absence.
- **In-crate `BlockCipher`/`Hash`/`Mac` impls on visible types lack `#[doc(hidden)]` on the impl
  block:** correctly absent from the baseline (impl of a doc-hidden *trait* is treated as hidden);
  honestly labeled internal in `traits.rs:11-17`.

---

## 4 · Findings mapped to the 5 focus areas

| Focus area | Outcome |
|---|---|
| **rust-api-baseline** (committed `cargo-public-api` baseline vs source) | **No source-supported defect in the checked scope.** Baseline matches source bidirectionally; doc-hidden omissions correct; the documented `--omit auto-trait-impls` gate gap is deliberate + compensated. |
| **c-abi** (header ⟷ FFI exports, always-on posture, symbol count) | **M-3** (`gmcrypto_version()` returns `"0.4.0"` — runtime-value defect, not header drift). Header/export set-identity, always-on posture, and the 63-vs-65 reconciliation all clean. |
| **feature-gated-api** (crypto-bigint exposure across feature flags) | **No source-supported defect in the checked scope.** Default-features surface is crypto-bigint-clean; sole residual is the documented opt-in `from_scalar(U256)`; no feature leaks stray public surface. |
| **doc-hidden-boundaries** (hidden items leaking into the visible SemVer surface) | **No source-supported defect in the checked scope.** No hidden curve type, `sign_raw_with_id`, `take_output`, in-crate trait impl, or `gmcrypto-simd` symbol surfaces into a visible signature or the baseline; one cosmetic re-export-attribute asymmetry only. |
| **docs-semver-claims** (stability/SemVer prose vs shipped state) | **M-1, M-2, L-1, L-2** — the cluster of doc/runtime-value staleness that survived the bump. Claims (1)–(4), the FFI symbol count, MSRV = 1.85, and the exact `=1.0.0` sibling pins all verified consistent. |

---

## 5 · Scope & residual risk (honesty caveats)

**Static analysis only** under the read-only constraint: Read + Grep + read-only git against the
**committed** artifacts on `main`. The following were deliberately **not** performed and remain
unverified by this pass:

1. **No `cargo public-api` run.** The baseline-vs-source equivalence is a read+grep correspondence,
   not a tool re-run. A tool-only rendering difference — exact type pretty-printing, impl ordering,
   an auto-derived impl that the omit-flags would or wouldn't drop — cannot be fully excluded. CI's
   enforced `git diff --exit-code` on a real regeneration is the authoritative check.
2. **No C-header / baseline regeneration.** The `gmcrypto.h` ⟷ source set-identity was verified by
   name/value/struct comparison, but **`cbindgen` was not run**, so byte-for-byte reproduction of
   the committed header is unproven (the CLAUDE.md drift gate covers this in CI).
3. **No feature-enabled or cross-target builds.** No compilation under any feature matrix, MSRV
   1.85, wasm32, or `--no-default-features`; cfg-gating was read, not exercised. A cfg combination
   that fails to compile, or a feature-gated item the source-grep mis-attributed, would not be
   caught here.
4. **`--omit auto-trait-impls` surface is structurally invisible to the baseline gate.** Any
   accidental loss of `Send`/`Sync`/`Unpin`/`RefUnwindSafe` membership on a public type is *not*
   recorded in the committed baseline and would not be caught by static inspection of it — it
   relies entirely on the now-enforced `cargo-semver-checks` forward gate, which this audit did not
   run.
5. **The crates.io publish itself is unverified** (no network). On-disk evidence proves only the
   signed tag, the `1.0.0` workspace version, and the exact sibling pins; whether `cargo publish`
   actually landed is **asserted by the tag message, not on-disk-proven**.

**Net residual risk is low for the API/ABI freeze** — the surface and the C ABI are internally
consistent and match source within the checkable scope — and is concentrated instead in
**documentation accuracy** (M-1 / M-2 / L-1 / L-2) plus the **M-3 runtime version string** that
will report `"0.4.0"` to every 1.0.0 C consumer. Per the failure-mode invariant this audit did
**not** treat the single-`Failed`/`None`/`bool` error surfaces as instability. Cryptographic
correctness and constant-time discipline are **out of scope** — see
`docs/audits/2026-06-02-ct-discipline-audit.md`.

---

## Provenance

Generated by a read-only Claude Code dynamic workflow (`audit-v1-api-abi-stability`, run
`wf_7d395b47-56e`). No files edited, nothing committed/pushed/published/tagged, no CI or secrets
touched during the audit. This document is a working-tree artifact; commit/track at your discretion
(per the branch+PR rule, the agent did not commit it).
