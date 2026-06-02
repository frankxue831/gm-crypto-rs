# Doc ↔ Code ↔ CI consistency audit — gm-crypto-rs `1.0.0`

| | |
|---|---|
| **Date** | 2026-06-02 |
| **Commit** | `12e26b4` (`main`, workspace `1.0.0`; HEAD is one commit past the signed `v1.0.0` tag `e4de463`, via PR #86) |
| **Question** | Do the docs (CLAUDE.md, README, SECURITY, CHANGELOG, `docs/v1.0-readiness.md`) match current code and CI across 5 focus areas: CT/dudect claims · threat-model/side-channel · fuzz count/scope · v1.0 SemVer/API/ABI · features/no_std/MSRV/C-ABI? |
| **Method** | Read-only multi-agent workflow (`audit-docs-vs-code-ci-consistency`): recon (authoritative counts) → 5-area parallel inspection checking doc↔code↔CI tri-directionally → per-finding adversarial verification (refute-by-default, risk-tier assignment) → dedupe/rank synthesis. 23 agents; 16 candidates → 12 labeled discrepancies + 2 clean-scopes + 1 refuted; **0 unresolved hypotheses**. |
| **Companions** | Cross-referenced 4 of the 5 audits already in `docs/audits/`: `api-abi-stability-audit`, `ct-discipline-audit`, `fuzz-coverage-gaps`, `ci-gate-review` (the 5th, `dependency-policy-audit`, was out of this mission's scope). Overlaps re-verified independently against current source/CI and labeled *already-reported* vs *NEW*. |
| **Static vs dynamic** | **Static / read-only only.** No CI executed, no `cargo public-api` / `cbindgen` / `cargo-semver-checks` / `cargo build` run; doc↔code↔CI correspondences are read-level against the committed YAML/source. |

## Executive summary

Compared the docs against the shipping `1.0.0` source and the five committed workflows. The
`v1.0.0` tag is cut and `cargo-semver-checks` is **enforced** (no `continue-on-error`), so the
SemVer/stability claims are now *live*, not aspirational. **12 labeled discrepancies —
1 release/SemVer-critical · 8 misleading-low-risk · 3 stale-wording** — plus **2 verified
clean-scopes** (C-1, C-2), **1 refuted** candidate (#7), and **0 unresolved hypotheses**. The
single highest-tier issue (`SECURITY.md` still declaring the line "pre-1.0 (0.x)") is a
stability-contract mismatch already raised by the api-abi companion (its M-1). The rest are
documentation / CI-summary staleness that survived the `0.16.0 → 1.0.0` bump; **none weakens a
constant-time gate or breaks the locked API/ABI/wire format.**

S-1 is the doc-vs-doc projection of M-4, and S-3 is a sub-part of M-6, so the 12 labeled entries
collapse to **≈10 distinct root issues**.

> **Count reconciliation (workflow self-correction):** the synthesis agent's own headline said
> "11 distinct findings — 1 / 6 / 4." That undercounts its own body, which labels **12** entries
> (R-1; M-1…M-8; S-1…S-3) = **1 / 8 / 3**. Reconciled here to the body's actual labels. (The
> structured run returned 15 confirmed / 1 refuted across the 16 raw dossier entries; the
> 15 confirmed map to the 12 discrepancy labels after merges + the 2 clean-scopes.)

---

## Confirmed discrepancies, ranked by tier

### 🔴 RELEASE/SEMVER-CRITICAL

#### R-1 · `SECURITY.md` still declares the crate line "pre-1.0 (0.x)" on a shipped, tagged 1.0.0
- **DOC:** `SECURITY.md:18` — `## API stability & SemVer`: *"The crate line is pre-1.0 (0.x); the
  **v1.0 readiness audit** (v0.21) froze and CI-guarded the public surface **ahead of a `1.0`
  commitment**…"* (present/future tense).
- **CODE/CI contradicting:** root `Cargo.toml:24` `version = "1.0.0"`; `git rev-list -n1 v1.0.0` =
  `e4de463` (signed tag); HEAD `12e26b4` = PR #86 "enforce cargo-semver-checks forward gate
  (post-1.0.0 publish)". Sibling docs already flipped: `README.md:92` *"The line graduates to
  **1.0 (stable)** with this release."*; `README.md:104` *"**From 1.0, SemVer is enforced**"*;
  `CHANGELOG.md:8` `## [1.0.0] - 2026-06-01`.
- **Mismatch:** The canonical stability-contract document a security integrator reads opens by
  declaring the line still 0.x — misleading in the **dangerous direction**: a reader stopping at
  the opening clause concludes SemVer is not binding and breakage is permitted (0.x semantics),
  the opposite of the now-enforced forward gate (`api-stability.yml:72-97`, no `continue-on-error`).
  Last touched in v0.23 (`41d1ca9`); `SECURITY.md` was **not** among the files re-synced by the
  bump PR #85 (`976bd72`). Mild mitigation: the same paragraph's later sentence ("The SemVer
  contract covers…") is present-tense-correct, giving a full-read reader mixed signals.
- **Tier rationale:** A stability/SemVer-contract claim that misleads a 1.0 consumer about an
  actual guarantee — not a crypto over-claim (so not security-critical), not functionally inert
  (so not stale-wording).
- **Overlap:** already reported — api-abi companion **M-1** (verbatim `SECURITY.md:18`).
  Independently re-verified here against current source.

---

### 🟠 MISLEADING-LOW-RISK

#### M-1 · `SECURITY.md`'s "not covered by SemVer" `#[doc(hidden)]` list stops at v0.22 — omits the v0.23-hidden surface
- **DOC:** `SECURITY.md:26-30` enumerates only `sm2::sign_raw_with_id`, the two
  `Sm4Cbc{Encryptor,Decryptor}::take_output` drains, and (since v0.22)
  `sm2::curve`/`sm2::scalar_mul`/`ProjectivePoint::to_affine`. A grep of `SECURITY.md` returns
  **zero** hits for `from_point`, `asn1::reader/writer/oid`, `traits::`, or `sm2::point`-as-module.
- **CODE/DOC contradicting:** the v0.23-hidden items are genuinely `#[doc(hidden)] pub` —
  `sm2/mod.rs:20-21,41-42` (`point` module + `ProjectivePoint` re-export),
  `public_key.rs:20-22,29-31,71-72` (`from_point`/`point`/`From<ProjectivePoint>`),
  `asn1/mod.rs:10-18` (reader/writer/oid), `lib.rs:76-77` (`traits`). The **full** sibling list
  lives at `README.md:114-123` and `CHANGELOG.md:86-98`.
- **Mismatch:** A reader treating `SECURITY.md` as authoritative could wrongly believe
  `ProjectivePoint` / `asn1::reader|writer|oid` / `traits` are SemVer-covered.
- **Why low-risk (not R-tier):** The machine-enforced contract is **correct** —
  `docs/api-baseline/gmcrypto-core.txt` has no matches for any omitted item, so the
  `cargo-public-api` drift-check + `cargo-semver-checks` gates do not treat them as covered; they
  show as `#[doc(hidden)]` in rustdoc. The harm is one incomplete prose enumeration in a secondary
  doc, contradicted by README + CHANGELOG + source. (Verifier down-tiered from the candidate's
  release-semver-critical.)
- **Overlap:** already reported — api-abi companion **M-2** (same `SECURITY.md:26-30`).

#### M-2 · `CLAUDE.md` describes the semver-checks leg as `continue-on-error` / `vs crates.io 0.16.0` — both literals false in the current YAML
- **DOC:** `CLAUDE.md:779` (Architecture map): *"(2) cargo-semver-checks **INFORMATIONAL pre-1.0
  (continue-on-error; vs crates.io 0.16.0**; becomes the enforced forward gate from 1.0)"*; echoed
  at `CLAUDE.md:122-123`.
- **CI contradicting:** `api-stability.yml:73` job name `cargo-semver-checks (enforced, >=1.0)`;
  `:86-88` comment *"ENFORCED from 1.0 … **No continue-on-error**: semver-checks compares HEAD
  against the latest crates.io release (now 1.0.0)"*; `:96-97` runs `cargo semver-checks
  check-release` with **no** error suppression. Repo-wide grep of `.github/workflows/` for
  `continue-on-error` returns **only** the negating comment at `api-stability.yml:87`.
  `check-release` baselines against the *latest* published version (now 1.0.0), not 0.16.0.
- **Mismatch:** `CLAUDE.md:779` asserts two concrete, verifiable falsehoods about a
  SemVer-enforcement gate — that it is non-blocking and baselines against 0.16.0 — the opposite of
  the enforced reality. Stays low-risk because it is an agent-facing doc and the truth is
  recoverable from the YAML and `CLAUDE.md:21`. (`CLAUDE.md:122-123` in isolation is defensible as
  v0.21-cycle-correct; #779's two false literals anchor the finding.)
- **Overlap:** **NEW.** The api-abi companion explicitly did not inspect `api-stability.yml` job
  state for this line.

#### M-3 · `docs/v1.0-readiness.md` checklist row 47 still marks `cargo-semver-checks` `⏳ flip at 1.0` / "informational pre-1.0" — already enforced
- **DOC:** `docs/v1.0-readiness.md:47` `| cargo-semver-checks enforced | ⏳ **flip at 1.0** |
  informational pre-1.0 (0.x permits breakage); becomes the forward gate from 1.0 (§3.A note, §4) |`.
- **CI contradicting:** `api-stability.yml:72-97` — job live and enforced, no `continue-on-error`
  (as M-2). git is decisive: bump PR #85 (`976bd72`) flipped the *adjacent* row (line 46 ⏳→✅) but
  left line 47; PR #86 (`12e26b4`, HEAD) flipped the CI to enforced but did **not** update the doc.
- **Mismatch:** The readiness checklist tells a maintainer the gate is still pending/informational
  while it is live. Direction is the *safe* one (under-claims an active guarantee). Authoritative
  consumer-facing docs (`README.md:104-105`, `CHANGELOG.md:18-19`) state enforcement correctly.
- **Tier note:** The candidate said misleading-low-risk; the dossier verifier re-tiered to
  stale-wording (under-claim, safe direction, historical report). Placed at **misleading-low-risk**
  because it concerns the *enforcement posture of a SemVer gate* and sits one row below a row PR #85
  *did* update (a reader reasonably trusts the table is current). **A reviewer may down-tier to
  stale-wording — flagged for human judgment.**
- **Overlap:** **NEW** (distinct from api-abi L-2, which cites the *status header* at `:1-23`).

#### M-4 · CLAUDE.md says both dudect workflows "stay on `ubuntu-latest`" — both are pinned to `ubuntu-24.04` (4 doc instances, one root)
- **DOC (4 stale instances):** `CLAUDE.md:813-814` *"The two dudect workflows / also stay on
  `ubuntu-latest`"*; `CLAUDE.md:776` *"dudect-pr.yml # 10K samples on ubuntu-latest"*;
  `CLAUDE.md:777` *"dudect-nightly.yml # 100K samples on ubuntu-latest"*.
- **CI contradicting:** `dudect-pr.yml:36` `runs-on: ubuntu-24.04` (comment `:30-31` *"pinned
  `ubuntu-24.04` (OS-label pin, **was `ubuntu-latest`**)"*); `dudect-nightly.yml:45` identical.
- **DOC self-contradiction (proving the pin is real):** `CLAUDE.md:200`, `:580` *"the dudect
  workflows are pinned to `ubuntu-24.04`"*, and `:986` *"Don't bump … the `runs-on: ubuntu-24.04`
  … casually (v0.18)"* all state the pin correctly. So this is both doc-vs-CI and doc-vs-doc.
- **Mismatch:** The stated runner *value* is wrong, and it **inverts the point of the v0.18 W1 pin**
  (the workflows were deliberately moved *off* `ubuntu-latest`). A reader could re-introduce float
  or misread the pin. The calibration-intent half (`:815-816`) is correct. No `|tau|<0.20` gate is
  loosened (gates still run on 24.04), so no real leak passes — hence low-risk, not
  security-critical.
- **Overlap:** **NEW** for the dudect-runner OS-label. Not raised by ct-discipline; the
  ci-gate-review companion reviews these workflows for gate *effectiveness* but not the
  `ubuntu-latest`-vs-`ubuntu-24.04` doc-string mismatch.

#### M-5 · CLAUDE.md dudect arch-map lists a 3-entry feature matrix — the workflows run 4 legs (the 4th gates the AEAD/XTS CT targets)
- **DOC:** `CLAUDE.md:776` *"matrix on features=[default, sm4-bitsliced, sm4-bitsliced-simd]"*;
  `:777` inherits ("same gate + matrix").
- **CI contradicting:** `dudect-pr.yml:73-77` and `dudect-nightly.yml:68-72` define a **4-entry**
  matrix, adding `"sm4-bitsliced-simd,sm4-aead,sm4-xts"` — the only leg that gates
  `ct_sm4_gcm_decrypt` / `ct_sm4_ccm_decrypt` / `ct_sm4_xts_decrypt` (conditional gates at
  `dudect-pr.yml:288-309`).
- **Mismatch:** A coverage-summary completeness gap — the arch-map omits the leg that exercises the
  AEAD/XTS constant-time targets. No functional effect on the gates that actually run (the
  workflows are authoritative).
- **Overlap:** **NEW.**

#### M-6 · README Quick-start does not compile against 1.0.0 — `Sm2PublicKey::from_point(key.public_key())` is a type error on a doc-hidden constructor
- **DOC (broken example):** `README.md:631` `let public = Sm2PublicKey::from_point(key.public_key());`
  (block `:617-636`).
- **CODE contradicting:** `private_key.rs:132-134` `public_key()` returns
  `crate::sm2::Sm2PublicKey`; `public_key.rs:20-22` `#[doc(hidden)] pub const fn from_point(point:
  ProjectivePoint) -> Self` (and `:72` `From` is from `ProjectivePoint` only). So a `Sm2PublicKey`
  is passed where a `ProjectivePoint` is required → **rustc E0308**, and `from_point` is off the
  supported surface (`#[doc(hidden)]`). The correct v1.0 line is `let public = key.public_key();`.
- **DOC self-contradiction:** `README.md:124-128` states `public_key()` returns `Sm2PublicKey`;
  `README.md:119` lists `Sm2PublicKey::{from_point, point}` as doc-hidden. The README's own example
  contradicts its own contract.
- **Not caught by CI:** the README is **not** a doctest — grep for `include_str!` across the three
  crates' `src/lib.rs` returns no match (`lib.rs:3` references the README only in prose), so
  `cargo test` never compiles it.
- **Cosmetic sub-part (→ S-3):** the same block (`:623` `use rand_core::UnwrapErr;`, `:633`
  `UnwrapErr(SysRng)`) and the wasm32 example (`:683`, `:686`) still wrap the RNG in `UnwrapErr`,
  which v0.23's fallible `TryCryptoRng` bound (`sign.rs:105`, `encrypt.rs:115`) made unnecessary.
  This **still compiles** (every `CryptoRng`/`SysRng` blanket-impls `TryCryptoRng`) and is pure
  stale-wording; the intended pattern is passing `getrandom::SysRng` directly (as the C shim does
  at `lib.rs:2028,2099` and every in-crate test). `CLAUDE.md:48` confirms v0.23 "drops the
  `UnwrapErr` adapter".
- **Mismatch:** The first snippet a 1.0 consumer copies fails to compile (the `from_point` line); a
  needless `UnwrapErr` import lingers (cosmetic). Misleads the first-time user but makes no false
  stability/SemVer/crypto guarantee.
- **Overlap:** the *facts* (public_key→Sm2PublicKey; from_point doc-hidden) are the api-abi
  companion's verified non-findings (§3); the **broken example itself is NEW** — api-abi did not
  inspect README code blocks.

#### M-7 · CHANGELOG `[1.0.0]` cross-references nonexistent `### v0.17`–`### v0.23` subsections; the v0.20 fuzz expansion (16→18) is absent
- **DOC:** `CHANGELOG.md:21-22` *"…detailed in the `### v0.17`–`### v0.23` subsections below"* and
  `:47` *"per-cycle subsections below for the detail."*; the only target count stated is `:273`
  *"with **16 targets**"* and `:290` *"all 16 targets"* — both inside the **[0.16.0]** section
  (header `:191`), recapping v0.14.
- **CODE/DOC contradicting:** `grep -cE '^### v0\.[0-9]' CHANGELOG.md` = **0**; the `[1.0.0]` body's
  `###` headers are generic; the only per-cycle markers are **bold** paragraphs at `:49`
  (`**v0.23 —**`), `:124` (`**v0.22 —**`), `:161` (`**v0.21 —**`) — v0.17–v0.20 have no paragraph.
  The v0.20 fuzz state is recorded nowhere (grep for `18 target | streaming-decryptor |
  fuzz_sm4_*_streaming | cargo fuzz coverage` in `CHANGELOG.md` → nothing). Ground truth = **18**
  (see C-1 / refuted #7).
- **Mismatch:** Dead anchor references + a shipped assurance change (the 16→18 fuzz expansion that
  *ships in 1.0.0*) recorded nowhere in the changelog. The CHANGELOG is the lone doc still implying
  16 + pointing at nonexistent anchors (current docs say 18: `README.md:22`, `CLAUDE.md:768/778`).
  A navigation-and-completeness defect that misdirects a 1.0.0 reader — above pure stale-wording
  because it actively misdirects.
- **Overlap:** **NEW.**

#### M-8 · CLAUDE.md documents `sm4-xts` as an MSRV-1.85 and wasm32 build-verification command; neither the ci.yml MSRV nor wasm32 job builds `sm4-xts`
- **DOC:** `CLAUDE.md:504` (`# MSRV reproducibility`) lists `…,sm4-aead,sm4-xts,crypto-bigint-scalar`;
  `CLAUDE.md:509-510` *"sm4-xts is pure-core/no_std, so it **must build on wasm32 too**"* + a
  `--features sm4-xts` wasm32 command. (Same-class: `CLAUDE.md:500` cargo-deny lists `sm4-xts`.)
- **CI contradicting:** `ci.yml:195` (msrv) builds `…,sm4-aead,crypto-bigint-scalar` — **no
  `sm4-xts`**; `ci.yml:319/323` (wasm32) build only `--no-default-features` and `--features
  sm4-aead` — never `sm4-xts`; `ci.yml:274` (deny) omits it. `sm4-xts` is compiled+tested only via
  `api-stability.yml:130-132` `--all-features` on `stable` (host x86_64) — never MSRV-1.85, never
  wasm32.
- **Mismatch:** The documented per-toolchain/per-target repro commands are not gated in CI for
  `sm4-xts`. Low practical impact: `sm4-xts` is pure-core with no new dep (`sm4-xts = []`), so an
  MSRV/wasm32-specific break unique to it and missed by the stable `--all-features` test is
  unlikely. (Caveat: CLAUDE.md's Commands section is a *local-repro* reference and nowhere claims
  CI *gates* `sm4-xts` on MSRV/wasm32 — so this is a doc-command-vs-CI-coverage gap, slightly
  narrower than "documented CI guarantee".)
- **Overlap:** **already reported** — ci-gate-review companion **Med** (lines 23, 37, 59:
  *"`sm4-xts` absent from every per-feature `ci.yml` gate … standalone clippy, wasm build,
  cargo-deny second pass, MSRV opt-in build"*). That companion frames it as a CI-effectiveness gap;
  this audit frames the same root as a doc-command-vs-CI mismatch. **Same root.**

---

### 🟡 STALE-WORDING

#### S-1 · CLAUDE.md "don't move dudect … to `ubuntu-latest`" rationale is internally contradicted by its own v0.18 `ubuntu-24.04` pin narrative (doc-vs-doc projection of M-4)
- **DOC-A (stale):** `CLAUDE.md:813-816` ("stay on `ubuntu-latest` … don't move dudect").
- **DOC-B (correct, ×3):** `CLAUDE.md:200`, `:580`, `:986` all say `ubuntu-24.04`.
- **CI tie-breaker:** `dudect-pr.yml:36` / `dudect-nightly.yml:45` = `ubuntu-24.04`.
- **Mismatch:** Two CLAUDE.md passages cannot both be right; the v0.18/`ubuntu-24.04` version
  matches the YAML, and DOC-A's own next clause names `ubuntu-24.04` as the calibration floor
  (conflating the stale label with the current target). No `|tau|` gate/target/threshold is
  misstated. **Treat M-4 + S-1 as one root issue** spanning 4 doc lines (#776, #777, #813–814)
  against the CI and against #200/#580/#986; listed separately only to record the doc-vs-doc
  direction.

#### S-2 · `docs/v1.0-readiness.md` status header narrates the publish as "now executing via `feat/v1.0-release`" / "taken later" — already completed
- **DOC:** `docs/v1.0-readiness.md:7-10` *"The `1.0.0` publish is now executing via the
  `feat/v1.0-release` branch (§4) … the irreversible `cargo publish` + signed tag are the final
  maintainer step after it merges"*; `:21-23` *"a **separate, deliberate step** taken later"*;
  `:252-253` §4 step 7 lists the semver-checks-enforce flip as still to perform.
- **CODE/CI contradicting:** `Cargo.toml:24` `version = "1.0.0"`; `git rev-list -n1 v1.0.0` =
  `e4de463`; `git log v1.0.0..HEAD` = only `12e26b4` (PR #86, the §4-step-7 flip *already
  performed* — `api-stability.yml:72-97`, no `continue-on-error`); `feat/v1.0-release` is
  superseded.
- **Mismatch:** Process-narrative staleness — no API/ABI/SemVer/wire guarantee is misstated; the
  pins are exact, the publish order is correct, the active guarantees are in place. A 1.0 consumer
  is misled only about *whether the publish already occurred*. This narrative is the root that
  leaves M-3 (row 47) and §4-step-7 stale.
- **Overlap:** already reported — api-abi companion **L-2** (`docs/v1.0-readiness.md:1-23`). Same
  root.

#### S-3 · README's lingering `UnwrapErr` RNG examples vs the `gmcrypto-c`/test `UnwrapErr`-free pattern (sub-part of M-6)
- See **M-6**'s cosmetic sub-part: `README.md:623/633/683/686` retain `UnwrapErr(SysRng)`;
  `sign.rs:105` / `encrypt.rs:115` take `TryCryptoRng`; the intended pattern (no wrapper) is what
  `gmcrypto-c/src/lib.rs:2028,2099` and all in-crate tests use; `CLAUDE.md:48` says v0.23 "drops the
  `UnwrapErr` adapter". **Still compiles** — pure stale-wording. Folded into M-6 because it shares
  the example block; recorded here at its own tier since in isolation it is not a compile break.
- **Overlap:** **NEW.**

---

## Verified clean-scopes (status = confirmed no-finding)

Positive verifications — checked and found consistent, not defects. Per the security-codebase rule
these are stated as **"no source-supported finding in the checked scope," not "no issues."**

#### C-1 · Side-channel scope in SECURITY.md/README is honestly bounded; the default SM4 S-box is a genuine public-counter constant-time scan — **no source-supported over-claim in the checked scope**
- `SECURITY.md:36-38` scopes side channels to "what the in-CI `dudect-bencher` harness exercises …
  NOT in scope"; `:132` *"The harness detects leaks; it does not prove constant-time"*;
  `README.md:640-642` mirrors. The strongest positive CT statement (`SECURITY.md:242-254`) is framed
  strictly in terms of secret-dependent branches/timing — the dudect channel — and does **not**
  assert cache/power/EM resistance; `SECURITY.md:367-369` + `README.md:86-87` add honesty caveats
  ("degrades to best-effort" on variable-time-multiply CPUs).
- Code confirms: `crates/gmcrypto-core/src/sm4/cipher.rs:604-608` `sbox_ct` walks a fixed
  256-iteration loop, `i_u8.ct_eq(&x)` on the secret, `result.conditional_assign(&S_BOX[i as
  usize], eq)` — the array index is the **public loop counter**, never `S_BOX[secret]`. The only
  `S_BOX[x as usize]` site (`cipher.rs:783`) is inside a `#[cfg(not(feature="sm4-bitsliced"))]
  #[test]` equivalence check, never compiled into the shipping cipher.
- **Overlap:** consistent with the ct-discipline companion's headline ("no source-supported
  timing-leak finding"; S-box row).

#### C-2 · Feature-flag table, std-removal, no_std posture, MSRV value, and C-ABI always-on / single-error-code claims all match code + CI — **no source-supported finding in the checked scope**
- **7 opt-in features + `default = []`:** `gmcrypto-core/Cargo.toml:64` `default = []`; the 7 flags
  at `:68/69/76/89/113/121/129`; the `std`-removal comment at `:77-81`. `README.md:138` "all 7 are
  opt-in" matches; no documented-but-removed or undocumented flag.
- **C-ABI always-on:** `gmcrypto-c/Cargo.toml:29` pulls core with `features = ["sm4-aead",
  "sm4-xts"]` unconditionally (comment `:23` "ALWAYS compiled"); **zero** `cfg(feature` gates in
  `gmcrypto-c/src/lib.rs`; `gmcrypto.h` has 36 gcm/ccm/xts symbol refs and no cfg-gating; single
  `GMCRYPTO_ERR = -1` (`lib.rs:116`); header drift gate live (`ci.yml:224-227`).
- **no_std:** `core/src/lib.rs:59` `#![no_std]`; no `std::` paths in core src; `--no-default-features`
  exercised (`ci.yml:319`, `api-stability.yml:130`).
- **MSRV 1.85:** root `Cargo.toml:24/25/28`; `README.md:140`, `CLAUDE.md:452/471`; `ci.yml:187` msrv
  toolchain "1.85" + wasm32 matrix; the dudect runner `@1.95.0` (`dudect-pr.yml:89`,
  `dudect-nightly.yml:84`) is explicitly labeled "MUST be >= MSRV 1.85" — correctly distinct, no
  conflation.
- **Overlap:** the always-on FFI half overlaps the api-abi companion's verified non-finding (§3,
  "v0.23 always-on AEAD/XTS FFI"). The features/no_std/MSRV portions are NEW/uncovered.

---

## Hypotheses / needs human confirmation

**None.** Every dossier entry that reached a verdict was source-confirmed or source-refuted; no
`status=uncertain` candidates, and independent re-verification surfaced none.

Two residuals are **process, not code**, and cannot be settled read-only (carried from the
companion audits, not new here):
1. **Whether `cargo publish` (`gmcrypto-simd → core → c`) actually landed on crates.io** — on-disk
   state proves only the signed tag, the `1.0.0` workspace version, and the exact `=1.0.0` sibling
   pins; the upload is asserted by the tag message, not network-verified (api-abi companion §2/§5.5).
2. **M-3's tier** (misleading-low-risk vs stale-wording) — depends on how authoritative a reader
   treats a now-historical readiness/runbook checklist. Flagged in M-3 for human judgment.

---

## Refuted candidates (status = refuted — checked and dismissed)

- **Fuzz target count / scope under-count or under-run (dossier #7).** **Refuted — no
  source-supported discrepancy.** The docs say **18** and the CI runs the full 18. Three-way
  set-equality verified: `fuzz/fuzz_targets/*.rs` = 18 files (incl. `fuzz_sm4_cbc_streaming_decrypt`
  + `fuzz_sm4_gcm_streaming_decrypt`), `fuzz/Cargo.toml` `[[bin]]` = 18, and `fuzz-nightly.yml:51-57`
  `FUZZ_TARGETS` = 18. `FUZZ_TARGETS` is the single source of truth, consumed by both the `fuzz`
  sweep loop (`:89`) and the non-gating `coverage` job loop (`:151`). Docs concur: `README.md:22`
  "18-target", `CLAUDE.md:768/778`. Note: `README.md:22` (fuzz, 18) and `README.md:31` (dudect
  `ct_*`, 18) are **distinct subsystems** that coincidentally both total 18 — no conflation. *(The
  CHANGELOG's stale "16" is captured separately as M-7, a different doc.)*

---

## Findings mapped to the 5 focus areas

| Focus area | Outcome |
|---|---|
| **CT / dudect** | **M-4** (CLAUDE.md says dudect runs on `ubuntu-latest`; CI pins `ubuntu-24.04` — 4 doc instances) + **M-5** (3-vs-4 feature-matrix summary, omitting the AEAD/XTS-gating leg) + **S-1** (doc-vs-doc projection of M-4). No gate threshold/target misstated; no real leak passes. |
| **Threat-model / side-channel** | **M-6** (README quickstart compile break + lingering `UnwrapErr`) + **S-3** (RNG-example staleness). **C-1**: disclaimers honestly bounded, SM4 S-box is a genuine public-counter CT scan — **no source-supported over-claim in the checked scope**. |
| **Fuzz count / scope** | **M-7** (CHANGELOG dead `### v0.NN` anchors + the v0.20 16→18 fuzz expansion recorded nowhere). The live fuzz count/scope is consistent (refuted #7). |
| **v1.0 SemVer / API / ABI** | **R-1** (SECURITY.md "pre-1.0 (0.x)" on a shipped 1.0.0) + **M-1** (stale `#[doc(hidden)]` enumeration) + **M-2** (CLAUDE.md `continue-on-error`/`0.16.0` false literals) + **M-3** (readiness row 47 ⏳) + **S-2** (readiness status-header narrative). Adjacent (already-reported, not in this dossier): api-abi companion **M-3** `gmcrypto_version()` returns `"0.4.0"` (`gmcrypto-c/src/lib.rs:301`) and **L-1** stale `html_root_url`. |
| **Features / no_std / MSRV / C-ABI** | **M-8** (`sm4-xts` documented as an MSRV/wasm32 repro command but not built by those CI jobs — same root as the ci-gate-review companion's Med). **C-2**: feature table, std-removal, no_std, MSRV 1.85, C-ABI always-on / single-`GMCRYPTO_ERR` all match — **no source-supported finding in the checked scope**. |

---

## Scope & residual risk

**Static / read-only only.** Read + Grep + read-only git against the committed artifacts on `main`
(HEAD `12e26b4`). Deliberately **not** performed, and unverified by this pass:

1. **No CI executed.** doc↔CI correspondences (`runs-on`, matrix entries, `continue-on-error`
   absence, the `sm4-xts` feature lists) are read-level against the committed YAML — a real run
   could differ if a workflow is overridden by repo settings (branch protection / required checks
   are not in the repo).
2. **No `cargo public-api`, `cbindgen`, or `cargo-semver-checks` run.** M-1's "absent from the
   baseline" is a grep of the *committed* `docs/api-baseline/gmcrypto-core.txt`, not a tool
   regeneration; M-2/M-3/R-1's "the gate is enforced" is read from the YAML, not a passing run.
3. **No compilation.** M-6's "would not compile" is a type-level reading of `public_key()`/
   `from_point` signatures; the `UnwrapErr` "still compiles" claim (M-6/S-3) is a trait-resolution
   reading; M-8's "unlikely to break on MSRV/wasm32" is inference from `sm4-xts = []` (no new dep),
   not a built target.
4. **crates.io publish unverified** (no network) — see Hypotheses §1.
5. **Dossier verdicts trusted as inputs.** This synthesis re-verified every cited file+line on both
   sides; where a verifier re-tiered a candidate (M-1, M-2, M-3) both tiers are recorded and the
   residual judgment (M-3) is surfaced for a human.

**Net residual risk is low and concentrated in documentation accuracy.** No constant-time gate is
loosened, no locked API/ABI/wire-format claim is broken, and the two crypto/feature clean-scopes
(C-1, C-2) held under adversarial re-reading. The one release-tier item (R-1) and the doc-hidden
enumeration (M-1) are safe to correct in a `1.0.1` (doc-only); the api-abi companion's
`gmcrypto_version()` `"0.4.0"` (its M-3) is the one *runtime-value* defect adjacent to this scope
and is worth folding into the same doc/value fix pass. Per the project posture, the
single-`Failed`/`None`/`bool` failure-mode invariant and the intentionally-uncovered
`#[doc(hidden)]` surface were **not** treated as defects. Cryptographic correctness / constant-time
discipline beyond the doc-claim check is out of scope — see
`docs/audits/2026-06-02-ct-discipline-audit.md`.

---

## Provenance

Generated by a read-only Claude Code dynamic workflow (`audit-docs-vs-code-ci-consistency`, run
`wf_9338e28e-aaf`). No files edited, nothing committed/pushed/published/tagged, no CI or secrets
touched during the audit. The synthesis agent's headline finding-count (1/6/4) was reconciled to
its own body (1/8/3) by the orchestrator before saving; all cited file+line evidence and the
`ci-gate-review` companion cross-reference were spot-verified on disk. This document is a
working-tree artifact; commit/track at your discretion (per the branch+PR rule, the agent did not
commit it).
