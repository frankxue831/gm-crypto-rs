# Pre-open-source audit

**Date:** 2026-05-17 · **Repo state:** v0.9.0 on `main` · **History:** 193
commits, 2.9 MB `.git`.

Purpose: a one-time review before flipping `frankxue831/gm-crypto-rs` from
private to public. Git history becomes permanently visible on a public repo,
so the bar is "nothing in the working tree *or* history should embarrass or
endanger us once it's world-readable, and the CI/community surface should be
credible for a cryptography library."

Findings are ranked by risk. Each is marked **[fixed]** (addressed in the
audit PR), **[ok]** (checked, no action), or **[action]** (a GitHub-settings
or human step that must happen outside the repo — see the go-live checklist).

---

## 🔴 Critical

### C1 — Self-hosted CI runner on a (soon-to-be) public repo  **[fixed]**

`ci.yml`'s five jobs ran on a self-hosted macOS runner
(`[self-hosted, macos, arm64, gmcrypto]`) and triggered on
`pull_request: branches: [main]` with no fork guard. On a public repo this
is remote code execution: any fork PR would run on the maintainer's Mac
(arbitrary code as the `ghrunner` account, warm-cache poisoning, potential
secret access). GitHub explicitly recommends never using self-hosted runners
with public repositories.

**Fix:** migrated all five jobs to GitHub-hosted `macos-14` (aarch64).
Public repos get unmetered Actions minutes, and fork PRs running on hosted
ephemeral runners is the normal, safe OSS model. Removed the self-hosted
cache tunings (`cache-bin: false`, `save-if: main` — both self-hosted
artifacts). The dudect workflows stay on `ubuntu-latest` (their `|tau|`
gates are calibrated to that image; see `docs/v0.5-dudect-recalibration.md`).
Also closed a coverage gap: CI now exercises `sm4-aead` (the v0.8/v0.9
flagship feature had zero build/test coverage — only the dudect matrix
touched it).

---

## 🟡 Should-fix (credibility / accuracy / privacy)

### S1 — Secret scan of working tree + full history  **[ok]**

No `gitleaks`/`trufflehog` available locally, so a manual high-signal sweep
across all 193 commits' blobs:

- `BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY`, AWS `AKIA…`, GitHub `ghp_…`,
  Slack `xox…`, generic `api_key=…` → **no real matches.** Only hits:
  `crates/gmcrypto-core/src/pem.rs`'s malformed-input test string
  (`-----BEGIN PRIVATE KEY-----\nABCD\n`) and the CLAUDE.md *rule text*
  "don't reference the Java prototype" (the rule, not an actual reference).
- Tracked `.pem` files: `tests/data/v0_3-sm2-pkcs8-encrypted.pem` and
  `…-spki.pem` are gmssl-generated throwaway KAT fixtures (referenced in the
  CLAUDE.md architecture map), not production keys. Safe to publish.
- `.gitignore` keeps `Cargo.lock` out (lib-crate policy); no `.env`/key
  globs needed because none are produced.

**Still recommended:** after going public, enable GitHub's free secret
scanning + push protection (catches future accidental commits), and
optionally run `gitleaks detect` once for an authoritative pass. → see C-list.

### S2 — Commit-author privacy  **[ok]**

All 193 commits use the GitHub noreply address
(`47923440+frankxue831@users.noreply.github.com`). The maintainer's personal
email is **not** in history. Two display names appear (`Fengxiang Xue`,
`Frank_Xue`) sharing that noreply email — cosmetic; an optional `.mailmap`
could unify them. No `authors` field in any `Cargo.toml` (deliberate, per
CLAUDE.md). Nothing to remediate.

### S3 — `CLAUDE.md` self-hosted runbook exposure  **[fixed]**

`CLAUDE.md` carried an ~138-line self-hosted-runner runbook (service-account
name, home paths, runner-registration token flow). Not secret, but stale the
moment C1's migration landed. Removed it and replaced with a short
"## CI runner" note describing the GitHub-hosted setup; updated the
"Workflow notes" bullet and the architecture-map `ci.yml` line accordingly.

### S4 — `SECURITY.md` dudect inventory was stale  **[fixed]**

`SECURITY.md` (the doc security reviewers read first) claimed "14 real `ct_*`
targets (12 + 2)" and never listed the v0.8/v0.9 AEAD targets. Corrected the
count to 17 (12 always-on + 2 `sm4-bitsliced-simd` + 3 `sm4-aead`) and added
a "Cfg-gated on `sm4-aead` (3)" subsection covering `ct_sm4_gcm_decrypt`,
`ct_sm4_ccm_decrypt`, `ct_sm4_gcm_decrypt_buffered`. (The README's count was
already corrected in the v0.9 W5 release-prep.)

### S5 — `CONTRIBUTING.md` unsafe-posture claim was wrong  **[fixed]**

Claimed `unsafe_code = "forbid"` *workspace-wide*. Actually `gmcrypto-core`
is `forbid`; `gmcrypto-c` and `gmcrypto-simd` are `warn` (unavoidable FFI /
SIMD `unsafe`, every block `// SAFETY:`-commented). Corrected, and added the
AEAD dudect targets to the contributor verification list.

### S6 — Missing community-health files  **[fixed]**

Added: `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1 by reference, with a
privacy-respecting GitHub-based reporting contact), `.github/CODEOWNERS`,
`.github/PULL_REQUEST_TEMPLATE.md`, and `.github/ISSUE_TEMPLATE/`
(`bug_report.md`, `feature_request.md`, and a `config.yml` that disables
blank issues and routes security reports to the private advisory channel —
so vulnerabilities don't land in public issues). `ci.yml`'s `paths-ignore`
already referenced these paths; they now exist.

### S7 — Vulnerability disclosure channel  **[ok]**

`SECURITY.md` points reporters to GitHub Security Advisories (private, no
email exposure) and states a 5-business-day acknowledgement target + "no bug
bounty". Appropriate for a single-maintainer project. The new
`ISSUE_TEMPLATE/config.yml` reinforces it.

---

## 🟢 Low / awareness

### L1 — "Not audited" disclaimer  **[ok]**

`SECURITY.md` states this is "a personal open-source project … not a
certified cryptographic module" with no production-suitability claim, and
`README.md`'s "What this isn't" section scopes it. Adequate. Consider a
one-line "not independently audited — use at your own risk" near the top of
the README if you want it more prominent.

### L2 — Export control  **[ok / awareness]**

SM2/SM3/SM4 are Chinese GB/GM-T national-standard algorithms. Publishing
open-source software implementing them on a public host is generally fine
(open-source/published cryptography is broadly exempt under the relevant
software exemptions). No action; noted for awareness.

### L3 — Test-fixture keys  **[ok]**

The two `.pem` fixtures + the inline KAT vectors are gmssl/OpenSSL-generated
test material, never reused as real keys. Safe.

---

## Go-live checklist (GitHub settings — must be done by a human in the UI)

These cannot be set from inside the repo; do them when flipping to public (or
immediately after):

- [ ] **Settings → Code security:** enable **Secret scanning** + **Push
      protection**, and **Dependabot** alerts + security updates (all free on
      public repos). Covers S1 going forward.
- [ ] **Settings → Actions → General:** set **Fork pull request workflows
      from outside collaborators** to *Require approval for all outside
      collaborators* (defence in depth even on hosted runners), and set
      **Workflow permissions** to *Read repository contents* (least
      privilege; the workflows need no write token).
- [ ] **Settings → Branches:** add a branch-protection rule on `main` —
      require the CI checks (build / msrv / cabi / deny / wasm32) + at least
      one approving review; disallow force-push.
- [ ] (Optional) Run one authoritative `gitleaks detect --no-git` on the
      working tree and `gitleaks detect` over history before flipping public.
- [ ] (Optional) Add a `.mailmap` to unify the two author display names (S2).
- [ ] Confirm the crates.io README/links render (they point at the GitHub
      repo, which becomes reachable on flip).

## What this audit did NOT change

- No git-history rewrite (none warranted — history is clean).
- No code/algorithm changes (out of scope for an open-sourcing audit).
- `CLAUDE.md` retained (it's a useful internal/agent guide; only the
  self-hosted runbook was removed). Keeping it public is a deliberate choice.
