# v1.0 open-source readiness checklist

**Started:** 2026-05-17 · **Repo state:** v0.9.0 on `main` (private) ·
**History:** 193 commits, 2.9 MB `.git`.

**Publication target: v1.0.** The repo stays **private** until then. This is
a standing checklist — items that are safe and cost-free now are done
immediately; items that only matter once the repo is public (or that have a
real cost while private) are **staged** and applied during the v1.0 pre-flip
pass. Git history becomes permanently visible on a public repo, so the bar is
"nothing in the working tree *or* history should embarrass or endanger us
once it's world-readable, and the CI / community surface should be credible
for a cryptography library."

Findings are ranked by risk. Each is marked **[done]** (landed now, in the
audit PR), **[ok]** (checked, no action), or **[staged — pre-publish]** (a
change prepared but deliberately deferred to the v1.0 flip — see the
pre-flip checklist at the end).

> **Why staged, not done:** the self-hosted-runner risk and the CLAUDE.md
> runbook exposure are *public-repo* problems only. While the repo is
> private, only trusted users can trigger CI, so the self-hosted runner is
> safe — and GitHub-hosted **macOS** minutes bill at a 10× multiplier
> against the private-repo quota (the exact cost the self-hosted runner was
> chosen to avoid). Migrating months early would burn quota for zero
> security benefit. So the migration is prepared and parked, not applied.

---

## 🔴 Critical

### C1 — Self-hosted CI runner must not survive the public flip  **[staged — pre-publish]**

`ci.yml`'s five jobs run on a self-hosted macOS runner
(`[self-hosted, macos, arm64, gmcrypto]`) and trigger on
`pull_request: branches: [main]`. **While the repo is private this is
safe** — only trusted users can open PRs that trigger CI. But the moment
the repo goes public it becomes remote code execution: any fork PR would
run on the maintainer's Mac (arbitrary code as the `ghrunner` account,
warm-cache poisoning, potential secret access). GitHub explicitly recommends
never using self-hosted runners with public repositories.

**Staged, not applied** (see the box at the top for the cost rationale). The
swap is one mechanical change to `ci.yml`, to be applied during the v1.0
pre-flip pass:

1. On all five jobs: `runs-on: [self-hosted, macos, arm64, gmcrypto]` →
   `runs-on: macos-14` (GitHub-hosted aarch64).
2. Delete the self-hosted-only cache tunings from every `Swatinem/rust-cache@v2`
   block: drop `cache-bin: "false"` and `save-if: ${{ github.ref == 'refs/heads/main' }}`
   (ephemeral hosted runners want rust-cache's defaults).
3. Bump `timeout-minutes` (cold hosted builds are slower than the warm
   self-hosted cache): build 15→30, msrv 10→20, cabi 10→20, deny 5→15,
   wasm32 10→20.
4. Replace the self-hosted header comment block + the `## CI runner` note
   in CLAUDE.md (see S3).

A header comment in `ci.yml` already flags this (`>>> BEFORE MAKING THIS
REPO PUBLIC …`). The dudect workflows stay on `ubuntu-latest` regardless
(their `|tau|` gates are calibrated to that image; see
`docs/v0.5-dudect-recalibration.md`).

**Done now (runner-independent):** closed a real coverage gap — `ci.yml`
now exercises `sm4-aead` (the v0.8/v0.9 flagship had zero build/test/clippy
coverage; only the dudect matrix touched it), across `gmcrypto-core`
(alone + with `sm4-bitsliced-simd`), `gmcrypto-c` (FFI), the MSRV build, the
`cargo-deny` opt-in pass, and the wasm32 builds. These run fine on the
current self-hosted runner.

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

### S3 — `CLAUDE.md` self-hosted runbook exposure  **[staged — pre-publish]**

`CLAUDE.md` carries an ~138-line self-hosted-runner runbook (service-account
name, home paths, runner-registration token flow). Not secret, and **still
operationally needed while the self-hosted runner is in use** (re-registering
the runner if it dies). So it stays until C1's migration happens. At the v1.0
pre-flip pass, remove the `## Self-hosted CI runner setup` section + trim the
"Workflow notes" bullet + update the architecture-map `ci.yml` line to
GitHub-hosted — together with the C1 runner swap (the runbook is dead weight
the instant the self-hosted runner is retired). This was prototyped during
the audit and reverted to keep the doc accurate to the current self-hosted
reality.

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

## v1.0 pre-flip checklist (do these when actually making the repo public)

**In the repo (staged changes to apply — see C1, S3):**

- [ ] Swap `ci.yml`'s five jobs from `[self-hosted, macos, arm64, gmcrypto]`
      to GitHub-hosted `macos-14`; drop the self-hosted cache tunings; bump
      timeouts (C1, step list).
- [ ] Remove the `## Self-hosted CI runner setup` runbook from `CLAUDE.md` +
      update the Workflow-notes bullet + the architecture-map `ci.yml` line
      (S3).
- [ ] Decommission the self-hosted runner (remove it in
      Settings → Actions → Runners; wipe `~ghrunner/actions-runner/_work`).

**In the GitHub UI (cannot be set from inside the repo):**

- [ ] **Settings → Code security:** enable **Secret scanning** + **Push
      protection**, and **Dependabot** alerts + security updates (all free on
      public repos). Forward-looking cover for S1.
- [ ] **Settings → Actions → General:** set **Fork pull request workflows
      from outside collaborators** to *Require approval for all outside
      collaborators* (defence in depth even on hosted runners), and set
      **Workflow permissions** to *Read repository contents* (least
      privilege; the workflows need no write token).
- [ ] **Settings → Branches:** add a branch-protection rule on `main` —
      require the CI checks (build / msrv / cabi / deny / wasm32) + at least
      one approving review; disallow force-push.

**Final sweep:**

- [ ] Run one authoritative `gitleaks detect` over history + working tree
      (no scanner was installed at audit time; the manual high-signal sweep
      was clean — S1).
- [ ] (Optional) Add a `.mailmap` to unify the two author display names (S2).
- [ ] (Optional) Add a one-line "not independently audited" banner near the
      top of the README (L1).
- [ ] Confirm the crates.io README/links render (they point at the GitHub
      repo, which becomes reachable on flip).
- [ ] Re-read `CLAUDE.md` once more with fresh eyes for any internal detail
      not wanted in public (it's retained deliberately as the agent guide).

## What this audit did NOT change

- No git-history rewrite (none warranted — history is clean).
- No code/algorithm changes (out of scope for an open-sourcing audit).
- The self-hosted runner stays live until v1.0 (publication is deferred);
  the migration is staged, not applied — see C1.
- `CLAUDE.md` retained as the internal/agent guide; only the self-hosted
  runbook is slated for removal at the flip (S3).
