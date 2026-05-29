# Open-source readiness checklist (public flip executed at v0.17)

**Started:** 2026-05-17 · **Repo state:** v0.9.0 on `main` (private) ·
**History:** 193 commits, 2.9 MB `.git`.

**Publication decision (updated 2026-05-29): go public at v0.17, NOT v1.0.**
The original plan targeted v1.0; that was superseded. The repo flips
**private → public** on the 0.x line as the **v0.17 public-flip milestone**
— a *repository* milestone, **not** a crates.io release (no crate code
changes; the workspace stays at `0.16.0`, crates.io skips `0.17.0` per the
v0.14 precedent) — so the project gets public audit/eyes *before* committing
to the 1.0 SemVer-stability promise. **v1.0 is reserved** for a later
readiness pass (dudect-gate hardening + API-stability review). See
`docs/v0.17-scope.md` and the dated execution note at the end of this file.
This is a standing checklist — items safe and cost-free while private were
done immediately; items that only matter once the repo is public (or that
had a real cost while private) were **staged** and are applied during the
v0.17 pre-flip pass. Git history becomes permanently visible on a public
repo, so the bar is "nothing in the working tree *or* history should
embarrass or endanger us once it's world-readable, and the CI / community
surface should be credible for a cryptography library."

Findings are ranked by risk. Each is marked **[done]** (landed now, in the
audit PR), **[ok]** (checked, no action), **[staged — pre-publish]** (a
change prepared while private), or **[done — v0.17]** (a staged change
applied at the v0.17 public flip — see the dated execution note at the end).

> **Why staged, not done:** the self-hosted-runner risk and the CLAUDE.md
> runbook exposure are *public-repo* problems only. While the repo is
> private, only trusted users can trigger CI, so the self-hosted runner is
> safe — and GitHub-hosted **macOS** minutes bill at a 10× multiplier
> against the private-repo quota (the exact cost the self-hosted runner was
> chosen to avoid). Migrating months early would burn quota for zero
> security benefit. So the migration was prepared and parked while private,
> then **applied at the v0.17 flip** (see the dated execution note at the end).

---

## 🔴 Critical

### C1 — Self-hosted CI runner must not survive the public flip  **[done — v0.17, repo side]**

`ci.yml`'s five jobs run on a self-hosted macOS runner
(`[self-hosted, macos, arm64, gmcrypto]`) and trigger on
`pull_request: branches: [main]`. **While the repo is private this is
safe** — only trusted users can open PRs that trigger CI. But the moment
the repo goes public it becomes remote code execution: any fork PR would
run on the maintainer's Mac (arbitrary code as the `ghrunner` account,
warm-cache poisoning, potential secret access). GitHub explicitly recommends
never using self-hosted runners with public repositories.

**Applied at the v0.17 flip** (it was staged while private — see the box at
the top for that cost rationale, and the dated execution note at the end).
The swap was one mechanical change to `ci.yml`:

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

### S3 — `CLAUDE.md` self-hosted runbook exposure  **[done — v0.17]**

`CLAUDE.md` carries an ~138-line self-hosted-runner runbook (service-account
name, home paths, runner-registration token flow). Not secret, and **still
operationally needed while the self-hosted runner is in use** (re-registering
the runner if it dies). It stayed while the self-hosted runner was in use;
**at the v0.17 flip it was removed** together with the C1 runner swap (the
runbook is dead weight the instant the self-hosted runner is retired): the
`## Self-hosted CI runner setup` section is gone, the "Workflow notes" bullet
+ the architecture-map `ci.yml` / `fuzz-nightly.yml` lines now read
GitHub-hosted, and the `>>> BEFORE PUBLIC FLIP` notes are removed.

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

## Pre-flip checklist (public flip = v0.17)

**In the repo (applied at v0.17 — see C1, S3 + the dated execution note):**

- [x] Swap `ci.yml`'s five jobs from `[self-hosted, macos, arm64, gmcrypto]`
      to GitHub-hosted `macos-14`; drop the self-hosted cache tunings; bump
      timeouts (C1, step list). **Done v0.17 — plus `fuzz-nightly.yml` →
      `ubuntu-latest` (the C1 gap).**
- [x] Remove the `## Self-hosted CI runner setup` runbook from `CLAUDE.md` +
      update the Workflow-notes bullet + the architecture-map `ci.yml` line
      (S3). **Done v0.17.**
- [ ] Decommission the self-hosted runner (remove it in
      Settings → Actions → Runners; wipe `~ghrunner/actions-runner/_work`).
      **W4 — after the PR merges + hosted CI is green.**

**In the GitHub UI / via API** (see the 2026-05-24 dry-run note below):

- [x] **Dependabot** alerts + automated security fixes — **enabled
      2026-05-24** (free on private repos; applied via the REST API).
- [x] **Workflow permissions** = *Read repository contents* — **already
      least-privilege** (`default_workflow_permissions: read`; no workflow
      declares `permissions:` or uses a write token). No change needed.
- [ ] **Settings → Code security:** enable **Secret scanning** + **Push
      protection**. **Confirmed BLOCKED while private** (API returns
      *"Secret scanning is not available for this repository"* — needs paid
      GitHub Advanced Security on private repos; **free the moment the repo
      is public**). Must be done at the flip. Forward-looking cover for S1.
- [ ] **Settings → Actions → General:** set **Fork pull request workflows
      from outside collaborators** to *Require approval for all outside
      collaborators*. **Confirmed BLOCKED while private** (API: *"Fork PR
      approval is not allowed for private repositories"* — private repos
      can't be forked publicly). Do at the flip.
- [ ] **Settings → Branches:** add a branch-protection rule on `main`.
      **Deferred to the flip** (decision 2026-05-24): set it together with
      the C1 CI swap so the required status-check names match the
      *hosted-runner* jobs, with a **solo-maintainer-friendly** config —
      block force-push + deletion, require the CI checks (build / msrv /
      cabi / deny / wasm32) once they run on hosted runners, admin bypass
      on, **no review requirement** (a lone maintainer can't approve their
      own PR). The audit's original "+ 1 approving review" is impractical
      for a single-maintainer repo unless a second account/bot is added.

**Final sweep:**

- [x] **`gitleaks` authoritative pass — done 2026-05-24, CLEAN.**
      `gitleaks` 8.30.1 over the full history (174 content commits): **0
      real secrets.** The only matches are intentional published test
      vectors / parser-rejection fixtures (the two `*-kat-sourcing.md`
      oracle recipes' hex keys, the gmssl encrypted-PKCS#8 KAT `.pem`, and
      `pem.rs`'s malformed-`BEGIN PRIVATE KEY` test string) — now codified
      in `.gitleaks.toml` so `gitleaks git` **and** `gitleaks dir` both
      report *no leaks found*. Strengthens S1 (the at-audit sweep had eyes
      on only 2 of the 4; both new hits are benign KAT hex).
- [x] Add a `.mailmap` to unify the two author display names (S2). **Done
      v0.17** (`git shortlog -sne` now collapses to one author).
- [x] Add a one-line "not independently audited" banner near the top of the
      README (L1). **Done v0.17.**
- [x] Re-read `CLAUDE.md` with fresh eyes for any internal detail not wanted
      in public. **Done v0.17** (the self-hosted runbook was the only such
      detail — removed per S3; `CLAUDE.md` is retained as the agent guide).
- [ ] **W4 (post-flip verify):** confirm the crates.io README/links resolve
      (they point at the GitHub repo, reachable once public).

## What this audit did NOT change

- No git-history rewrite (none warranted — history is clean).
- No code/algorithm changes (out of scope for an open-sourcing audit).
- The self-hosted runner is retired at the v0.17 flip; the CI migration was
  applied — see C1 and the dated execution note.
- `CLAUDE.md` retained as the internal/agent guide; the self-hosted runbook
  was removed at the v0.17 flip (S3).

---

## 2026-05-24 pre-flip dry-run (item 2 — GitHub settings)

A dry-run of the "GitHub UI" pre-flip items, to apply what is safe now and
empirically confirm what GitHub blocks on a private repo (rather than
assume). Repo state: v0.12.0 on `main`, still **private**. Auth: `repo` +
`workflow` scopes.

**Applied now (safe + reversible, available on private repos):**

- **Dependabot alerts** — `PUT /repos/{o}/{r}/vulnerability-alerts` → `204`.
- **Dependabot automated security fixes** — `PUT …/automated-security-fixes`
  → `204`; verified `{"enabled":true}`.
- **`.gitleaks.toml`** added (codifies the 4 benign test-vector matches; both
  scan modes now clean).

**Confirmed already-correct (no change):**

- **Workflow token** is already `default_workflow_permissions: read` and
  `can_approve_pull_request_reviews: false`; no workflow needs a write token.

**Confirmed BLOCKED while private** (GitHub API errors — these can only be
enabled at/after the public flip):

- Secret scanning — `422 "Secret scanning is not available for this
  repository"` (needs paid GHAS on private; free on public).
- Push protection — depends on secret scanning → same wall.
- Fork-PR approval — `422 "Fork PR approval is not allowed for private
  repositories"`.

**Deferred by decision:** branch protection on `main` → set at the flip with
the C1 CI swap, solo-maintainer-friendly config (see the pre-flip checklist).

Net: item 2 is as complete as it can be while private. The three blocked
settings + branch protection are the only GitHub-side actions left for the
flip, all enumerated in the pre-flip checklist above.

---

## 2026-05-29 — v0.17 public-flip execution

The repo flips public at **v0.17** (decision change — see the updated
framing at the top). Repo-side staged changes were applied on branch
`chore/v0.17-public-flip` (codex-reviewed plan; this is *not* a crates.io
release — workspace stays `0.16.0`).

**Applied in this PR (repo side):**

- **C1 — `ci.yml` off self-hosted.** All five jobs `runs-on: macos-14`
  (GitHub-hosted aarch64); dropped the self-hosted `cache-bin` / `save-if`
  rust-cache tunings; bumped timeouts (build 15→30, msrv/cabi/wasm32 10→20,
  deny 5→15); rewrote the self-hosted header comment.
- **C1 gap — `fuzz-nightly.yml` off self-hosted.** The original C1 covered
  only `ci.yml`; `fuzz-nightly.yml` *also* ran on the self-hosted runner
  (it has no `pull_request` trigger, so it was never a fork-PR RCE vector,
  but it had to move so the runner can be fully retired — and to take the
  adversarial fuzz workload off the personal Mac). Now `runs-on:
  ubuntu-latest`, installing nightly + the pinned `cargo-fuzz 0.13.1` per
  run.
- **S3 — `CLAUDE.md` runbook removed.** Deleted the `## Self-hosted CI
  runner setup` section (~140 lines); rewrote the Workflow-notes bullet +
  the architecture-map `ci.yml` / `fuzz-nightly.yml` lines to GitHub-hosted;
  removed the `>>> BEFORE PUBLIC FLIP` notes; recorded the v0.17 milestone
  in the header.

**Remaining GitHub-side actions (apply at the flip, in order):**

- [ ] Smoke the hosted `fuzz-nightly` via `gh workflow run fuzz-nightly.yml
      --ref main` (PR CI never runs the nightly) — confirm green.
- [ ] Decommission the self-hosted runner (Settings → Actions → Runners →
      remove; `./svc.sh stop && ./svc.sh uninstall`; wipe `_work`).
- [ ] Flip visibility → **Public**.
- [ ] Enable Secret scanning + Push protection (free once public).
- [ ] Fork-PR approval = "Require approval for all outside collaborators".
- [ ] Branch protection on `main`: block force-push + deletion; require the
      **exact post-swap check context names** (build & test / msrv / cabi /
      cargo-deny / **each wasm32 matrix leg**); admin bypass on; no review
      requirement (solo maintainer).

History note: the deleted runbook (service-account `ghrunner`, the
`/Users/ghrunner` service-account paths) remains in git history. Per the
"What this audit did NOT change" section, no history rewrite is warranted —
those are a throwaway service account's paths, not secrets, and `gitleaks`
over full history is clean.
