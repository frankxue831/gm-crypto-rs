# 2026-08-15 — disclosure audit

The first full audit against `docs/disclosure-boundary.md`. It answers, for every
tracked file, whether its content is qualified to be public — and separately,
what is already permanent in history and in the published archives.

**Verdict: five P1 findings, all remediated in #154. The working tree is clean.
Nothing found required rotation, and nothing found justifies a history rewrite.**
Twelve items are recorded below as open decisions (§6): they are not defects, but
they are choices that were never made explicitly, and the audit's real product is
that list.

## 1. Scope and method

| Corpus | Files | Method |
|---|---|---|
| `docs/` prose (A–M, incl. dated docs) | 15 | full read, line by line |
| `docs/` prose (N–Z) + root docs + manifests | 72 | full read, line by line |
| `.github/**`, `fuzz/**`, C examples, KAT fixture recipes | 69 | full read, line by line |
| `crates/**/*.rs` | 85 | full comment/string surface + every file header |
| Everything tracked | 313 | `check_disclosure_boundary.py --worktree` |
| Everything ever committed | 1 268 blobs | `check_disclosure_boundary.py --history` |

Four independent reviewers worked the four prose/source corpora in parallel
against the §2 rubric, with the already-known findings named up front so they
would report *additional* instances rather than re-report. Two P1s were found by
human reading that the pattern sweep had missed — see §3 — which is the argument
for keeping Phase 2 rather than trusting the scanner alone.

Beyond files, the surfaces a repository scan does not reach:

| Surface | Result |
|---|---|
| Commit + tag author identities | **Clean.** Every commit and the tag use the GitHub noreply address; no personal email in any identity. |
| Published `.crate` archives, all three crates @ 1.11.0 | **Clean.** Downloaded from `static.crates.io` and scanned; no home paths, no account names, no private-sibling references. |
| PR and issue bodies (100 most recent) | **Clean.** The only pattern hits are dependabot changelog SHAs and a 16-byte GCM tag from a KAT. |
| `gitleaks` full-history secret scan | **Green**, and green throughout the period in which every finding below was introduced. |

That last row is the point of this whole exercise: the secret scanner was never
wrong, it was answering a different question.

## 2. What was checked and found clean

Recording the negative results, because an audit that lists only findings gives
no information about coverage.

- **No credentials, tokens, or private-key material** anywhere in tree or history.
- **No personal email addresses.** The only address-shaped strings are the
  maintainer's GitHub noreply address and the GB/T 32918 worked-example
  identities, which are published test vectors — the standard's own signature and
  key-exchange examples are computed over those exact ID strings.
- **No machine hostnames, no private IP addresses, no internal service URLs.**
- **Test fixtures are sound.** All six certificate fixtures use reserved test
  names (`gmtest` organisation, `gmtest.example`); the X.509 private keys are
  deliberately not committed and the GmSSL regeneration recipe is present; the
  one committed private key is a throwaway whose password is published alongside
  it by design, with a one-command regen recipe. A `strings` sweep of every `.der`
  and `.pem` fixture surfaced no path, hostname, or identity.
- **The CI credential surface is minimal**: `permissions: contents: read`
  throughout, no `secrets.*` reference, no `pull_request_target`, no self-hosted
  runner.
- **Rust source is clean** of every P1 class across all 85 files.

## 3. P1 findings — all remediated

All five landed in #154. None is a secret; none required rotation.

| # | Location | What | Found by |
|---|---|---|---|
| 1 | `docs/2026-08-11-pr149-review-remediation-plan.md` | Absolute path into a local agent-plugin cache: a home directory, an OS account name, and a local tool's layout and pinned version | pattern sweep |
| 2 | `docs/2026-08-10-assurance-hardening-implementation-plan.md` | A 32-hex project-tracker page ID — a resolvable handle into a private workspace | **human read** |
| 3 | `crates/gmcrypto-core/tests/sm2_kx_kat.rs` | KAT provenance citing `/private/tmp/<dir>/…png` on the maintainer's machine | **human read** |
| 4 | `docs/v1.1-sm2kx-kat-sourcing.md` | The same citation, second instance | pattern sweep (after #3) |
| 5 | *(same class as #1)* | — the `.codex` path was the only instance of its kind | pattern sweep |

Findings 2 and 3 are the ones worth dwelling on. Neither matches a naive
"leak" pattern: a 32-hex string is indistinguishable from the KAT vectors this
repository is full of, and a `/private/tmp/…` path looks entirely ordinary.
Both were caught by a person reading for *meaning*. The rules added in #155
encode both classes afterwards — the record-ID rule anchored on adjacent context
rather than hex shape — but the rules exist because the human pass found them
first, not the other way round.

Finding 3 also cost the reader something, which is worth separating from the
privacy question: a provenance claim citing a file no auditor can open is weaker
than one citing the standard's own section. The fix improves the document.

## 4. History triage

Six distinct P1 items are permanent in reachable history:

| Item | Paths | Disposition |
|---|---|---|
| `/Users/<name>` | `docs/v0.3-scope.md`, `v0.4-scope.md`, `v0.5-scope.md`, `2026-08-11-…-plan.md` | **Accept.** Working-tree copies are clean; three were cleaned long ago. |
| `/Users/<runner-account>` | `CLAUDE.md` (historical), `docs/pre-opensource-audit.md` (current, deliberate) | **Accept.** A retired throwaway service account, already reasoned about in that audit. |
| Tracker page ID | `docs/2026-08-10-…-plan.md` | **Accept.** Addresses a private record that still requires authentication to read. |

**No history rewrite.** Per `docs/disclosure-boundary.md` §5: rewriting a public
repository's history invalidates every fork and clone, breaks every PR ref and
commit link, and does not touch the published archives or anyone's existing copy.
For mild PII the cost is real and the benefit is near zero. For a live credential
the calculus would flip — but the secret scan is clean, so it does not arise.

The first three rows are also the empirical case for the per-commit range scan
in #155: those scope docs' *working trees* were clean at every merge, so a
squashed net-diff gate would have passed every one of those PRs.

Five distinct P2 items are in history only and need no action: two internal tool
names in a since-cleaned `.gitleaks.toml`, the two scratch-path citations from
§3, and a README link to a private companion repo, removed long ago and now
banned by CLAUDE.md.

## 5. The gate that now exists

#155 adds `check_disclosure_boundary.py` and its workflow, so this audit's
mechanical classes cannot silently recur. Verified against the real case: the
range scan over the commit that introduced findings 1 and 2 reports both.

One honest limitation. The gate catches classes that are *mechanically*
identifiable. It cannot catch "this entire document is an internal working note",
which is the root cause behind findings 1 and 2 — both live in session plan
documents committed into `docs/`. That is why #155 also adds a convention to
CLAUDE.md rather than only a rule: working documents belong outside the
repository. The rule is the backstop, not the fix.

## 6. Open decisions

None of these is a defect. Each is a choice this project has been making
implicitly, and the value of writing them down is that they stop being re-raised
by every future review. Recommendations are exactly that; the call is the
maintainer's.

**D1 — Private-sibling internals.** Naming the private downstream crate is
deliberate: `docs/ECOSYSTEM.md` is a normative charter that lists its members,
including unpublished ones. Its *internals* are a separate question — the charter
and evidence docs also name the downstream's internal CI script paths, test
target names, gate self-tests, its uncredentialed cross-repo read relationship,
and one of its defects. *Recommendation: keep the crate name and the verification
obligations; state them without naming private script paths, and drop the
downstream-defect narration. Lowest-value, highest-specificity disclosure.*

**D2 — AI-assisted development disclosure.** Attributions to AI review tooling
appear in ~20 source comments, 4 workflows, and many docs; `CASE-STUDY.md` makes
the assisted-development story explicit and public on purpose. Separately, five
plan documents open with a header addressed to *automated workers*, and some docs
record model versions, session-resume mechanics, and opaque workflow run IDs.
*Recommendation: keep the attributions — they are deliberate, and for an
assurance-focused project the provenance of a review is real information. Drop
the machine-addressed scaffolding, the run IDs, and the session mechanics: those
address tooling, not readers, and carry no reader value.*

**D3 — Private tracker as a system of record.** Eight documents reference the
private tracker by product name as where a milestone "lives". *Recommendation:
genericize to "the project tracker". Near-zero cost; removes a standing invitation
to name IDs, which is how finding 2 happened.*

**D4 — Retired self-hosted runner detail.** Four documents record the runner
label, the service account, and the precise RCE path a public fork PR would have
had. *Recommendation: keep. The infrastructure is retired, so nothing is exposed,
and the detail is the reasoning behind a real security decision — the single most
instructive item in the pre-open-source audit.*

**D5 — Other private projects.** A release-review checklist references an
unrelated private product line by name, and two documents reference a private
prototype repository. *Recommendation: genericize the product reference; the
prototype mentions are the rule ("don't reference it"), not references, and can
stay — though stating the rule without the name would be cleaner.*

**D6 — Published assurance gaps.** Two workflows and several docs state precisely
which timing-leak magnitudes CI does *not* catch. *Recommendation: keep, and
record the decision so it stops being re-raised. This project's security posture
is built on stating what is not covered; suppressing it would make the assurance
claims dishonest. This is deliberate transparency, and a reader should be able to
tell it apart from an unreviewed leak — which is the entire purpose of §2.2 of
the policy.*

**D7 — Internal tool names in ignore-file comments and the changelog.**
`.gitignore` comments and one changelog entry name local-only tooling.
*Recommendation: genericize the comments; keep the ignore patterns, which are
protective.*

**D8 — Session documents in `docs/`.** Two dated plan documents are one-shot
operator runbooks for work already merged, and seven audit records carry
provenance blocks with agent run IDs. *Recommendation: keep the records — they
are genuine project history — but strip the machine-addressed headers and the
opaque run IDs, and apply the CLAUDE.md convention going forward.*

**D9 — Third-party contributor handle.** `docs/version-history.md` credits an
external contributor by handle. *Recommendation: keep. It is already public via
the merged PR, and crediting contributors is correct.*

## 7. Recurrence

The audit is a one-time full pass; recurrence is handled by the existing
baseline-and-drift pattern this repository already uses for the API baseline, the
cbindgen header, and the workflow policy fingerprints:

- **Per PR:** the #155 gate — worktree plus every commit's added lines.
- **Per release:** re-run the sweep and triage findings.
  `docs/disclosure-boundary.md` §4 is the normative source for that obligation.
  It is deliberately not back-fitted into `docs/v1.0.0-release-review.md`, which
  is a record of what that review actually did, not a live checklist — so the
  next release review is the first to carry the line.
- **Full re-audit:** only when the policy itself changes, or after a bulk import
  of external content.
