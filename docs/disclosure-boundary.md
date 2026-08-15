# Disclosure boundary — policy and review protocol

**Status:** Normative for what this repository publishes.
**Established:** 2026-08-15. First audit against it: `docs/2026-08-15-disclosure-audit.md`.

This repository is public. Everything in the working tree, everything in git
history, every published `.crate` archive, and every PR body is world-readable
and permanently so. This document defines what is allowed to be there, and the
protocol for checking.

## 1. Why this exists separately from the secret scan

`gitleaks` already runs over the full committed history on every eligible push
and PR (`.github/workflows/gitleaks.yml`, pinned and checksum-verified). It
answers one question well: **is there a credential here?**

It does not answer a second question: **is there information here that is not a
credential, but that a public repository has no reason to carry?** A home
directory. An OS account name. A private host address. A resolvable handle into
a private tracker. The internals of a private sibling repository. The layout of
the maintainer's local tooling.

None of that trips a secret scanner, because none of it is a secret. That is
precisely why it accumulates unnoticed. The 2026-08-15 audit found five such
items in the working tree, the oldest introduced fourteen months earlier, all of
them through a repository whose secret scan had been green the entire time.

The distinction drives everything below:

|  | Secret | Non-secret disclosure |
|---|---|---|
| Example | an API token | a home-directory path |
| Detected by | `gitleaks` | `check_disclosure_boundary.py` |
| On discovery | **rotate first**, then remove | remove; nothing to rotate |
| History rewrite | justified for a live credential | not justified (see §5) |

## 2. The policy

Three classes. The point of writing them down is that "should this be public?"
becomes a lookup rather than a judgment call re-made from scratch each time.

### 2.1 Never public — remove on sight

Credentials of any kind; personal email addresses; absolute paths into a user's
home directory (`/Users/<name>`, `/home/<name>`, `C:\Users\<name>`); personal
machine hostnames; private network addresses; identifiers that address a record
in a private external system; paths into a local agent-session or scratch
directory.

The common test: **it identifies a person or a machine, or it addresses a
private system, and no reader of a cryptography library gains anything from
it.** There is no legitimate reader-facing use, so there is no trade to weigh.

### 2.2 Decide explicitly — allowed only with a recorded reason

Content that may be entirely intentional, but must not arrive by accident:

- **References to private or unpublished sibling projects**, and — separately,
  and more sensitively — *their internals*: commit SHAs, internal test target
  names, internal CI script names, known defects.
- **Internal process and tooling disclosure**: names of AI-agent tooling, plugin
  or skill identifiers, session artifacts, run IDs, plan scaffolding addressed
  to automated workers, private tracker references.
- **Infrastructure detail**: CI runner labels and service accounts, cache
  topology, cross-repository trust relationships.
- **Published assurance gaps**: precise statements of which guarantees CI does
  *not* enforce.

The last one deserves care, because the honest answer is often "publish it".
This project's security posture is built on stating what is *not* covered — the
dudect gate's demoted targets are documented in exactly that spirit, and hiding
them would make the assurance claims dishonest. The rule is not "suppress"; it
is **decide once, in writing, and apply consistently**. A reader should be able
to tell the difference between deliberate transparency and an unreviewed leak.

### 2.3 Qualified — publish freely

Anything derivable from the code itself; standards references and published test
vectors; the project's public identity (the maintainer's GitHub handle and
noreply address); public URLs; CI configuration and pinned tool versions with
their checksums; generic paths that name no user (`~/.cargo/...`).

Two recurring cases worth naming, because both look like findings and neither
is: the GB/T 32918 worked-example identities (`ALICE123@YAHOO.COM` and its
counterpart) are *published test vectors* — the standard's own signature and
key-exchange examples are computed over those exact ID strings, so the KATs
cannot use anything else. And the certificate fixtures under
`crates/gmcrypto-core/tests/data/` are throwaway keys with a committed
regeneration recipe; their subject names are deliberately reserved test names.

## 3. The gate

`.github/scripts/check_disclosure_boundary.py` encodes §2 as executable rules,
run by `.github/workflows/disclosure-boundary.yml`. Standard library only, so
the job needs no install step and no upstream release can break it.

### 3.1 Severities

**P1 fails the build.** §2.1 content — unambiguous, no trade to weigh.

**P2 is reported, and does not fail the build.** §2.2 content — it needs a
recorded human decision, and a CI job is the wrong place to make one. Advisory
findings are written to the job summary so they are *seen*; a report nobody
opens is not a report.

This mirrors the dudect gate's existing posture: a required threshold where the
signal is unambiguous, telemetry where it needs calibration first. `--strict`
promotes P2 to failing, for audit runs.

### 3.2 Modes

| Mode | Scans | Used by |
|---|---|---|
| `--worktree` | every tracked file at HEAD | the PR/push gate |
| `--range A..B` | lines added by **each commit**, one at a time | the PR gate |
| `--history` | every blob reachable from every ref | audits only |
| `--self-test` | that every rule still fires | the gate, first step |

`--range` is deliberately not a squashed `base...head` diff. A leak introduced
in one commit and removed in the next leaves no trace in the net diff, but is
permanent in public history once merged — and this repository contains real
instances: `/Users/<name>` survives in the history of three v0.x scope docs
whose working-tree copies are clean. The net diff would have called those PRs
clean.

`--history` is an audit tool, not a CI mode. History cannot be corrected without
a rewrite, so its findings are triaged into a record (§5) rather than gated;
wiring it to CI would produce a job that is permanently red for things nobody
intends to change.

### 3.3 Allowlist discipline

Every entry requires the **path** to match, and — where the site is specific —
the **matched text** as well. That AND-condition is inherited from
`.gitleaks.toml`, for the same reason stated there: allowlisting a whole file,
or a whole tree, is the easy version and silently covers the next real finding
in it.

Every entry carries a `reason`. The self-test fails if one does not. An entry
whose reason is "to make CI green" is a bug — the finding was either real (fix
it) or intentional (say why, in one sentence a future reader can evaluate).

Allowlisting an existing site does not weaken the rule; it converts the rule
into a **drift detector** for that class. The private-sibling rule is
allowlisted on the charter and evidence docs that legitimately discuss it,
precisely so that a *new* file naming a private sibling still reports and forces
a decision.

### 3.4 Self-test

A rule that has silently stopped matching is worse than no rule, because the
green check then reads as assurance. Every rule must fire on a known-bad fixture
and stay quiet on its known-good counterpart, and the test fails loudly — naming
the stale rule — when one does not. Same posture as
`check_assurance_policy.py`'s mutation self-test.

The known-good fixtures matter as much as the known-bad ones. This repository is
full of 32-hex KAT vectors, so the external-record-id rule is anchored on
adjacent context rather than on hex shape alone, and a bare vector is a fixture
asserting it stays quiet.

## 4. The review protocol

### Phase 1 — automated sweep (recall)

`gitleaks` for secrets; `check_disclosure_boundary.py --history --strict` for
disclosure. Both over full history, not just the working tree.

Then the surfaces a repository scan does not reach, which are easy to forget
because they are not files: commit and tag author identities
(`git log --format='%an <%ae>' | sort -u`), GitHub-side text (PR and issue
bodies, release notes), CI logs and uploaded artifacts, and the published
`.crate` archives — which are immutable, so what shipped is what shipped.
`cargo package --list` before a publish shows exactly which files will go.

### Phase 2 — human pass (precision)

A scanner cannot judge "unnecessary". Read in risk order, not alphabetical:

1. **`docs/` prose** — by far the highest yield. Working notes, plans, evidence
   docs and audit records are written mid-task and carry the author's local
   context. Every P1 the 2026-08-15 audit found was in this class or reachable
   from it.
2. **CI workflows and scripts** — paths, runner detail, tooling.
3. **Test fixtures and binary blobs** — confirm every committed key is a
   throwaway with a regeneration recipe, and that no fixture embeds a path,
   hostname, or identity.
4. **Source comments** — lowest yield. Grep the comment surface for the
   patterns; read every file-header block, since that is where stray notes
   settle.

Record a verdict per file. The full pass happens **once**; afterwards the
repository's existing baseline-and-drift pattern applies (the same shape as the
API baseline, the cbindgen header, and the policy fingerprints): only new lines
need review, at PR time, which is what the gate automates.

### Phase 3 — triage

See §5 — the rules differ for an already-public repository.

### Phase 4 — prevention

The gate (§3) is the mechanical half. The conventions are the other half:

- **Everything under the repository root is presumed public.** Session and agent
  working documents belong in a scratch directory outside the repository, not in
  `docs/`. The 2026-08-11 leak happened exactly this way: a working plan written
  during a session was committed into `docs/` with its local paths intact.
- **Evidence and provenance use relative or citable references, never absolute
  paths.** A provenance claim that cites a file no auditor can open is weaker
  than one citing the standard's own section — so this rule improves the
  document as well as protecting the boundary.
- **The release-review template carries a boundary line**: sweep re-run,
  findings triaged. That is what makes this recurring rather than one-time.

## 5. Triage rules for an already-public repository

Removal never un-leaks. Anything that has been public must be assumed collected.
The response therefore depends on what the item *is*, not on how it feels.

| Finding | Action |
|---|---|
| Live credential | **Rotate first.** Removal is cleanup, not remediation. Then remove, and rewrite history if the credential cannot be rotated. |
| Non-secret disclosure in the working tree | Remove it. This is the case the gate prevents from recurring. |
| Non-secret disclosure in history only | **Fix HEAD; accept history.** Do not rewrite. |
| GitHub-side text (PR/issue bodies) | Editable, and worth editing — but assume it was indexed while up. |
| Published `.crate` archive | Immutable. Cannot be corrected; only superseded. |

The history rule deserves its reasoning stated, because the instinct is to
rewrite. Rewriting a public repository's history invalidates every fork and
clone, breaks every PR ref and every commit link in the changelog and issue
history, and does not touch the published archives or anyone's existing copy. For
mild PII the cost is real and the benefit is close to zero. For a live credential
the calculus flips entirely — but that is the secret scanner's domain, and it is
clean.

This is the same reasoning `docs/pre-opensource-audit.md` already applied to the
retired runner account's paths, and the same shape as the licence-text decision
in `docs/ECOSYSTEM.md` §3: what shipped, shipped; correct forward.

## 6. Running it

```bash
# What CI runs.
python3 .github/scripts/check_disclosure_boundary.py --self-test
python3 .github/scripts/check_disclosure_boundary.py --worktree

# What CI runs on a PR, in addition: every commit's added lines.
python3 .github/scripts/check_disclosure_boundary.py --range origin/main..HEAD

# The audit sweep. Not wired to CI; expect findings that history cannot fix.
python3 .github/scripts/check_disclosure_boundary.py --history --strict
```

A P1 in your PR means: remove the content. If it is deliberate, add a scoped
allowlist entry with a reason — and expect the reason to be reviewed, since it
is the only thing standing between the rule and the next real finding.
