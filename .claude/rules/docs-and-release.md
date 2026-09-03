---
paths:
  - "docs/**"
  - "README.md"
  - "CHANGELOG.md"
  - "SECURITY.md"
  - "CONTRIBUTING.md"
  - "CLAUDE.md"
  - "crates/*/README.md"
---

# Documentation and release records

## Where things go

- `README.md` is the crates.io landing page: no per-version scope sections,
  no verbose history rows. Per-release narrative → `CHANGELOG.md` +
  `docs/vX.Y-scope.md` only. The CHANGELOG heading date is the day the crates
  go live, not the prep-merge date.
- `CLAUDE.md` keeps only what every session needs; per-cycle narrative goes
  to `docs/version-history.md` (prepend) and area rules to
  `.claude/rules/`. Touch `CLAUDE.md` only where a **live** constraint moved:
  the release table, the current-cycle block (**replace**, not append),
  commands. `**Earlier — vX.Y —**` never belongs there.
- Don't commit session working documents (plans, runbooks, scratch with paths
  or tracker IDs) into `docs/`. Policy: `docs/disclosure-boundary.md`. Don't
  cite an absolute local path as KAT/evidence provenance.
- Don't restate the private sibling's file layout in `docs/ECOSYSTEM.md`
  (obligations only; D1), and don't "restore consistency" by copying private
  commands into the charter.
- Licence text ships from **1.11.0** onward; 1.9.0 and earlier stay without
  it. crates.io skipped `1.10.0` and `1.9.1` (`docs/v1.9.1-release-review.md`).

## Disclosure boundary

```bash
python3 .github/scripts/check_disclosure_boundary.py --self-test
python3 .github/scripts/check_disclosure_boundary.py --worktree
python3 .github/scripts/check_disclosure_boundary.py --range origin/main..HEAD
```

P2 lines are advisory (pre-existing gate-evidence docs trip ~12); only P1
blocks. **Never edit committed evidence docs to silence P2s.**

## Release records

- Every release: Gate #1 evidence `docs/vX.Y.Z-gate1-evidence.md` — the
  private envelope's `ci/check-compatibility-gate.sh` output, verbatim, with
  the framing prose distinguishing the **gated SHA** from **`RELEASE_SHA`**.
  Never write a "current tip" SHA into a doc that later commits will move;
  write the check (`git diff <gated-sha> <tip> --stat -- crates/ Cargo.toml`
  must be empty).
- Runbooks (`docs/vX.Y.Z-release-review.md`) exist for 1.11.0–1.11.2; the
  §13 post-publish page checks in the 1.11.2 one are the template.
- Publish is the maintainer's authenticated call unless explicitly delegated
  for that release. When handing over commands, put the `cd` **inside** the
  code block (the app Run button uses the current directory) and **name the
  SHA** on `git tag` — `HEAD` may have moved. Tags are SSH-signed
  (`gpg.format = ssh`); verify with `git tag -v vX.Y.Z`. Default `git tag`
  sort is lexicographic (`v1.11.0` < `v1.2.0`) — use `--sort=-v:refname`.
- Release-prep PR (no source): workspace version, both sibling pins,
  `fuzz/Cargo.lock` path-dep refresh, CHANGELOG heading, CLAUDE.md release
  table + current-cycle block, `version-history.md` paragraph.

## docs.rs render

Feature badges come from `#![cfg_attr(docsrs, feature(doc_cfg))]` in core's
`lib.rs`, switched on by `rustdoc-args = ["--cfg", "docsrs"]` — inert on
stable, unstable on nightly, so a malformed render surfaces only on docs.rs
after publish. Run the nightly render before cutting:

```bash
cargo +nightly rustdoc -p gmcrypto-core --all-features -- --cfg docsrs
grep -c 'stab portability' target/doc/gmcrypto_core/index.html
```

`doc_auto_cfg` was removed in 1.92 and merged into `doc_cfg`; no per-item
`doc(cfg(...))` needed. Type pages live at their **definition** path
(`sm4/ccm_streaming/struct.X.html`), not the re-export path.

## Spec PRs

A `docs/vX.Y-scope.md` spec gets a "must pin before code" maintainer review.
Verify each pin against the code, revise the spec, then plan — never
implement from the first draft. Codex review prompts ~500 words or they hang;
don't paste full files.
