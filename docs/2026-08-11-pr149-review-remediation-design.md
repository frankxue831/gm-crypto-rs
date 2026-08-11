# PR #149 Review Remediation Design

**Date:** 2026-08-11

## Goal

Resolve all five open review threads on PR #149 without changing production
cryptographic code, public APIs, the C ABI, or any dudect threshold. Preserve
the established rule that a genuine GmSSL mismatch blocks merging while a
third-party oracle outage remains visible but non-blocking.

## Chosen approach

Use a repair-first GmSSL cache policy, make interoperability execution status
unambiguous in every run, encode the noise twin's telemetry-only status as an
executable invariant, add deliberate mutation coverage for the complete noise
twin wiring, and reconcile every shipped C example banner with the new syntax
gate.

The narrower alternative—repairing only a missing or non-executable cached
binary—was rejected because an executable wrong-version or damaged binary can
also create a sticky green skip. Making third-party GmSSL infrastructure fully
blocking was rejected because it would reverse the approved failure
classification and let an upstream outage block unrelated repository changes.

## GmSSL cache repair and status reporting

The provision step defines the expected binary, install prefix, source
directory, and exact `GmSSL 3.2.0` version string. A cache hit is usable only
when the binary exists, is executable, and reports that exact first-line
version. Any other state is treated as a degraded cache: the step validates
that the prefix is the narrowly scoped runner path, removes the broken prefix
and temporary source directory, then performs a clean pinned source build and
install. The existing independent version assertion remains as a drift guard
after provisioning.

The job name will explicitly state that mismatches gate while infrastructure is
non-blocking. A final `always()` reporting step emits
`INTEROP_SUITE=ran|skipped` to both the log and job summary on every run, along
with the raw cache, provision, version, and suite outcomes. A failed suite is
classified as `ran` and remains blocking through its uncompensated step. A
skipped suite is visibly classified as non-passing infrastructure telemetry.

## Assurance-policy invariants

The policy verifier will require the repair-first cache-health checks, the
transparent job name, and the unconditional final execution-state report. It
also binds each exact dudect `Parse and gate` step to its complete executable
semantics. A dedicated extractor requires exactly one
`python3 - <<'PY'` heredoc, a fail-fast `set -euo pipefail` shell preamble, the
exact closing marker, and no additional active shell command before or after
the heredoc. The entire embedded Python program is parsed with `ast.parse`;
the SHA-256 fingerprint of its attribute-free `ast.dump` must match a
hard-coded, reviewed PR or nightly fingerprint. This is an intentional
execution boundary: a legitimate control-flow change must update the workflow,
the reviewed fingerprint, and mutation coverage together. The previous
semantic diagnostics remain for useful failure labels, including the immutable
one-element `required_telemetry` tuple, immutable gate-map snapshots, overlap
rejection, snapshot-only gate loops, and print-only `NOISE-TWIN:` output.

The verifier compares `active_run()` with the complete reviewed canonical
script for the C-example compiler, gitleaks installer, GmSSL version assertion,
GmSSL interoperability suite, GmSSL report, and both dudect producers. The
gitleaks scan remains an exact single-command step. Whole-line comments remain
free to evolve, but every active shell line, its order, and every guard in
these boundaries are fixed. Dudect parsing remains protected separately by the
complete embedded-Python AST fingerprint described above.

All protected YAML metadata keys use one mapping-key recognizer. It treats
plain, single-quoted, and double-quoted spellings—including valid `\x`, `\u`,
and `\U` escapes in double-quoted keys—and whitespace before the colon as the
same key, then requires a unique value or an exact zero count.
This closes first-value/last-value disagreement for `branches`, `fetch-depth`,
job names, step IDs, `if`, `continue-on-error`, `shell`, `env`, and `run`.
Each protected command-bearing step now declares and uniquely retains
`shell: bash`: the policy verifier, C compiler, GmSSL version/suite/report,
gitleaks install/scan, and dudect producer/parser steps. Unexpected step
environment mappings are rejected; the few required mappings must equal their
reviewed source lines exactly.

The critical job envelope is also fixed. Build, C ABI, GmSSL interoperability,
and PR dudect retain the complete existing folded skip-CI expression; nightly
dudect and gitleaks retain no job condition. None may add job or workflow
`defaults`, job tolerance, or an unexpected job environment. The interop job
environment remains exactly `GMSSL_TAG=v3.2.0` plus cache epoch `1`. Dudect
retains `ubuntu-24.04`, Rust `1.95.0`, the 10/40 minute timeouts, the exact four
feature legs, and the 10K×3 / 100K×5 producer budgets. Ordered step-header
contracts prevent a second checkout or an environment-tampering step from
being inserted into build, C ABI, interop, gitleaks, or dudect execution.
Finally, the gitleaks trigger requires unique `main` push and pull-request
branches and rejects any spelling of `paths` or `paths-ignore` within `on`.
Each protected job key itself must also occur exactly once, so a later quoted
or Unicode-escaped duplicate cannot replace the job that the verifier read.

Checkout action steps are complete source contracts: gitleaks retains only
`fetch-depth: 0`, while both dudect checkouts retain no `with` mapping or
alternate `ref`. The CI build/policy, C ABI, GmSSL, and cargo-deny jobs likewise
retain exactly one metadata-free checkout of the triggering revision. The
cargo-deny checkout is included because the verifier directly claims its
pinned installer and both dependency-policy commands; MSRV, SIMD, and wasm
jobs are not silently promoted into this assurance scope. Dudect also fixes
the Rust toolchain and rust-cache action metadata. A top-level list marker
written as a dash on its own line is counted as a step header, preventing an
otherwise invisible command from being placed between reviewed steps. Before
the dudect producer runs, the workflow environment and runner-capture script
are fixed exactly; this prevents an ordinary workflow edit from persisting
`BASH_ENV` through `GITHUB_ENV` and changing the producer or parser shell
boundary.

Deliberate mutation self-tests will prove that the verifier rejects:

- promoting the noise twin into a PR or nightly gate map;
- rebinding any PR/nightly gate snapshot, the nightly sentinel snapshot, or
  the final failure state; short-circuiting completeness or gate loops; or
  replacing the conditional process exit with unconditional success;
- gating the noise-twin value through completeness, a dynamic snapshot append,
  an effective union, or after dynamically clearing telemetry membership;
- removing `required_telemetry` from either workflow;
- removing the `NOISE-TWIN:` output from either workflow;
- deregistering `BenchName("noise_twin_class_split")`;
- adding early success, false-condition wrappers, fabricated output, digest
  rebinding, or any other active line to the GmSSL, gitleaks, or C scripts;
- skipping or tolerating the policy verifier, C compiler, gitleaks install or
  scan, or either dudect parse step/job through execution metadata;
- adding duplicate execution or metadata keys whose last value could override
  the reviewed first value;
- quoting or spacing protected keys to skip metadata checks; adding workflow
  or job defaults, false job conditions, unexpected environments, custom
  shells, or extra checkout steps;
- hiding protected keys behind valid double-quoted Unicode escapes, appending
  duplicate critical jobs, or inserting a dash-alone step;
- adding checkout inputs or an alternate ref, skipping the pinned dudect
  toolchain, or poisoning a later shell through `GITHUB_ENV`/`BASH_ENV`;
- retargeting a protected CI checkout away from the triggering revision, or
  overriding that action through quoted metadata;
- shrinking either dudect run/sample budget, deleting a feature leg, changing
  the pinned runner/toolchain/timeout, or bypassing the complete producer loop;
- replacing the GmSSL version assertion with success, hard-coding the reported
  suite outcome, or skipping/tolerating the final report;
- weakening cache repair or unconditional interop status reporting.

## C example documentation

The five remaining stale banners—`sm2_sign.c`, `sm2_key_exchange.c`,
`sm4_ccm.c`, `sm4_gcm_streaming.c`, and `sm4_xts_sector.c`—will state that CI
syntax-checks the translation unit while linking and functional execution stay
local. No example behavior changes.

## Verification and merge gate

Implementation follows RED/GREEN cycles through
`.github/scripts/check_assurance_policy.py`. Final local evidence includes the
policy verifier with mutation self-tests, actionlint for changed workflows,
YAML parsing, strict compilation of all nine C examples, real GmSSL 3.2.0
13/13 interoperability, Rust formatting/tests/clippy, header drift, gitleaks,
and a clean branch.

The dudect implementation continues to fail only when a measured value is
strictly greater than `0.20`; equality therefore passes. Current maintenance
comments and job names describe the unchanged contract as `|tau| <= 0.20`.

After pushing, PR #149 must be non-conflicting and every required GitHub check
must succeed. The Draft PR is marked ready only after those conditions hold;
merge is attempted only after a fresh readiness check. GitHub review threads
are not replied to or resolved automatically unless the user separately
authorizes those comment writes.
