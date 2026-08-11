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
will also reject `noise_twin_class_split` as a mapping key anywhere in either
dudect workflow; the target may appear only in `required_telemetry` and output
formatting, never in `required_low`, `required_high`, or
`gross_regression_sentinel`.

Deliberate mutation self-tests will prove that the verifier rejects:

- promoting the noise twin into a PR or nightly gate map;
- removing `required_telemetry` from either workflow;
- removing the `NOISE-TWIN:` output from either workflow;
- deregistering `BenchName("noise_twin_class_split")`;
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

After pushing, PR #149 must be non-conflicting and every required GitHub check
must succeed. The Draft PR is marked ready only after those conditions hold;
merge is attempted only after a fresh readiness check. GitHub review threads
are not replied to or resolved automatically unless the user separately
authorizes those comment writes.
