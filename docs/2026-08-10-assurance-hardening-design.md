# Assurance Hardening Design

**Date:** 2026-08-10

**Status:** Approved for implementation

**Scope:** CI integrity, timing-test telemetry, and project-state documentation. No cryptographic production implementation changes.

## Objective

Strengthen the evidence around the existing `1.11.0` release line without opening a new feature cycle. The change must make shipped C examples, secret scanning, dependency policy, GmSSL interoperability, and dudect measurement integrity more explicit and harder to regress. The v2 sans-I/O TLCP engine remains deferred until a concrete consumer, owner, and day-one assurance baseline exist.

## Chosen approach

Use staged enforcement:

- Immediately gate deterministic, repository-owned checks: C example compilation, committed-history secret scanning, and the existing cargo-deny runtime profiles.
- Make a genuine GmSSL interoperability mismatch blocking while treating oracle acquisition, build, cache, or version drift as non-blocking infrastructure failures that remain visible in the job summary.
- Add a class-split-aware dudect noise twin as required telemetry only. Its presence is enforced, but its measured `|tau|` does not affect pass/fail until several GitHub-hosted nightly runs establish whether it tracks the observed class-split noise.
- Reconcile repository and Notion documentation with the resulting state without claiming unmerged changes have landed.

The rejected alternatives are a minimal CI-only change, which leaves the known class-split measurement question untouched, and immediate relative dudect enforcement, which lacks calibration evidence and could turn runner noise into an unreliable gate.

## Repository changes

### C example gate

The existing `cabi` job will compile every `crates/gmcrypto-c/examples/*.c` translation unit after header regeneration. The command will use the runner C compiler with C11, `-Wall`, `-Wextra`, `-Werror`, the committed header include path, and syntax-only mode. This catches malformed examples and stale declarations without introducing linker or runtime-loader variability.

The file list will be discovered from the examples directory rather than duplicated in workflow YAML. The shell loop must fail when the glob finds no example and must print each compiled path for reviewable logs.

### Secret scanning

A dedicated `gitleaks` job will:

1. check out full history with `fetch-depth: 0`;
2. install an exact gitleaks version;
3. run `gitleaks git --no-banner --redact --verbose` from the repository root.

The committed `.gitleaks.toml` remains the single allowlist. Generated targets, local fuzz corpora, and analysis artifacts are not part of this history scan.

### cargo-deny alignment

CI will pin cargo-deny `0.20.2` and use its global-option-before-command syntax:

```text
cargo deny --exclude-dev check
cargo deny --features gmcrypto-core/digest-traits,gmcrypto-core/cipher-traits,gmcrypto-core/sm4-bitsliced,gmcrypto-core/sm4-bitsliced-simd,gmcrypto-core/sm4-aead,gmcrypto-core/sm4-xts,gmcrypto-core/crypto-bigint-scalar,gmcrypto-core/sm2-key-exchange,gmcrypto-core/x509,gmcrypto-core/tlcp,gmcrypto-core/aead-traits --exclude-dev check
```

The runtime profile remains the exact feature set already exercised by CI. `gmcrypto-c/regen-header` is deliberately excluded because its optional `cbindgen` tree is build tooling rather than a downstream runtime dependency. `deny.toml`, `CLAUDE.md`, and workflow comments will describe this real policy and will not claim an `--all-features` pass.

### GmSSL failure classification

The `interop-gmssl` job itself will no longer use `continue-on-error`. Oracle provisioning and oracle-version assertion become individually identified, step-level `continue-on-error` operations. GitHub preserves their pre-tolerance result in `steps.<id>.outcome`.

The 13-test interoperability suite runs only when provisioning and version assertion both have `outcome == 'success'`. Its step remains uncompensated: a skipped-test census, wire mismatch, or gmcrypto regression fails the job and blocks merging once the check is required.

If provisioning or version validation fails, the suite is skipped and an `always()` summary step emits a warning plus a `GITHUB_STEP_SUMMARY` explanation identifying the infrastructure stage. The overall job remains successful so a third-party outage does not block unrelated work. Checkout or Rust setup failures remain ordinary CI failures because they affect repository-owned CI execution, not the GmSSL oracle specifically.

### Class-split dudect noise twin

The timing harness will add one target named `noise_twin_class_split`. It will randomly assign dudect classes to two distinct fixed 32-byte inputs and time the same fixed-iteration, branch-free XOR/rotate accumulation for either input. The operation performs no table lookup, allocation, early return, or data-dependent loop bound. `std::hint::black_box` prevents the compiler from deleting the fixed workload.

The twin captures the structural ingredients missing from the existing fix-vs-fix probes: two fixed input values, two storage locations, and a true input-selected class split. It is intentionally not claimed to be duration-matched to field inversion in this first calibration phase.

Both PR and nightly parsers will require one measurement per harness run for the twin. Missing or renamed telemetry fails completeness. Its `|tau|` is printed as `NOISE-TWIN` telemetry and never modifies `required_low`, the `0.55` sentinels, or relative-gate telemetry. Existing thresholds remain byte-for-byte unchanged.

The August 7 SIMD CBC fanout event will be recorded with its five measurements, `0.2008` median, `0.20` threshold, and the three subsequent same-commit passes. No leak or false-positive conclusion will be asserted; it remains a monitoring event.

## Notion changes

The current project page and related work/risk records will be fetched immediately before mutation. Updates will:

- replace the stale statement that fuzz coverage is not consumed with the post-PR-141 behavior;
- mark the v2 sans-I/O TLCP engine decision as explicitly deferred, with the existing consumer/owner/baseline reopen conditions;
- record the August 7 dudect event as monitoring, without weakening the gate;
- mark repository hardening work as in progress or pending merge until it exists on `main`;
- retain the explicit “not independently audited” limitation.

Existing database structure, owners, relations, and unrelated historical notes will be preserved.

## Validation strategy

Configuration behavior will use red/green policy assertions: before edits, focused checks must demonstrate the new workflow wiring is absent; after edits, the same assertions must pass. Because the changes are primarily workflow configuration, validation combines structural and executable evidence:

- parse every workflow with Ruby Psych and run focused assertions over the relevant expressions, step IDs, and failure-classification paths;
- compile every C example locally with the CI flags;
- run gitleaks against committed history;
- generate a fresh lockfile in a clean source snapshot and run both cargo-deny profiles;
- run the GmSSL 3.2.0 suite with `GMCRYPTO_GMSSL=1` and verify 13 tests execute;
- build and execute the dudect harness at a bounded smoke budget, verifying the new target is measured and parsed;
- run formatting, workspace tests, the relevant feature tests, and clippy with warnings denied;
- re-fetch changed Notion records to verify exact resulting content and status.

## Non-goals

- No external security audit is represented as completed.
- No production cryptographic algorithm, public API, C ABI, or release version changes.
- No F21 CBC-unpad dudect target.
- No authoritative noise-twin-relative threshold before hosted-runner calibration.
- No v2 TLCP engine implementation.

## Completion criteria

The work is complete when every repository change above is present on the implementation branch, all validation commands pass with fresh evidence, Notion reflects the local/pending-merge state accurately, and the final diff contains no unrelated modifications.
