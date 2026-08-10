# Assurance Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic CI gates, correctly classify GmSSL infrastructure failures, introduce required-but-nonblocking class-split dudect telemetry, and synchronize repository/Notion project state.

**Architecture:** Keep repository-owned checks blocking. The C and dependency gates live in the existing `CI` workflow; committed-history secret scanning lives in a dedicated workflow with no path exclusions, because `ci.yml` intentionally skips doc-only main pushes. Classify GmSSL failures within one stable job by using step-level `continue-on-error` plus `steps.<id>.outcome`; only the actual interoperability suite remains uncompensated. Add one telemetry-only dudect target and require measurement completeness without changing any statistical threshold.

**Post-review amendment (2026-08-10):** The implementation extracts gitleaks into `.github/workflows/gitleaks.yml`, reports cache degradation independently from oracle unavailability, uses indentation-scoped semantic policy checks with deliberate mutation self-tests, and puts the noise twin behind opaque, materialized inputs plus a non-inlined fixed-work helper. These decisions supersede the illustrative first-draft snippets below where they differ.

**Tech Stack:** GitHub Actions YAML, Python 3 standard library, Rust benchmark harness, C11 compiler, gitleaks 8.30.1, cargo-deny 0.20.2, Notion connector.

---

### Task 1: Add a red/green assurance-policy verifier

**Files:**
- Create: `.github/scripts/check_assurance_policy.py`
- Modify: `.github/workflows/ci.yml`
- Create: `.github/workflows/gitleaks.yml`

- [ ] **Step 1: Create the failing policy verifier**

Create `.github/scripts/check_assurance_policy.py` with this complete content:

```python
#!/usr/bin/env python3
"""Structural regression checks for the assurance-critical CI wiring."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
CI = (ROOT / ".github/workflows/ci.yml").read_text()
DUDECT_PR = (ROOT / ".github/workflows/dudect-pr.yml").read_text()
DUDECT_NIGHTLY = (ROOT / ".github/workflows/dudect-nightly.yml").read_text()
TIMING = (ROOT / "crates/gmcrypto-core/benches/timing_leaks.rs").read_text()

failures: list[str] = []


def require(label: str, condition: bool) -> None:
    if not condition:
        failures.append(label)


interop = CI.split("  interop-gmssl:\n", 1)[1].split("\n  cabi:\n", 1)[0]
require("policy verifier is executed by CI", "python3 .github/scripts/check_assurance_policy.py" in CI)
require("C examples are compiled", "Compile shipped C examples" in CI)
require("C example gate uses strict syntax flags", "-std=c11 -Wall -Wextra -Werror -fsyntax-only" in CI)
require("gitleaks is pinned", "tool: gitleaks@8.30.1" in CI)
require("gitleaks checkout has full history", "fetch-depth: 0" in CI)
require("gitleaks scans committed history", "gitleaks git --no-banner --redact --verbose" in CI)
require("cargo-deny is pinned to 0.20.2", "tool: cargo-deny@0.20.2" in CI)
require("cargo-deny default profile uses 0.20 syntax", "cargo deny --exclude-dev check" in CI)
require(
    "cargo-deny runtime profile uses 0.20 syntax",
    "--exclude-dev check" in CI and "cargo deny --features gmcrypto-core/digest-traits" in CI,
)
require("GmSSL job is not globally tolerated", re.search(r"^    continue-on-error:", interop, re.M) is None)
require("GmSSL provisioning has a stable id", "id: gmssl-provision" in interop)
require("GmSSL version assertion has a stable id", "id: gmssl-version" in interop)
require("GmSSL infrastructure is step-tolerated", interop.count("continue-on-error: true") >= 3)
require(
    "interop runs only with a ready pinned oracle",
    "if: steps.gmssl-provision.outcome == 'success' && steps.gmssl-version.outcome == 'success'"
    in interop,
)
require("GmSSL infrastructure status is summarized", "Report GmSSL infrastructure status" in interop)
require("noise twin benchmark exists", "fn noise_twin_class_split(" in TIMING)
require("noise twin benchmark is registered", 'BenchName("noise_twin_class_split")' in TIMING)
for workflow_name, workflow in (("PR", DUDECT_PR), ("nightly", DUDECT_NIGHTLY)):
    require(
        f"{workflow_name} dudect requires noise-twin telemetry",
        'required_telemetry = ["noise_twin_class_split"]' in workflow,
    )
    require(f"{workflow_name} dudect labels noise-twin output", "NOISE-TWIN:" in workflow)

if failures:
    for failure in failures:
        print(f"FAIL: {failure}")
    raise SystemExit(1)

print("assurance workflow policy: ok")
```

- [ ] **Step 2: Run the verifier and confirm RED**

Run:

```bash
python3 .github/scripts/check_assurance_policy.py
```

Expected: exit 1 with failures for the C-example gate, gitleaks job, cargo-deny 0.20.2 syntax, GmSSL step IDs/classification, and noise twin.

- [ ] **Step 3: Wire the verifier into the build job**

Immediately after `actions/checkout@v4` in `jobs.build.steps`, insert:

```yaml
      - name: Verify assurance workflow policy
        run: python3 .github/scripts/check_assurance_policy.py
```

The verifier remains red until Tasks 2 and 3 complete.

### Task 2: Add deterministic CI gates and GmSSL failure classification

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `deny.toml`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add the C-example compiler gate**

After `cargo test -p gmcrypto-c` in `jobs.cabi.steps`, insert:

```yaml
      - name: Compile shipped C examples
        shell: bash
        run: |
          set -euo pipefail
          shopt -s nullglob
          examples=(crates/gmcrypto-c/examples/*.c)
          if (( ${#examples[@]} == 0 )); then
            echo "::error::no shipped C examples found"
            exit 1
          fi
          for example in "${examples[@]}"; do
            echo "checking $example"
            cc -std=c11 -Wall -Wextra -Werror -fsyntax-only \
              -I crates/gmcrypto-c/include "$example"
          done
```

- [ ] **Step 2: Add the committed-history gitleaks job**

Insert this job before `interop-gmssl` and use the same skip-CI expression as the surrounding jobs:

```yaml
  secrets:
    name: gitleaks (committed history)
    runs-on: ubuntu-24.04
    if: >-
      !contains(github.event.pull_request.title, '[skip ci]') &&
      !contains(github.event.pull_request.title, '[ci skip]') &&
      !contains(github.event.pull_request.title, '[no ci]') &&
      !contains(github.event.pull_request.title, '[skip actions]') &&
      !contains(github.event.head_commit.message, '[skip ci]') &&
      !contains(github.event.head_commit.message, '[ci skip]') &&
      !contains(github.event.head_commit.message, '[no ci]') &&
      !contains(github.event.head_commit.message, '[skip actions]')
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Install gitleaks
        uses: taiki-e/install-action@v2
        with:
          tool: gitleaks@8.30.1
      - name: Scan committed history
        run: gitleaks git --no-banner --redact --verbose
```

- [ ] **Step 3: Upgrade and align cargo-deny**

Change the install pin and two commands to:

```yaml
          tool: cargo-deny@0.20.2
```

```yaml
        run: cargo deny --exclude-dev check
```

```yaml
        run: cargo deny --features gmcrypto-core/digest-traits,gmcrypto-core/cipher-traits,gmcrypto-core/sm4-bitsliced,gmcrypto-core/sm4-bitsliced-simd,gmcrypto-core/sm4-aead,gmcrypto-core/sm4-xts,gmcrypto-core/crypto-bigint-scalar,gmcrypto-core/sm2-key-exchange,gmcrypto-core/x509,gmcrypto-core/tlcp,gmcrypto-core/aead-traits --exclude-dev check
```

Update `deny.toml` lines 60-61 and `CLAUDE.md` supply-chain commands to name the default plus explicit runtime-profile passes. State that `regen-header` is excluded and remove every claim that CI runs cargo-deny with `--all-features`.

- [ ] **Step 4: Reclassify GmSSL failures within the existing job**

Remove job-level `continue-on-error: true`. Give the cache, provisioning, and version steps IDs and tolerate only those infrastructure steps:

```yaml
      - name: Cache GmSSL install prefix
        id: gmssl-cache
        continue-on-error: true
        uses: actions/cache@v4
```

Replace the conditional build step with one unconditional provisioning step:

```yaml
      - name: Provision GmSSL ${{ env.GMSSL_TAG }} oracle
        id: gmssl-provision
        continue-on-error: true
        env:
          CACHE_HIT: ${{ steps.gmssl-cache.outputs.cache-hit }}
        run: |
          set -euxo pipefail
          if [ "$CACHE_HIT" != "true" ]; then
            git clone --depth 1 --branch "$GMSSL_TAG" \
              https://github.com/guanzhi/GmSSL.git "$RUNNER_TEMP/gmssl-src"
            cmake -S "$RUNNER_TEMP/gmssl-src" -B "$RUNNER_TEMP/gmssl-src/build" \
              -DCMAKE_BUILD_TYPE=Release \
              -DBUILD_SHARED_LIBS=OFF \
              -DCMAKE_INSTALL_PREFIX="$HOME/gmssl-$GMSSL_TAG"
            cmake --build "$RUNNER_TEMP/gmssl-src/build" --parallel
            cmake --install "$RUNNER_TEMP/gmssl-src/build"
          fi
          test -x "$HOME/gmssl-$GMSSL_TAG/bin/gmssl"
```

Run the path and version steps only after successful provisioning. Give the version step `id: gmssl-version` and `continue-on-error: true`. Add this exact condition to the 13-test suite:

```yaml
        if: steps.gmssl-provision.outcome == 'success' && steps.gmssl-version.outcome == 'success'
```

Append an infrastructure summary that cannot mask an interop failure:

```yaml
      - name: Report GmSSL infrastructure status
        if: ${{ always() && (steps.gmssl-provision.outcome != 'success' || steps.gmssl-version.outcome != 'success') }}
        env:
          PROVISION_OUTCOME: ${{ steps.gmssl-provision.outcome }}
          VERSION_OUTCOME: ${{ steps.gmssl-version.outcome }}
        run: |
          echo "::warning title=GmSSL infrastructure unavailable::provision=$PROVISION_OUTCOME version=$VERSION_OUTCOME; interoperability suite was not run"
          {
            echo "### GmSSL infrastructure unavailable"
            echo
            echo "The interoperability suite was not run because the pinned oracle could not be prepared."
            echo
            echo "- provision: \`$PROVISION_OUTCOME\`"
            echo "- version assertion: \`$VERSION_OUTCOME\`"
            echo
            echo "This is non-blocking infrastructure telemetry, not a gmcrypto-core interoperability pass."
          } >> "$GITHUB_STEP_SUMMARY"
```

- [ ] **Step 5: Validate Task 2 locally**

Run:

```bash
for example in crates/gmcrypto-c/examples/*.c; do cc -std=c11 -Wall -Wextra -Werror -fsyntax-only -I crates/gmcrypto-c/include "$example"; done
gitleaks git --no-banner --redact --verbose
cargo generate-lockfile
cargo deny --exclude-dev check
cargo deny --features gmcrypto-core/digest-traits,gmcrypto-core/cipher-traits,gmcrypto-core/sm4-bitsliced,gmcrypto-core/sm4-bitsliced-simd,gmcrypto-core/sm4-aead,gmcrypto-core/sm4-xts,gmcrypto-core/crypto-bigint-scalar,gmcrypto-core/sm2-key-exchange,gmcrypto-core/x509,gmcrypto-core/tlcp,gmcrypto-core/aead-traits --exclude-dev check
```

Expected: every command exits 0. The policy verifier still fails only on the missing noise twin.

- [ ] **Step 6: Commit deterministic CI hardening**

```bash
git add .github/workflows/ci.yml .github/scripts/check_assurance_policy.py deny.toml CLAUDE.md
git commit -m "ci: harden assurance gates and classify gmssl failures"
```

### Task 3: Add required nonblocking dudect noise-twin telemetry

**Files:**
- Modify: `crates/gmcrypto-core/benches/timing_leaks.rs`
- Modify: `.github/workflows/dudect-pr.yml`
- Modify: `.github/workflows/dudect-nightly.yml`
- Modify: `.github/scripts/check_assurance_policy.py`

- [ ] **Step 1: Confirm the policy verifier is RED only for the twin**

Run `python3 .github/scripts/check_assurance_policy.py` and confirm the remaining failures name the benchmark, registration, and PR/nightly telemetry wiring.

- [ ] **Step 2: Add the fixed-work class-split target**

Add this function after the two existing `noise_floor_*` probes:

```rust
/// Two-distinct-input, fixed-work noise reference for class-split telemetry.
///
/// Unlike the v0.19 fix-vs-fix probes, the two dudect classes select distinct
/// values at distinct addresses. The timed body has no data-dependent branch,
/// lookup, allocation, or loop bound. This first calibration target is
/// telemetry only; it is not claimed to be duration-matched to field invert.
fn noise_twin_class_split(runner: &mut CtRunner, rng: &mut BenchRng) {
    let left = [0x36u8; 32];
    let right = [0xc9u8; 32];
    for _ in 0..sample_count() {
        let (class, input) = if rng.random::<bool>() {
            (Class::Left, &left)
        } else {
            (Class::Right, &right)
        };
        runner.run_one(class, || {
            let mut acc = 0x9e37_79b9_7f4a_7c15u64;
            for _ in 0..8 {
                for &byte in input {
                    acc = acc.rotate_left(7) ^ u64::from(std::hint::black_box(byte));
                }
            }
            std::hint::black_box(acc)
        });
    }
}
```

Register it in the base `benches` vector:

```rust
        BenchMetadata {
            name: BenchName("noise_twin_class_split"),
            seed: None,
            benchfn: noise_twin_class_split,
        },
```

Update the module census from fifteen to sixteen base targets and describe the twin as nonblocking required telemetry.

- [ ] **Step 3: Require measurement completeness in both parsers**

In each inline parser, define:

```python
          required_telemetry = ["noise_twin_class_split"]
```

Include `required_telemetry` in the completeness loop, without adding it to `required_low`, `required_high`, or `gross_regression_sentinel`. After blocking/sentinel output, print:

```python
          for name in required_telemetry:
              print(f"NOISE-TWIN: {name} {telem(name)} (required measurement; non-blocking value)")
```

- [ ] **Step 4: Verify GREEN and execute a bounded real measurement**

Run:

```bash
python3 .github/scripts/check_assurance_policy.py
cargo fmt --all -- --check
DUDECT_SAMPLES=1000 cargo bench -p gmcrypto-core --bench timing_leaks --features crypto-bigint-scalar -- --filter noise_twin_class_split
```

Expected: policy verifier exits 0; format check exits 0; benchmark output contains one `bench noise_twin_class_split` line with a parsed `max tau` value.

- [ ] **Step 5: Commit the telemetry target**

```bash
git add crates/gmcrypto-core/benches/timing_leaks.rs .github/workflows/dudect-pr.yml .github/workflows/dudect-nightly.yml .github/scripts/check_assurance_policy.py
git commit -m "bench: add class-split dudect noise twin telemetry"
```

### Task 4: Reconcile repository assurance documentation

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `CLAUDE.md`
- Modify: `docs/v0.5-dudect-recalibration.md`
- Modify: `docs/2026-08-10-assurance-hardening-design.md` only if implementation evidence requires a correction

- [ ] **Step 1: Update the Unreleased maintenance record**

Record that C examples are now compiled in CI, gitleaks history scanning is continuous, cargo-deny is pinned/aligned, and GmSSL mismatches are blocking while third-party oracle infrastructure failures are explicitly nonblocking. Replace the previous point-in-time gitleaks and “CI does not build C examples” statements rather than leaving contradictory history.

- [ ] **Step 2: Record the August 7 timing event**

Append a dated section to `docs/v0.5-dudect-recalibration.md` containing:

- run `31151022062`, exact runner image `20260720.247.2`;
- SIMD fanout measurements `0.0213, 0.2038, 0.0291, 0.2008, 0.3748` and median `0.2008` against `0.20`;
- same-commit/image follow-up medians `0.0444`, `0.0292`, and `0.0980` on August 8-10;
- monitoring conclusion only: no threshold change and no leak/false-positive classification.

- [ ] **Step 3: Update the living developer contract**

In `CLAUDE.md`, change the base target census to sixteen, describe `noise_twin_class_split` as required nonblocking telemetry, remove it from the deferred backlog, retain F21 as open, update cargo-deny 0.20.2 command syntax, and describe the GmSSL failure classification accurately.

- [ ] **Step 4: Verify documentation consistency and commit**

Run:

```bash
rg -n "CI does not build C examples|Nothing in CI runs gitleaks|cargo deny check --exclude-dev|base count is now 15|class-split-aware .*noise-twin.*deferred" CHANGELOG.md CLAUDE.md deny.toml docs/v0.5-dudect-recalibration.md
git diff --check
```

Expected: no stale claims; `git diff --check` exits 0.

```bash
git add CHANGELOG.md CLAUDE.md docs/v0.5-dudect-recalibration.md docs/2026-08-10-assurance-hardening-design.md
git commit -m "docs: record assurance hardening and dudect monitoring"
```

### Task 5: Synchronize Notion project state

**External records:**
- Project page: `35ca01fccd2b811ab179e824f1d5ca15`
- Existing O2 work item, dudect monitoring risk, fuzz-coverage narrative, and interop/gitleaks work items discovered from the project page and its related data sources

- [ ] **Step 1: Fetch current records immediately before mutation**

Fetch the project page, then fetch/query each linked work-item and risk data source. Preserve the returned schemas, page IDs, owners, relations, and exact old content for search-and-replace updates.

- [ ] **Step 2: Apply evidence-bounded updates**

- Replace the stale fuzz statement with: coverage summaries are surfaced in the job summary and missing coverage data is blocking; coverage percentage remains ungated.
- Set the O2 sans-I/O TLCP decision to Deferred while retaining its reopen gate: named consumer, committed owner, day-one test/security baseline, and explicit crate-boundary decision.
- Add the August 7 SIMD fanout event to the existing dudect monitoring risk with the exact measurements and “monitoring/no threshold change” conclusion.
- Mark C-example, gitleaks, cargo-deny, and GmSSL hardening as pending merge on `codex/assurance-hardening`, not landed on `main`.
- Retain the independent-audit limitation unchanged.

- [ ] **Step 3: Re-fetch and verify**

Re-fetch every mutated page. Confirm the replacement text is present, the stale text is absent, O2 is Deferred with all four reopen conditions, the timing event is Monitoring, and no unrelated properties or page sections changed.

### Task 6: Full verification and branch completion

**Files:** All changed files on `codex/assurance-hardening`

- [ ] **Step 1: Validate configuration and policy**

```bash
python3 .github/scripts/check_assurance_policy.py
ruby -e 'require "yaml"; Dir[".github/workflows/*.yml"].sort.each { |p| YAML.parse_file(p); puts "ok #{p}" }'
gitleaks git --no-banner --redact --verbose
```

- [ ] **Step 2: Validate the executable gates**

```bash
for example in crates/gmcrypto-c/examples/*.c; do cc -std=c11 -Wall -Wextra -Werror -fsyntax-only -I crates/gmcrypto-c/include "$example"; done
cargo generate-lockfile
cargo deny --exclude-dev check
cargo deny --features gmcrypto-core/digest-traits,gmcrypto-core/cipher-traits,gmcrypto-core/sm4-bitsliced,gmcrypto-core/sm4-bitsliced-simd,gmcrypto-core/sm4-aead,gmcrypto-core/sm4-xts,gmcrypto-core/crypto-bigint-scalar,gmcrypto-core/sm2-key-exchange,gmcrypto-core/x509,gmcrypto-core/tlcp,gmcrypto-core/aead-traits --exclude-dev check
GMCRYPTO_GMSSL=1 cargo test -p gmcrypto-core --test interop_gmssl --features sm4-aead -- --nocapture
DUDECT_SAMPLES=1000 cargo bench -p gmcrypto-core --bench timing_leaks --features crypto-bigint-scalar -- --filter noise_twin_class_split
```

- [ ] **Step 3: Run the full Rust regression suite**

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo test -p gmcrypto-core --all-features
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features sm4-aead,sm4-bitsliced-simd,digest-traits,cipher-traits,crypto-bigint-scalar,sm2-key-exchange,x509,tlcp,aead-traits --all-targets -- -D warnings
```

- [ ] **Step 4: Audit scope and status**

```bash
git diff origin/main...HEAD --check
git diff origin/main...HEAD --stat
git status --short --branch
```

Inspect the full diff requirement-by-requirement against the design. Confirm no production cryptographic source, public API, C ABI, release version, F21 target, or authoritative timing threshold changed.

- [ ] **Step 5: Commit any verification-only corrections**

If verification required changes, stage only those files and commit with a focused message. Leave the branch clean and do not push or open a PR unless explicitly requested.
