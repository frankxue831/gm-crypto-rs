# PR #149 Review Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve all five open PR #149 review threads, prove the changes locally and in GitHub Actions, and merge only after a fresh readiness audit.

**Architecture:** Keep `.github/scripts/check_assurance_policy.py` as the executable contract for workflow structure. Repair unusable GmSSL caches before running the independently pinned version guard, make suite execution state visible on every run, and encode the noise twin's telemetry-only status plus completeness wiring as mutation-tested invariants. Limit non-workflow edits to the five stale C-example banners and the review-remediation documentation.

**Tech Stack:** GitHub Actions YAML, Python 3 standard library, Bash, CMake, GmSSL 3.2.0, actionlint, Cargo/Rust, GitHub CLI and GitHub GraphQL.

---

### Task 1: Lock the noise twin to telemetry-only status

**Files:**
- Modify: `.github/scripts/check_assurance_policy.py`
- Read: `.github/workflows/dudect-pr.yml`
- Read: `.github/workflows/dudect-nightly.yml`
- Read: `crates/gmcrypto-core/benches/timing_leaks.rs`

- [ ] **Step 1: Add gate-promotion mutations before adding the invariant**

Add these two `must_reject` calls to `mutation_self_test()`:

```python
    must_reject(
        "PR noise twin promoted into a threshold map",
        "PR dudect keeps noise-twin telemetry out of gate maps",
        dudect_pr=DUDECT_PR.replace(
            "          required_low  = {\n",
            '          required_low  = {\n              "noise_twin_class_split": 0.20,\n',
            1,
        ),
    )
    must_reject(
        "nightly noise twin promoted into a threshold map",
        "nightly dudect keeps noise-twin telemetry out of gate maps",
        dudect_nightly=DUDECT_NIGHTLY.replace(
            "          required_low  = {\n",
            '          required_low  = {\n              "noise_twin_class_split": 0.20,\n',
            1,
        ),
    )
```

- [ ] **Step 2: Run the policy verifier and confirm RED**

Run:

```bash
python3 .github/scripts/check_assurance_policy.py
```

Expected: exit 1 with both `mutation was not rejected` messages. This proves the current verifier permits premature promotion.

- [ ] **Step 3: Add the telemetry-only invariant**

Compile one key-pattern regex once inside `audit()` and extend the existing PR/nightly loop:

```python
    gate_key = re.compile(r'^\s*"noise_twin_class_split"\s*:', re.M)
    for workflow_name, workflow in (("PR", dudect_pr), ("nightly", dudect_nightly)):
        require(
            f"{workflow_name} dudect requires noise-twin telemetry",
            'required_telemetry = ["noise_twin_class_split"]' in workflow,
        )
        require(f"{workflow_name} dudect labels noise-twin output", "NOISE-TWIN:" in workflow)
        require(
            f"{workflow_name} dudect keeps noise-twin telemetry out of gate maps",
            gate_key.search(workflow) is None,
        )
```

- [ ] **Step 4: Add deliberate completeness mutations**

Add mutation cases that independently remove the PR/nightly `required_telemetry` assignment, replace each workflow's `NOISE-TWIN:` label, and remove the benchmark registration:

```python
    for label, key, workflow in (
        ("PR", "dudect_pr", DUDECT_PR),
        ("nightly", "dudect_nightly", DUDECT_NIGHTLY),
    ):
        must_reject(
            f"{label} required noise telemetry removed",
            f"{label} dudect requires noise-twin telemetry",
            **{key: workflow.replace(
                '          required_telemetry = ["noise_twin_class_split"]\n',
                "",
                1,
            )},
        )
        must_reject(
            f"{label} noise telemetry label removed",
            f"{label} dudect labels noise-twin output",
            **{key: workflow.replace("NOISE-TWIN:", "TELEMETRY:", 1)},
        )
    must_reject(
        "noise twin benchmark deregistered",
        "noise twin benchmark is registered",
        timing=TIMING.replace('BenchName("noise_twin_class_split")', 'BenchName("noise_twin_removed")', 1),
    )
```

- [ ] **Step 5: Verify GREEN**

Run:

```bash
python3 .github/scripts/check_assurance_policy.py
```

Expected: `assurance workflow policy: ok (semantic checks + mutation self-tests)`.

- [ ] **Step 6: Commit the policy increment**

```bash
git add .github/scripts/check_assurance_policy.py
git commit -m "test: lock dudect noise twin to telemetry only"
```

### Task 2: Repair sticky GmSSL caches and expose suite execution

**Files:**
- Modify: `.github/scripts/check_assurance_policy.py`
- Modify: `.github/workflows/ci.yml`
- Modify: `CLAUDE.md` only if its workflow description names the old check

- [ ] **Step 1: Extend the policy contract first**

Change the report lookup to `Report GmSSL interoperability status`, capture `provision_script`, and add these requirements:

```python
    provision_script = active_run(provision)
    require(
        "GmSSL check name discloses non-blocking infrastructure",
        scalar(interop, "name", 4) == "gmssl interop (mismatch gates; infra non-blocking)",
    )
    require(
        "GmSSL repairs an unusable cache before provisioning",
        all(token in provision_script for token in (
            "cache_usable=false",
            'cached_version="$("$oracle" version 2>/dev/null | head -n1 || true)"',
            'if [ "$cached_version" = "$want" ]; then',
            'rm -rf -- "$prefix" "$source_dir"',
        )),
    )
    require(
        "GmSSL status is always reported",
        scalar(report, "if", 8) == "${{ always() }}",
    )
    require(
        "GmSSL suite execution is machine-visible",
        'echo "INTEROP_SUITE=$interop_state"' in report_script
        and 'echo "INTEROP_SUITE=\\`$interop_state\\`"' in report_script,
    )
```

Replace the old conditional-report requirement; the always-report rule supersedes it. Keep the four raw outcome environment checks and the summary requirement.

Add two mutations: remove the cached-version equality check and change `${{ always() }}` to the old degradation-only expression. Each must be rejected by the corresponding new requirement.

- [ ] **Step 2: Run the policy verifier and confirm RED**

Run:

```bash
python3 .github/scripts/check_assurance_policy.py
```

Expected: exit 1 for the transparent check name, repair-first cache handling, renamed report step, and unconditional status report.

- [ ] **Step 3: Implement repair-first provisioning**

Rename the job to `gmssl interop (mismatch gates; infra non-blocking)` and replace the provision shell body with:

```yaml
        run: |
          set -euxo pipefail
          prefix="$HOME/gmssl-$GMSSL_TAG"
          oracle="$prefix/bin/gmssl"
          source_dir="$RUNNER_TEMP/gmssl-src"
          want="GmSSL ${GMSSL_TAG#v}"
          cache_usable=false
          if [ "$CACHE_HIT" = "true" ] && [ -x "$oracle" ]; then
            cached_version="$("$oracle" version 2>/dev/null | head -n1 || true)"
            if [ "$cached_version" = "$want" ]; then
              cache_usable=true
            fi
          fi
          if [ "$cache_usable" != "true" ]; then
            case "$prefix" in
              "$HOME"/gmssl-v*) ;;
              *) echo "::error::refusing to clean unexpected GmSSL prefix: $prefix"; exit 1 ;;
            esac
            rm -rf -- "$prefix" "$source_dir"
            git clone --depth 1 --branch "$GMSSL_TAG" \
              https://github.com/guanzhi/GmSSL.git "$source_dir"
            cmake -S "$source_dir" -B "$source_dir/build" \
              -DCMAKE_BUILD_TYPE=Release \
              -DBUILD_SHARED_LIBS=OFF \
              -DCMAKE_INSTALL_PREFIX="$prefix"
            cmake --build "$source_dir/build" --parallel
            cmake --install "$source_dir/build"
          fi
          test -x "$oracle"
```

Retain comments explaining the static build and exact cache key, adapting paths to `prefix` and `source_dir` where necessary.

- [ ] **Step 4: Make final suite status unconditional**

Rename the report step and replace it with:

```yaml
      - name: Report GmSSL interoperability status
        if: ${{ always() }}
        env:
          CACHE_OUTCOME: ${{ steps.gmssl-cache.outcome }}
          PROVISION_OUTCOME: ${{ steps.gmssl-provision.outcome }}
          VERSION_OUTCOME: ${{ steps.gmssl-version.outcome }}
          SUITE_OUTCOME: ${{ steps.gmssl-suite.outcome }}
        run: |
          if [ "$SUITE_OUTCOME" = "skipped" ]; then
            interop_state=skipped
          else
            interop_state=ran
          fi
          echo "INTEROP_SUITE=$interop_state"
          {
            echo "### GmSSL interoperability status"
            echo
            echo "INTEROP_SUITE=\`$interop_state\`"
            echo
            echo "- cache: \`$CACHE_OUTCOME\`"
            echo "- provision: \`$PROVISION_OUTCOME\`"
            echo "- version assertion: \`$VERSION_OUTCOME\`"
            echo "- interoperability suite: \`$SUITE_OUTCOME\`"
          } >> "$GITHUB_STEP_SUMMARY"
          if [ "$PROVISION_OUTCOME" != "success" ] || [ "$VERSION_OUTCOME" != "success" ]; then
            echo "::warning title=GmSSL infrastructure unavailable::cache=$CACHE_OUTCOME provision=$PROVISION_OUTCOME version=$VERSION_OUTCOME suite=$SUITE_OUTCOME"
            echo "This is non-blocking infrastructure telemetry, not an interoperability pass." >> "$GITHUB_STEP_SUMMARY"
          elif [ "$CACHE_OUTCOME" != "success" ]; then
            echo "::warning title=GmSSL cache degraded::cache=$CACHE_OUTCOME; fallback provisioning succeeded; suite=$SUITE_OUTCOME"
            echo "Fallback provisioning recovered the cache failure; the suite outcome remains authoritative." >> "$GITHUB_STEP_SUMMARY"
          fi
```

The uncompensated suite step remains unchanged, so `SUITE_OUTCOME=failure` still fails the job even though the final report runs.

- [ ] **Step 5: Verify GREEN and workflow syntax**

Run:

```bash
python3 .github/scripts/check_assurance_policy.py
actionlint .github/workflows/ci.yml
ruby -e 'require "psych"; Psych.safe_load(File.read(".github/workflows/ci.yml"), aliases: true)'
```

Expected: all commands exit 0.

- [ ] **Step 6: Commit the GmSSL change**

```bash
git add .github/scripts/check_assurance_policy.py .github/workflows/ci.yml CLAUDE.md
git commit -m "ci: repair degraded gmssl cache state"
```

### Task 3: Reconcile all shipped C-example banners

**Files:**
- Modify: `crates/gmcrypto-c/examples/sm2_sign.c`
- Modify: `crates/gmcrypto-c/examples/sm2_key_exchange.c`
- Modify: `crates/gmcrypto-c/examples/sm4_ccm.c`
- Modify: `crates/gmcrypto-c/examples/sm4_gcm_streaming.c`
- Modify: `crates/gmcrypto-c/examples/sm4_xts_sector.c`

- [ ] **Step 1: Record the stale-text failure**

Run:

```bash
rg -n "CI does not build C examples|documentation-only" crates/gmcrypto-c/examples
```

Expected: five stale banners are reported.

- [ ] **Step 2: Replace each stale banner**

Use wording appropriate to each example while preserving the common contract:

```c
 * CI syntax-checks this example. Link and run it locally to confirm the
 * <surface name> works end-to-end from C.
```

For `sm2_sign.c`, remove the obsolete claim that no C toolchain is pinned. Do not change executable code.

- [ ] **Step 3: Verify all nine translation units and stale-text absence**

Run:

```bash
if rg -n "CI does not build C examples|documentation-only" crates/gmcrypto-c/examples; then exit 1; fi
for example in crates/gmcrypto-c/examples/*.c; do
  cc -std=c11 -Wall -Wextra -Werror -fsyntax-only \
    -I crates/gmcrypto-c/include "$example"
done
```

Expected: no stale text and all nine examples compile.

- [ ] **Step 4: Commit the banner reconciliation**

```bash
git add crates/gmcrypto-c/examples/sm2_sign.c \
  crates/gmcrypto-c/examples/sm2_key_exchange.c \
  crates/gmcrypto-c/examples/sm4_ccm.c \
  crates/gmcrypto-c/examples/sm4_gcm_streaming.c \
  crates/gmcrypto-c/examples/sm4_xts_sector.c
git commit -m "docs: align all C example CI banners"
```

### Task 4: Full local completion audit

**Files:** All files changed on `codex/assurance-hardening`

- [ ] **Step 1: Validate policy and workflow configuration**

```bash
python3 .github/scripts/check_assurance_policy.py
actionlint .github/workflows/ci.yml .github/workflows/dudect-pr.yml \
  .github/workflows/dudect-nightly.yml .github/workflows/gitleaks.yml
ruby -e 'require "psych"; Dir[".github/workflows/*.yml"].sort.each { |p| Psych.safe_load(File.read(p), aliases: true) }'
git diff --check origin/main...HEAD
```

Expected: all exit 0.

- [ ] **Step 2: Validate security and interoperability gates**

```bash
gitleaks git --no-banner --redact --verbose
cargo deny --exclude-dev check
cargo deny --features gmcrypto-core/digest-traits,gmcrypto-core/cipher-traits,gmcrypto-core/sm4-bitsliced,gmcrypto-core/sm4-bitsliced-simd,gmcrypto-core/sm4-aead,gmcrypto-core/sm4-xts,gmcrypto-core/crypto-bigint-scalar,gmcrypto-core/sm2-key-exchange,gmcrypto-core/x509,gmcrypto-core/tlcp,gmcrypto-core/aead-traits --exclude-dev check
GMCRYPTO_GMSSL=1 cargo test -p gmcrypto-core --test interop_gmssl --features sm4-aead -- --nocapture
```

Expected: no leaks, both deny profiles pass, and GmSSL runs 13/13 tests.

- [ ] **Step 3: Validate Rust and C regressions**

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo test -p gmcrypto-core --all-features
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features sm4-aead,sm4-bitsliced-simd,digest-traits,cipher-traits,crypto-bigint-scalar,sm2-key-exchange,x509,tlcp,aead-traits --all-targets -- -D warnings
cargo build -p gmcrypto-c --features regen-header
git diff --exit-code crates/gmcrypto-c/include/gmcrypto.h
```

Expected: all tests/lints pass and header regeneration creates no diff.

- [ ] **Step 4: Prove scope and threshold invariants**

```bash
git diff --quiet origin/main...HEAD -- crates/gmcrypto-core/src crates/gmcrypto-simd/src crates/gmcrypto-c/src
if git diff -U0 origin/main...HEAD -- .github/workflows/dudect-pr.yml .github/workflows/dudect-nightly.yml \
  | rg '^[+-].*"[a-z0-9_]+": [0-9]+\.[0-9]+'; then exit 1; fi
test -z "$(git status --short)"
```

Expected: no production source diff, no threshold-map numeric changes, and a clean worktree.

### Task 5: Push, re-check review state, and merge only when ready

**External state:** GitHub PR #149

- [ ] **Step 1: Push the complete branch**

```bash
git push origin codex/assurance-hardening
```

- [ ] **Step 2: Re-fetch thread-aware comments**

```bash
python3 /Users/fengxiang/.codex/plugins/cache/openai-curated-remote/github/0.1.8-2841cf9749ae/skills/gh-address-comments/scripts/fetch_comments.py
```

Expected: the same five threads may remain unresolved because no reply/resolve write was authorized, but their anchors are current or outdated and every requested code change is present in the branch.

- [ ] **Step 3: Wait for required checks and audit readiness**

Use `gh pr checks 149 --watch --interval 10 --required` and then inspect:

```bash
gh pr view 149 --json state,isDraft,mergeable,mergeStateStatus,reviewDecision,statusCheckRollup,headRefOid,baseRefOid,url
```

Ready means: PR open, remote head equals local HEAD, no failing or pending required check, `mergeable` is `MERGEABLE`, and `mergeStateStatus` is not `BEHIND`, `BLOCKED`, `DIRTY`, or `UNKNOWN`. Unresolved review threads must not violate repository protection.

- [ ] **Step 4: Mark ready and perform one final audit**

Convert the Draft PR to ready-for-review, then repeat the metadata and required-check queries. Do not merge if the state changes or a new check starts failing.

- [ ] **Step 5: Merge PR #149**

Use the repository's permitted merge method only after Step 4 proves readiness. Confirm the returned merged state and merge commit SHA, then verify `origin/main` contains that commit.
