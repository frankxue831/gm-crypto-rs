#!/usr/bin/env python3
"""Semantic regression checks for assurance-critical workflow wiring."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    candidate = ROOT / path
    return candidate.read_text() if candidate.exists() else ""


CI = read(".github/workflows/ci.yml")
GITLEAKS = read(".github/workflows/gitleaks.yml")
DUDECT_PR = read(".github/workflows/dudect-pr.yml")
DUDECT_NIGHTLY = read(".github/workflows/dudect-nightly.yml")
TIMING = read("crates/gmcrypto-core/benches/timing_leaks.rs")


def indented_block(text: str, header: str, indent: int) -> str:
    """Return one YAML mapping/list block, bounded by indentation."""
    lines = text.splitlines()
    try:
        start = lines.index(" " * indent + header)
    except ValueError:
        return ""
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        current_indent = len(line) - len(line.lstrip())
        if current_indent <= indent:
            end = index
            break
    return "\n".join(lines[start:end])


def job(text: str, name: str) -> str:
    return indented_block(text, f"{name}:", 2)


def step_named(job_text: str, name: str) -> str:
    return indented_block(job_text, f"- name: {name}", 6)


def step_uses(job_text: str, action: str) -> str:
    return indented_block(job_text, f"- uses: {action}", 6)


def scalar(block: str, key: str, indent: int) -> str | None:
    prefix = " " * indent
    match = re.search(rf"^{re.escape(prefix)}{re.escape(key)}:\s*(.*?)\s*$", block, re.M)
    return match.group(1) if match else None


def active_run(step: str) -> str:
    """Extract active shell from a step's run key, excluding YAML comments."""
    lines = step.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^ {8}run:\s*(.*)$", line)
        if not match:
            continue
        value = match.group(1)
        if value and value != "|":
            return value
        body: list[str] = []
        for candidate in lines[index + 1 :]:
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= 8:
                break
            stripped = candidate.strip()
            if stripped and not stripped.startswith("#"):
                body.append(stripped)
        return "\n".join(body)
    return ""


def audit(ci: str, gitleaks: str, dudect_pr: str, dudect_nightly: str, timing: str) -> list[str]:
    failures: list[str] = []

    def require(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    build = job(ci, "build")
    cabi = job(ci, "cabi")
    deny = job(ci, "deny")
    interop = job(ci, "interop-gmssl")

    policy_step = step_named(build, "Verify assurance workflow policy")
    require(
        "policy verifier is executed by the build job",
        active_run(policy_step) == "python3 .github/scripts/check_assurance_policy.py",
    )

    c_examples = step_named(cabi, "Compile shipped C examples")
    c_script = active_run(c_examples)
    require("C examples are compiled by the cabi job", bool(c_examples))
    require(
        "C example gate uses strict syntax flags",
        "-std=c11 -Wall -Wextra -Werror -fsyntax-only" in c_script,
    )
    require("C example gate fails an empty glob", "${#examples[@]} == 0" in c_script)

    trigger = indented_block(gitleaks, "on:", 0)
    push_trigger = indented_block(trigger, "push:", 2)
    pull_request_trigger = indented_block(trigger, "pull_request:", 2)
    scan = job(gitleaks, "scan")
    checkout = step_uses(scan, "actions/checkout@v4")
    install = step_named(scan, "Install gitleaks")
    scan_step = step_named(scan, "Scan committed history")
    require("dedicated gitleaks workflow exists", bool(gitleaks))
    require(
        "gitleaks workflow scans main pushes",
        scalar(push_trigger, "branches", 4) == "[main]",
    )
    require(
        "gitleaks workflow scans main pull requests",
        scalar(pull_request_trigger, "branches", 4) == "[main]",
    )
    require(
        "gitleaks workflow has no path exclusions",
        "paths:" not in trigger and "paths-ignore:" not in trigger,
    )
    require("gitleaks checkout has full history", scalar(checkout, "fetch-depth", 10) == "0")
    require("gitleaks is pinned", "tool: gitleaks@8.30.1" in install)
    require(
        "gitleaks scans committed history",
        active_run(scan_step) == "gitleaks git --no-banner --redact --verbose",
    )

    deny_install = step_named(deny, "Install cargo-deny")
    deny_default = step_named(deny, "Run cargo-deny (default features, excluding dev-deps)")
    deny_runtime = step_named(deny, "Run cargo-deny (runtime opt-in features, excluding dev-deps)")
    require("cargo-deny is pinned to 0.20.2", "tool: cargo-deny@0.20.2" in deny_install)
    require(
        "cargo-deny default profile uses 0.20 syntax",
        active_run(deny_default) == "cargo deny --exclude-dev check",
    )
    runtime_run = active_run(deny_runtime)
    require(
        "cargo-deny runtime profile uses 0.20 syntax",
        runtime_run.startswith("cargo deny --features gmcrypto-core/digest-traits")
        and runtime_run.endswith("--exclude-dev check"),
    )

    cache = step_named(interop, "Cache GmSSL install prefix")
    provision = step_named(interop, "Provision GmSSL ${{ env.GMSSL_TAG }} oracle")
    version = step_named(interop, "Assert oracle version (drift guard)")
    suite = step_named(interop, "gmssl interop suite (13 tests)")
    report = step_named(interop, "Report GmSSL infrastructure status")
    require(
        "GmSSL job is not globally tolerated",
        scalar(interop, "continue-on-error", 4) is None,
    )
    require("GmSSL cache has a stable id", scalar(cache, "id", 8) == "gmssl-cache")
    require("GmSSL provisioning has a stable id", scalar(provision, "id", 8) == "gmssl-provision")
    require("GmSSL version assertion has a stable id", scalar(version, "id", 8) == "gmssl-version")
    require("GmSSL suite has a stable id", scalar(suite, "id", 8) == "gmssl-suite")
    for label, block in (("cache", cache), ("provisioning", provision), ("version", version)):
        require(
            f"GmSSL {label} failure is step-tolerated",
            scalar(block, "continue-on-error", 8) == "true",
        )
    require(
        "GmSSL interoperability suite is blocking",
        scalar(suite, "continue-on-error", 8) is None,
    )
    require(
        "interop runs only with a ready pinned oracle",
        scalar(suite, "if", 8)
        == "steps.gmssl-provision.outcome == 'success' && steps.gmssl-version.outcome == 'success'",
    )
    report_if = scalar(report, "if", 8) or ""
    report_script = active_run(report)
    require(
        "GmSSL cache/provision/version degradation triggers reporting",
        all(name in report_if for name in ("gmssl-cache.outcome", "gmssl-provision.outcome", "gmssl-version.outcome")),
    )
    require(
        "GmSSL infrastructure outcomes are summarized",
        all(name in report for name in ("CACHE_OUTCOME:", "PROVISION_OUTCOME:", "VERSION_OUTCOME:", "SUITE_OUTCOME:"))
        and "GITHUB_STEP_SUMMARY" in report_script,
    )

    require("noise twin benchmark exists", "fn noise_twin_class_split(" in timing)
    require("noise twin fixed-work helper cannot inline", "#[inline(never)]\nfn noise_twin_fixed_work(" in timing)
    require(
        "noise twin materializes opaque distinct inputs",
        "std::hint::black_box([0x36u8; 32])" in timing
        and "std::hint::black_box([0xc9u8; 32])" in timing,
    )
    require(
        "noise twin makes the selected reference opaque before timing",
        "let input = std::hint::black_box(input);" in timing,
    )
    require("noise twin benchmark is registered", 'BenchName("noise_twin_class_split")' in timing)
    for workflow_name, workflow in (("PR", dudect_pr), ("nightly", dudect_nightly)):
        require(
            f"{workflow_name} dudect requires noise-twin telemetry",
            'required_telemetry = ["noise_twin_class_split"]' in workflow,
        )
        require(f"{workflow_name} dudect labels noise-twin output", "NOISE-TWIN:" in workflow)

    return failures


def mutation_self_test() -> list[str]:
    failures: list[str] = []

    def must_reject(label: str, expected: str, **overrides: str) -> None:
        found = audit(
            overrides.get("ci", CI),
            overrides.get("gitleaks", GITLEAKS),
            overrides.get("dudect_pr", DUDECT_PR),
            overrides.get("dudect_nightly", DUDECT_NIGHTLY),
            overrides.get("timing", TIMING),
        )
        if not any(expected in failure for failure in found):
            failures.append(f"mutation was not rejected: {label}")

    must_reject(
        "commented-out gitleaks command",
        "gitleaks scans committed history",
        gitleaks=GITLEAKS.replace(
            "        run: gitleaks git --no-banner --redact --verbose",
            "        # run: gitleaks git --no-banner --redact --verbose",
            1,
        ),
    )
    must_reject(
        "gitleaks command moved out of its named scan step",
        "gitleaks scans committed history",
        gitleaks=GITLEAKS.replace(
            "      - name: Scan committed history\n"
            "        run: gitleaks git --no-banner --redact --verbose",
            "      - name: Scan committed history\n"
            "        run: 'true'\n"
            "      - name: Unrelated diagnostic\n"
            "        run: gitleaks git --no-banner --redact --verbose",
            1,
        ),
    )
    must_reject(
        "shallow gitleaks checkout",
        "gitleaks checkout has full history",
        gitleaks=GITLEAKS.replace("          fetch-depth: 0", "          fetch-depth: 1", 1),
    )
    must_reject(
        "gitleaks push moved off main",
        "gitleaks workflow scans main pushes",
        gitleaks=GITLEAKS.replace(
            "  push:\n    branches: [main]",
            "  push:\n    branches: [develop]",
            1,
        ),
    )
    must_reject(
        "gitleaks pull request moved off main",
        "gitleaks workflow scans main pull requests",
        gitleaks=GITLEAKS.replace(
            "  pull_request:\n    branches: [main]",
            "  pull_request:\n    branches: [develop]",
            1,
        ),
    )
    must_reject(
        "tolerated interoperability suite",
        "interoperability suite is blocking",
        ci=CI.replace(
            "      - name: gmssl interop suite (13 tests)\n",
            "      - name: gmssl interop suite (13 tests)\n        continue-on-error: true\n",
            1,
        ),
    )
    must_reject(
        "inlinable noise-twin helper",
        "fixed-work helper cannot inline",
        timing=TIMING.replace("#[inline(never)]\nfn noise_twin_fixed_work(", "fn noise_twin_fixed_work(", 1),
    )
    return failures


failures = audit(CI, GITLEAKS, DUDECT_PR, DUDECT_NIGHTLY, TIMING)
if not failures:
    failures.extend(mutation_self_test())

if failures:
    for failure in failures:
        print(f"FAIL: {failure}")
    raise SystemExit(1)

print("assurance workflow policy: ok (semantic checks + mutation self-tests)")
