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
require(
    "C example gate uses strict syntax flags",
    "-std=c11 -Wall -Wextra -Werror -fsyntax-only" in CI,
)
require("gitleaks is pinned", "tool: gitleaks@8.30.1" in CI)
require("gitleaks checkout has full history", "fetch-depth: 0" in CI)
require("gitleaks scans committed history", "gitleaks git --no-banner --redact --verbose" in CI)
require("cargo-deny is pinned to 0.20.2", "tool: cargo-deny@0.20.2" in CI)
require("cargo-deny default profile uses 0.20 syntax", "cargo deny --exclude-dev check" in CI)
require(
    "cargo-deny runtime profile uses 0.20 syntax",
    "--exclude-dev check" in CI
    and "cargo deny --features gmcrypto-core/digest-traits" in CI,
)
require(
    "GmSSL job is not globally tolerated",
    re.search(r"^    continue-on-error:", interop, re.M) is None,
)
require("GmSSL provisioning has a stable id", "id: gmssl-provision" in interop)
require("GmSSL version assertion has a stable id", "id: gmssl-version" in interop)
require(
    "GmSSL infrastructure is step-tolerated",
    interop.count("continue-on-error: true") >= 3,
)
require(
    "interop runs only with a ready pinned oracle",
    "if: steps.gmssl-provision.outcome == 'success' && steps.gmssl-version.outcome == 'success'"
    in interop,
)
require(
    "GmSSL infrastructure status is summarized",
    "Report GmSSL infrastructure status" in interop,
)
require("noise twin benchmark exists", "fn noise_twin_class_split(" in TIMING)
require(
    "noise twin benchmark is registered",
    'BenchName("noise_twin_class_split")' in TIMING,
)
for workflow_name, workflow in (("PR", DUDECT_PR), ("nightly", DUDECT_NIGHTLY)):
    require(
        f"{workflow_name} dudect requires noise-twin telemetry",
        'required_telemetry = ["noise_twin_class_split"]' in workflow,
    )
    require(
        f"{workflow_name} dudect labels noise-twin output",
        "NOISE-TWIN:" in workflow,
    )

if failures:
    for failure in failures:
        print(f"FAIL: {failure}")
    raise SystemExit(1)

print("assurance workflow policy: ok")
