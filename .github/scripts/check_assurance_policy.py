#!/usr/bin/env python3
"""Semantic regression checks for assurance-critical workflow wiring."""

from pathlib import Path
import ast
import hashlib
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


def key_count(block: str, key: str, indent: int) -> int:
    """Count exact YAML mapping keys at one indentation level."""
    prefix = " " * indent
    return len(re.findall(rf"^{re.escape(prefix)}{re.escape(key)}:\s*", block, re.M))


def active_run(step: str) -> str:
    """Extract active shell from a step's run key, excluding YAML comments."""
    lines = step.splitlines()
    matches = [
        (index, match)
        for index, line in enumerate(lines)
        if (match := re.match(r"^ {8}run:\s*(.*)$", line))
    ]
    if len(matches) != 1:
        return ""
    index, match = matches[0]
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


def literal_run_body(step: str) -> str | None:
    """Return a literal-block run body with the YAML indentation removed."""
    lines = step.splitlines()
    matches = [
        index for index, line in enumerate(lines) if re.match(r"^ {8}run:\s*", line)
    ]
    if len(matches) != 1 or lines[matches[0]] != "        run: |":
        return None
    body: list[str] = []
    for candidate in lines[matches[0] + 1 :]:
        if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= 8:
            break
        if not candidate:
            body.append("")
        elif candidate.startswith("          "):
            body.append(candidate[10:])
        else:
            return None
    return "\n".join(body).rstrip()


def reviewed_python_heredoc(step: str) -> tuple[str, str] | None:
    """Check the shell envelope, then return Python source and AST fingerprint."""
    body = literal_run_body(step)
    if body is None:
        return None
    lines = body.splitlines()
    opening = [index for index, line in enumerate(lines) if line == "python3 - <<'PY'"]
    closing = [index for index, line in enumerate(lines) if line == "PY"]
    if len(opening) != 1 or len(closing) != 1 or closing[0] <= opening[0]:
        return None

    def active_shell(lines_to_check: list[str]) -> list[str]:
        return [
            line.strip()
            for line in lines_to_check
            if line.strip() and not line.lstrip().startswith("#")
        ]

    if active_shell(lines[: opening[0]]) != ["set -euo pipefail"]:
        return None
    if active_shell(lines[closing[0] + 1 :]):
        return None

    python_source = "\n".join(lines[opening[0] + 1 : closing[0]]) + "\n"
    try:
        tree = ast.parse(python_source)
    except SyntaxError:
        return None
    fingerprint = hashlib.sha256(
        ast.dump(tree, include_attributes=False).encode()
    ).hexdigest()
    return python_source, fingerprint


def active_source_lines(block: str) -> list[str]:
    """Return non-comment source lines while preserving indentation and order."""
    active: list[str] = []
    for line in block.splitlines():
        source = line.split("#", 1)[0].rstrip()
        if source.strip():
            active.append(source)
    return active


def contains_line_sequence(lines: list[str], expected: tuple[str, ...]) -> bool:
    """Return whether exact active lines occur contiguously in order."""
    width = len(expected)
    return any(tuple(lines[index : index + width]) == expected for index in range(len(lines) - width + 1))


def active_loop_body(block: str, header: str) -> list[str]:
    """Return active lines in the one exact Python loop headed by ``header``."""
    lines = block.splitlines()
    matches = [index for index, line in enumerate(lines) if line.rstrip() == header]
    if len(matches) != 1:
        return []
    start = matches[0]
    base_indent = len(header) - len(header.lstrip())
    body: list[str] = []
    for line in lines[start + 1 :]:
        source = line.split("#", 1)[0].rstrip()
        if not source.strip():
            continue
        if len(source) - len(source.lstrip()) <= base_indent:
            break
        body.append(source)
    return body


def strict_shell(script: str) -> bool:
    """Require fail-fast shell execution without local error tolerance."""
    return script.startswith("set -euo pipefail\n") and "||" not in script and "set +e" not in script


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
    require(
        "policy verifier execution metadata is blocking",
        key_count(policy_step, "if", 8) == 0
        and key_count(policy_step, "continue-on-error", 8) == 0
        and key_count(policy_step, "shell", 8) == 0
        and key_count(policy_step, "env", 8) == 0
        and key_count(build, "continue-on-error", 4) == 0,
    )

    c_examples = step_named(cabi, "Compile shipped C examples")
    c_script = active_run(c_examples)
    c_compile_command = (
        "cc -std=c11 -Wall -Wextra -Werror -fsyntax-only \\\n"
        '-I crates/gmcrypto-c/include "$example"'
    )
    c_compile_loop = (
        'for example in "${examples[@]}"; do\n'
        'echo "checking $example"\n'
        f"{c_compile_command}\n"
        "done"
    )
    c_empty_glob_guard = (
        "if (( ${#examples[@]} == 0 )); then\n"
        'echo "::error::no shipped C examples found"\n'
        "exit 1\n"
        "fi"
    )
    c_canonical_script = (
        "set -euo pipefail\n"
        "shopt -s nullglob\n"
        "examples=(crates/gmcrypto-c/examples/*.c)\n"
        f"{c_empty_glob_guard}\n"
        f"{c_compile_loop}"
    )
    require("C examples are compiled by the cabi job", bool(c_examples))
    require(
        "C example gate uses strict syntax flags",
        "-std=c11 -Wall -Wextra -Werror -fsyntax-only" in c_script,
    )
    require("C example gate fails an empty glob", c_empty_glob_guard in c_script)
    require(
        "C example compile command is structurally blocking",
        strict_shell(c_script)
        and c_compile_loop in c_script
        and scalar(c_examples, "continue-on-error", 8) is None,
    )
    require(
        "C example compile script matches reviewed canonical execution",
        c_script == c_canonical_script,
    )
    require(
        "C example execution metadata is blocking",
        key_count(c_examples, "if", 8) == 0
        and key_count(c_examples, "continue-on-error", 8) == 0
        and key_count(c_examples, "shell", 8) == 1
        and scalar(c_examples, "shell", 8) == "bash"
        and key_count(c_examples, "env", 8) == 0
        and key_count(cabi, "continue-on-error", 4) == 0,
    )

    trigger = indented_block(gitleaks, "on:", 0)
    push_trigger = indented_block(trigger, "push:", 2)
    pull_request_trigger = indented_block(trigger, "pull_request:", 2)
    scan = job(gitleaks, "scan")
    checkout = step_uses(scan, "actions/checkout@v4")
    install = step_named(scan, "Install gitleaks")
    scan_step = step_named(scan, "Scan committed history")
    install_script = active_run(install)
    checksum_command = 'echo "$GITLEAKS_SHA256  $archive" | sha256sum --check --status'
    extraction_command = 'tar -xzf "$archive" -C "$install_dir" gitleaks'
    verified_extraction = (
        f"{checksum_command}\n"
        'mkdir -p "$install_dir"\n'
        f"{extraction_command}"
    )
    gitleaks_install_canonical = (
        "set -euo pipefail\n"
        "GITLEAKS_VERSION=8.30.1\n"
        "GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb\n"
        'archive="$RUNNER_TEMP/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"\n'
        'install_dir="$RUNNER_TEMP/gitleaks-bin"\n'
        "curl --fail --silent --show-error --location \\\n"
        '--output "$archive" \\\n'
        '"https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"\n'
        f"{checksum_command}\n"
        'mkdir -p "$install_dir"\n'
        f"{extraction_command}\n"
        '"$install_dir/gitleaks" version\n'
        'echo "$install_dir" >> "$GITHUB_PATH"'
    )
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
    require(
        "gitleaks installs the pinned official release",
        "GITLEAKS_VERSION=8.30.1" in install_script
        and "https://github.com/gitleaks/gitleaks/releases/download/" in install_script
        and "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" in install_script
        and 'tar -xzf "$archive" -C "$install_dir" gitleaks' in install_script
        and 'echo "$install_dir" >> "$GITHUB_PATH"' in install_script,
    )
    require(
        "gitleaks verifies the pinned release checksum",
        "GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
        in install_script
        and checksum_command in install_script,
    )
    require(
        "gitleaks checksum command is structurally blocking",
        strict_shell(install_script)
        and verified_extraction in install_script
        and scalar(install, "continue-on-error", 8) is None,
    )
    require(
        "gitleaks scans committed history",
        active_run(scan_step) == "gitleaks git --no-banner --redact --verbose",
    )
    require(
        "gitleaks install script matches reviewed canonical execution",
        install_script == gitleaks_install_canonical,
    )
    require(
        "gitleaks execution metadata is blocking",
        key_count(install, "if", 8) == 0
        and key_count(install, "continue-on-error", 8) == 0
        and key_count(install, "shell", 8) == 1
        and scalar(install, "shell", 8) == "bash"
        and key_count(install, "env", 8) == 0
        and key_count(scan_step, "if", 8) == 0
        and key_count(scan_step, "continue-on-error", 8) == 0
        and key_count(scan_step, "shell", 8) == 0
        and key_count(scan_step, "env", 8) == 0
        and key_count(scan, "if", 4) == 0
        and key_count(scan, "continue-on-error", 4) == 0,
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
    report = step_named(interop, "Report GmSSL interoperability status")
    suite_env = indented_block(suite, "env:", 8)
    provision_script = active_run(provision)
    suite_script = active_run(suite)
    report_script = active_run(report)
    require(
        "GmSSL check name discloses non-blocking infrastructure",
        scalar(interop, "name", 4) == "gmssl interop (mismatch gates; infra non-blocking)",
    )
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
    suite_command = (
        "cargo test -p gmcrypto-core --test interop_gmssl --features sm4-aead \\\n"
        "-- --nocapture 2>&1 | tee interop.txt"
    )
    suite_skip_guard = (
        "if grep -q 'skipping: GMCRYPTO_GMSSL' interop.txt; then\n"
        'echo "::error::interop tests SKIPPED - GMCRYPTO_GMSSL did not reach the test process"\n'
        "exit 1\n"
        "fi"
    )
    suite_census_guard = (
        "if ! grep -qE '13 passed' interop.txt; then\n"
        'echo "::error::expected 13 interop tests to pass - census drifted"\n'
        "exit 1\n"
        "fi"
    )
    suite_execution = f"{suite_command}\n{suite_skip_guard}\n{suite_census_guard}"
    suite_canonical_script = f"set -euo pipefail\n{suite_execution}"
    require(
        "GmSSL interoperability suite enables oracle execution",
        scalar(suite_env, "GMCRYPTO_GMSSL", 10) == "'1'",
    )
    require(
        "GmSSL interoperability command is structurally blocking",
        strict_shell(suite_script) and suite_execution in suite_script,
    )
    require(
        "GmSSL interoperability script matches reviewed canonical execution",
        suite_script == suite_canonical_script,
    )
    require(
        "GmSSL interoperability suite metadata is blocking",
        key_count(suite, "if", 8) == 1
        and scalar(suite, "if", 8)
        == "steps.gmssl-provision.outcome == 'success' && steps.gmssl-version.outcome == 'success'"
        and key_count(suite, "continue-on-error", 8) == 0
        and key_count(suite, "shell", 8) == 0
        and key_count(suite, "env", 8) == 1
        and key_count(interop, "continue-on-error", 4) == 0
        and active_source_lines(suite_env)
        == ["        env:", "          GMCRYPTO_GMSSL: '1'"],
    )
    require(
        "GmSSL interoperability suite keeps active skip and census guards",
        suite_skip_guard in suite_script and suite_census_guard in suite_script,
    )
    tag_validation = (
        '          if [[ ! "$GMSSL_TAG" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+$ ]]; then\n'
        '            echo "::error::invalid GMSSL_TAG: $GMSSL_TAG"\n'
        "            exit 1\n"
        "          fi"
    )
    prefix_assignment = '          prefix="$HOME/gmssl-$GMSSL_TAG"'
    tag_validation_index = provision.find(tag_validation)
    prefix_assignment_index = provision.find(prefix_assignment)
    require(
        "GmSSL validates its tag before constructing cleanup paths",
        tag_validation_index >= 0
        and prefix_assignment_index >= 0
        and tag_validation_index < prefix_assignment_index,
    )
    repair_decision = (
        "          cache_usable=false\n"
        '          if [ "$CACHE_HIT" = "true" ] && [ -x "$oracle" ]; then\n'
        '            cached_version="$("$oracle" version 2>/dev/null | head -n1 || true)"\n'
        '            if [ "$cached_version" = "$want" ]; then\n'
        "              cache_usable=true\n"
        "            fi\n"
        "          fi\n"
        '          if [ "$cache_usable" != "true" ]; then'
    )
    require(
        "GmSSL repairs an unusable cache before provisioning",
        repair_decision in provision and 'rm -rf -- "$prefix" "$source_dir"' in provision_script,
    )
    require(
        "GmSSL explains immutable exact-cache repair",
        "repairing this run only because exact caches are immutable; "
        "bump GMSSL_CACHE_EPOCH to replace it" in provision_script,
    )
    require(
        "GmSSL status is always reported",
        scalar(report, "if", 8) == "${{ always() }}",
    )
    suite_outcome_mapping = (
        '          case "$SUITE_OUTCOME" in\n'
        "            success|failure) interop_state=ran ;;\n"
        "            skipped) interop_state=skipped ;;\n"
        "            cancelled) interop_state=cancelled ;;\n"
        "            *) interop_state=unknown ;;\n"
        "          esac"
    )
    require(
        "GmSSL suite outcome mapping is explicit",
        suite_outcome_mapping in report,
    )
    require(
        "GmSSL suite execution is machine-visible",
        'echo "INTEROP_SUITE=$interop_state"' in report_script
        and 'echo "INTEROP_SUITE=\\`$interop_state\\`"' in report_script,
    )
    outcome_summary = (
        'echo "- cache: \\`$CACHE_OUTCOME\\`"',
        'echo "- provision: \\`$PROVISION_OUTCOME\\`"',
        'echo "- version assertion: \\`$VERSION_OUTCOME\\`"',
        'echo "- interoperability suite: \\`$SUITE_OUTCOME\\`"',
    )
    require(
        "GmSSL infrastructure outcomes are summarized",
        all(name in report for name in ("CACHE_OUTCOME:", "PROVISION_OUTCOME:", "VERSION_OUTCOME:", "SUITE_OUTCOME:"))
        and all(line in report_script for line in outcome_summary)
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
    noise_twin_reference = re.compile(r"\bnoise_twin_class_split\b")
    noise_twin_registration = re.compile(
        r"^\s*name:\s*BenchName\([\"']noise_twin_class_split[\"']\),\s*$",
        re.M,
    )
    require("noise twin benchmark is registered", noise_twin_registration.search(timing) is not None)
    dudect_jobs = {
        "PR": job(dudect_pr, "smoke"),
        "nightly": job(dudect_nightly, "full"),
    }
    parse_steps = {
        workflow_name: step_named(job_text, "Parse and gate")
        for workflow_name, job_text in dudect_jobs.items()
    }
    # These hashes are the reviewed executable-semantics boundary for the
    # complete embedded Python programs. A deliberate executable change must
    # update the workflow, this fingerprint, and the mutation suite together.
    reviewed_ast_fingerprints = {
        "PR": "5d293b9156867e07678c57cb1d445615af7b4d2bdc214702d979373d992236ab",
        "nightly": "e711283e7a833ebe16eb3a6687149c1701fe9f468f3a1c57e7c49cf6fd3abd6c",
    }
    assignment = '          required_telemetry = ("noise_twin_class_split",)'
    dudect_contract = {
        "PR": {
            "uses": (
                'required_telemetry = ("noise_twin_class_split",)',
                "for name in (*required_high, *required_low, *required_telemetry):",
                "if any(name in required_telemetry for name, _ in blocking_items):",
                "for name in required_telemetry:",
            ),
            "snapshot": (
                "          required_high_items = tuple(required_high.items())",
                "          required_low_items = tuple(required_low.items())",
                "          blocking_items = required_high_items + required_low_items",
                "          if any(name in required_telemetry for name, _ in blocking_items):",
                '              raise SystemExit("FAIL: required telemetry promoted to a blocking dudect gate")',
                "          for name, lower_bound in required_high_items:",
            ),
            "gate_loops": (
                "          for name, lower_bound in required_high_items:",
                "          for name, upper_bound in required_low_items:",
            ),
        },
        "nightly": {
            "uses": (
                'required_telemetry = ("noise_twin_class_split",)',
                "for name in (*required_high, *required_low, *gross_regression_sentinel, *required_telemetry):",
                "if any(name in required_telemetry for name, _ in blocking_items):",
                "for name in required_telemetry:",
            ),
            "snapshot": (
                "          required_high_items = tuple(required_high.items())",
                "          required_low_items = tuple(required_low.items())",
                "          gross_regression_sentinel_items = tuple(gross_regression_sentinel.items())",
                "          blocking_items = required_high_items + required_low_items + gross_regression_sentinel_items",
                "          if any(name in required_telemetry for name, _ in blocking_items):",
                '              raise SystemExit("FAIL: required telemetry promoted to a blocking dudect gate")',
                "          for name, lower_bound in required_high_items:",
            ),
            "gate_loops": (
                "          for name, lower_bound in required_high_items:",
                "          for name, upper_bound in required_low_items:",
                "          for name, upper_bound in gross_regression_sentinel_items:",
            ),
        },
    }
    gate_loop = re.compile(r"^ {10}for name, (?:lower_bound|upper_bound) in .+:$")
    output_header = "          for name in required_telemetry:"
    output_body = [
        '              print(f"NOISE-TWIN: {name} {telem(name)} (required measurement; non-blocking value)")'
    ]
    for workflow_name, parse_step in parse_steps.items():
        contract = dudect_contract[workflow_name]
        heredoc = reviewed_python_heredoc(parse_step)
        parse_env = indented_block(parse_step, "env:", 8)
        require(
            f"{workflow_name} dudect shell wrapper matches reviewed heredoc boundary",
            heredoc is not None,
        )
        require(
            f"{workflow_name} dudect executable semantics match reviewed fingerprint",
            heredoc is not None
            and heredoc[1] == reviewed_ast_fingerprints[workflow_name],
        )
        require(
            f"{workflow_name} dudect execution metadata is blocking",
            key_count(parse_step, "if", 8) == 0
            and key_count(parse_step, "continue-on-error", 8) == 0
            and key_count(parse_step, "shell", 8) == 0
            and key_count(parse_step, "env", 8) == 1
            and key_count(dudect_jobs[workflow_name], "continue-on-error", 4) == 0
            and active_source_lines(parse_env)
            == ["        env:", "          MATRIX_FEATURES: ${{ matrix.features }}"],
        )
        active_lines = active_source_lines(parse_step)
        active_noise_twin_references = [
            line for line in active_lines if noise_twin_reference.search(line)
        ]
        telemetry_uses = tuple(
            line.strip() for line in active_lines if re.search(r"\brequired_telemetry\b", line)
        )
        actual_gate_loops = tuple(line for line in active_lines if gate_loop.fullmatch(line))
        exact_consumption_boundary = contains_line_sequence(active_lines, contract["snapshot"])
        exact_uses = telemetry_uses == contract["uses"]
        require(
            f"{workflow_name} dudect requires noise-twin telemetry",
            active_lines.count(assignment) == 1,
        )
        require(
            f"{workflow_name} dudect labels noise-twin output",
            active_loop_body(parse_step, output_header) == output_body,
        )
        require(
            f"{workflow_name} dudect keeps noise-twin telemetry out of gate maps",
            len(active_noise_twin_references) == 1
            and active_noise_twin_references[0] == assignment,
        )
        require(
            f"{workflow_name} dudect limits required_telemetry to approved uses",
            exact_uses,
        )
        require(
            f"{workflow_name} dudect gate loops consume validated snapshots",
            actual_gate_loops == contract["gate_loops"],
        )
        require(
            f"{workflow_name} dudect required-low gate consumes validated snapshot",
            "          for name, upper_bound in required_low_items:" in actual_gate_loops,
        )
        require(
            f"{workflow_name} dudect runtime-rejects telemetry gate promotion",
            exact_consumption_boundary and exact_uses,
        )

    return failures


def mutation_self_test() -> list[str]:
    failures: list[str] = []

    baselines = {
        "ci": CI,
        "gitleaks": GITLEAKS,
        "dudect_pr": DUDECT_PR,
        "dudect_nightly": DUDECT_NIGHTLY,
        "timing": TIMING,
    }

    def replace_once(text: str, before: str, after: str, label: str) -> str:
        """Build one mutation only when its exact anchor is unique."""
        count = text.count(before)
        if count != 1:
            failures.append(f"mutation anchor count was {count}, expected 1: {label}")
            return text
        mutated = text.replace(before, after, 1)
        if mutated == text:
            failures.append(f"mutation anchor did not change input: {label}")
        return mutated

    def must_reject(label: str, expected: str, **overrides: str) -> None:
        if not overrides or not any(
            value != baselines.get(name) for name, value in overrides.items()
        ):
            failures.append(f"mutation input was unchanged: {label}")
            return
        found = audit(
            overrides.get("ci", CI),
            overrides.get("gitleaks", GITLEAKS),
            overrides.get("dudect_pr", DUDECT_PR),
            overrides.get("dudect_nightly", DUDECT_NIGHTLY),
            overrides.get("timing", TIMING),
        )
        if not any(expected in failure for failure in found):
            failures.append(f"mutation was not rejected: {label}")

    interop = job(CI, "interop-gmssl")
    provision = step_named(interop, "Provision GmSSL ${{ env.GMSSL_TAG }} oracle")
    report = step_named(interop, "Report GmSSL interoperability status")

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
        "unverified gitleaks release asset",
        "gitleaks verifies the pinned release checksum",
        gitleaks=GITLEAKS.replace(
            "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
            "0" * 64,
            1,
        ),
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
        "GmSSL tag validation weakened to a non-empty check",
        "GmSSL validates its tag before constructing cleanup paths",
        ci=CI.replace(
            provision,
            provision.replace(
                '          if [[ ! "$GMSSL_TAG" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+$ ]]; then',
                '          if [ -z "$GMSSL_TAG" ]; then',
                1,
            ),
            1,
        ),
    )
    must_reject(
        "cached oracle executable guard removed",
        "GmSSL repairs an unusable cache before provisioning",
        ci=CI.replace(
            provision,
            provision.replace(
                '          if [ "$CACHE_HIT" = "true" ] && [ -x "$oracle" ]; then',
                '          if [ "$CACHE_HIT" = "true" ]; then',
                1,
            ),
            1,
        ),
    )
    must_reject(
        "cached oracle accepted without an exact version match",
        "GmSSL repairs an unusable cache before provisioning",
        ci=CI.replace(
            provision,
            provision.replace(
                '          if [ "$cached_version" = "$want" ]; then',
                '          if [ -n "$cached_version" ]; then',
                1,
            ),
            1,
        ),
    )
    must_reject(
        "cached oracle usability assignment moved outside exact equality",
        "GmSSL repairs an unusable cache before provisioning",
        ci=CI.replace(
            provision,
            provision.replace(
                "              cache_usable=true\n            fi",
                "            fi\n            cache_usable=true",
                1,
            ),
            1,
        ),
    )
    must_reject(
        "GmSSL rebuild condition polarity flipped",
        "GmSSL repairs an unusable cache before provisioning",
        ci=CI.replace(
            provision,
            provision.replace(
                '          if [ "$cache_usable" != "true" ]; then',
                '          if [ "$cache_usable" = "true" ]; then',
                1,
            ),
            1,
        ),
    )
    must_reject(
        "GmSSL report restored to degradation-only execution",
        "GmSSL status is always reported",
        ci=CI.replace(
            report,
            report.replace(
                "        if: ${{ always() }}",
                "        if: ${{ always() && (steps.gmssl-cache.outcome != 'success' || "
                "steps.gmssl-provision.outcome != 'success' || "
                "steps.gmssl-version.outcome != 'success') }}",
                1,
            ),
            1,
        ),
    )
    must_reject(
        "skipped GmSSL suite misreported as ran",
        "GmSSL suite outcome mapping is explicit",
        ci=CI.replace(
            report,
            report.replace(
                "            skipped) interop_state=skipped ;;",
                "            skipped) interop_state=ran ;;",
                1,
            ),
            1,
        ),
    )
    must_reject(
        "GmSSL cache outcome omitted from the emitted summary",
        "GmSSL infrastructure outcomes are summarized",
        ci=CI.replace(
            report,
            report.replace('            echo "- cache: \\`$CACHE_OUTCOME\\`"\n', "", 1),
            1,
        ),
    )
    must_reject(
        "inlinable noise-twin helper",
        "fixed-work helper cannot inline",
        timing=TIMING.replace("#[inline(never)]\nfn noise_twin_fixed_work(", "fn noise_twin_fixed_work(", 1),
    )
    must_reject(
        "PR noise twin added to required_low",
        "PR dudect keeps noise-twin telemetry out of gate maps",
        dudect_pr=DUDECT_PR.replace(
            "          required_low  = {\n",
            "          required_low  = {\n              \"noise_twin_class_split\": 0.20,\n",
            1,
        ),
    )
    must_reject(
        "nightly noise twin added to required_low",
        "nightly dudect keeps noise-twin telemetry out of gate maps",
        dudect_nightly=DUDECT_NIGHTLY.replace(
            "          required_low  = {\n",
            "          required_low  = {\n              \"noise_twin_class_split\": 0.20,\n",
            1,
        ),
    )
    must_reject(
        "PR noise-twin telemetry requirement removed",
        "PR dudect requires noise-twin telemetry",
        dudect_pr=DUDECT_PR.replace(
            '          required_telemetry = ("noise_twin_class_split",)\n',
            "",
            1,
        ),
    )
    must_reject(
        "nightly noise-twin telemetry requirement removed",
        "nightly dudect requires noise-twin telemetry",
        dudect_nightly=DUDECT_NIGHTLY.replace(
            '          required_telemetry = ("noise_twin_class_split",)\n',
            "",
            1,
        ),
    )
    must_reject(
        "PR noise-twin output label removed",
        "PR dudect labels noise-twin output",
        dudect_pr=DUDECT_PR.replace("NOISE-TWIN:", "TELEMETRY:", 1),
    )
    must_reject(
        "nightly noise-twin output label removed",
        "nightly dudect labels noise-twin output",
        dudect_nightly=DUDECT_NIGHTLY.replace("NOISE-TWIN:", "TELEMETRY:", 1),
    )
    must_reject(
        "noise-twin benchmark registration removed",
        "noise twin benchmark is registered",
        timing=TIMING.replace(
            'BenchName("noise_twin_class_split")',
            'BenchName("noise_twin_removed")',
            1,
        ),
    )
    must_reject(
        "PR noise twin added to required_low with single quotes",
        "PR dudect keeps noise-twin telemetry out of gate maps",
        dudect_pr=DUDECT_PR.replace(
            "          required_low  = {\n",
            "          required_low  = {\n              'noise_twin_class_split': 0.20,\n",
            1,
        ),
    )
    must_reject(
        "nightly noise twin added to required_low with single quotes",
        "nightly dudect keeps noise-twin telemetry out of gate maps",
        dudect_nightly=DUDECT_NIGHTLY.replace(
            "          required_low  = {\n",
            "          required_low  = {\n              'noise_twin_class_split': 0.20,\n",
            1,
        ),
    )
    must_reject(
        "PR noise twin added through required_high subscript",
        "PR dudect keeps noise-twin telemetry out of gate maps",
        dudect_pr=DUDECT_PR.replace(
            '          required_high = {"negative_control": 1.0}\n',
            '          required_high = {"negative_control": 1.0}\n'
            '          required_high["noise_twin_class_split"] = 0.20\n',
            1,
        ),
    )
    must_reject(
        "PR noise twin added through required_low subscript",
        "PR dudect keeps noise-twin telemetry out of gate maps",
        dudect_pr=DUDECT_PR.replace(
            '          matrix_features = os.environ.get("MATRIX_FEATURES", "")\n',
            '          required_low["noise_twin_class_split"] = 0.20\n'
            '          matrix_features = os.environ.get("MATRIX_FEATURES", "")\n',
            1,
        ),
    )
    must_reject(
        "nightly noise twin added through required_high subscript",
        "nightly dudect keeps noise-twin telemetry out of gate maps",
        dudect_nightly=DUDECT_NIGHTLY.replace(
            '          required_high = {"negative_control": 1.0}\n',
            '          required_high = {"negative_control": 1.0}\n'
            '          required_high["noise_twin_class_split"] = 0.20\n',
            1,
        ),
    )
    must_reject(
        "nightly noise twin added through required_low subscript",
        "nightly dudect keeps noise-twin telemetry out of gate maps",
        dudect_nightly=DUDECT_NIGHTLY.replace(
            '          matrix_features = os.environ.get("MATRIX_FEATURES", "")\n',
            '          required_low["noise_twin_class_split"] = 0.20\n'
            '          matrix_features = os.environ.get("MATRIX_FEATURES", "")\n',
            1,
        ),
    )
    must_reject(
        "nightly noise twin added through gross-regression sentinel subscript",
        "nightly dudect keeps noise-twin telemetry out of gate maps",
        dudect_nightly=DUDECT_NIGHTLY.replace(
            "          fail = False\n",
            '          gross_regression_sentinel["noise_twin_class_split"] = 0.20\n'
            "          fail = False\n",
            1,
        ),
    )
    must_reject(
        "PR noise-twin telemetry requirement commented out",
        "PR dudect requires noise-twin telemetry",
        dudect_pr=DUDECT_PR.replace(
            '          required_telemetry = ("noise_twin_class_split",)\n',
            '          # required_telemetry = ("noise_twin_class_split",)\n',
            1,
        ),
    )
    must_reject(
        "nightly noise-twin telemetry requirement commented out",
        "nightly dudect requires noise-twin telemetry",
        dudect_nightly=DUDECT_NIGHTLY.replace(
            '          required_telemetry = ("noise_twin_class_split",)\n',
            '          # required_telemetry = ("noise_twin_class_split",)\n',
            1,
        ),
    )
    must_reject(
        "PR noise-twin output label commented out",
        "PR dudect labels noise-twin output",
        dudect_pr=DUDECT_PR.replace(
            '              print(f"NOISE-TWIN:',
            '              # print(f"NOISE-TWIN:',
            1,
        ),
    )
    must_reject(
        "nightly noise-twin output label commented out",
        "nightly dudect labels noise-twin output",
        dudect_nightly=DUDECT_NIGHTLY.replace(
            '              print(f"NOISE-TWIN:',
            '              # print(f"NOISE-TWIN:',
            1,
        ),
    )
    must_reject(
        "noise-twin benchmark registration commented out",
        "noise twin benchmark is registered",
        timing=TIMING.replace(
            '            name: BenchName("noise_twin_class_split"),',
            '            // name: BenchName("noise_twin_class_split"),',
            1,
        ),
    )
    must_reject(
        "PR noise twin added through required_low.update dictionary",
        "PR dudect keeps noise-twin telemetry out of gate maps",
        dudect_pr=DUDECT_PR.replace(
            '          matrix_features = os.environ.get("MATRIX_FEATURES", "")\n',
            '          required_low.update({"noise_twin_class_split": 0.20})\n'
            '          matrix_features = os.environ.get("MATRIX_FEATURES", "")\n',
            1,
        ),
    )
    must_reject(
        "nightly noise twin added through required_low.update keyword",
        "nightly dudect keeps noise-twin telemetry out of gate maps",
        dudect_nightly=DUDECT_NIGHTLY.replace(
            '          matrix_features = os.environ.get("MATRIX_FEATURES", "")\n',
            "          required_low.update(noise_twin_class_split=0.20)\n"
            '          matrix_features = os.environ.get("MATRIX_FEATURES", "")\n',
            1,
        ),
    )
    must_reject(
        "nightly noise twin added through gross-regression sentinel setdefault",
        "nightly dudect keeps noise-twin telemetry out of gate maps",
        dudect_nightly=DUDECT_NIGHTLY.replace(
            "          fail = False\n",
            '          gross_regression_sentinel.setdefault("noise_twin_class_split", 0.20)\n'
            "          fail = False\n",
            1,
        ),
    )
    must_reject(
        "PR telemetry runtime guard omits required_high",
        "PR dudect runtime-rejects telemetry gate promotion",
        dudect_pr=DUDECT_PR.replace(
            "          blocking_items = required_high_items + required_low_items\n",
            "          blocking_items = required_low_items\n",
            1,
        ),
    )
    must_reject(
        "nightly telemetry runtime guard omits gross-regression sentinel",
        "nightly dudect runtime-rejects telemetry gate promotion",
        dudect_nightly=DUDECT_NIGHTLY.replace(
            "          blocking_items = required_high_items + required_low_items + gross_regression_sentinel_items\n",
            "          blocking_items = required_high_items + required_low_items\n",
            1,
        ),
    )
    must_reject(
        "PR telemetry runtime rejection commented out",
        "PR dudect runtime-rejects telemetry gate promotion",
        dudect_pr=DUDECT_PR.replace(
            '              raise SystemExit("FAIL: required telemetry promoted to a blocking dudect gate")',
            '              # raise SystemExit("FAIL: required telemetry promoted to a blocking dudect gate")',
            1,
        ),
    )
    must_reject(
        "nightly telemetry runtime rejection changed to print",
        "nightly dudect runtime-rejects telemetry gate promotion",
        dudect_nightly=DUDECT_NIGHTLY.replace(
            '              raise SystemExit("FAIL: required telemetry promoted to a blocking dudect gate")',
            '              print("FAIL: required telemetry promoted to a blocking dudect gate")',
            1,
        ),
    )
    must_reject(
        "PR telemetry promotion inserted after runtime guard",
        "PR dudect runtime-rejects telemetry gate promotion",
        dudect_pr=DUDECT_PR.replace(
            "          sys.exit(1 if fail else 0)\n",
            "          required_low[required_telemetry[0]] = 0.20\n"
            "          sys.exit(1 if fail else 0)\n",
            1,
        ),
    )
    must_reject(
        "PR telemetry value used as a direct gate",
        "PR dudect limits required_telemetry to approved uses",
        dudect_pr=DUDECT_PR.replace(
            "          sys.exit(1 if fail else 0)\n",
            "          for name in required_telemetry:\n"
            "              if med(name) > 0.20:\n"
            "                  fail = True\n"
            "          sys.exit(1 if fail else 0)\n",
            1,
        ),
    )
    must_reject(
        "nightly telemetry value used as a direct gate",
        "nightly dudect limits required_telemetry to approved uses",
        dudect_nightly=DUDECT_NIGHTLY.replace(
            "          sys.exit(1 if fail else 0)\n",
            "          for name in required_telemetry:\n"
            "              if med(name) > 0.20:\n"
            "                  fail = True\n"
            "          sys.exit(1 if fail else 0)\n",
            1,
        ),
    )
    must_reject(
        "PR telemetry copied into required_low then cleared before overlap guard",
        "PR dudect limits required_telemetry to approved uses",
        dudect_pr=DUDECT_PR.replace(
            '          required_telemetry = ("noise_twin_class_split",)\n',
            '          required_telemetry = ["noise_twin_class_split"]\n',
            1,
        ).replace(
            "          fail = False\n",
            "          required_low.update(dict.fromkeys(required_telemetry, 0.20))\n"
            "          fail = False\n",
            1,
        ).replace(
            "          if any(name in required_telemetry for name, _ in blocking_items):\n",
            "          required_telemetry.clear()\n"
            "          if any(name in required_telemetry for name, _ in blocking_items):\n",
            1,
        ),
    )
    must_reject(
        "PR required-low gate consumes effective union with telemetry",
        "PR dudect required-low gate consumes validated snapshot",
        dudect_pr=DUDECT_PR.replace(
            "          for name, upper_bound in required_low_items:\n",
            "          for name, upper_bound in (required_low | dict.fromkeys(required_telemetry, 0.20)).items():\n",
            1,
        ),
    )
    must_reject(
        "GmSSL cargo-test pipeline replaced with true",
        "GmSSL interoperability command is structurally blocking",
        ci=CI.replace(
            "          cargo test -p gmcrypto-core --test interop_gmssl --features sm4-aead \\\n"
            "            -- --nocapture 2>&1 | tee interop.txt",
            "          true",
            1,
        ),
    )
    must_reject(
        "GmSSL cargo-test pipeline tolerated",
        "GmSSL interoperability command is structurally blocking",
        ci=CI.replace(
            "            -- --nocapture 2>&1 | tee interop.txt",
            "            -- --nocapture 2>&1 | tee interop.txt || true",
            1,
        ),
    )
    must_reject(
        "gitleaks checksum failure tolerated",
        "gitleaks checksum command is structurally blocking",
        gitleaks=GITLEAKS.replace(
            '          echo "$GITLEAKS_SHA256  $archive" | sha256sum --check --status',
            '          echo "$GITLEAKS_SHA256  $archive" | sha256sum --check --status || true',
            1,
        ),
    )
    must_reject(
        "C example compilation failure tolerated",
        "C example compile command is structurally blocking",
        ci=CI.replace(
            '              -I crates/gmcrypto-c/include "$example"',
            '              -I crates/gmcrypto-c/include "$example" || true',
            1,
        ),
    )

    # Execution-boundary mutations: these model ordinary YAML/shell/Python
    # edits that preserve the old verifier's anchor snippets while bypassing
    # the assurance gate. Each mutation uses a unique checked anchor and must
    # be rejected under the specific policy label named below.
    must_reject(
        "PR dudect required-low snapshot rebound empty",
        "PR dudect executable semantics match reviewed fingerprint",
        dudect_pr=replace_once(
            DUDECT_PR,
            "          required_low_items = tuple(required_low.items())\n",
            "          required_low_items = tuple(required_low.items())\n"
            "          required_low_items = ()\n",
            "PR required-low snapshot rebind",
        ),
    )
    must_reject(
        "nightly dudect required-low snapshot rebound empty",
        "nightly dudect executable semantics match reviewed fingerprint",
        dudect_nightly=replace_once(
            DUDECT_NIGHTLY,
            "          required_low_items = tuple(required_low.items())\n",
            "          required_low_items = tuple(required_low.items())\n"
            "          required_low_items = ()\n",
            "nightly required-low snapshot rebind",
        ),
    )
    must_reject(
        "nightly dudect sentinel snapshot rebound empty",
        "nightly dudect executable semantics match reviewed fingerprint",
        dudect_nightly=replace_once(
            DUDECT_NIGHTLY,
            "          gross_regression_sentinel_items = tuple(gross_regression_sentinel.items())\n",
            "          gross_regression_sentinel_items = tuple(gross_regression_sentinel.items())\n"
            "          gross_regression_sentinel_items = ()\n",
            "nightly sentinel snapshot rebind",
        ),
    )
    for workflow_name, source, key, completeness_header, gate_header in (
        (
            "PR",
            DUDECT_PR,
            "dudect_pr",
            "          for name in (*required_high, *required_low, *required_telemetry):\n",
            "          for name, upper_bound in required_low_items:\n",
        ),
        (
            "nightly",
            DUDECT_NIGHTLY,
            "dudect_nightly",
            "          for name in (*required_high, *required_low, *gross_regression_sentinel, *required_telemetry):\n",
            "          for name, upper_bound in required_low_items:\n",
        ),
    ):
        must_reject(
            f"{workflow_name} dudect completeness loop short-circuited",
            f"{workflow_name} dudect executable semantics match reviewed fingerprint",
            **{
                key: replace_once(
                    source,
                    completeness_header,
                    completeness_header + "              continue\n",
                    f"{workflow_name} completeness continue",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect required-low gate loop short-circuited",
            f"{workflow_name} dudect executable semantics match reviewed fingerprint",
            **{
                key: replace_once(
                    source,
                    gate_header,
                    gate_header + "              continue\n",
                    f"{workflow_name} gate continue",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect failure state reset before exit",
            f"{workflow_name} dudect executable semantics match reviewed fingerprint",
            **{
                key: replace_once(
                    source,
                    "          sys.exit(1 if fail else 0)\n",
                    "          fail = False\n"
                    "          sys.exit(1 if fail else 0)\n",
                    f"{workflow_name} fail reset",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect unconditional success exit",
            f"{workflow_name} dudect executable semantics match reviewed fingerprint",
            **{
                key: replace_once(
                    source,
                    "          sys.exit(1 if fail else 0)\n",
                    "          sys.exit(0)\n",
                    f"{workflow_name} sys.exit(0)",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect completeness directly gates telemetry value",
            f"{workflow_name} dudect executable semantics match reviewed fingerprint",
            **{
                key: replace_once(
                    source,
                    completeness_header
                    + "              got = len(findings.get(name, []))\n"
                    + "              if got != n_runs:\n",
                    completeness_header
                    + "              got = len(findings.get(name, []))\n"
                    + "              if got != n_runs or med(name) > 0.20:\n",
                    f"{workflow_name} completeness value gate",
                )
            },
        )
        blocking_assignment = (
            "          blocking_items = required_high_items + required_low_items\n"
            if workflow_name == "PR"
            else "          blocking_items = required_high_items + required_low_items + gross_regression_sentinel_items\n"
        )
        must_reject(
            f"{workflow_name} dudect dynamically promotes telemetry through snapshot append",
            f"{workflow_name} dudect executable semantics match reviewed fingerprint",
            **{
                key: replace_once(
                    source,
                    blocking_assignment,
                    blocking_assignment
                    + "          for name in required_telemetry:\n"
                    + "              required_low_items += ((name, 0.20),)\n",
                    f"{workflow_name} dynamic telemetry gate",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect dynamically clears telemetry through globals",
            f"{workflow_name} dudect executable semantics match reviewed fingerprint",
            **{
                key: replace_once(
                    source,
                    '          required_telemetry = ("noise_twin_class_split",)\n',
                    '          required_telemetry = ("noise_twin_class_split",)\n'
                    '          globals()["required_telemetry"] = ()\n',
                    f"{workflow_name} globals telemetry clear",
                )
            },
        )

    gmssl_command = (
        "          cargo test -p gmcrypto-core --test interop_gmssl --features sm4-aead \\\n"
        "            -- --nocapture 2>&1 | tee interop.txt"
    )
    must_reject(
        "GmSSL suite exits successfully before execution",
        "GmSSL interoperability script matches reviewed canonical execution",
        ci=replace_once(
            CI,
            "          set -euo pipefail\n" + gmssl_command,
            "          set -euo pipefail\n          exit 0\n" + gmssl_command,
            "GmSSL early success exit",
        ),
    )
    must_reject(
        "GmSSL cargo pipeline hidden behind false-and",
        "GmSSL interoperability script matches reviewed canonical execution",
        ci=replace_once(
            CI,
            gmssl_command,
            gmssl_command.replace("          cargo test", "          false && cargo test", 1),
            "GmSSL false-and pipeline",
        ),
    )
    must_reject(
        "GmSSL suite fakes the expected census",
        "GmSSL interoperability script matches reviewed canonical execution",
        ci=replace_once(
            CI,
            gmssl_command,
            "          printf '13 passed\\n' > interop.txt",
            "GmSSL fake census",
        ),
    )
    must_reject(
        "GmSSL suite step skipped with false condition",
        "GmSSL interoperability suite metadata is blocking",
        ci=replace_once(
            CI,
            "        if: steps.gmssl-provision.outcome == 'success' && steps.gmssl-version.outcome == 'success'\n",
            "        if: ${{ false }}\n",
            "GmSSL suite if false",
        ),
    )

    must_reject(
        "gitleaks install exits successfully before verification",
        "gitleaks install script matches reviewed canonical execution",
        gitleaks=replace_once(
            GITLEAKS,
            "          set -euo pipefail\n          GITLEAKS_VERSION=8.30.1\n",
            "          set -euo pipefail\n          exit 0\n          GITLEAKS_VERSION=8.30.1\n",
            "gitleaks early success exit",
        ),
    )
    must_reject(
        "gitleaks checksum hidden behind false-and",
        "gitleaks install script matches reviewed canonical execution",
        gitleaks=replace_once(
            GITLEAKS,
            '          echo "$GITLEAKS_SHA256  $archive" | sha256sum --check --status\n',
            '          false && echo "$GITLEAKS_SHA256  $archive" | sha256sum --check --status\n',
            "gitleaks false-and checksum",
        ),
    )
    must_reject(
        "gitleaks checksum trusts a dynamically rebound digest",
        "gitleaks install script matches reviewed canonical execution",
        gitleaks=replace_once(
            GITLEAKS,
            '          echo "$GITLEAKS_SHA256  $archive" | sha256sum --check --status\n',
            '          GITLEAKS_SHA256="$(sha256sum "$archive" | cut -d\' \' -f1)"\n'
            '          echo "$GITLEAKS_SHA256  $archive" | sha256sum --check --status\n',
            "gitleaks digest rebind",
        ),
    )

    c_examples_assignment = "          examples=(crates/gmcrypto-c/examples/*.c)\n"
    c_loop = (
        '          for example in "${examples[@]}"; do\n'
        '            echo "checking $example"\n'
        "            cc -std=c11 -Wall -Wextra -Werror -fsyntax-only \\\n"
        '              -I crates/gmcrypto-c/include "$example"\n'
        "          done\n"
    )
    must_reject(
        "C example list reset empty after globbing",
        "C example compile script matches reviewed canonical execution",
        ci=replace_once(
            CI,
            c_examples_assignment,
            c_examples_assignment + "          examples=()\n",
            "C examples reset empty",
        ),
    )
    must_reject(
        "C example compile loop hidden behind false condition",
        "C example compile script matches reviewed canonical execution",
        ci=replace_once(
            CI,
            c_loop,
            "          if false; then\n" + c_loop + "          fi\n",
            "C examples false wrapper",
        ),
    )

    must_reject(
        "policy verifier step skipped with false condition",
        "policy verifier execution metadata is blocking",
        ci=replace_once(
            CI,
            "      - name: Verify assurance workflow policy\n"
            "        run: python3 .github/scripts/check_assurance_policy.py\n",
            "      - name: Verify assurance workflow policy\n"
            "        if: ${{ false }}\n"
            "        run: python3 .github/scripts/check_assurance_policy.py\n",
            "policy verifier if false",
        ),
    )
    must_reject(
        "policy verifier step failure tolerated",
        "policy verifier execution metadata is blocking",
        ci=replace_once(
            CI,
            "      - name: Verify assurance workflow policy\n"
            "        run: python3 .github/scripts/check_assurance_policy.py\n",
            "      - name: Verify assurance workflow policy\n"
            "        continue-on-error: true\n"
            "        run: python3 .github/scripts/check_assurance_policy.py\n",
            "policy verifier continue-on-error",
        ),
    )
    must_reject(
        "policy verifier build job failure tolerated",
        "policy verifier execution metadata is blocking",
        ci=replace_once(
            CI,
            "  build:\n",
            "  build:\n    continue-on-error: true\n",
            "policy verifier job continue-on-error",
        ),
    )

    for workflow_name, source, key, job_name in (
        ("PR", DUDECT_PR, "dudect_pr", "smoke"),
        ("nightly", DUDECT_NIGHTLY, "dudect_nightly", "full"),
    ):
        parse_header = "      - name: Parse and gate\n"
        must_reject(
            f"{workflow_name} dudect parse step skipped with false condition",
            f"{workflow_name} dudect execution metadata is blocking",
            **{
                key: replace_once(
                    source,
                    parse_header,
                    parse_header + "        if: ${{ false }}\n",
                    f"{workflow_name} parse if false",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect parse failure tolerated",
            f"{workflow_name} dudect execution metadata is blocking",
            **{
                key: replace_once(
                    source,
                    parse_header,
                    parse_header + "        continue-on-error: true\n",
                    f"{workflow_name} parse continue-on-error",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect job failure tolerated",
            f"{workflow_name} dudect execution metadata is blocking",
            **{
                key: replace_once(
                    source,
                    f"  {job_name}:\n",
                    f"  {job_name}:\n    continue-on-error: true\n",
                    f"{workflow_name} job continue-on-error",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect shell wrapper gains an active command",
            f"{workflow_name} dudect shell wrapper matches reviewed heredoc boundary",
            **{
                key: replace_once(
                    source,
                    "        run: |\n          set -euo pipefail\n          python3 - <<'PY'\n",
                    "        run: |\n          set -euo pipefail\n          true\n          python3 - <<'PY'\n",
                    f"{workflow_name} shell wrapper command",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect heredoc closing marker changes",
            f"{workflow_name} dudect shell wrapper matches reviewed heredoc boundary",
            **{
                key: replace_once(
                    source,
                    "          PY\n\n      - name: Upload raw log\n",
                    "          PY_CHANGED\n\n      - name: Upload raw log\n",
                    f"{workflow_name} heredoc closing marker",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect parse matrix environment drifts",
            f"{workflow_name} dudect execution metadata is blocking",
            **{
                key: replace_once(
                    source,
                    step_named(job(source, job_name), "Parse and gate"),
                    replace_once(
                        step_named(job(source, job_name), "Parse and gate"),
                        "          MATRIX_FEATURES: ${{ matrix.features }}\n",
                        "          MATRIX_FEATURES: default\n",
                        f"{workflow_name} matrix environment field",
                    ),
                    f"{workflow_name} matrix environment step",
                )
            },
        )

    c_step_header = "      - name: Compile shipped C examples\n"
    must_reject(
        "C example compile step skipped with false condition",
        "C example execution metadata is blocking",
        ci=replace_once(CI, c_step_header, c_step_header + "        if: ${{ false }}\n", "C step if false"),
    )
    must_reject(
        "C example compile step failure tolerated",
        "C example execution metadata is blocking",
        ci=replace_once(
            CI,
            c_step_header,
            c_step_header + "        continue-on-error: true\n",
            "C step continue-on-error",
        ),
    )
    must_reject(
        "C ABI job failure tolerated",
        "C example execution metadata is blocking",
        ci=replace_once(CI, "  cabi:\n", "  cabi:\n    continue-on-error: true\n", "C job continue-on-error"),
    )

    install_header = "      - name: Install gitleaks\n"
    scan_header = "      - name: Scan committed history\n"
    for label, header in (("install", install_header), ("scan", scan_header)):
        must_reject(
            f"gitleaks {label} step skipped with false condition",
            "gitleaks execution metadata is blocking",
            gitleaks=replace_once(
                GITLEAKS,
                header,
                header + "        if: ${{ false }}\n",
                f"gitleaks {label} if false",
            ),
        )
        must_reject(
            f"gitleaks {label} step failure tolerated",
            "gitleaks execution metadata is blocking",
            gitleaks=replace_once(
                GITLEAKS,
                header,
                header + "        continue-on-error: true\n",
                f"gitleaks {label} continue-on-error",
            ),
        )
    must_reject(
        "gitleaks scan job failure tolerated",
        "gitleaks execution metadata is blocking",
        gitleaks=replace_once(
            GITLEAKS,
            "  scan:\n",
            "  scan:\n    continue-on-error: true\n",
            "gitleaks job continue-on-error",
        ),
    )
    must_reject(
        "GmSSL interoperability job failure tolerated",
        "GmSSL interoperability suite metadata is blocking",
        ci=replace_once(
            CI,
            "  interop-gmssl:\n",
            "  interop-gmssl:\n    continue-on-error: true\n",
            "GmSSL job continue-on-error",
        ),
    )
    must_reject(
        "gitleaks scan job skipped with false condition",
        "gitleaks execution metadata is blocking",
        gitleaks=replace_once(
            GITLEAKS,
            "  scan:\n",
            "  scan:\n    if: false\n",
            "gitleaks job if false",
        ),
    )
    must_reject(
        "C example compiler shell drifts from bash",
        "C example execution metadata is blocking",
        ci=replace_once(
            CI,
            "      - name: Compile shipped C examples\n        shell: bash\n",
            "      - name: Compile shipped C examples\n        shell: sh\n",
            "C step custom shell",
        ),
    )
    must_reject(
        "C example compiler gains unexpected environment",
        "C example execution metadata is blocking",
        ci=replace_once(
            CI,
            "      - name: Compile shipped C examples\n        shell: bash\n",
            "      - name: Compile shipped C examples\n"
            "        shell: bash\n"
            "        env:\n"
            "          BYPASS: '1'\n",
            "C step environment",
        ),
    )
    must_reject(
        "policy verifier gains a custom shell",
        "policy verifier execution metadata is blocking",
        ci=replace_once(
            CI,
            "      - name: Verify assurance workflow policy\n"
            "        run: python3 .github/scripts/check_assurance_policy.py\n",
            "      - name: Verify assurance workflow policy\n"
            "        shell: bash\n"
            "        run: python3 .github/scripts/check_assurance_policy.py\n",
            "policy verifier shell",
        ),
    )
    must_reject(
        "policy verifier gains unexpected environment",
        "policy verifier execution metadata is blocking",
        ci=replace_once(
            CI,
            "      - name: Verify assurance workflow policy\n"
            "        run: python3 .github/scripts/check_assurance_policy.py\n",
            "      - name: Verify assurance workflow policy\n"
            "        env:\n"
            "          PYTHONOPTIMIZE: '1'\n"
            "        run: python3 .github/scripts/check_assurance_policy.py\n",
            "policy verifier environment",
        ),
    )
    must_reject(
        "gitleaks installer gains unexpected environment",
        "gitleaks execution metadata is blocking",
        gitleaks=replace_once(
            GITLEAKS,
            "      - name: Install gitleaks\n        shell: bash\n",
            "      - name: Install gitleaks\n"
            "        shell: bash\n"
            "        env:\n"
            "          GITLEAKS_SHA256: bypass\n",
            "gitleaks install environment",
        ),
    )
    must_reject(
        "gitleaks installer shell drifts from bash",
        "gitleaks execution metadata is blocking",
        gitleaks=replace_once(
            GITLEAKS,
            "      - name: Install gitleaks\n        shell: bash\n",
            "      - name: Install gitleaks\n        shell: sh\n",
            "gitleaks install shell",
        ),
    )
    must_reject(
        "gitleaks scan gains a custom shell",
        "gitleaks execution metadata is blocking",
        gitleaks=replace_once(
            GITLEAKS,
            "      - name: Scan committed history\n"
            "        run: gitleaks git --no-banner --redact --verbose\n",
            "      - name: Scan committed history\n"
            "        shell: bash\n"
            "        run: gitleaks git --no-banner --redact --verbose\n",
            "gitleaks scan shell",
        ),
    )
    must_reject(
        "gitleaks scan gains unexpected environment",
        "gitleaks execution metadata is blocking",
        gitleaks=replace_once(
            GITLEAKS,
            "      - name: Scan committed history\n"
            "        run: gitleaks git --no-banner --redact --verbose\n",
            "      - name: Scan committed history\n"
            "        env:\n"
            "          GITLEAKS_CONFIG: /dev/null\n"
            "        run: gitleaks git --no-banner --redact --verbose\n",
            "gitleaks scan environment",
        ),
    )
    for workflow_name, source, key, job_name in (
        ("PR", DUDECT_PR, "dudect_pr", "smoke"),
        ("nightly", DUDECT_NIGHTLY, "dudect_nightly", "full"),
    ):
        parse_step = step_named(job(source, job_name), "Parse and gate")
        must_reject(
            f"{workflow_name} dudect parse gains a custom shell",
            f"{workflow_name} dudect execution metadata is blocking",
            **{
                key: replace_once(
                    source,
                    parse_step,
                    replace_once(
                        parse_step,
                        "      - name: Parse and gate\n",
                        "      - name: Parse and gate\n        shell: bash\n",
                        f"{workflow_name} parse shell field",
                    ),
                    f"{workflow_name} parse shell step",
                )
            },
        )
    must_reject(
        "GmSSL suite gains a custom shell",
        "GmSSL interoperability suite metadata is blocking",
        ci=replace_once(
            CI,
            "      - name: gmssl interop suite (13 tests)\n",
            "      - name: gmssl interop suite (13 tests)\n        shell: bash\n",
            "GmSSL suite shell",
        ),
    )
    for label, source, source_key, job_name, step_name, expected in (
        (
            "policy verifier",
            CI,
            "ci",
            "build",
            "Verify assurance workflow policy",
            "policy verifier is executed by the build job",
        ),
        (
            "C example compiler",
            CI,
            "ci",
            "cabi",
            "Compile shipped C examples",
            "C example compile script matches reviewed canonical execution",
        ),
        (
            "GmSSL suite",
            CI,
            "ci",
            "interop-gmssl",
            "gmssl interop suite (13 tests)",
            "GmSSL interoperability script matches reviewed canonical execution",
        ),
        (
            "gitleaks installer",
            GITLEAKS,
            "gitleaks",
            "scan",
            "Install gitleaks",
            "gitleaks install script matches reviewed canonical execution",
        ),
        (
            "gitleaks scanner",
            GITLEAKS,
            "gitleaks",
            "scan",
            "Scan committed history",
            "gitleaks scans committed history",
        ),
    ):
        target_step = step_named(job(source, job_name), step_name)
        must_reject(
            f"{label} gains a duplicate run key",
            expected,
            **{
                source_key: replace_once(
                    source,
                    target_step,
                    target_step + "\n        run: 'true'",
                    f"{label} duplicate run",
                )
            },
        )
    for workflow_name, source, key, job_name in (
        ("PR", DUDECT_PR, "dudect_pr", "smoke"),
        ("nightly", DUDECT_NIGHTLY, "dudect_nightly", "full"),
    ):
        parse_step = step_named(job(source, job_name), "Parse and gate")
        must_reject(
            f"{workflow_name} dudect parser gains a duplicate run key",
            f"{workflow_name} dudect shell wrapper matches reviewed heredoc boundary",
            **{
                key: replace_once(
                    source,
                    parse_step,
                    parse_step + "\n        run: 'true'",
                    f"{workflow_name} parser duplicate run",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect parser gains a duplicate environment key",
            f"{workflow_name} dudect execution metadata is blocking",
            **{
                key: replace_once(
                    source,
                    parse_step,
                    replace_once(
                        parse_step,
                        "          MATRIX_FEATURES: ${{ matrix.features }}\n",
                        "          MATRIX_FEATURES: ${{ matrix.features }}\n"
                        "        env:\n"
                        "          MATRIX_FEATURES: default\n",
                        f"{workflow_name} parser duplicate env field",
                    ),
                    f"{workflow_name} parser duplicate env step",
                )
            },
        )
    must_reject(
        "C example compiler gains a duplicate shell key",
        "C example execution metadata is blocking",
        ci=replace_once(
            CI,
            "      - name: Compile shipped C examples\n        shell: bash\n",
            "      - name: Compile shipped C examples\n"
            "        shell: bash\n"
            "        shell: sh\n",
            "C duplicate shell",
        ),
    )
    must_reject(
        "gitleaks installer gains a duplicate shell key",
        "gitleaks execution metadata is blocking",
        gitleaks=replace_once(
            GITLEAKS,
            "      - name: Install gitleaks\n        shell: bash\n",
            "      - name: Install gitleaks\n"
            "        shell: bash\n"
            "        shell: sh\n",
            "gitleaks duplicate shell",
        ),
    )
    must_reject(
        "GmSSL suite gains a duplicate false condition",
        "GmSSL interoperability suite metadata is blocking",
        ci=replace_once(
            CI,
            "        if: steps.gmssl-provision.outcome == 'success' && steps.gmssl-version.outcome == 'success'\n",
            "        if: steps.gmssl-provision.outcome == 'success' && steps.gmssl-version.outcome == 'success'\n"
            "        if: ${{ false }}\n",
            "GmSSL duplicate if",
        ),
    )
    must_reject(
        "GmSSL suite gains a duplicate oracle environment",
        "GmSSL interoperability suite metadata is blocking",
        ci=replace_once(
            CI,
            "        env:\n          GMCRYPTO_GMSSL: '1'\n",
            "        env:\n"
            "          GMCRYPTO_GMSSL: '1'\n"
            "        env:\n"
            "          GMCRYPTO_GMSSL: '0'\n",
            "GmSSL duplicate env",
        ),
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
