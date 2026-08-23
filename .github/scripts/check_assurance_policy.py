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


MAPPING_LINE = re.compile(
    r"^(?P<indent> *)(?P<key>"
    r"[A-Za-z0-9_-]+|"
    r"'(?:[^']|'')*'|"
    r'"(?:[^"\\]|\\.)*"'
    r")[ \t]*:[ \t]*(?P<value>.*?)[ \t]*$"
)


def decode_double_quoted_key(token: str) -> str | None:
    """Decode YAML double-quoted escapes used by protected mapping keys."""
    simple = {
        "0": "\0",
        "a": "\a",
        "b": "\b",
        "t": "\t",
        "n": "\n",
        "v": "\v",
        "f": "\f",
        "r": "\r",
        "e": "\x1b",
        " ": " ",
        '"': '"',
        "/": "/",
        "\\": "\\",
        "N": "\x85",
        "_": "\xa0",
        "L": "\u2028",
        "P": "\u2029",
    }
    raw = token[1:-1]
    decoded: list[str] = []
    index = 0
    while index < len(raw):
        if raw[index] != "\\":
            decoded.append(raw[index])
            index += 1
            continue
        if index + 1 >= len(raw):
            return None
        escape = raw[index + 1]
        if escape in simple:
            decoded.append(simple[escape])
            index += 2
            continue
        widths = {"x": 2, "u": 4, "U": 8}
        width = widths.get(escape)
        if width is None or index + 2 + width > len(raw):
            return None
        digits = raw[index + 2 : index + 2 + width]
        if not re.fullmatch(r"[0-9A-Fa-f]+", digits):
            return None
        codepoint = int(digits, 16)
        if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
            return None
        decoded.append(chr(codepoint))
        index += 2 + width
    return "".join(decoded)


def mapping_line(line: str) -> tuple[int, str, str] | None:
    """Return indentation, decoded key, and value for one YAML mapping line."""
    match = MAPPING_LINE.fullmatch(line)
    if match is None:
        return None
    token = match.group("key")
    if token.startswith("'"):
        key = token[1:-1].replace("''", "'")
    elif token.startswith('"'):
        key = decode_double_quoted_key(token)
        if key is None:
            return None
    else:
        key = token
    return len(match.group("indent")), key, match.group("value")


BLOCK_SCALAR_VALUE = re.compile(
    r"[|>](?:[1-9][+-]?|[+-][1-9]?)?(?:[ \t]+#.*)?"
)


def has_mapping_delimiter(source: str) -> bool:
    """Return whether one physical line contains a block-mapping colon."""
    quote: str | None = None
    flow_depth = 0
    index = 0
    while index < len(source):
        char = source[index]
        if quote == "'":
            if char == "'" and index + 1 < len(source) and source[index + 1] == "'":
                index += 2
                continue
            if char == "'":
                quote = None
        elif quote == '"':
            if char == "\\":
                index += 2
                continue
            if char == '"':
                quote = None
        elif char in "'\"":
            quote = char
        elif char in "[{":
            flow_depth += 1
        elif char in "]}" and flow_depth:
            flow_depth -= 1
        elif (
            char == ":"
            and flow_depth == 0
            and (index + 1 == len(source) or source[index + 1] in " \t#")
        ):
            return True
        index += 1
    return False


def canonical_mapping_key_syntax(text: str) -> bool:
    """Reject non-canonical YAML key forms outside scalar value bodies.

    Protected workflows deliberately use only single-line plain, single-
    quoted, or double-quoted mapping keys. YAML's alternate explicit-key,
    tag, anchor, alias, and continued-quoted spellings can otherwise decode to
    policy metadata while evading the line-oriented semantic checks. Literal
    and folded scalar values are skipped as data, so shell and embedded Python
    are never interpreted as workflow keys.
    """
    scalar_owner_indent: int | None = None
    for line in text.splitlines():
        stripped = line.lstrip(" ")
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if scalar_owner_indent is not None:
            if indent > scalar_owner_indent:
                continue
            scalar_owner_indent = None

        content = stripped
        sequence_item = False
        if content == "-":
            continue
        if content.startswith("- ") or content.startswith("-\t"):
            sequence_item = True
            content = content[1:].lstrip(" \t")

        parsed = mapping_line(content)
        if parsed is not None:
            value = parsed[2]
            if BLOCK_SCALAR_VALUE.fullmatch(value):
                scalar_owner_indent = indent
            continue

        # A sequence scalar is data rather than a key. A sequence mapping
        # entry, however, still has to use the canonical key grammar above.
        if sequence_item and not has_mapping_delimiter(content):
            continue

        if has_mapping_delimiter(content):
            return False
        if content[0] in "?:!&*'\"":
            return False

    return True


def mapping_values(block: str, key: str, indent: int | None = None) -> list[str]:
    """Return all values for one YAML mapping key at the selected indentation."""
    values: list[str] = []
    for line in block.splitlines():
        parsed = mapping_line(line)
        if parsed is None:
            continue
        line_indent, decoded_key, value = parsed
        if decoded_key == key and (indent is None or line_indent == indent):
            values.append(value)
    return values


def mapping_keys(block: str, indent: int) -> tuple[str, ...]:
    """Return decoded mapping keys at one indentation level in source order."""
    return tuple(
        parsed[1]
        for line in block.splitlines()
        if (parsed := mapping_line(line)) is not None and parsed[0] == indent
    )


def scalar(block: str, key: str, indent: int) -> str | None:
    """Return a scalar only when its mapping key occurs exactly once."""
    values = mapping_values(block, key, indent)
    return values[0] if len(values) == 1 else None


def key_count(block: str, key: str, indent: int | None = None) -> int:
    """Count YAML mapping keys using the unified key recognizer."""
    return len(mapping_values(block, key, indent))


def mapping_block(block: str, key: str, indent: int) -> list[str]:
    """Return active source lines for one unique scalar and its folded body."""
    lines = block.splitlines()
    matches = [
        index
        for index, line in enumerate(lines)
        if (parsed := mapping_line(line)) is not None
        and parsed[0] == indent
        and parsed[1] == key
    ]
    if len(matches) != 1:
        return []
    start = matches[0]
    selected = [lines[start].split("#", 1)[0].rstrip()]
    for line in lines[start + 1 :]:
        source = line.split("#", 1)[0].rstrip()
        if not source.strip():
            continue
        if len(source) - len(source.lstrip()) <= indent:
            break
        selected.append(source)
    return selected


def step_headers(job_text: str) -> tuple[str, ...]:
    """Return the exact ordered list of active top-level step headers."""
    return tuple(
        line[6:]
        for line in active_source_lines(job_text)
        if line == "      -" or line.startswith("      - ")
    )


def exact_action_step(job_text: str, action: str, expected: list[str]) -> bool:
    """Require one action step and its complete active source contract."""
    return (
        step_headers(job_text).count(f"- uses: {action}") == 1
        and active_source_lines(step_uses(job_text, action)) == expected
    )


def active_run(step: str) -> str:
    """Extract active shell from a step's run key, excluding YAML comments."""
    lines = step.splitlines()
    matches = [
        (index, parsed[2])
        for index, line in enumerate(lines)
        if (parsed := mapping_line(line)) is not None
        and parsed[0] == 8
        and parsed[1] == "run"
    ]
    if len(matches) != 1:
        return ""
    index, value = matches[0]
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
        (index, parsed[2])
        for index, line in enumerate(lines)
        if (parsed := mapping_line(line)) is not None
        and parsed[0] == 8
        and parsed[1] == "run"
    ]
    if len(matches) != 1 or matches[0][1] != "|":
        return None
    run_index = matches[0][0]
    body: list[str] = []
    for candidate in lines[run_index + 1 :]:
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


def reviewed_source_fingerprint(block: str) -> str:
    """Hash raw nonblank, non-whole-line-comment source in exact order."""
    reviewed = "\n".join(
        line
        for line in block.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    return hashlib.sha256(reviewed.encode()).hexdigest()


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

    for workflow_name, source in (
        ("CI", ci),
        ("gitleaks", gitleaks),
        ("PR dudect", dudect_pr),
        ("nightly dudect", dudect_nightly),
    ):
        require(
            f"{workflow_name} workflow uses canonical YAML mapping-key syntax",
            canonical_mapping_key_syntax(source),
        )

    ci_env = indented_block(ci, "env:", 0)
    require(
        "CI workflow environment is exact",
        key_count(ci, "env", 0) == 1
        and active_source_lines(ci_env)
        == [
            "env:",
            "  CARGO_TERM_COLOR: always",
            '  RUSTFLAGS: "-D warnings"',
        ],
    )
    require(
        "gitleaks workflow has no top-level environment",
        key_count(gitleaks, "env", 0) == 0,
    )

    build = job(ci, "build")
    cabi = job(ci, "cabi")
    deny = job(ci, "deny")
    interop = job(ci, "interop-gmssl")
    require("build job key is unique", key_count(ci, "build", 2) == 1)
    require("cabi job key is unique", key_count(ci, "cabi", 2) == 1)
    require("GmSSL job key is unique", key_count(ci, "interop-gmssl", 2) == 1)
    require("cargo-deny job key is unique", key_count(ci, "deny", 2) == 1)
    # Reviewed executable/configuration boundaries for all protected jobs.
    # Any active source change must update its hash and mutation coverage.
    reviewed_jobs = {
        "build": build,
        "cabi": cabi,
        "GmSSL": interop,
        "cargo-deny": deny,
        "gitleaks scan": job(gitleaks, "scan"),
        "PR dudect": job(dudect_pr, "smoke"),
        "nightly dudect": job(dudect_nightly, "full"),
    }
    reviewed_job_fingerprints = {
        "build": "637d188f176673a1513f2641b27c0f581bfd7c672eef9bc69658a51aafcdfb70",
        "cabi": "4ff7eccfa333d3858ef97ceb3e517c043c44a962e7333976d21896cf1b404c31",
        "GmSSL": "796eafa03285b30a7b70389b5c4ddab6f064fae0339f3b898de0210a4601ab79",
        "cargo-deny": "efc9a2787bc8b48022d35d3419af0e9987c6a11c3a5c44959fc93b1d33be9174",
        "gitleaks scan": "c7889df5e874f1a5cee871c24cd49cc539d845c0627861e49b1a9e6335d1c15f",
        "PR dudect": "02889db2f608919b72204beaccc6c67591df6ecb836d25ad08c6f54529c7acb5",
        "nightly dudect": "e273f148c2ccb6dc17d39c93678a152f36f8458b584af21ee4778bbfeb727953",
    }
    for label, expected_fingerprint in reviewed_job_fingerprints.items():
        require(
            f"{label} job reviewed source fingerprint matches",
            reviewed_source_fingerprint(reviewed_jobs[label])
            == expected_fingerprint,
        )
    for label, protected_job, expected_keys in (
        (
            "build",
            build,
            ("name", "runs-on", "if", "timeout-minutes", "steps"),
        ),
        (
            "cabi",
            cabi,
            ("name", "runs-on", "if", "timeout-minutes", "steps"),
        ),
        (
            "GmSSL",
            interop,
            ("name", "runs-on", "if", "timeout-minutes", "env", "steps"),
        ),
        (
            "cargo-deny",
            deny,
            ("name", "runs-on", "if", "timeout-minutes", "steps"),
        ),
    ):
        require(
            f"{label} job top-level key sequence is exact",
            mapping_keys(protected_job, 4) == expected_keys,
        )
    for label, protected_job in (
        ("build", build),
        ("cabi", cabi),
        ("GmSSL", interop),
        ("cargo-deny", deny),
    ):
        require(
            f"{label} checkout step is exact",
            exact_action_step(
                protected_job,
                "actions/checkout@v7",
                ["      - uses: actions/checkout@v7"],
            ),
        )

    skip_ci_if = [
        "    if: >-",
        "      !contains(github.event.pull_request.title, '[skip ci]') &&",
        "      !contains(github.event.pull_request.title, '[ci skip]') &&",
        "      !contains(github.event.pull_request.title, '[no ci]') &&",
        "      !contains(github.event.pull_request.title, '[skip actions]') &&",
        "      !contains(github.event.head_commit.message, '[skip ci]') &&",
        "      !contains(github.event.head_commit.message, '[ci skip]') &&",
        "      !contains(github.event.head_commit.message, '[no ci]') &&",
        "      !contains(github.event.head_commit.message, '[skip actions]')",
    ]
    require(
        "workflow defaults cannot alter assurance commands",
        all(key_count(source, "defaults", 0) == 0 for source in (ci, gitleaks, dudect_pr, dudect_nightly)),
    )
    build_contract = (
        key_count(build, "if", 4) == 1
        and mapping_block(build, "if", 4) == skip_ci_if
        and key_count(build, "continue-on-error", 4) == 0
        and key_count(build, "defaults", 4) == 0
        and key_count(build, "env", 4) == 0
    )
    require("build job contract is exact", build_contract)
    require(
        "build step prefix is exact",
        step_headers(build)[:2]
        == (
            "- uses: actions/checkout@v7",
            "- name: Verify assurance workflow policy",
        ),
    )
    require("build has no dash-alone steps", "-" not in step_headers(build))
    cabi_contract = (
        key_count(cabi, "if", 4) == 1
        and mapping_block(cabi, "if", 4) == skip_ci_if
        and key_count(cabi, "continue-on-error", 4) == 0
        and key_count(cabi, "defaults", 4) == 0
        and key_count(cabi, "env", 4) == 0
    )
    require("cabi job contract is exact", cabi_contract)
    require(
        "cabi step sequence is exact",
        step_headers(cabi)
        == (
            "- uses: actions/checkout@v7",
            "- uses: dtolnay/rust-toolchain@stable",
            "- uses: Swatinem/rust-cache@v2",
            "- name: cargo build -p gmcrypto-c --release",
            "- name: Regenerate header via cbindgen",
            "- name: Verify committed header is up-to-date",
            "- name: cargo test -p gmcrypto-c",
            "- name: Compile shipped C examples",
        ),
    )

    policy_step = step_named(build, "Verify assurance workflow policy")
    require(
        "policy verifier is executed by the build job",
        active_run(policy_step) == "python3 .github/scripts/check_assurance_policy.py",
    )
    policy_metadata = (
        key_count(policy_step, "if", 8) == 0
        and key_count(policy_step, "continue-on-error", 8) == 0
        and key_count(policy_step, "shell", 8) == 1
        and scalar(policy_step, "shell", 8) == "bash"
        and key_count(policy_step, "env", 8) == 0
        and key_count(policy_step, "run", 8) == 1
        and key_count(policy_step, "name", 8) == 0
        and key_count(build, "continue-on-error", 4) == 0
    )
    require("policy verifier metadata is exact", policy_metadata)
    require("policy verifier execution metadata is blocking", policy_metadata)

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
    c_metadata = (
        key_count(c_examples, "if", 8) == 0
        and key_count(c_examples, "continue-on-error", 8) == 0
        and key_count(c_examples, "shell", 8) == 1
        and scalar(c_examples, "shell", 8) == "bash"
        and key_count(c_examples, "env", 8) == 0
        and key_count(c_examples, "run", 8) == 1
        and key_count(c_examples, "name", 8) == 0
        and key_count(cabi, "continue-on-error", 4) == 0
    )
    require("C example metadata is exact", c_metadata)
    require("C example execution metadata is blocking", c_metadata)

    trigger = indented_block(gitleaks, "on:", 0)
    push_trigger = indented_block(trigger, "push:", 2)
    pull_request_trigger = indented_block(trigger, "pull_request:", 2)
    scan = job(gitleaks, "scan")
    require("gitleaks job key is unique", key_count(gitleaks, "scan", 2) == 1)
    require(
        "gitleaks scan job top-level key sequence is exact",
        mapping_keys(scan, 4)
        == ("name", "runs-on", "timeout-minutes", "steps"),
    )
    checkout = step_uses(scan, "actions/checkout@v7")
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
        "gitleaks triggers are exact",
        key_count(gitleaks, "on", 0) == 1
        and key_count(trigger, "push", 2) == 1
        and key_count(trigger, "pull_request", 2) == 1
        and key_count(trigger, "workflow_dispatch", 2) == 1
        and scalar(push_trigger, "branches", 4) == "[main]"
        and scalar(pull_request_trigger, "branches", 4) == "[main]"
        and key_count(trigger, "paths") == 0
        and key_count(trigger, "paths-ignore") == 0,
    )
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
        key_count(trigger, "paths") == 0 and key_count(trigger, "paths-ignore") == 0,
    )
    checkout_metadata = (
        key_count(checkout, "fetch-depth", 10) == 1
        and scalar(checkout, "fetch-depth", 10) == "0"
        and key_count(checkout, "if", 8) == 0
        and key_count(checkout, "continue-on-error", 8) == 0
        and key_count(checkout, "shell", 8) == 0
        and key_count(checkout, "env", 8) == 0
    )
    checkout_exact = active_source_lines(checkout) == [
        "      - uses: actions/checkout@v7",
        "        with:",
        "          fetch-depth: 0",
    ]
    require("gitleaks checkout step is exact", checkout_exact)
    require("gitleaks checkout metadata is exact", checkout_metadata)
    require("gitleaks checkout has full history", checkout_metadata and checkout_exact)
    require(
        "gitleaks step sequence is exact",
        step_headers(scan)
        == (
            "- uses: actions/checkout@v7",
            "- name: Install gitleaks",
            "- name: Scan committed history",
        ),
    )
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
    install_metadata = (
        key_count(install, "if", 8) == 0
        and key_count(install, "continue-on-error", 8) == 0
        and key_count(install, "shell", 8) == 1
        and scalar(install, "shell", 8) == "bash"
        and key_count(install, "env", 8) == 0
        and key_count(install, "run", 8) == 1
        and key_count(install, "name", 8) == 0
    )
    scan_metadata = (
        key_count(scan_step, "if", 8) == 0
        and key_count(scan_step, "continue-on-error", 8) == 0
        and key_count(scan_step, "shell", 8) == 1
        and scalar(scan_step, "shell", 8) == "bash"
        and key_count(scan_step, "env", 8) == 0
        and key_count(scan_step, "run", 8) == 1
        and key_count(scan_step, "name", 8) == 0
    )
    scan_job_contract = (
        key_count(scan, "if", 4) == 0
        and key_count(scan, "continue-on-error", 4) == 0
        and key_count(scan, "defaults", 4) == 0
        and key_count(scan, "env", 4) == 0
        and scalar(scan, "runs-on", 4) == "ubuntu-24.04"
        and scalar(scan, "timeout-minutes", 4) == "10"
    )
    require("gitleaks install metadata is exact", install_metadata)
    require("gitleaks scan metadata is exact", scan_metadata)
    require("gitleaks scan job contract is exact", scan_job_contract)
    require(
        "gitleaks execution metadata is blocking",
        install_metadata and scan_metadata and scan_job_contract,
    )

    deny_install = step_named(deny, "Install cargo-deny")
    deny_toolchain = step_uses(deny, "dtolnay/rust-toolchain@stable")
    deny_lockfile = step_named(deny, "Generate lockfile")
    deny_default = step_named(deny, "Run cargo-deny (default features, excluding dev-deps)")
    deny_runtime = step_named(deny, "Run cargo-deny (runtime opt-in features, excluding dev-deps)")
    require(
        "cargo-deny step sequence is exact",
        step_headers(deny)
        == (
            "- uses: actions/checkout@v7",
            "- uses: dtolnay/rust-toolchain@stable",
            "- name: Install cargo-deny",
            "- name: Generate lockfile",
            "- name: Run cargo-deny (default features, excluding dev-deps)",
            "- name: Run cargo-deny (runtime opt-in features, excluding dev-deps)",
        ),
    )
    require(
        "cargo-deny toolchain step is exact",
        active_source_lines(deny_toolchain)
        == ["      - uses: dtolnay/rust-toolchain@stable"],
    )
    require(
        "cargo-deny install step is exact",
        active_source_lines(deny_install)
        == [
            "      - name: Install cargo-deny",
            "        uses: taiki-e/install-action@v2",
            "        with:",
            "          tool: cargo-deny@0.20.2",
        ],
    )
    require(
        "cargo-deny lockfile step is exact",
        active_source_lines(deny_lockfile)
        == [
            "      - name: Generate lockfile",
            "        shell: bash",
            "        run: cargo generate-lockfile",
        ],
    )
    require(
        "cargo-deny default command step is exact",
        active_source_lines(deny_default)
        == [
            "      - name: Run cargo-deny (default features, excluding dev-deps)",
            "        shell: bash",
            "        run: cargo deny --exclude-dev check",
        ],
    )
    require(
        "cargo-deny runtime command step is exact",
        active_source_lines(deny_runtime)
        == [
            "      - name: Run cargo-deny (runtime opt-in features, excluding dev-deps)",
            "        shell: bash",
            "        run: cargo deny --features gmcrypto-core/digest-traits,gmcrypto-core/cipher-traits,gmcrypto-core/sm4-bitsliced,gmcrypto-core/sm4-bitsliced-simd,gmcrypto-core/sm4-aead,gmcrypto-core/sm4-xts,gmcrypto-core/crypto-bigint-scalar,gmcrypto-core/sm2-key-exchange,gmcrypto-core/x509,gmcrypto-core/tlcp,gmcrypto-core/aead-traits --exclude-dev check",
        ],
    )
    deny_job_contract = (
        scalar(deny, "name", 4) == "cargo-deny (no forbidden runtime deps)"
        and scalar(deny, "runs-on", 4) == "macos-14"
        and key_count(deny, "if", 4) == 1
        and mapping_block(deny, "if", 4) == skip_ci_if
        and scalar(deny, "timeout-minutes", 4) == "15"
        and mapping_keys(deny, 4)
        == ("name", "runs-on", "if", "timeout-minutes", "steps")
    )
    require("cargo-deny job contract is exact", deny_job_contract)
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
    put_path = step_named(interop, "Put gmssl on PATH")
    interop_env = indented_block(interop, "env:", 4)
    provision_env = indented_block(provision, "env:", 8)
    suite_env = indented_block(suite, "env:", 8)
    report_env = indented_block(report, "env:", 8)
    provision_script = active_run(provision)
    version_script = active_run(version)
    suite_script = active_run(suite)
    report_script = active_run(report)
    interop_job_contract = (
        scalar(interop, "name", 4) == "gmssl interop (mismatch gates; infra non-blocking)"
        and scalar(interop, "runs-on", 4) == "ubuntu-24.04"
        and scalar(interop, "timeout-minutes", 4) == "25"
        and key_count(interop, "if", 4) == 1
        and mapping_block(interop, "if", 4) == skip_ci_if
        and key_count(interop, "continue-on-error", 4) == 0
        and key_count(interop, "defaults", 4) == 0
        and key_count(interop, "env", 4) == 1
        and active_source_lines(interop_env)
        == [
            "    env:",
            "      GMSSL_TAG: v3.2.0",
            "      GMSSL_CACHE_EPOCH: '1'",
        ]
    )
    require("GmSSL job contract is exact", interop_job_contract)
    require(
        "GmSSL step sequence is exact",
        step_headers(interop)
        == (
            "- uses: actions/checkout@v7",
            "- uses: dtolnay/rust-toolchain@stable",
            "- name: Cache cargo",
            "- name: Cache GmSSL install prefix",
            "- name: Provision GmSSL ${{ env.GMSSL_TAG }} oracle",
            "- name: Put gmssl on PATH",
            "- name: Assert oracle version (drift guard)",
            "- name: gmssl interop suite (13 tests)",
            "- name: Report GmSSL interoperability status",
        ),
    )
    cache_metadata = (
        scalar(cache, "id", 8) == "gmssl-cache"
        and scalar(cache, "continue-on-error", 8) == "true"
        and key_count(cache, "if", 8) == 0
        and key_count(cache, "shell", 8) == 0
        and key_count(cache, "env", 8) == 0
    )
    provision_metadata = (
        scalar(provision, "id", 8) == "gmssl-provision"
        and scalar(provision, "continue-on-error", 8) == "true"
        and key_count(provision, "if", 8) == 0
        and key_count(provision, "shell", 8) == 0
        and key_count(provision, "env", 8) == 1
        and key_count(provision, "run", 8) == 1
        and active_source_lines(provision_env)
        == [
            "        env:",
            "          CACHE_HIT: ${{ steps.gmssl-cache.outputs.cache-hit }}",
        ]
    )
    version_metadata = (
        scalar(version, "id", 8) == "gmssl-version"
        and scalar(version, "if", 8) == "steps.gmssl-provision.outcome == 'success'"
        and scalar(version, "continue-on-error", 8) == "true"
        and scalar(version, "shell", 8) == "bash"
        and key_count(version, "env", 8) == 0
        and key_count(version, "run", 8) == 1
        and key_count(version, "name", 8) == 0
    )
    suite_metadata = (
        scalar(suite, "id", 8) == "gmssl-suite"
        and scalar(suite, "if", 8)
        == "steps.gmssl-provision.outcome == 'success' && steps.gmssl-version.outcome == 'success'"
        and key_count(suite, "continue-on-error", 8) == 0
        and scalar(suite, "shell", 8) == "bash"
        and key_count(suite, "env", 8) == 1
        and key_count(suite, "run", 8) == 1
        and key_count(suite, "name", 8) == 0
        and active_source_lines(suite_env)
        == ["        env:", "          GMCRYPTO_GMSSL: '1'"]
    )
    report_metadata = (
        scalar(report, "if", 8) == "${{ always() }}"
        and key_count(report, "continue-on-error", 8) == 0
        and scalar(report, "shell", 8) == "bash"
        and key_count(report, "env", 8) == 1
        and key_count(report, "run", 8) == 1
        and key_count(report, "id", 8) == 0
        and key_count(report, "name", 8) == 0
        and active_source_lines(report_env)
        == [
            "        env:",
            "          CACHE_OUTCOME: ${{ steps.gmssl-cache.outcome }}",
            "          PROVISION_OUTCOME: ${{ steps.gmssl-provision.outcome }}",
            "          VERSION_OUTCOME: ${{ steps.gmssl-version.outcome }}",
            "          SUITE_OUTCOME: ${{ steps.gmssl-suite.outcome }}",
        ]
    )
    require(
        "GmSSL step ids are exact",
        cache_metadata and provision_metadata and version_metadata and suite_metadata,
    )
    require("GmSSL version metadata is exact", version_metadata)
    require("GmSSL suite metadata is exact", suite_metadata)
    require("GmSSL report metadata is exact", report_metadata)
    version_canonical_script = (
        "set -euo pipefail\n"
        'want="GmSSL ${GMSSL_TAG#v}"\n'
        'got="$(gmssl version | head -n1)"\n'
        'if [ "$got" != "$want" ]; then\n'
        'echo "::error::ORACLE DRIFT - NOT a gmcrypto-core regression."\n'
        'echo "  expected: $want"\n'
        'echo "  found:    $got"\n'
        'echo "This job pins its reference implementation. A mismatch means the"\n'
        'echo "GmSSL tag, cache, or build moved - not that our wire output changed."\n'
        'echo "Fix: correct GMSSL_TAG, or bump GMSSL_CACHE_EPOCH, or re-baseline."\n'
        "exit 1\n"
        "fi\n"
        'echo "oracle: $got"'
    )
    report_canonical_script = (
        "set -euo pipefail\n"
        'case "$SUITE_OUTCOME" in\n'
        "success|failure) interop_state=ran ;;\n"
        "skipped) interop_state=skipped ;;\n"
        "cancelled) interop_state=cancelled ;;\n"
        "*) interop_state=unknown ;;\n"
        "esac\n"
        'echo "INTEROP_SUITE=$interop_state"\n'
        "{\n"
        'echo "### GmSSL interoperability status"\n'
        "echo\n"
        'echo "INTEROP_SUITE=\\`$interop_state\\`"\n'
        "echo\n"
        'echo "- cache: \\`$CACHE_OUTCOME\\`"\n'
        'echo "- provision: \\`$PROVISION_OUTCOME\\`"\n'
        'echo "- version assertion: \\`$VERSION_OUTCOME\\`"\n'
        'echo "- interoperability suite: \\`$SUITE_OUTCOME\\`"\n'
        '} >> "$GITHUB_STEP_SUMMARY"\n'
        'if [ "$PROVISION_OUTCOME" != "success" ] || [ "$VERSION_OUTCOME" != "success" ]; then\n'
        'echo "::warning title=GmSSL infrastructure unavailable::cache=$CACHE_OUTCOME '
        'provision=$PROVISION_OUTCOME version=$VERSION_OUTCOME suite=$SUITE_OUTCOME"\n'
        "{\n"
        'echo "The interoperability suite was not run because the pinned oracle could not be prepared."\n'
        "echo\n"
        'echo "This is non-blocking infrastructure telemetry, not an interoperability pass."\n'
        '} >> "$GITHUB_STEP_SUMMARY"\n'
        'elif [ "$CACHE_OUTCOME" != "success" ]; then\n'
        'echo "::warning title=GmSSL cache degraded::cache=$CACHE_OUTCOME; '
        'fallback provisioning succeeded; suite=$SUITE_OUTCOME"\n'
        "{\n"
        'echo "The cache step failed, but fallback provisioning and version validation succeeded."\n'
        "echo\n"
        'echo "Fallback provisioning recovered the cache failure; the suite outcome remains authoritative."\n'
        '} >> "$GITHUB_STEP_SUMMARY"\n'
        "fi"
    )
    require(
        "GmSSL version script matches reviewed canonical execution",
        version_script == version_canonical_script,
    )
    require(
        "GmSSL report script matches reviewed canonical execution",
        report_script == report_canonical_script,
    )
    require(
        "GmSSL path step metadata is exact",
        scalar(put_path, "if", 8) == "steps.gmssl-provision.outcome == 'success'"
        and key_count(put_path, "continue-on-error", 8) == 0
        and key_count(put_path, "shell", 8) == 0
        and key_count(put_path, "env", 8) == 0
        and key_count(put_path, "run", 8) == 1,
    )
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
        suite_metadata and interop_job_contract,
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
    dudect_sources = {"PR": dudect_pr, "nightly": dudect_nightly}
    dudect_job_keys = {"PR": "smoke", "nightly": "full"}
    for workflow_name, source in dudect_sources.items():
        require(
            f"{workflow_name} dudect job key is unique",
            key_count(source, dudect_job_keys[workflow_name], 2) == 1,
        )
    parse_steps = {
        workflow_name: step_named(job_text, "Parse and gate")
        for workflow_name, job_text in dudect_jobs.items()
    }
    dudect_producer_names = {
        "PR": "Run dudect harness (smoke budget, 3 runs for median)",
        "nightly": "Run dudect harness (nightly budget, 5 runs for median)",
    }
    producer_steps = {
        workflow_name: step_named(job_text, dudect_producer_names[workflow_name])
        for workflow_name, job_text in dudect_jobs.items()
    }
    dudect_job_config = {
        "PR": {
            "name": "timing-leak smoke (10K×3 median, |tau|<=0.20, features=${{ matrix.features }})",
            "timeout": "10",
            "samples": '"10000"',
            "runs": '"3"',
            "has_skip_if": True,
        },
        "nightly": {
            "name": "timing-leak nightly (100K×5 median, |tau|<=0.20, features=${{ matrix.features }})",
            "timeout": "40",
            "samples": '"100000"',
            "runs": '"5"',
            "has_skip_if": False,
        },
    }
    dudect_matrix = [
        "      matrix:",
        "        features:",
        '          - "default"',
        '          - "sm4-bitsliced"',
        '          - "sm4-bitsliced-simd"',
        '          - "sm4-bitsliced-simd,sm4-aead,sm4-xts,sm2-key-exchange,tlcp"',
    ]
    dudect_producer_canonical = (
        "set -euxo pipefail\n"
        'if [ "$MATRIX_FEATURES" = "default" ]; then\n'
        'FEATURES="crypto-bigint-scalar"\n'
        "else\n"
        'FEATURES="$MATRIX_FEATURES,crypto-bigint-scalar"\n'
        "fi\n"
        'for i in $(seq 1 "$DUDECT_RUNS"); do\n'
        'echo "=== dudect run $i/$DUDECT_RUNS (features=$FEATURES) ==="\n'
        'cargo bench --bench timing_leaks --features "$FEATURES" 2>&1 | tee "dudect-$i.log"\n'
        "done"
    )
    dudect_capture_canonical = (
        "set +e\n"
        'echo "=== Runner image ==="\n'
        'echo "ImageVersion: ${ImageVersion:-<unset>}"\n'
        'echo "ImageOS:      ${ImageOS:-<unset>}"\n'
        "echo\n"
        'echo "=== Kernel ==="\n'
        "uname -a\n"
        "echo\n"
        'echo "=== CPU ==="\n'
        "lscpu 2>/dev/null | head -30 || cat /proc/cpuinfo | head -25\n"
        "echo\n"
        'echo "=== CPU governor / turbo state ==="\n'
        "for cpu in /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor; do\n"
        '[ -r "$cpu" ] && echo "$cpu = $(cat "$cpu")"\n'
        "done\n"
        "[ -r /sys/devices/system/cpu/intel_pstate/no_turbo ] && \\\n"
        'echo "intel_pstate/no_turbo = $(cat /sys/devices/system/cpu/intel_pstate/no_turbo)"\n'
        "echo\n"
        'echo "=== Rust ==="\n'
        "rustc -Vv\n"
        "cargo -V"
    )
    for workflow_name, dudect_job in dudect_jobs.items():
        config = dudect_job_config[workflow_name]
        workflow_source = dudect_sources[workflow_name]
        producer = producer_steps[workflow_name]
        checkout_step = step_uses(dudect_job, "actions/checkout@v7")
        toolchain_step = step_uses(dudect_job, "dtolnay/rust-toolchain@1.95.0")
        rust_cache_step = step_uses(dudect_job, "Swatinem/rust-cache@v2")
        capture_step = step_named(
            dudect_job,
            "Capture runner environment (for noise-floor correlation)",
        )
        workflow_env = indented_block(workflow_source, "env:", 0)
        producer_env = indented_block(producer, "env:", 8)
        matrix_block = indented_block(dudect_job, "matrix:", 6)
        expected_headers = (
            "- uses: actions/checkout@v7",
            "- uses: dtolnay/rust-toolchain@1.95.0",
            "- uses: Swatinem/rust-cache@v2",
            "- name: Capture runner environment (for noise-floor correlation)",
            f"- name: {dudect_producer_names[workflow_name]}",
            "- name: Parse and gate",
            "- name: Upload raw log",
        )
        has_exact_if = (
            key_count(dudect_job, "if", 4) == 1
            and mapping_block(dudect_job, "if", 4) == skip_ci_if
            if config["has_skip_if"]
            else key_count(dudect_job, "if", 4) == 0
        )
        expected_job_keys = (
            ("name", "runs-on", "if", "timeout-minutes", "strategy", "steps")
            if config["has_skip_if"]
            else ("name", "runs-on", "timeout-minutes", "strategy", "steps")
        )
        require(
            f"{workflow_name} dudect job top-level key sequence is exact",
            mapping_keys(dudect_job, 4) == expected_job_keys,
        )
        job_contract = (
            scalar(dudect_job, "name", 4) == config["name"]
            and scalar(dudect_job, "runs-on", 4) == "ubuntu-24.04"
            and scalar(dudect_job, "timeout-minutes", 4) == config["timeout"]
            and has_exact_if
            and key_count(dudect_job, "continue-on-error", 4) == 0
            and key_count(dudect_job, "defaults", 4) == 0
            and key_count(dudect_job, "env", 4) == 0
            and mapping_keys(dudect_job, 4) == expected_job_keys
        )
        require(f"{workflow_name} dudect job contract is exact", job_contract)
        require(
            f"{workflow_name} dudect workflow environment is exact",
            key_count(workflow_source, "env", 0) == 1
            and active_source_lines(workflow_env)
            == ["env:", "  CARGO_TERM_COLOR: always"],
        )
        require(
            f"{workflow_name} dudect step sequence is exact",
            step_headers(dudect_job) == expected_headers,
        )
        require(
            f"{workflow_name} dudect checkout step is exact",
            active_source_lines(checkout_step)
            == ["      - uses: actions/checkout@v7"],
        )
        require(
            f"{workflow_name} dudect rust toolchain metadata is exact",
            active_source_lines(toolchain_step)
            == ["      - uses: dtolnay/rust-toolchain@1.95.0"],
        )
        require(
            f"{workflow_name} dudect rust cache step is exact",
            active_source_lines(rust_cache_step)
            == [
                "      - uses: Swatinem/rust-cache@v2",
                "        with:",
                "          shared-key: gmcrypto-stable-${{ strategy.job-index }}",
            ],
        )
        capture_metadata = (
            key_count(capture_step, "if", 8) == 0
            and key_count(capture_step, "continue-on-error", 8) == 0
            and key_count(capture_step, "shell", 8) == 0
            and key_count(capture_step, "env", 8) == 0
            and key_count(capture_step, "uses", 8) == 0
            and key_count(capture_step, "with", 8) == 0
            and key_count(capture_step, "run", 8) == 1
            and key_count(capture_step, "name", 8) == 0
        )
        require(
            f"{workflow_name} dudect capture metadata is exact",
            capture_metadata,
        )
        require(
            f"{workflow_name} dudect capture script is exact",
            capture_metadata and active_run(capture_step) == dudect_capture_canonical,
        )
        require(
            f"{workflow_name} dudect matrix is exact",
            key_count(dudect_job, "matrix", 6) == 1
            and active_source_lines(matrix_block) == dudect_matrix,
        )
        producer_contract = (
            key_count(producer, "if", 8) == 0
            and key_count(producer, "continue-on-error", 8) == 0
            and scalar(producer, "shell", 8) == "bash"
            and key_count(producer, "env", 8) == 1
            and key_count(producer, "run", 8) == 1
            and key_count(producer, "name", 8) == 0
            and active_source_lines(producer_env)
            == [
                "        env:",
                f"          DUDECT_SAMPLES: {config['samples']}",
                f"          DUDECT_RUNS: {config['runs']}",
                "          MATRIX_FEATURES: ${{ matrix.features }}",
            ]
        )
        require(f"{workflow_name} dudect producer contract is exact", producer_contract)
        require(f"{workflow_name} dudect producer metadata is exact", producer_contract)
        require(
            f"{workflow_name} dudect producer script is exact",
            active_run(producer)
            == (
                dudect_producer_canonical
                if workflow_name == "PR"
                else dudect_producer_canonical.replace(
                    'tee "dudect-$i.log"',
                    'tee "dudect-nightly-$i.log"',
                )
            ),
        )
    # These hashes are the reviewed executable-semantics boundary for the
    # complete embedded Python programs. A deliberate executable change must
    # update the workflow, this fingerprint, and the mutation suite together.
    reviewed_ast_fingerprints = {
        "PR": "085ee6e3d89aa8e0210ec35602138c242626c3876652f56939ac26cd8f8cc350",
        "nightly": "e3ee78b3a3551c592bab77a445977fe1e991a97c0903192a57acf56e9b7f030e",
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
        parse_metadata = (
            key_count(parse_step, "if", 8) == 0
            and key_count(parse_step, "continue-on-error", 8) == 0
            and scalar(parse_step, "shell", 8) == "bash"
            and key_count(parse_step, "env", 8) == 1
            and key_count(parse_step, "run", 8) == 1
            and key_count(parse_step, "name", 8) == 0
            and key_count(dudect_jobs[workflow_name], "continue-on-error", 4) == 0
            and active_source_lines(parse_env)
            == ["        env:", "          MATRIX_FEATURES: ${{ matrix.features }}"]
        )
        require(f"{workflow_name} dudect parse metadata is exact", parse_metadata)
        require(
            f"{workflow_name} dudect execution metadata is blocking",
            parse_metadata,
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

    def replace_in_job(
        text: str,
        job_name: str,
        before: str,
        after: str,
        label: str,
    ) -> str:
        target = job(text, job_name)
        mutated = replace_once(target, before, after, f"{label} field")
        return replace_once(text, target, mutated, f"{label} job")

    def replace_in_step(
        text: str,
        job_name: str,
        step_name: str,
        before: str,
        after: str,
        label: str,
    ) -> str:
        target_job = job(text, job_name)
        target_step = step_named(target_job, step_name)
        mutated_step = replace_once(target_step, before, after, f"{label} field")
        mutated_job = replace_once(
            target_job,
            target_step,
            mutated_step,
            f"{label} step",
        )
        return replace_once(text, target_job, mutated_job, f"{label} job")

    def replace_in_uses(
        text: str,
        job_name: str,
        action: str,
        before: str,
        after: str,
        label: str,
    ) -> str:
        target_job = job(text, job_name)
        target_step = step_uses(target_job, action)
        mutated_step = replace_once(target_step, before, after, f"{label} field")
        mutated_job = replace_once(
            target_job,
            target_step,
            mutated_step,
            f"{label} step",
        )
        return replace_once(text, target_job, mutated_job, f"{label} job")

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
            "        shell: bash\n"
            "        run: gitleaks git --no-banner --redact --verbose",
            "      - name: Scan committed history\n"
            "        shell: bash\n"
            "        run: 'true'\n"
            "      - name: Unrelated diagnostic\n"
            "        shell: bash\n"
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
            "        shell: bash\n"
            "        run: python3 .github/scripts/check_assurance_policy.py\n",
            "      - name: Verify assurance workflow policy\n"
            "        if: ${{ false }}\n"
            "        shell: bash\n"
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
            "        shell: bash\n"
            "        run: python3 .github/scripts/check_assurance_policy.py\n",
            "      - name: Verify assurance workflow policy\n"
            "        continue-on-error: true\n"
            "        shell: bash\n"
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
            "        shell: bash\n"
            "        run: python3 .github/scripts/check_assurance_policy.py\n",
            "      - name: Verify assurance workflow policy\n"
            "        shell: bash {0} || true\n"
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
            "        shell: bash\n"
            "        run: python3 .github/scripts/check_assurance_policy.py\n",
            "      - name: Verify assurance workflow policy\n"
            "        shell: bash\n"
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
            "        shell: bash\n"
            "        run: gitleaks git --no-banner --redact --verbose\n",
            "      - name: Scan committed history\n"
            "        shell: bash {0} || true\n"
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
            "        shell: bash\n"
            "        run: gitleaks git --no-banner --redact --verbose\n",
            "      - name: Scan committed history\n"
            "        shell: bash\n"
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

    # Metadata spelling mutations: YAML mapping keys may be plain or quoted,
    # and whitespace before the colon is insignificant.  Each mutation below
    # must be rejected by the same unique-key contract as its plain spelling.
    for label, mutated, expected, source_key in (
        (
            "policy verifier quoted continue-on-error key",
            replace_in_step(
                CI,
                "build",
                "Verify assurance workflow policy",
                "      - name: Verify assurance workflow policy\n",
                "      - name: Verify assurance workflow policy\n"
                '        "continue-on-error" : true\n',
                "policy quoted continue",
            ),
            "policy verifier metadata is exact",
            "ci",
        ),
        (
            "C compiler quoted false condition",
            replace_in_step(
                CI,
                "cabi",
                "Compile shipped C examples",
                "      - name: Compile shipped C examples\n",
                "      - name: Compile shipped C examples\n"
                "        'if' : false\n",
                "C quoted if",
            ),
            "C example metadata is exact",
            "ci",
        ),
        (
            "GmSSL suite quoted continue-on-error key",
            replace_in_step(
                CI,
                "interop-gmssl",
                "gmssl interop suite (13 tests)",
                "      - name: gmssl interop suite (13 tests)\n",
                "      - name: gmssl interop suite (13 tests)\n"
                '        "continue-on-error" : true\n',
                "GmSSL quoted continue",
            ),
            "GmSSL suite metadata is exact",
            "ci",
        ),
        (
            "PR dudect parser quoted false condition",
            replace_in_step(
                DUDECT_PR,
                "smoke",
                "Parse and gate",
                "      - name: Parse and gate\n",
                "      - name: Parse and gate\n        'if' : false\n",
                "PR parser quoted if",
            ),
            "PR dudect parse metadata is exact",
            "dudect_pr",
        ),
        (
            "gitleaks scanner quoted continue-on-error key",
            replace_in_step(
                GITLEAKS,
                "scan",
                "Scan committed history",
                "      - name: Scan committed history\n",
                "      - name: Scan committed history\n"
                '        "continue-on-error" : true\n',
                "gitleaks quoted continue",
            ),
            "gitleaks scan metadata is exact",
            "gitleaks",
        ),
    ):
        must_reject(label, expected, **{source_key: mutated})

    # Duplicate first/last values exercise unique-key enforcement instead of
    # relying on whichever duplicate the old first-match regex happened to see.
    must_reject(
        "gitleaks fetch depth has a malicious trailing duplicate",
        "gitleaks checkout metadata is exact",
        gitleaks=replace_once(
            GITLEAKS,
            "          fetch-depth: 0\n",
            "          fetch-depth: 0\n          fetch-depth: 1\n",
            "duplicate fetch depth",
        ),
    )
    must_reject(
        "gitleaks push branches have a malicious trailing duplicate",
        "gitleaks triggers are exact",
        gitleaks=replace_once(
            GITLEAKS,
            "  push:\n    branches: [main]\n",
            "  push:\n    branches: [main]\n    branches: [develop]\n",
            "duplicate push branches",
        ),
    )
    must_reject(
        "GmSSL suite id has a malicious trailing duplicate",
        "GmSSL step ids are exact",
        ci=replace_in_step(
            CI,
            "interop-gmssl",
            "gmssl interop suite (13 tests)",
            "        id: gmssl-suite\n",
            "        id: gmssl-suite\n        id: bypass-suite\n",
            "duplicate suite id",
        ),
    )
    must_reject(
        "GmSSL report condition has a malicious trailing duplicate",
        "GmSSL report metadata is exact",
        ci=replace_in_step(
            CI,
            "interop-gmssl",
            "Report GmSSL interoperability status",
            "        if: ${{ always() }}\n",
            "        if: ${{ always() }}\n        if: false\n",
            "duplicate report if",
        ),
    )
    must_reject(
        "GmSSL job name has a malicious trailing duplicate",
        "GmSSL job contract is exact",
        ci=replace_in_job(
            CI,
            "interop-gmssl",
            "    name: gmssl interop (mismatch gates; infra non-blocking)\n",
            "    name: gmssl interop (mismatch gates; infra non-blocking)\n"
            "    name: misleading-success\n",
            "duplicate GmSSL job name",
        ),
    )

    skip_if = (
        "    if: >-\n"
        "      !contains(github.event.pull_request.title, '[skip ci]') &&\n"
        "      !contains(github.event.pull_request.title, '[ci skip]') &&\n"
        "      !contains(github.event.pull_request.title, '[no ci]') &&\n"
        "      !contains(github.event.pull_request.title, '[skip actions]') &&\n"
        "      !contains(github.event.head_commit.message, '[skip ci]') &&\n"
        "      !contains(github.event.head_commit.message, '[ci skip]') &&\n"
        "      !contains(github.event.head_commit.message, '[no ci]') &&\n"
        "      !contains(github.event.head_commit.message, '[skip actions]')\n"
    )
    must_reject(
        "build job is forced off",
        "build job contract is exact",
        ci=replace_in_job(CI, "build", skip_if, "    if: ${{ false }}\n", "build never-if"),
    )
    must_reject(
        "build job gains a duplicate false condition",
        "build job contract is exact",
        ci=replace_in_job(
            CI,
            "build",
            skip_if,
            skip_if + "    'if' : false\n",
            "build duplicate if",
        ),
    )
    must_reject(
        "nightly dudect job is forced off",
        "nightly dudect job contract is exact",
        dudect_nightly=replace_in_job(
            DUDECT_NIGHTLY,
            "full",
            "  full:\n",
            "  full:\n    if: false\n",
            "nightly never-if",
        ),
    )
    must_reject(
        "workflow defaults wrap assurance commands",
        "workflow defaults cannot alter assurance commands",
        ci=replace_once(
            CI,
            "permissions:\n",
            "defaults:\n  run:\n    shell: bash {0} || true\n\npermissions:\n",
            "workflow defaults shell",
        ),
    )
    must_reject(
        "build job defaults wrap assurance commands",
        "build job contract is exact",
        ci=replace_in_job(
            CI,
            "build",
            "  build:\n",
            "  build:\n    defaults:\n      run:\n        shell: bash {0} || true\n",
            "build defaults shell",
        ),
    )
    must_reject(
        "build job gains unexpected environment",
        "build job contract is exact",
        ci=replace_in_job(
            CI,
            "build",
            "  build:\n",
            "  build:\n    env:\n      PYTHONOPTIMIZE: '1'\n",
            "build job env",
        ),
    )
    must_reject(
        "interop cache epoch drifts",
        "GmSSL job contract is exact",
        ci=replace_in_job(
            CI,
            "interop-gmssl",
            "      GMSSL_CACHE_EPOCH: '1'\n",
            "      GMSSL_CACHE_EPOCH: '0'\n",
            "GmSSL cache epoch",
        ),
    )

    full_features = '          - "sm4-bitsliced-simd,sm4-aead,sm4-xts,sm2-key-exchange,tlcp"\n'
    for workflow_name, source, source_key, job_name, producer_name, runs, samples in (
        (
            "PR",
            DUDECT_PR,
            "dudect_pr",
            "smoke",
            "Run dudect harness (smoke budget, 3 runs for median)",
            "3",
            "10000",
        ),
        (
            "nightly",
            DUDECT_NIGHTLY,
            "dudect_nightly",
            "full",
            "Run dudect harness (nightly budget, 5 runs for median)",
            "5",
            "100000",
        ),
    ):
        must_reject(
            f"{workflow_name} dudect producer runs only once",
            f"{workflow_name} dudect producer contract is exact",
            **{
                source_key: replace_in_step(
                    source,
                    job_name,
                    producer_name,
                    f'          DUDECT_RUNS: "{runs}"\n',
                    '          DUDECT_RUNS: "1"\n',
                    f"{workflow_name} producer runs",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect producer exits before the loop",
            f"{workflow_name} dudect producer script is exact",
            **{
                source_key: replace_in_step(
                    source,
                    job_name,
                    producer_name,
                    "        run: |\n",
                    "        run: |\n          exit 0\n",
                    f"{workflow_name} producer early exit",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect producer gains quoted tolerance",
            f"{workflow_name} dudect producer metadata is exact",
            **{
                source_key: replace_in_step(
                    source,
                    job_name,
                    producer_name,
                    f"      - name: {producer_name}\n",
                    f"      - name: {producer_name}\n"
                    "        'continue-on-error' : true\n",
                    f"{workflow_name} producer quoted continue",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect producer gains custom shell",
            f"{workflow_name} dudect producer metadata is exact",
            **{
                source_key: replace_in_step(
                    source,
                    job_name,
                    producer_name,
                    f"      - name: {producer_name}\n",
                    f"      - name: {producer_name}\n        shell: bash {{0}} || true\n",
                    f"{workflow_name} producer custom shell",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect full feature leg is removed",
            f"{workflow_name} dudect matrix is exact",
            **{
                source_key: replace_once(
                    source,
                    full_features,
                    "",
                    f"{workflow_name} full feature leg",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect full feature leg is replaced",
            f"{workflow_name} dudect matrix is exact",
            **{
                source_key: replace_once(
                    source,
                    full_features,
                    '          - "sm4-bitsliced-simd"\n',
                    f"{workflow_name} replaced full feature leg",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect sample budget drifts",
            f"{workflow_name} dudect producer contract is exact",
            **{
                source_key: replace_in_step(
                    source,
                    job_name,
                    producer_name,
                    f'          DUDECT_SAMPLES: "{samples}"\n',
                    '          DUDECT_SAMPLES: "1"\n',
                    f"{workflow_name} producer samples",
                )
            },
        )

    must_reject(
        "PR dudect runner drifts",
        "PR dudect job contract is exact",
        dudect_pr=replace_in_job(
            DUDECT_PR,
            "smoke",
            "    runs-on: ubuntu-24.04\n",
            "    runs-on: ubuntu-latest\n",
            "PR runner",
        ),
    )
    must_reject(
        "nightly dudect timeout shrinks",
        "nightly dudect job contract is exact",
        dudect_nightly=replace_in_job(
            DUDECT_NIGHTLY,
            "full",
            "    timeout-minutes: 40\n",
            "    timeout-minutes: 4\n",
            "nightly timeout",
        ),
    )
    must_reject(
        "PR dudect toolchain drifts",
        "PR dudect step sequence is exact",
        dudect_pr=replace_in_job(
            DUDECT_PR,
            "smoke",
            "      - uses: dtolnay/rust-toolchain@1.95.0\n",
            "      - uses: dtolnay/rust-toolchain@stable\n",
            "PR toolchain",
        ),
    )

    must_reject(
        "gitleaks gains a second checkout",
        "gitleaks step sequence is exact",
        gitleaks=replace_once(
            GITLEAKS,
            "      - name: Install gitleaks\n",
            "      - uses: actions/checkout@v7\n      - name: Install gitleaks\n",
            "gitleaks second checkout",
        ),
    )
    must_reject(
        "PR dudect inserts checkout before parse",
        "PR dudect step sequence is exact",
        dudect_pr=replace_once(
            DUDECT_PR,
            "      - name: Parse and gate\n",
            "      - uses: actions/checkout@v7\n      - name: Parse and gate\n",
            "PR second checkout",
        ),
    )
    must_reject(
        "interop gains a second checkout",
        "GmSSL step sequence is exact",
        ci=replace_in_job(
            CI,
            "interop-gmssl",
            "      - uses: dtolnay/rust-toolchain@stable\n",
            "      - uses: actions/checkout@v7\n"
            "      - uses: dtolnay/rust-toolchain@stable\n",
            "interop second checkout",
        ),
    )
    must_reject(
        "cabi gains a second checkout",
        "cabi step sequence is exact",
        ci=replace_in_job(
            CI,
            "cabi",
            "      - uses: dtolnay/rust-toolchain@stable\n",
            "      - uses: actions/checkout@v7\n"
            "      - uses: dtolnay/rust-toolchain@stable\n",
            "cabi second checkout",
        ),
    )
    must_reject(
        "build inserts a step before checkout",
        "build step prefix is exact",
        ci=replace_in_job(
            CI,
            "build",
            "      - uses: actions/checkout@v7\n",
            "      - name: Tamper environment\n        run: 'true'\n"
            "      - uses: actions/checkout@v7\n",
            "build first step",
        ),
    )

    must_reject(
        "gitleaks trigger gains quoted path exclusions",
        "gitleaks triggers are exact",
        gitleaks=replace_once(
            GITLEAKS,
            "    branches: [main]\n  workflow_dispatch:\n",
            "    branches: [main]\n    'paths-ignore' : ['docs/**']\n  workflow_dispatch:\n",
            "quoted paths-ignore",
        ),
    )

    version_step = step_named(interop, "Assert oracle version (drift guard)")
    must_reject(
        "GmSSL version assertion becomes a no-op",
        "GmSSL version script matches reviewed canonical execution",
        ci=replace_once(
            CI,
            version_step,
            "      - name: Assert oracle version (drift guard)\n"
            "        id: gmssl-version\n"
            "        if: steps.gmssl-provision.outcome == 'success'\n"
            "        continue-on-error: true\n"
            "        shell: bash\n"
            "        run: 'true'",
            "GmSSL version step",
        ),
    )
    must_reject(
        "GmSSL report hard-codes suite success",
        "GmSSL report metadata is exact",
        ci=replace_in_step(
            CI,
            "interop-gmssl",
            "Report GmSSL interoperability status",
            "          SUITE_OUTCOME: ${{ steps.gmssl-suite.outcome }}\n",
            "          SUITE_OUTCOME: success\n",
            "GmSSL report outcome",
        ),
    )
    must_reject(
        "GmSSL report failure is tolerated",
        "GmSSL report metadata is exact",
        ci=replace_in_step(
            CI,
            "interop-gmssl",
            "Report GmSSL interoperability status",
            "      - name: Report GmSSL interoperability status\n",
            "      - name: Report GmSSL interoperability status\n"
            "        continue-on-error: true\n",
            "GmSSL report continue",
        ),
    )
    must_reject(
        "GmSSL report gains a custom shell",
        "GmSSL report metadata is exact",
        ci=replace_in_step(
            CI,
            "interop-gmssl",
            "Report GmSSL interoperability status",
            "      - name: Report GmSSL interoperability status\n",
            "      - name: Report GmSSL interoperability status\n"
            "        shell: bash {0} || true\n",
            "GmSSL report shell",
        ),
    )
    must_reject(
        "GmSSL report is forced off",
        "GmSSL report metadata is exact",
        ci=replace_in_step(
            CI,
            "interop-gmssl",
            "Report GmSSL interoperability status",
            "        if: ${{ always() }}\n",
            "        if: false\n",
            "GmSSL report if false",
        ),
    )

    # YAML double-quoted keys decode Unicode escapes before key comparison.
    # These are valid spellings of already-protected keys, not new metadata.
    for label, expected, source_key, mutated in (
        (
            "policy verifier Unicode-escaped continue-on-error key",
            "policy verifier metadata is exact",
            "ci",
            replace_in_step(
                CI,
                "build",
                "Verify assurance workflow policy",
                "      - name: Verify assurance workflow policy\n",
                "      - name: Verify assurance workflow policy\n"
                '        "continue\\u002don\\u002derror" : true\n',
                "policy Unicode continue",
            ),
        ),
        (
            "C compiler Unicode-escaped false condition",
            "C example metadata is exact",
            "ci",
            replace_in_step(
                CI,
                "cabi",
                "Compile shipped C examples",
                "      - name: Compile shipped C examples\n",
                "      - name: Compile shipped C examples\n"
                '        "i\\u0066" : false\n',
                "C Unicode if",
            ),
        ),
        (
            "workflow Unicode-escaped defaults key",
            "workflow defaults cannot alter assurance commands",
            "ci",
            replace_once(
                CI,
                "permissions:\n",
                '"de\\u0066aults" :\n'
                "  run:\n"
                "    shell: bash {0} || true\n\n"
                "permissions:\n",
                "Unicode workflow defaults",
            ),
        ),
        (
            "gitleaks Unicode-escaped path exclusions",
            "gitleaks triggers are exact",
            "gitleaks",
            replace_once(
                GITLEAKS,
                "    branches: [main]\n  workflow_dispatch:\n",
                "    branches: [main]\n"
                '    "paths\\u002dignore" : [\'docs/**\']\n'
                "  workflow_dispatch:\n",
                "Unicode paths-ignore",
            ),
        ),
    ):
        must_reject(label, expected, **{source_key: mutated})

    must_reject(
        "gitleaks checkout pins an attacker-controlled ref",
        "gitleaks checkout step is exact",
        gitleaks=replace_in_uses(
            GITLEAKS,
            "scan",
            "actions/checkout@v7",
            "          fetch-depth: 0",
            "          fetch-depth: 0\n          ref: refs/heads/unreviewed",
            "gitleaks checkout ref",
        ),
    )
    must_reject(
        "gitleaks checkout gains an extra with input",
        "gitleaks checkout step is exact",
        gitleaks=replace_in_uses(
            GITLEAKS,
            "scan",
            "actions/checkout@v7",
            "          fetch-depth: 0",
            "          fetch-depth: 0\n          persist-credentials: false",
            "gitleaks checkout extra input",
        ),
    )
    must_reject(
        "gitleaks checkout gains a quoted duplicate uses key",
        "gitleaks checkout step is exact",
        gitleaks=replace_in_uses(
            GITLEAKS,
            "scan",
            "actions/checkout@v7",
            "      - uses: actions/checkout@v7\n",
            "      - uses: actions/checkout@v7\n"
            '        "uses" : attacker/checkout@v1\n',
            "gitleaks quoted uses",
        ),
    )
    must_reject(
        "gitleaks checkout gains a Unicode-escaped duplicate uses key",
        "gitleaks checkout step is exact",
        gitleaks=replace_in_uses(
            GITLEAKS,
            "scan",
            "actions/checkout@v7",
            "      - uses: actions/checkout@v7\n",
            "      - uses: actions/checkout@v7\n"
            '        "u\\u0073es" : attacker/checkout@v1\n',
            "gitleaks Unicode uses",
        ),
    )
    for workflow_name, source, source_key, job_name in (
        ("PR", DUDECT_PR, "dudect_pr", "smoke"),
        ("nightly", DUDECT_NIGHTLY, "dudect_nightly", "full"),
    ):
        must_reject(
            f"{workflow_name} dudect checkout pins an unreviewed ref",
            f"{workflow_name} dudect checkout step is exact",
            **{
                source_key: replace_in_uses(
                    source,
                    job_name,
                    "actions/checkout@v7",
                    "      - uses: actions/checkout@v7\n",
                    "      - uses: actions/checkout@v7\n"
                    "        with:\n"
                    "          ref: refs/heads/unreviewed\n",
                    f"{workflow_name} checkout ref",
                )
            },
        )
        must_reject(
            f"{workflow_name} dudect Rust toolchain is skipped",
            f"{workflow_name} dudect rust toolchain metadata is exact",
            **{
                source_key: replace_in_uses(
                    source,
                    job_name,
                    "dtolnay/rust-toolchain@1.95.0",
                    "      - uses: dtolnay/rust-toolchain@1.95.0",
                    "      - uses: dtolnay/rust-toolchain@1.95.0\n"
                    "        if: false",
                    f"{workflow_name} toolchain if false",
                )
            },
        )

    duplicate_jobs = (
        (
            "build job has a quoted trailing duplicate",
            "build job key is unique",
            "ci",
            replace_once(
                CI,
                "\n  msrv:\n",
                "\n  \"build\" :\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: 'true'\n"
                "\n  msrv:\n",
                "duplicate build job",
            ),
        ),
        (
            "C ABI job has a trailing duplicate",
            "cabi job key is unique",
            "ci",
            replace_once(
                CI,
                "\n  deny:\n",
                "\n  cabi:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: 'true'\n"
                "\n  deny:\n",
                "duplicate cabi job",
            ),
        ),
        (
            "GmSSL job has a Unicode-escaped trailing duplicate",
            "GmSSL job key is unique",
            "ci",
            replace_once(
                CI,
                "\n  cabi:\n",
                '\n  "interop\\u002dgmssl" :\n'
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: 'true'\n"
                "\n  cabi:\n",
                "duplicate GmSSL job",
            ),
        ),
        (
            "gitleaks job has a quoted trailing duplicate",
            "gitleaks job key is unique",
            "gitleaks",
            replace_once(
                GITLEAKS,
                "        run: gitleaks git --no-banner --redact --verbose\n",
                "        run: gitleaks git --no-banner --redact --verbose\n"
                "\n  'scan' :\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: 'true'\n",
                "duplicate gitleaks job",
            ),
        ),
        (
            "PR dudect job has a Unicode-escaped trailing duplicate",
            "PR dudect job key is unique",
            "dudect_pr",
            replace_once(
                DUDECT_PR,
                "          retention-days: 7\n",
                "          retention-days: 7\n"
                '\n  "sm\\u006fke" :\n'
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: 'true'\n",
                "duplicate PR dudect job",
            ),
        ),
        (
            "nightly dudect job has a trailing duplicate",
            "nightly dudect job key is unique",
            "dudect_nightly",
            replace_once(
                DUDECT_NIGHTLY,
                "          retention-days: 30\n",
                "          retention-days: 30\n"
                "\n  full:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: 'true'\n",
                "duplicate nightly dudect job",
            ),
        ),
    )
    for label, expected, source_key, mutated in duplicate_jobs:
        must_reject(label, expected, **{source_key: mutated})

    must_reject(
        "build hides a dash-alone step before checkout",
        "build step prefix is exact",
        ci=replace_in_job(
            CI,
            "build",
            "      - uses: actions/checkout@v7\n",
            "      -\n"
            "        name: Hidden environment tamper\n"
            "        run: 'true'\n"
            "      - uses: actions/checkout@v7\n",
            "build dash-alone step",
        ),
    )
    must_reject(
        "build hides a dash-alone step after the policy verifier",
        "build has no dash-alone steps",
        ci=replace_in_job(
            CI,
            "build",
            "      - name: Install Rust stable\n",
            "      -\n"
            "        name: Hidden post-policy environment tamper\n"
            "        run: 'true'\n"
            "      - name: Install Rust stable\n",
            "build post-policy dash-alone step",
        ),
    )
    must_reject(
        "gitleaks hides a dash-alone step before install",
        "gitleaks step sequence is exact",
        gitleaks=replace_in_job(
            GITLEAKS,
            "scan",
            "      - name: Install gitleaks\n",
            "      -\n"
            "        name: Hidden environment tamper\n"
            "        run: 'true'\n"
            "      - name: Install gitleaks\n",
            "gitleaks dash-alone step",
        ),
    )
    must_reject(
        "PR dudect hides an environment writer before the producer",
        "PR dudect step sequence is exact",
        dudect_pr=replace_in_job(
            DUDECT_PR,
            "smoke",
            "      - name: Run dudect harness (smoke budget, 3 runs for median)\n",
            "      -\n"
            "        name: Hidden environment tamper\n"
            "        run: echo 'BASH_ENV=/tmp/bypass' >> \"$GITHUB_ENV\"\n"
            "      - name: Run dudect harness (smoke budget, 3 runs for median)\n",
            "PR dudect dash-alone environment step",
        ),
    )

    must_reject(
        "PR dudect workflow injects BASH_ENV",
        "PR dudect workflow environment is exact",
        dudect_pr=replace_once(
            DUDECT_PR,
            "  CARGO_TERM_COLOR: always\n",
            "  CARGO_TERM_COLOR: always\n  BASH_ENV: /tmp/bypass\n",
            "PR workflow BASH_ENV",
        ),
    )
    for workflow_name, source, source_key, job_name in (
        ("PR", DUDECT_PR, "dudect_pr", "smoke"),
        ("nightly", DUDECT_NIGHTLY, "dudect_nightly", "full"),
    ):
        capture_name = "Capture runner environment (for noise-floor correlation)"
        must_reject(
            f"{workflow_name} dudect capture persists BASH_ENV through GITHUB_ENV",
            f"{workflow_name} dudect capture script is exact",
            **{
                source_key: replace_in_step(
                    source,
                    job_name,
                    capture_name,
                    "        run: |\n",
                    "        run: |\n"
                    '          echo "BASH_ENV=$RUNNER_TEMP/bash-env" >> "$GITHUB_ENV"\n',
                    f"{workflow_name} capture environment write",
                )
            },
        )
    must_reject(
        "PR dudect cache step injects BASH_ENV metadata",
        "PR dudect rust cache step is exact",
        dudect_pr=replace_in_uses(
            DUDECT_PR,
            "smoke",
            "Swatinem/rust-cache@v2",
            "      - uses: Swatinem/rust-cache@v2\n",
            "      - uses: Swatinem/rust-cache@v2\n"
            "        env:\n"
            "          BASH_ENV: /tmp/bypass\n",
            "PR rust cache BASH_ENV",
        ),
    )

    for label, expected, job_name in (
        ("build checkout pins main", "build checkout step is exact", "build"),
        ("C ABI checkout pins main", "cabi checkout step is exact", "cabi"),
        ("GmSSL checkout pins main", "GmSSL checkout step is exact", "interop-gmssl"),
        ("cargo-deny checkout pins main", "cargo-deny checkout step is exact", "deny"),
    ):
        must_reject(
            label,
            expected,
            ci=replace_in_uses(
                CI,
                job_name,
                "actions/checkout@v7",
                "      - uses: actions/checkout@v7",
                "      - uses: actions/checkout@v7\n"
                "        with:\n"
                "          ref: main",
                f"{label} field",
            ),
        )

    for label, expected, job_name, injected in (
        (
            "build checkout gains quoted duplicate uses",
            "build checkout step is exact",
            "build",
            '        "uses" : attacker/checkout@v1\n',
        ),
        (
            "C ABI checkout gains Unicode-escaped duplicate uses",
            "cabi checkout step is exact",
            "cabi",
            '        "u\\u0073es" : attacker/checkout@v1\n',
        ),
        (
            "GmSSL checkout gains Unicode-escaped false condition",
            "GmSSL checkout step is exact",
            "interop-gmssl",
            '        "i\\u0066" : false\n',
        ),
        (
            "build checkout gains environment metadata",
            "build checkout step is exact",
            "build",
            "        env:\n          BASH_ENV: /tmp/bypass\n",
        ),
        (
            "C ABI checkout becomes tolerated",
            "cabi checkout step is exact",
            "cabi",
            "        continue-on-error: true\n",
        ),
    ):
        must_reject(
            label,
            expected,
            ci=replace_in_uses(
                CI,
                job_name,
                "actions/checkout@v7",
                "      - uses: actions/checkout@v7",
                "      - uses: actions/checkout@v7\n" + injected.rstrip(),
                f"{label} field",
            ),
        )

    must_reject(
        "cargo-deny job has a trailing duplicate",
        "cargo-deny job key is unique",
        ci=replace_once(
            CI,
            "\n  wasm32:\n",
            "\n  deny:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: 'true'\n"
            "\n  wasm32:\n",
            "duplicate cargo-deny job",
        ),
    )

    def add_job_field(
        text: str,
        job_name: str,
        field: str,
        label: str,
    ) -> str:
        target = job(text, job_name)
        runner = scalar(target, "runs-on", 4)
        if runner is None:
            failures.append(f"mutation could not identify runner: {label}")
            return text
        anchor = f"    runs-on: {runner}\n"
        return replace_in_job(
            text,
            job_name,
            anchor,
            anchor + field,
            label,
        )

    def add_skipped_dependency(text: str, job_name: str, label: str) -> str:
        mutated = add_job_field(
            text,
            job_name,
            "    needs: skip-assurance\n",
            f"{label} needs field",
        )
        if "\n  skip-assurance:" in mutated:
            failures.append(f"mutation helper job already existed: {label}")
            return mutated
        return (
            mutated.rstrip()
            + "\n\n"
            + "  skip-assurance:\n"
            + "    runs-on: ubuntu-latest\n"
            + "    if: false\n"
            + "    steps:\n"
            + "      - run: 'true'\n"
        )

    protected_job_cases = (
        ("build", "ci", CI, "build"),
        ("cabi", "ci", CI, "cabi"),
        ("GmSSL", "ci", CI, "interop-gmssl"),
        ("cargo-deny", "ci", CI, "deny"),
        ("gitleaks scan", "gitleaks", GITLEAKS, "scan"),
        ("PR dudect", "dudect_pr", DUDECT_PR, "smoke"),
        ("nightly dudect", "dudect_nightly", DUDECT_NIGHTLY, "full"),
    )
    for job_label, source_name, source, job_name in protected_job_cases:
        expected = f"{job_label} job top-level key sequence is exact"
        must_reject(
            f"{job_label} job gains a container",
            expected,
            **{
                source_name: add_job_field(
                    source,
                    job_name,
                    "    container: ghcr.io/example/fake-tools:latest\n",
                    f"{job_label} container",
                )
            },
        )
        must_reject(
            f"{job_label} job depends on a skipped helper",
            expected,
            **{
                source_name: add_skipped_dependency(
                    source,
                    job_name,
                    f"{job_label} skipped dependency",
                )
            },
        )

    for label, before, after in (
        (
            "cargo-deny job name is disguised",
            "    name: cargo-deny (no forbidden runtime deps)\n",
            "    name: dependency diagnostics\n",
        ),
        (
            "cargo-deny job runner changes",
            "    runs-on: macos-14\n",
            "    runs-on: ubuntu-latest\n",
        ),
        (
            "cargo-deny job timeout changes",
            "    timeout-minutes: 15\n",
            "    timeout-minutes: 1\n",
        ),
    ):
        must_reject(
            label,
            "cargo-deny job contract is exact",
            ci=replace_in_job(CI, "deny", before, after, label),
        )

    deny_job = job(CI, "deny")
    deny_install = step_named(deny_job, "Install cargo-deny")
    deny_shadow_step = (
        "      - name: Shadow cargo-deny\n"
        "        shell: bash\n"
        "        run: |\n"
        "          fake_dir=\"$RUNNER_TEMP/fake-deny\"\n"
        "          mkdir -p \"$fake_dir\"\n"
        "          printf '#!/usr/bin/env bash\\nexit 0\\n' > \"$fake_dir/cargo-deny\"\n"
        "          chmod +x \"$fake_dir/cargo-deny\"\n"
        "          echo \"$fake_dir\" >> \"$GITHUB_PATH\"\n"
    )
    shadowed_deny = replace_once(
        deny_job,
        deny_install,
        deny_install + "\n" + deny_shadow_step.rstrip(),
        "cargo-deny PATH shadow step",
    )
    must_reject(
        "cargo-deny is shadowed through GITHUB_PATH",
        "cargo-deny step sequence is exact",
        ci=replace_once(CI, deny_job, shadowed_deny, "shadowed cargo-deny job"),
    )

    for label, step_name, injected, expected in (
        (
            "cargo-deny installer is skipped",
            "Install cargo-deny",
            "        if: false\n",
            "cargo-deny install step is exact",
        ),
        (
            "cargo-deny lockfile step is skipped",
            "Generate lockfile",
            "        if: false\n",
            "cargo-deny lockfile step is exact",
        ),
        (
            "cargo-deny default command is tolerated",
            "Run cargo-deny (default features, excluding dev-deps)",
            "        continue-on-error: true\n",
            "cargo-deny default command step is exact",
        ),
        (
            "cargo-deny runtime command uses a custom shell",
            "Run cargo-deny (runtime opt-in features, excluding dev-deps)",
            "        shell: sh\n",
            "cargo-deny runtime command step is exact",
        ),
    ):
        must_reject(
            label,
            expected,
            ci=replace_in_step(
                CI,
                "deny",
                step_name,
                f"      - name: {step_name}\n",
                f"      - name: {step_name}\n" + injected,
                label,
            ),
        )

    must_reject(
        "cargo-deny toolchain action gains environment metadata",
        "cargo-deny toolchain step is exact",
        ci=replace_in_uses(
            CI,
            "deny",
            "dtolnay/rust-toolchain@stable",
            "      - uses: dtolnay/rust-toolchain@stable",
            "      - uses: dtolnay/rust-toolchain@stable\n"
            "        env:\n"
            "          BASH_ENV: /tmp/fake-deny",
            "cargo-deny toolchain environment",
        ),
    )

    must_reject(
        "CI workflow gains a BASH_ENV function-injection path",
        "CI workflow environment is exact",
        ci=replace_once(
            CI,
            "env:\n  CARGO_TERM_COLOR: always\n",
            "env:\n"
            "  BASH_ENV: .github/scripts/fake-build-env\n"
            "  CARGO_TERM_COLOR: always\n",
            "CI workflow BASH_ENV",
        ),
    )
    must_reject(
        "gitleaks workflow gains a BASH_ENV fake-function path",
        "gitleaks workflow has no top-level environment",
        gitleaks=replace_once(
            GITLEAKS,
            "permissions:\n  contents: read\n\nconcurrency:\n",
            "permissions:\n"
            "  contents: read\n"
            "\n"
            "env:\n"
            "  BASH_ENV: .github/scripts/fake-gitleaks-env\n"
            "\n"
            "concurrency:\n",
            "gitleaks workflow BASH_ENV",
        ),
    )

    build_job = job(CI, "build")
    policy_step = step_named(build_job, "Verify assurance workflow policy")
    cargo_shadow_step = (
        "      - name: Shadow cargo after policy verification\n"
        "        shell: bash\n"
        "        run: |\n"
        "          fake_dir=\"$RUNNER_TEMP/fake-cargo\"\n"
        "          mkdir -p \"$fake_dir\"\n"
        "          printf '#!/usr/bin/env bash\\nexit 0\\n' > \"$fake_dir/cargo\"\n"
        "          chmod +x \"$fake_dir/cargo\"\n"
        "          echo \"$fake_dir\" >> \"$GITHUB_PATH\"\n"
    )
    shadowed_build = replace_once(
        build_job,
        policy_step,
        policy_step + "\n" + cargo_shadow_step.rstrip(),
        "build cargo PATH shadow step",
    )
    build_fingerprint_label = "build job reviewed source fingerprint matches"
    must_reject(
        "build job shadows cargo through GITHUB_PATH after policy verification",
        build_fingerprint_label,
        ci=replace_once(CI, build_job, shadowed_build, "shadowed build job"),
    )
    must_reject(
        "build job replaces workspace tests with success",
        build_fingerprint_label,
        ci=replace_in_step(
            CI,
            "build",
            "cargo test (tests + doctests; benches excluded — see dudect-pr.yml)",
            "        run: cargo test --workspace\n",
            "        run: 'true'\n",
            "build workspace test command",
        ),
    )
    must_reject(
        "build job replaces the Rust toolchain action",
        build_fingerprint_label,
        ci=replace_in_step(
            CI,
            "build",
            "Install Rust stable",
            "        uses: dtolnay/rust-toolchain@stable\n",
            "        uses: attacker/rust-toolchain@v1\n",
            "build toolchain action",
        ),
    )
    must_reject(
        "build job drops the clippy toolchain input",
        build_fingerprint_label,
        ci=replace_in_step(
            CI,
            "build",
            "Install Rust stable",
            "          components: rustfmt, clippy",
            "          components: rustfmt",
            "build toolchain input",
        ),
    )
    must_reject(
        "build cache action gains unreviewed metadata",
        build_fingerprint_label,
        ci=replace_in_step(
            CI,
            "build",
            "Cache cargo",
            "        uses: Swatinem/rust-cache@v2",
            "        uses: Swatinem/rust-cache@v2\n"
            "        with:\n"
            "          key: attacker-controlled",
            "build cache metadata",
        ),
    )

    for step_name, command in (
        (
            "cargo build -p gmcrypto-c --release",
            "cargo build -p gmcrypto-c --release",
        ),
        (
            "Regenerate header via cbindgen",
            "cargo build -p gmcrypto-c --features regen-header",
        ),
        (
            "Verify committed header is up-to-date",
            "git diff --exit-code crates/gmcrypto-c/include/gmcrypto.h",
        ),
        ("cargo test -p gmcrypto-c", "cargo test -p gmcrypto-c"),
    ):
        must_reject(
            f"cabi replaces {step_name} with success",
            "cabi job reviewed source fingerprint matches",
            ci=replace_in_step(
                CI,
                "cabi",
                step_name,
                f"        run: {command}",
                "        run: 'true'",
                f"cabi {step_name} command",
            ),
        )

    must_reject(
        "GmSSL cargo cache uses an unreviewed action",
        "GmSSL job reviewed source fingerprint matches",
        ci=replace_in_step(
            CI,
            "interop-gmssl",
            "Cache cargo",
            "        uses: Swatinem/rust-cache@v2\n",
            "        uses: attacker/rust-cache@v1\n",
            "GmSSL cargo cache action",
        ),
    )
    must_reject(
        "GmSSL oracle cache uses an unreviewed action",
        "GmSSL job reviewed source fingerprint matches",
        ci=replace_in_step(
            CI,
            "interop-gmssl",
            "Cache GmSSL install prefix",
            "        uses: actions/cache@v6\n",
            "        uses: attacker/cache@v1\n",
            "GmSSL oracle cache action",
        ),
    )
    must_reject(
        "GmSSL oracle cache path drifts",
        "GmSSL job reviewed source fingerprint matches",
        ci=replace_in_step(
            CI,
            "interop-gmssl",
            "Cache GmSSL install prefix",
            "          path: ~/gmssl-${{ env.GMSSL_TAG }}\n",
            "          path: /tmp/fake-gmssl\n",
            "GmSSL oracle cache path",
        ),
    )

    must_reject(
        "gitleaks scan job name drifts",
        "gitleaks scan job reviewed source fingerprint matches",
        gitleaks=replace_in_job(
            GITLEAKS,
            "scan",
            "    name: gitleaks (committed history)\n",
            "    name: secret diagnostics\n",
            "gitleaks scan job name",
        ),
    )
    must_reject(
        "cargo-deny lockfile command gains an inline source suffix",
        "cargo-deny job reviewed source fingerprint matches",
        ci=replace_in_step(
            CI,
            "deny",
            "Generate lockfile",
            "        run: cargo generate-lockfile",
            "        run: cargo generate-lockfile # reviewed-source drift",
            "cargo-deny lockfile inline source",
        ),
    )
    must_reject(
        "PR dudect upload uses an unreviewed action",
        "PR dudect job reviewed source fingerprint matches",
        dudect_pr=replace_in_step(
            DUDECT_PR,
            "smoke",
            "Upload raw log",
            "        uses: actions/upload-artifact@v7\n",
            "        uses: attacker/upload-artifact@v1\n",
            "PR dudect upload action",
        ),
    )
    must_reject(
        "nightly dudect upload retention drifts",
        "nightly dudect job reviewed source fingerprint matches",
        dudect_nightly=replace_in_step(
            DUDECT_NIGHTLY,
            "full",
            "Upload raw log",
            "          retention-days: 30",
            "          retention-days: 1",
            "nightly dudect upload retention",
        ),
    )

    parser_preflight_label = "CI workflow uses canonical YAML mapping-key syntax"
    for label, injected in (
        (
            "GmSSL suite gains an explicit plain tolerance key",
            "        ? continue-on-error\n        : true\n",
        ),
        (
            "GmSSL suite gains an explicit Unicode-escaped tolerance key",
            '        ? "continue-on-\\u0065rror"\n        : true\n',
        ),
        (
            "GmSSL suite gains an explicit double-quoted tolerance key",
            '        ? "continue-on-error"\n        : true\n',
        ),
        (
            "GmSSL suite gains an explicit single-quoted tolerance key",
            "        ? 'continue-on-error'\n        : true\n",
        ),
        (
            "GmSSL suite gains an explicit block-scalar tolerance key",
            "        ? |-\n          continue-on-error\n        : true\n",
        ),
        (
            "GmSSL suite gains a short-tagged tolerance key",
            "        !!str continue-on-error: true\n",
        ),
        (
            "GmSSL suite gains a URI-tagged tolerance key",
            "        !<tag:yaml.org,2002:str> continue-on-error: true\n",
        ),
        (
            "GmSSL suite gains a continued double-quoted tolerance key",
            '        "continue-on-\\\n          error" : true\n',
        ),
    ):
        must_reject(
            label,
            parser_preflight_label,
            ci=replace_in_step(
                CI,
                "interop-gmssl",
                "gmssl interop suite (13 tests)",
                "        id: gmssl-suite\n",
                injected + "        id: gmssl-suite\n",
                label,
            ),
        )

    tolerate_anchor = replace_once(
        CI,
        "env:\n  CARGO_TERM_COLOR: always\n",
        "env:\n"
        '  &tolerate continue-on-error: "marker"\n'
        "  CARGO_TERM_COLOR: always\n",
        "GmSSL suite alias tolerance anchor",
    )
    must_reject(
        "GmSSL suite gains an alias tolerance key",
        parser_preflight_label,
        ci=replace_in_step(
            tolerate_anchor,
            "interop-gmssl",
            "gmssl interop suite (13 tests)",
            "        id: gmssl-suite\n",
            "        *tolerate: true\n        id: gmssl-suite\n",
            "GmSSL suite alias tolerance",
        ),
    )

    skip_anchor = replace_once(
        CI,
        "env:\n  CARGO_TERM_COLOR: always\n",
        "env:\n  &skipkey if: marker\n  CARGO_TERM_COLOR: always\n",
        "policy verifier alias condition anchor",
    )
    must_reject(
        "policy verifier gains an alias false condition",
        parser_preflight_label,
        ci=replace_in_step(
            skip_anchor,
            "build",
            "Verify assurance workflow policy",
            "        shell: bash\n",
            "        *skipkey: ${{ false }}\n        shell: bash\n",
            "policy verifier alias condition",
        ),
    )

    must_reject(
        "build job gains a tagged tolerance key",
        parser_preflight_label,
        ci=replace_in_job(
            CI,
            "build",
            "    timeout-minutes: 30\n",
            "    !!str continue-on-error: true\n    timeout-minutes: 30\n",
            "build tagged tolerance",
        ),
    )

    must_reject(
        "gitleaks trigger gains an explicit quoted path exclusion",
        "gitleaks workflow uses canonical YAML mapping-key syntax",
        gitleaks=replace_once(
            GITLEAKS,
            "  pull_request:\n    branches: [main]\n",
            "  pull_request:\n"
            "    branches: [main]\n"
            '    ? "paths\\u002dignore"\n'
            "    :\n"
            "      - '**'\n",
            "gitleaks explicit quoted path exclusion",
        ),
    )

    must_reject(
        "gitleaks scan gains an alias tolerance key",
        "gitleaks workflow uses canonical YAML mapping-key syntax",
        gitleaks=replace_once(
            replace_once(
                GITLEAKS,
                "permissions:\n  contents: read\n",
                "permissions:\n"
                "  contents: read\n"
                "  &tolerate continue-on-error: marker\n",
                "gitleaks alias tolerance anchor",
            ),
            "      - name: Scan committed history\n",
            "      - name: Scan committed history\n        *tolerate: true\n",
            "gitleaks alias tolerance key",
        ),
    )

    must_reject(
        "PR dudect producer gains a tagged tolerance key",
        "PR dudect workflow uses canonical YAML mapping-key syntax",
        dudect_pr=replace_in_step(
            DUDECT_PR,
            "smoke",
            "Run dudect harness (smoke budget, 3 runs for median)",
            "        shell: bash\n",
            "        !!str continue-on-error: true\n        shell: bash\n",
            "PR dudect tagged producer tolerance",
        ),
    )

    must_reject(
        "nightly dudect parser gains an explicit quoted tolerance key",
        "nightly dudect workflow uses canonical YAML mapping-key syntax",
        dudect_nightly=replace_in_step(
            DUDECT_NIGHTLY,
            "full",
            "Parse and gate",
            "        shell: bash\n",
            "        ? 'continue-on-error'\n"
            "        : true\n"
            "        shell: bash\n",
            "nightly dudect explicit parser tolerance",
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
