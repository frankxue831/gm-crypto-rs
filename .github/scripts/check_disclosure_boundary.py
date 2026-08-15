#!/usr/bin/env python3
"""Disclosure-boundary scanner for gm-crypto-rs.

`gitleaks` answers "is there a CREDENTIAL in this repository?". This answers a
different and complementary question: "is there information here that is not a
credential, but that a public repository has no reason to carry?" — a home
directory, an OS account name, a machine hostname, a private host address, the
internals of a private sibling repository, or the scaffolding of the
maintainer's local tooling.

Nothing this script finds needs rotating. That is exactly why gitleaks does not
find it, and why it went unnoticed until a manual sweep on 2026-08-15 turned up
an absolute path into a local agent-plugin cache in `docs/`. See
`docs/disclosure-boundary.md` for the policy this file implements; the policy is
the "why", this file is the enforceable "what".

## Severities

  P1 (blocking)  — never belongs in a public repository. Fails CI.
  P2 (advisory)  — needs a recorded human decision, not an automatic verdict.
                   Reported to the job summary; does NOT fail CI unless
                   --strict is passed.

The split is deliberate and follows the dudect gate's existing posture in this
repo: a required threshold for what is unambiguous, telemetry for what needs
calibration before it can be trusted to gate. A P2 that turns out to be
intentional is resolved by adding a scoped allowlist entry with a reason —
never by deleting the rule.

## Modes

  --worktree        every tracked file at HEAD (the default; the enforced gate)
  --range A..B      lines ADDED by each commit in the range, scanned commit by
                    commit rather than as one squashed diff. A leak introduced
                    in one commit and removed in the next is invisible to a
                    net-diff scan but is permanent in public history — and this
                    repository has real instances of exactly that (`/Users/…`
                    survives in the history of three v0.x scope docs whose
                    working-tree copies are clean).
  --history         every blob reachable from every ref. The audit tool, not a
                    CI mode: history cannot be fixed without a rewrite, so
                    findings here are triaged into a record, not gated.
  --self-test       prove every rule still fires on a known-bad fixture

Python 3 standard library only; no third-party dependency, so the CI job needs
no install step and cannot be broken by an upstream release.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

BLOCKING = "P1"
ADVISORY = "P2"

# Files that are binary by nature; a match inside them is meaningless.
BINARY_SUFFIXES = (
    ".der", ".pem", ".bin", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico",
    ".woff", ".woff2", ".zip", ".gz", ".xz", ".crate",
)


# --------------------------------------------------------------------------
# Rules
#
# Each rule's `pattern` is written so that it does NOT match its own source
# text here (character classes begin with `[`, which no class admits), so this
# file does not trip the rules it defines. The four rules whose patterns embed
# a literal trigger word are the exception and are allowlisted for this path
# below, individually and with a reason.
# --------------------------------------------------------------------------

RULES = [
    {
        "id": "home-path",
        "severity": BLOCKING,
        "description": "Absolute path into a user's home directory",
        "pattern": re.compile(r"(?:/Users/|/home/|C:\\Users\\)[A-Za-z0-9._-]+"),
        # Never personal: GitHub-hosted runners use these exact account names,
        # so they carry no information about any individual.
        "exempt": [re.compile(r"^(?:/Users/|/home/|C:\\Users\\)runner$")],
        "why": "publishes an OS account name and local filesystem layout",
    },
    {
        "id": "personal-email",
        "severity": BLOCKING,
        "description": "Email address that is not a known non-personal address",
        # The domain must START with a letter, which keeps version pins such as
        # `cargo-deny@0.20.2` and `rust-toolchain@1.95.0` from reading as
        # addresses. `@v2` / `@stable` have no dot and never match.
        "pattern": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z][A-Za-z0-9.-]*\.[A-Za-z]{2,}"),
        "exempt": [
            # The maintainer's GitHub noreply address is the project's public
            # identity, used in .mailmap and every commit.
            re.compile(r"@users\.noreply\.github\.com$"),
            # Commit-trailer convention.
            re.compile(r"^noreply@anthropic\.com$"),
            # GB/T 32918 worked-example identities. These are published test
            # vectors, not addresses: the standard's own SM2 signature and
            # key-exchange examples are computed over these exact ID strings,
            # so the KATs cannot use anything else.
            re.compile(r"^(?:ALICE123|BILL456)@YAHOO\.COM$"),
        ],
        "why": "publishes a personal contact address",
    },
    {
        "id": "private-host",
        "severity": BLOCKING,
        "description": "RFC 1918 / link-local IP address",
        # Full dotted quads only. A loose pattern reads version numbers such as
        # `10.1` as addresses, which would make the rule pure noise here.
        "pattern": re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|169\.254\.\d{1,3}\.\d{1,3})\b"
        ),
        "exempt": [],
        "why": "discloses private network topology",
    },
    {
        "id": "credential-url",
        "severity": BLOCKING,
        "description": "URL carrying inline basic-auth credentials",
        "pattern": re.compile(r"https?://[^/\s:@]+:[^/\s@]+@[A-Za-z0-9.-]+"),
        "exempt": [],
        "why": "embeds a credential in a URL",
    },
    {
        "id": "session-artifact",
        "severity": BLOCKING,
        "description": "Path into an agent session/scratch directory",
        "pattern": re.compile(r"(?:/private)?/tmp/claude-[0-9A-Za-z_-]+|\.claude/projects/"),
        "exempt": [],
        "why": "publishes a local session path that is meaningless to any reader",
    },
    {
        "id": "external-record-id",
        "severity": BLOCKING,
        "description": "Identifier addressing a record in a private external system",
        # Context-anchored on purpose. A bare 32-hex run is indistinguishable
        # from the published KAT vectors this repository is full of, so the
        # match must sit next to a word that makes it a RECORD id. Found the
        # real instance (a project-tracker page ID in a plan doc) with zero
        # false positives across the tree.
        "pattern": re.compile(
            r"(?i)(?:(?:notion|project\s+page|page\s+id|workspace|data\s+source)"
            r"[^0-9a-f\n]{0,40}\b[0-9a-f]{32}\b"
            r"|\bnotion\.(?:so|site)/[A-Za-z0-9/_-]+)"
        ),
        "exempt": [],
        "why": "a resolvable handle into a private system; discloses that the record exists and how to address it",
    },
    {
        "id": "local-scratch-path",
        "severity": ADVISORY,
        "description": "Path into a local scratch/temp directory",
        # Session directories are the P1 `session-artifact` rule's job; excluded
        # here so a session path is reported once, at the higher severity.
        "pattern": re.compile(r"(?:/private)?/tmp/(?!claude-)[A-Za-z0-9._-]+"),
        "exempt": [],
        "why": "cites a location no reader can reach, and hints at local working method",
    },
    {
        "id": "agent-tooling",
        "severity": ADVISORY,
        "description": "Reference to local AI-agent tooling or plan scaffolding",
        "pattern": re.compile(
            r"\.codex/|\.cursor/|\.aider|\.claude/|superpowers:|REQUIRED SUB-SKILL"
            r"|\.repolens|RepoLens|docs/superpowers/"
        ),
        "exempt": [],
        "why": "internal process scaffolding, not project documentation",
    },
    {
        "id": "private-repo",
        "severity": ADVISORY,
        "description": "Reference to a private or unpublished sibling project",
        "pattern": re.compile(r"gmcrypto-envelope-lite|gm-crypto-rs-demo|gm-crypto-lite-java"),
        "exempt": [],
        "why": "names a repository the public cannot see; its internals are not public information",
    },
    {
        "id": "local-hostname",
        "severity": ADVISORY,
        "description": "Personal machine hostname",
        "pattern": re.compile(
            r"\b[A-Za-z0-9-]+\.(?:local|lan|internal)\b|MacBook|Mac-mini|\biMac\b"
        ),
        "exempt": [],
        "why": "identifies a specific personal machine",
    },
]

RULES_BY_ID = {r["id"]: r for r in RULES}


# --------------------------------------------------------------------------
# Allowlist
#
# Every entry requires the PATH to match AND (when `regexes` is present) the
# matched text to match — the same AND-condition discipline `.gitleaks.toml`
# uses, and for the same reason: allowlisting a whole file, or a whole tree,
# is the easy version and silently covers the next real finding in it.
#
# Every entry states WHY. An entry without a reason is a bug.
# --------------------------------------------------------------------------

SELF = r"^\.github/scripts/check_disclosure_boundary\.py$"
POLICY_DOC = r"^docs/disclosure-boundary\.md$"

ALLOWLIST = [
    {
        "rules": [
            "private-repo", "agent-tooling", "local-hostname",
            "session-artifact", "local-scratch-path", "external-record-id",
        ],
        "paths": [SELF],
        "reason": (
            "This scanner's own rule definitions necessarily contain the literal "
            "trigger words for these four rules. The rules stay ACTIVE on this file "
            "for every other pattern, and --self-test proves each still fires, so "
            "this cannot hide a stale rule."
        ),
    },
    {
        "rules": ["private-repo", "agent-tooling", "home-path"],
        "paths": [POLICY_DOC],
        "reason": "The policy document has to quote the classes it defines in order to define them.",
    },
    {
        "rules": ["home-path"],
        "paths": [r"^docs/pre-opensource-audit\.md$"],
        # Split so this file does not itself contain the literal it allows;
        # `home-path` therefore stays ACTIVE on this scanner.
        "regexes": [r"^/Users/" + r"ghrunner$"],
        "reason": (
            "A documented, accepted finding: the retired self-hosted runner's "
            "throwaway service account. That audit reasons explicitly about why no "
            "history rewrite is warranted; deleting the reference would delete the "
            "reasoning, not the exposure."
        ),
    },
    {
        "rules": ["local-scratch-path"],
        "paths": [r"^\.github/scripts/check_assurance_policy\.py$"],
        "regexes": [r"^/tmp/(?:bypass|fake-deny|fake-gmssl)$"],
        "reason": (
            "Synthetic paths inside that checker's mutation fixtures — they are the "
            "ATTACK being rejected (a PATH-shadowing step), not a real location. "
            "Pinned by exact name so a different scratch path there still reports."
        ),
    },
    {
        "rules": ["local-scratch-path"],
        "paths": [r"^docs/v1\.4-x509-ffi-plan\.md$"],
        "regexes": [r"^/tmp/(?:sm3_fix|x509v)$"],
        "reason": (
            "Ephemeral build directories in a historical plan. They name no user and "
            "no machine, and nothing depends on them; recorded rather than rewritten."
        ),
    },
    {
        "rules": ["agent-tooling"],
        "paths": [r"^\.gitignore$"],
        "reason": "A protective ignore entry. Removing it would make a leak MORE likely, not less.",
    },
    {
        "rules": ["agent-tooling"],
        "paths": [r"^CHANGELOG\.md$"],
        "reason": (
            "One historical entry records REMOVING two internal scratch-path ignore "
            "rules, so it names them. Whether the changelog should narrate local "
            "tooling at all is an open decision in the 2026-08-15 audit."
        ),
    },
    {
        "rules": ["agent-tooling"],
        "paths": [r"^docs/v0\.2\.0-release-review\.md$"],
        "regexes": [r"^\.claude/$"],
        "reason": "A packaging checklist asserting the published .crate does NOT contain that directory.",
    },
    {
        "rules": ["agent-tooling"],
        "paths": [
            r"^docs/2026-08-10-assurance-hardening-implementation-plan\.md$",
            r"^docs/2026-08-11-pr149-review-remediation-plan\.md$",
            r"^docs/v1\.1-sm2-key-exchange-plan\.md$",
            r"^docs/v1\.3-x509-sm2-plan\.md$",
        ],
        "reason": (
            "Four historical plan documents carry an agent-directive header. Recorded "
            "as an OPEN DECISION in docs/2026-08-15-disclosure-audit.md rather than "
            "silently rewritten: they are part of the project record, and whether that "
            "record should narrate its own tooling is the maintainer's call. Allowlisted "
            "by exact path so any NEW occurrence still reports."
        ),
    },
    {
        "rules": ["private-repo"],
        "paths": [
            r"^docs/ECOSYSTEM\.md$",
            r"^docs/v1\.11\.0-gate1-evidence\.md$",
            r"^docs/v1\.9\.1-gate1-evidence\.md$",
            r"^docs/v1\.9\.1-release-review\.md$",
            r"^docs/version-history\.md$",
            r"^CLAUDE\.md$",
            r"^CHANGELOG\.md$",
        ],
        "reason": (
            "ECOSYSTEM.md is a normative charter that deliberately names its member "
            "crates, including unpublished ones; the gate-evidence docs record runs "
            "against the downstream suite. Allowlisted by exact path so the rule still "
            "functions as a drift detector: a NEW file naming a private sibling reports "
            "and forces a decision. How MUCH downstream internal detail those existing "
            "files should carry is an open decision in the 2026-08-15 audit."
        ),
    },
]


def allowlisted(rule_id: str, path: str, matched: str) -> bool:
    for entry in ALLOWLIST:
        if rule_id not in entry["rules"]:
            continue
        if not any(re.search(p, path) for p in entry["paths"]):
            continue
        regexes = entry.get("regexes")
        if regexes is None:
            return True
        if any(re.search(r, matched) for r in regexes):
            return True
    return False


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------


class Finding:
    __slots__ = ("severity", "rule_id", "path", "line", "matched", "context")

    def __init__(self, severity, rule_id, path, line, matched, context):
        self.severity = severity
        self.rule_id = rule_id
        self.path = path
        self.line = line
        self.matched = matched
        self.context = context

    def __str__(self):
        where = f"{self.path}:{self.line}" if self.line else self.path
        return f"{self.severity} [{self.rule_id}] {where}: {self.matched}"


def scan_text(text: str, path: str, line_offset_labels=None):
    """Yield findings for one file's text. `line_offset_labels` maps an index to
    a display label, used by range mode where 'line number' means 'in commit X'."""
    findings = []
    for idx, line in enumerate(text.splitlines(), 1):
        if len(line) > 4096:
            line = line[:4096]
        for rule in RULES:
            for m in rule["pattern"].finditer(line):
                matched = m.group(0)
                if any(e.search(matched) for e in rule["exempt"]):
                    continue
                if allowlisted(rule["id"], path, matched):
                    continue
                label = line_offset_labels(idx) if line_offset_labels else idx
                findings.append(
                    Finding(rule["severity"], rule["id"], path, label, matched, line.strip()[:160])
                )
    return findings


def git(*args, binary=False):
    out = subprocess.run(
        ["git", *args], capture_output=True, check=True
    ).stdout
    return out if binary else out.decode("utf-8", "replace")


def tracked_files():
    return [p for p in git("ls-files").split("\n") if p]


def scan_worktree():
    findings = []
    for path in tracked_files():
        if path.endswith(BINARY_SUFFIXES):
            continue
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError:
            continue
        if b"\0" in raw[:8192]:
            continue
        findings.extend(scan_text(raw.decode("utf-8", "replace"), path))
    return findings


def scan_range(rev_range: str):
    """Scan lines ADDED by each commit in the range, one commit at a time.

    Deliberately not a squashed `base...head` diff: a leak added in one commit
    and removed in the next leaves no trace in the net diff but is permanent in
    the public history once merged.
    """
    findings = []
    commits = [c for c in git("rev-list", "--reverse", rev_range).split("\n") if c]
    for sha in commits:
        diff = git("show", "--format=", "--unified=0", "--no-color", sha)
        current = "(unknown)"
        for line in diff.split("\n"):
            if line.startswith("+++ b/"):
                current = line[6:]
            elif line.startswith("+") and not line.startswith("+++"):
                if current.endswith(BINARY_SUFFIXES):
                    continue
                added = line[1:]
                for f in scan_text(added, current):
                    f.line = f"added in {sha[:9]}"
                    findings.append(f)
    return findings, len(commits)


def scan_history():
    """Every blob reachable from every ref.

    Reachability matters: `--batch-all-objects` would also return dangling
    objects from local rebases and amends, which are never pushed and never
    cloned, so reporting them would overstate the public exposure.
    """
    listing = git("rev-list", "--objects", "--all")
    blob_path = {}
    for line in listing.split("\n"):
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[1]:
            blob_path.setdefault(parts[0], parts[1])

    oids = list(blob_path)
    proc = subprocess.Popen(
        ["git", "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    findings = []
    scanned = 0
    for oid in oids:
        proc.stdin.write((oid + "\n").encode())
        proc.stdin.flush()
        header = proc.stdout.readline().decode("utf-8", "replace").split()
        if len(header) < 3:
            continue
        # `rev-list --objects` names trees as well as blobs. Their bodies MUST
        # still be consumed: skipping one desynchronizes the --batch stream and
        # every subsequent read lands mid-object.
        data = proc.stdout.read(int(header[2]))
        proc.stdout.read(1)
        if header[1] != "blob":
            continue
        if b"\0" in data[:8192]:
            continue
        path = blob_path[oid]
        if path.endswith(BINARY_SUFFIXES):
            continue
        scanned += 1
        for f in scan_text(data.decode("utf-8", "replace"), path):
            f.line = f"blob {oid[:9]}"
            findings.append(f)
    proc.stdin.close()
    proc.wait()
    return findings, scanned


# --------------------------------------------------------------------------
# Self-test
#
# Same posture as check_assurance_policy.py's mutation_self_test(): a rule that
# has silently stopped matching is worse than no rule, because the green check
# is then a false assurance. Every rule must fire on a known-bad fixture and
# stay quiet on its known-good counterpart.
#
# Fixtures are assembled by concatenation so that this file's own source does
# not contain the literal strings — otherwise the scanner would report itself
# and the four allowlist entries above would have to be widened.
# --------------------------------------------------------------------------

def self_test() -> int:
    U = "/Users/"
    BAD = [
        ("home-path", U + "alice/projects/thing"),
        ("home-path", "/home/" + "bob/.config"),
        ("personal-email", "someone" + "@example.org"),
        ("private-host", "connect to 192.168." + "1.44 for the oracle"),
        ("credential-url", "https://user:hunter2" + "@internal.example.com/repo.git"),
        ("session-artifact", "/private/tmp/" + "claude-502/scratch/notes.md"),
        # SYNTHETIC id. Never use a real one here: the fixture is committed, so
        # a real value would republish the exact thing the rule exists to keep
        # out — which is precisely what happened on the first draft of this file.
        ("external-record-id", "Project " + "page: `0123456789abcdef0123456789abcdef`"),
        ("external-record-id", "see https://www." + "notion.so/Some-Private-Page-abc123"),
        ("local-scratch-path", "verified against /private/" + "tmp/sm2pdf/params-hi-01.png"),
        ("agent-tooling", "python3 ~/." + "codex/plugins/cache/run.py"),
        ("agent-tooling", "REQUIRED " + "SUB-SKILL: use the planner"),
        ("private-repo", "gmcrypto-" + "envelope-lite passes its suite"),
        ("local-hostname", "built on Frank-" + "MacBook-Pro overnight"),
        ("local-hostname", "ssh build-box" + ".local for the oracle"),
    ]
    GOOD = [
        # CI-standard runner accounts carry no personal information.
        U + "runner/work/gm-crypto-rs",
        "/home/" + "runner/.cargo/bin",
        # Version pins must never read as email addresses.
        "tool: cargo-deny" + "@0.20.2",
        "uses: dtolnay/rust-toolchain" + "@1.95.0",
        "uses: actions/checkout" + "@v7",
        # The project's public identity and the GB/T worked-example IDs.
        "47923440+frankxue831" + "@users.noreply.github.com",
        "let id = b\"ALICE123" + "@YAHOO.COM\";",
        # Version numbers are not IP addresses.
        "crypto-bigint 0.7 requires 1.85, MSRV 10.1 is not a host",
        # Generic tilde paths name no user.
        "export PATH=~/.cargo/" + "bin:$PATH",
        # THE false positive that matters: this repository is full of 32-hex
        # KAT vectors. A bare hex run must never read as an external record ID.
        "let k = hex!(\"6C89347354DE2484C60B4AB1FDE4C6E5\");",
        "K = 6C893473 54DE2484 C60B4AB1 FDE4C6E5 (klen = 128)",
        "commit 5cf8fec02d03bc3cab7f2c1013463fc96e785383 exported read-only",
    ]

    failures = []
    for rule_id, fixture in BAD:
        hits = [f for f in scan_text(fixture, "self-test/fixture.txt") if f.rule_id == rule_id]
        if not hits:
            failures.append(
                f"rule {rule_id!r} did NOT fire on its known-bad fixture "
                f"({fixture!r}) — the rule is stale or was silently broken"
            )
    for fixture in GOOD:
        hits = scan_text(fixture, "self-test/fixture.txt")
        if hits:
            failures.append(
                f"known-good fixture ({fixture!r}) produced {len(hits)} false "
                f"positive(s): {[h.rule_id for h in hits]}"
            )

    # A session path must report ONCE, at the higher severity — otherwise the
    # P1 arrives paired with a P2 for the same bytes and the advisory channel
    # fills up with duplicates of things that already failed the build.
    session_hits = scan_text(
        "/private/tmp/" + "claude-502/scratch/notes.md", "self-test/fixture.txt"
    )
    session_rules = sorted(h.rule_id for h in session_hits)
    if session_rules != ["session-artifact"]:
        failures.append(
            f"a session path should fire only 'session-artifact', fired {session_rules}"
        )

    covered = {rule_id for rule_id, _ in BAD}
    for rule in RULES:
        if rule["id"] not in covered:
            failures.append(f"rule {rule['id']!r} has NO known-bad fixture — add one")

    for entry in ALLOWLIST:
        if not entry.get("reason"):
            failures.append(f"allowlist entry for {entry['rules']} has no reason")
        for rule_id in entry["rules"]:
            if rule_id not in RULES_BY_ID:
                failures.append(f"allowlist names unknown rule {rule_id!r}")

    if failures:
        print("disclosure-boundary self-test: FAILED", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(
        f"disclosure-boundary self-test: ok "
        f"({len(RULES)} rules, {len(BAD)} positive + {len(GOOD)} negative fixtures)"
    )
    return 0


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def report(findings, scanned_desc: str, strict: bool) -> int:
    blocking = [f for f in findings if f.severity == BLOCKING]
    advisory = [f for f in findings if f.severity == ADVISORY]

    for f in blocking:
        print(f"::error::{f}")
        print(f"    {f.context}")
    for f in advisory:
        print(f"::warning::{f}")
        print(f"    {f.context}")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        # Written BEFORE the exit decision, so the table renders on a failing
        # run too — the #121 lesson: a report nobody can see is not a report.
        lines = [
            "## Disclosure boundary",
            "",
            f"Scanned: {scanned_desc}",
            "",
            f"- **{len(blocking)}** blocking (P1)",
            f"- **{len(advisory)}** advisory (P2 — needs a recorded decision, not a failure)",
            "",
        ]
        if findings:
            lines += ["| Sev | Rule | Location | Match |", "|---|---|---|---|"]
            for f in blocking + advisory:
                match = f.matched.replace("|", "\\|")[:80]
                lines.append(f"| {f.severity} | `{f.rule_id}` | `{f.path}:{f.line}` | `{match}` |")
        else:
            lines.append("No findings.")
        lines += [
            "",
            "P1 fails this job. P2 is reported for a human decision and is resolved "
            "either by removing the content or by adding a scoped allowlist entry "
            "with a reason in `.github/scripts/check_disclosure_boundary.py`. "
            "See `docs/disclosure-boundary.md`.",
        ]
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

    print()
    print(f"disclosure boundary: scanned {scanned_desc}")
    print(f"  blocking (P1): {len(blocking)}")
    print(f"  advisory (P2): {len(advisory)}")

    if blocking:
        print(
            "\nFAIL: content that does not belong in a public repository.\n"
            "Remove it, or — if it is deliberate — add a scoped allowlist entry\n"
            "with a reason in .github/scripts/check_disclosure_boundary.py.",
            file=sys.stderr,
        )
        return 1
    if advisory and strict:
        print("\nFAIL (--strict): advisory findings present.", file=sys.stderr)
        return 1
    print("\nok")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--worktree", action="store_true", help="scan tracked files at HEAD (default)")
    mode.add_argument("--range", metavar="A..B", help="scan lines added by each commit in a range")
    mode.add_argument("--history", action="store_true", help="scan all blobs reachable from all refs")
    mode.add_argument("--self-test", action="store_true", help="prove every rule still fires")
    ap.add_argument("--strict", action="store_true", help="treat advisory (P2) findings as failures")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    if args.range:
        findings, n = scan_range(args.range)
        return report(findings, f"lines added by {n} commit(s) in {args.range}", args.strict)

    if args.history:
        findings, n = scan_history()
        return report(findings, f"{n} text blob(s) reachable from all refs", args.strict)

    findings = scan_worktree()
    return report(findings, f"{len(tracked_files())} tracked file(s) at HEAD", args.strict)


if __name__ == "__main__":
    sys.exit(main())
