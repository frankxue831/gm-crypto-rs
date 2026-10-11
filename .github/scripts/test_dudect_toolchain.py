"""Execute each workflow's real toolchain guard against controlled tool output."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
NAME = "Verify effective dudect toolchain"
RUSTC = "rustc 1.95.0 (59807616e 2026-04-14)\nbinary: rustc\ncommit-hash: " + "a" * 40 + "\nrelease: 1.95.0\nhost: x86_64-unknown-linux-gnu\n"
CARGO = "cargo 1.95.0 (example 2026-04-14)\n"
ACTIVE = "1.95.0-x86_64-unknown-linux-gnu (overridden by environment variable RUSTUP_TOOLCHAIN)\n"


class ToolchainTests(unittest.TestCase):
    def guards(self):
        for filename in ("dudect-pr.yml", "dudect-main.yml", "dudect-nightly.yml"):
            text = (ROOT / ".github/workflows" / filename).read_text()
            match = re.search(r"      - name: " + NAME + r"\n(.*?)(?=      - (?:uses|name):)", text, re.S)
            self.assertIsNotNone(match, f"{filename}: missing effective toolchain verification")
            self.assertIn("    env:\n      RUSTUP_TOOLCHAIN: 1.95.0\n", text)
            body = re.search(r"          python3 - <<'PY'\n(.*?)          PY\n", match[1], re.S)
            self.assertIsNotNone(body, f"{filename}: missing executable identity check")
            yield filename, "\n".join(line[10:] for line in body[1].splitlines())

    def execute(self, script, rustc=RUSTC, cargo=CARGO, active=ACTIVE, selected="1.95.0"):
        with tempfile.TemporaryDirectory() as tmp:
            for name, output in (("rustc", rustc), ("cargo", cargo), ("rustup", active)):
                tool = Path(tmp) / name
                # Shell quote controlled fixture output; exercise real subprocesses.
                tool.write_text("#!/bin/sh\nprintf '%s' '" + output.replace("'", "'\"'\"'") + "'\n")
                tool.chmod(0o755)
            env = dict(os.environ, PATH=tmp, RUSTUP_TOOLCHAIN=selected)
            return subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True)

    def test_intended_compiler_is_accepted_and_printed(self):
        for name, guard in self.guards():
            with self.subTest(workflow=name):
                result = self.execute(guard)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(RUSTC.strip(), result.stdout)
                self.assertIn(CARGO.strip(), result.stdout)
                self.assertIn(ACTIVE.strip(), result.stdout)

    def test_wrong_effective_identity_is_rejected(self):
        cases = [
            {"selected": "stable"}, {"selected": ""},
            {"rustc": RUSTC.replace("1.95.0", "1.98.1")},
            {"cargo": CARGO.replace("1.95.0", "1.98.1")},
            {"active": ACTIVE.replace("1.95.0", "stable")},
            {"rustc": RUSTC.replace("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu")},
            {"rustc": "rustc 1.95.0\n"},
        ]
        for name, guard in self.guards():
            for case in cases:
                with self.subTest(workflow=name, case=case):
                    result = self.execute(guard, **case)
                    self.assertNotEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
