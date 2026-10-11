"""Exercise real parser equivalence and fail-closed qualification sequencing."""
import contextlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

import native_gfni as native

# Independent, minimized x86 Rust output. Never generate this from REQUIRED_TESTS:
# that hid a scalar-only test which both SIMD feature configurations compile out.
CORRECTNESS = (Path(__file__).parent / "fixtures/native_gfni_correctness.txt").read_text()


class CorrectnessReceiptTests(unittest.TestCase):
    def test_feature_applicable_output_oracles_and_dispatch_executables(self):
        native.require_correctness(CORRECTNESS)

    def test_original_scalar_only_requirement_is_rejected(self):
        with patch.object(native, "REQUIRED_TESTS", native.REQUIRED_TESTS + (
                "sm4::cipher::tests::sbox_ct_matches_lut",)):
            with self.assertRaisesRegex(ValueError, "sbox_ct_matches_lut"):
                native.require_correctness(CORRECTNESS)

    def test_missing_ignored_or_duplicate_table_oracle_is_rejected(self):
        record = "test sm4::sbox_bitsliced::tests::bitsliced_matches_table ... ok"
        for replacement in ("", record.replace("ok", "ignored"), record + "\n" + record):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(ValueError, "bitsliced_matches_table"):
                native.require_correctness(CORRECTNESS.replace(record, replacement))

    def test_compiled_inventory_includes_million_but_cannot_prove_execution(self):
        listing = re.sub(r"^test (\S+) \.\.\. .*", r"\1: test", CORRECTNESS, flags=re.M)
        native.require_correctness(listing, listing=True)
        with self.assertRaisesRegex(ValueError, "did not execute"):
            native.require_correctness(listing)
        with self.assertRaisesRegex(ValueError, "gbt32907_one_million_rounds"):
            native.require_correctness(listing.replace(native.MILLION + ": test", ""), listing=True)
        with self.assertRaisesRegex(ValueError, "dispatch_lane_position_sweep"):
            native.require_correctness(listing.replace("dispatch_lane_position_sweep: test", "", 1), listing=True)


def passing_logs(source):
    names = sorted(set(re.findall(r'"((?:ct_|noise_|negative_control)[a-z0-9_]*)"', source)))
    return "".join(f"bench {name} ... : max tau = {2.0 if name == 'negative_control' else 0.01:.5f}\n" for name in names)


class ParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with contextlib.redirect_stdout(io.StringIO()):
            cls.guard, cls.source, cls.fingerprint = native.reviewed_programs()
        # Independent textual extraction of the production nightly heredoc.
        # After study isolation, that parser lives in dudect-main.yml.
        workflow = (native.ROOT / ".github/workflows/dudect-main.yml").read_text()
        step = workflow.split("      - name: Parse and gate\n", 1)[1]
        cls.original = textwrap.dedent(step.split("          python3 - <<'PY'\n", 1)[1].split("          PY\n", 1)[0])

    def test_extracted_parser_is_verbatim_reviewed_source(self):
        self.assertEqual(self.source, self.original)
        self.assertEqual(self.fingerprint, "40f28788c76669f50266dc6375b732753debd48894e52926ed103dbcaacaf2d2")

    def test_original_and_reused_parser_agree_on_regressions(self):
        good = passing_logs(self.source)
        cases = [
            (good, 0),
            (good.replace("ct_sm4_ctr_encrypt ... : max tau = 0.01000", "ct_sm4_ctr_encrypt ... : max tau = 0.21000"), 1),
            (good.replace("ct_fp_invert ... : max tau = 0.01000", "ct_fp_invert ... : max tau = 0.56000"), 1),
            (good.replace("negative_control ... : max tau = 2.00000", "negative_control ... : max tau = 1.00000"), 1),
            (good.replace("noise_twin_class_split", "missing_twin"), 1),
            (good.replace("ct_sm4_encrypt_block_bitsliced_simd", "missing_simd"), 1),
        ]
        for leg in native.LEGS:
            extra = [(good.replace("ct_sm4_gcm_decrypt_buffered", "missing_aead"), 1 if "sm4-aead" in leg else 0)]
            for log, expected in cases + extra:
                with self.subTest(leg=leg, log=log), tempfile.TemporaryDirectory() as tmp:
                    directory = Path(tmp)
                    for i in range(1, 6):
                        (directory / f"dudect-nightly-{i}.log").write_text(log)
                    env = dict(os.environ, MATRIX_FEATURES=leg)
                    direct = subprocess.run([sys.executable, "-c", self.original], cwd=directory,
                                            env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    reused = native.parse_logs(self.source, directory, env)
                    self.assertEqual((reused.returncode, reused.stdout), (direct.returncode, direct.stdout))
                    self.assertEqual(reused.returncode, expected, reused.stdout)

    def test_negative_control_and_telemetry_required_in_each_pass(self):
        for replacement in ("negative_control", "noise_twin_class_split"):
            with tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                for i in range(1, 6):
                    log = passing_logs(self.source)
                    if i == 3:
                        log = log.replace(replacement, "missing_target")
                    (directory / f"dudect-nightly-{i}.log").write_text(log)
                result = native.parse_logs(self.source, directory, dict(os.environ, MATRIX_FEATURES=native.LEGS[0]))
                self.assertNotEqual(result.returncode, 0)

    def test_incomplete_and_extra_passes_rejected(self):
        for count in (0, 4, 6):
            with tempfile.TemporaryDirectory() as tmp:
                for i in range(1, count + 1):
                    (Path(tmp) / f"dudect-nightly-{i}.log").write_text("")
                with self.assertRaisesRegex(ValueError, "exactly five"):
                    native.parse_logs(self.source, Path(tmp), {})

    def test_protected_workflow_mutation_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in (".github/scripts/check_assurance_policy.py", ".github/scripts/v115_nightly.py", ".github/workflows/ci.yml",
                         ".github/workflows/gitleaks.yml", ".github/workflows/dudect-pr.yml",
                         ".github/workflows/dudect-main.yml", "crates/gmcrypto-core/benches/timing_leaks.rs"):
                dest = root / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(native.ROOT / name, dest)
            nightly = root / ".github/workflows/dudect-main.yml"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(native.reviewed_programs(root)[1], self.source)
            nightly.write_text(nightly.read_text().replace('"ct_sm4_ctr_encrypt": 0.20', '"ct_sm4_ctr_encrypt": 0.99'))
            rejected = io.StringIO()
            with contextlib.redirect_stdout(rejected), self.assertRaises(SystemExit):
                native.reviewed_programs(root)
            self.assertIn("nightly dudect executable semantics match reviewed fingerprint", rejected.getvalue())


class PythonRuntimeTests(unittest.TestCase):
    def test_wrong_python_is_recorded_and_rejected_before_policy_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            with patch.object(native.sys, "version_info", (3, 12, 3, "final", 0)), \
                    patch.object(native, "reviewed_programs") as policy:
                with self.assertRaisesRegex(ValueError, "requires CPython 3.14.8"):
                    native.python_preflight(output)
            policy.assert_not_called()
            runtime = json.loads((output / "python-runtime.json").read_text())
            self.assertEqual(runtime["version_info"], [3, 12, 3, "final", 0])
            self.assertEqual(runtime["executable"], sys.executable)
            self.assertFalse((output / "assurance-policy.log").exists())

    def test_rejected_assurance_never_returns_programs(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(native.sys, "version_info", (3, 14, 8, "final", 0)), \
                    patch.object(native, "reviewed_programs", side_effect=SystemExit(1)):
                with self.assertRaises(SystemExit):
                    native.python_preflight(Path(tmp))
            self.assertTrue((Path(tmp) / "python-runtime.json").is_file())


class SequenceTests(unittest.TestCase):
    def exercise(self, failure=None, overrides=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Source fingerprints are tested with real files in ParserTests;
            # these fixtures isolate command order and stopping behavior.
            for name in ("Cargo.toml", "crates/gmcrypto-core/Cargo.toml", "crates/gmcrypto-simd/Cargo.toml",
                         "crates/gmcrypto-core/benches/timing_leaks.rs", ".github/workflows/dudect-main.yml",
                         ".github/scripts/check_assurance_policy.py", ".github/scripts/native_gfni.py"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture")
            (root / "target/release/deps").mkdir(parents=True)
            commands = []
            env = dict(MATRIX_FEATURES=native.LEGS[1], GITHUB_SHA="a" * 40,
                       GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_RUN_ATTEMPT="1", RUSTUP_TOOLCHAIN="1.95.0")
            env.update(overrides or {})

            def popen(args, **kwargs):
                commands.append((args, dict(kwargs["env"])))
                code, text = 0, ""
                if args[:2] == ["git", "rev-parse"]:
                    text = "a" * 40 + "\n"
                elif args[:2] == ["cargo", "generate-lockfile"]:
                    (root / "Cargo.lock").write_text("locked graph")
                elif native.DETECTOR in args:
                    text = f"test {native.DETECTOR} ... ok\n"
                    if failure == "hardware":
                        code, text = 101, "GFNI+AVX2 path is unavailable\n"
                    if failure == "zero-tests":
                        text = "running 0 tests\n"
                elif native.MILLION in args:
                    text = f"test {native.MILLION} ... {'ignored' if failure == 'million' else 'ok'}\n"
                elif args[:2] == ["cargo", "test"]:
                    text = CORRECTNESS
                    if failure == "dispatch-executable":
                        text = text.replace("Running tests/lane_position_x32.rs", "Running tests/missing.rs")
                    if failure == "dispatch-sweep":
                        text = text.replace("test dispatch_lane_position_sweep ... ok", "test dispatch_lane_position_sweep ... ignored", 1)
                    if failure == "integration":
                        text = text.replace("test encrypt_blocks_matches_per_block_at_every_length ... ok\n", "")
                    if failure == "table-oracle":
                        text = text.replace("test sm4::sbox_bitsliced::tests::bitsliced_matches_table ... ok\n", "")
                    if failure == "lock":
                        (root / "Cargo.lock").write_text("changed")
                elif args[:2] == ["cargo", "bench"] and failure == "timing":
                    code = 1
                return type("Process", (), {"stdout": io.StringIO(text), "wait": lambda self: code})()

            original_read = Path.read_text

            def read(path, *args, **kwargs):
                if str(path) == "/etc/os-release":
                    return 'ID=ubuntu\nVERSION_ID="24.04"\n'
                return original_read(path, *args, **kwargs)

            preflight_error = {"python": ValueError("qualification requires CPython 3.14.8"),
                               "policy": SystemExit(1)}.get(failure)
            with patch.object(native, "ROOT", root), \
                    patch.object(native, "python_preflight", return_value=("guard", "parser", "hash"), side_effect=preflight_error), \
                    patch.object(native.subprocess, "Popen", side_effect=popen), \
                    patch.object(native, "parse_logs", return_value=subprocess.CompletedProcess([], 0, "OK")), \
                    patch.object(Path, "read_text", read), contextlib.redirect_stdout(io.StringIO()):
                code = native.qualify(root / "evidence", env)
            result = json.loads((root / "evidence/result.json").read_text())
            return code, result, commands

    def test_complete_sequence_and_matched_locked_features(self):
        for leg in native.LEGS:
            with self.subTest(leg=leg):
                code, result, commands = self.exercise(overrides={"MATRIX_FEATURES": leg})
                self.assertEqual(code, 0, result)
                self.assertEqual(result["status"], "QUALIFIED")
                cargo = [(args, env) for args, env in commands if args[0] == "cargo"]
                timing = [args for args, _ in cargo if args[1] == "bench"]
                self.assertEqual(len(timing), 5)
                for args, env in cargo:
                    if args[1] in ("test", "bench"):
                        self.assertIn("--locked", args)
                        self.assertEqual(args[args.index("--features") + 1], leg + ",crypto-bigint-scalar")
                        self.assertEqual(env["GMCRYPTO_SIMD_EXPECT_GFNI"], "1")
                        self.assertEqual(env["DUDECT_SAMPLES"], "100000")
                tests = [args for args, _ in cargo if args[1] == "test"]
                self.assertIn(native.DETECTOR, tests[0])
                self.assertNotIn("--lib", tests[1])
                self.assertEqual(tests[1][-3:], ["--", "--format", "pretty"])
                self.assertIn("--ignored", tests[2])
                self.assertIn(native.MILLION, tests[2])

    def test_preflight_or_correctness_failure_never_reaches_timing(self):
        for failure in ("python", "policy", "hardware", "zero-tests", "integration", "table-oracle", "dispatch-executable", "dispatch-sweep", "million", "lock"):
            with self.subTest(failure=failure):
                code, result, commands = self.exercise(failure)
                self.assertEqual(code, 1)
                self.assertEqual(result["status"], "NOT QUALIFIED")
                self.assertFalse(any(args[:2] == ["cargo", "bench"] for args, _ in commands))
                if failure in ("python", "policy"):
                    self.assertFalse(any(args[0] == "cargo" for args, _ in commands))
                    self.assertEqual(result["stage"], "Python runtime and assurance preflight")

    def test_original_requirement_stops_before_million_and_timing(self):
        with patch.object(native, "REQUIRED_TESTS", native.REQUIRED_TESTS + (
                "sm4::cipher::tests::sbox_ct_matches_lut",)):
            for leg in native.LEGS:
                code, result, commands = self.exercise(overrides={"MATRIX_FEATURES": leg})
                self.assertEqual(code, 1)
                self.assertEqual(result["stage"], "release output correctness")
                self.assertIn("sbox_ct_matches_lut", result["reason"])
                self.assertFalse(any(native.MILLION in args or args[:2] == ["cargo", "bench"]
                                     for args, _ in commands))

    def test_timing_failure_is_not_retried(self):
        code, result, commands = self.exercise("timing")
        self.assertEqual(code, 1)
        self.assertEqual(sum(args[:2] == ["cargo", "bench"] for args, _ in commands), 1)

    def test_reruns_unknown_features_and_build_overrides_rejected(self):
        for overrides in ({"GITHUB_RUN_ATTEMPT": "2"}, {"MATRIX_FEATURES": "default"},
                          {"RUSTFLAGS": "-C target-cpu=native"}, {"CARGO_PROFILE_BENCH_LTO": "false"},
                          {"CARGO_BUILD_RUSTC": "alternate"}, {"CARGO_BUILD_RUSTC_WRAPPER": "wrapper"},
                          {"CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER": "wrapper"}):
            with self.subTest(overrides=overrides):
                code, _, commands = self.exercise(overrides=overrides)
                self.assertEqual(code, 1)
                self.assertEqual(commands, [])


if __name__ == "__main__":
    unittest.main()
