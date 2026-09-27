"""Run with python3 -m unittest discover -s .github/scripts -p 'test_*.py'."""
import unittest
import csv
import hashlib
import io
import json
import tempfile
import zipfile
from pathlib import Path
from extract_dudect_history import parse_job, extract


def log(passes=5):
    lines = [
        "rustc 1.95.0 (setup-action)",
        "##[group]Runner Image", "Image: ubuntu-24.04", "Version: 20260907.300.1",
        "##[endgroup]", 'echo "=== Rust ==="',
        "=== CPU ===", "Model name: AMD EPYC 9V74 80-Core Processor",
        "=== Rust ===", "rustc 1.98.1 (actual-compiler)", "cargo 1.98.1 (actual-cargo)",
        "##[group]Run for i in ...", "DUDECT_SAMPLES: 100000",
        "+ echo '=== dudect run 1/5 (features=crypto-bigint-scalar) ==='",
    ]
    for i in range(1, passes + 1):
        lines += [f"=== dudect run {i}/5 (features=crypto-bigint-scalar) ===",
                  "bench ct_fp_invert seeded with 0x1234",
                  "bench ct_fp_invert ... : n == +0.097M, max t = -221.67172, max tau = -0.71175, (5/tau)^2 = 49"]
    lines += ["RUNNER-CPU: AMD EPYC 9V74 80-Core Processor"]
    return "\n".join("2026-09-17T05:17:00.0000000Z " + s for s in lines)


class ParseTests(unittest.TestCase):
    # Taking the first rustc line would silently mis-stratify every historical job.
    def test_actual_environment_and_signed_precision(self):
        meta, rows, issues = parse_job(log())
        self.assertEqual(meta.get("rustc"), "rustc 1.98.1 (actual-compiler)")
        self.assertEqual(meta.get("sample_budget"), "100000")
        self.assertEqual(meta.get("cargo"), "cargo 1.98.1 (actual-cargo)")
        self.assertEqual(meta.get("image_version"), "20260907.300.1")
        self.assertEqual(meta.get("cpu_env"), "AMD EPYC 9V74 80-Core Processor")
        self.assertEqual(meta.get("cpu_gate"), meta.get("cpu_env"))
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[0]["max_tau"], "-0.71175")
        self.assertEqual(rows[0]["max_t"], "-221.67172")
        self.assertEqual(rows[0]["n_millions"], "+0.097")
        self.assertEqual(rows[0]["seed"], "0x1234")
        self.assertEqual(rows[0]["pass"], 1)
        self.assertEqual(issues, [])

    def test_cross_checks_printed_gate_lists_against_signed_bench_output(self):
        text = log() + "\nSENTINEL: ct_fp_invert median|tau|=0.7117 (runs=['0.7117', '0.7117', '0.7117', '0.7117', '0.7117'] median=0.7117)"
        meta, _, issues = parse_job(text)
        self.assertEqual(meta.get("gate_targets_checked"), 1)
        self.assertNotIn("gate_values_mismatch:ct_fp_invert", issues)
        _, _, issues = parse_job(text.replace("runs=['0.7117'", "runs=['0.1000'"))
        self.assertIn("gate_values_mismatch:ct_fp_invert", issues)

    def test_missing_passes_are_explicit(self):
        _, rows, issues = parse_job(log(4))
        self.assertEqual(len(rows), 4)
        self.assertIn("missing_passes:5", issues)
        self.assertIn("incomplete_target:ct_fp_invert", issues)

    def test_duplicate_results_are_preserved_and_flagged(self):
        text = log() + "\nbench ct_fp_invert ... : n == +0.099M, max t = +1.00000, max tau = +0.01000, (5/tau)^2 = 250000"
        _, rows, issues = parse_job(text)
        self.assertEqual(len(rows), 6)
        self.assertIn("duplicate_result:5:ct_fp_invert", issues)

    def test_malformed_or_nonfinite_result_is_flagged(self):
        _, rows, issues = parse_job(log().replace("-0.71175", "NaN", 1))
        self.assertEqual(len(rows), 4)
        self.assertIn("malformed_result:1:ct_fp_invert", issues)

    def test_absent_metadata_is_unknown_not_inferred_from_setup(self):
        meta, rows, issues = parse_job("rustc 1.95.0 (setup-action)\n")
        self.assertEqual(meta.get("rustc", ""), "")
        self.assertEqual(rows, [])
        self.assertIn("missing_passes:1,2,3,4,5", issues)


class ExtractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.archive = self.root / "10-attempt-1.zip"
        with zipfile.ZipFile(self.archive, "w") as z:
            z.writestr("3_timing-leak nightly (features=default).txt", log())
        self.manifest = self.root / "manifest.csv"
        with self.manifest.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["run_id", "attempt", "created_at", "head_sha", "event", "conclusion", "status", "archive_bytes", "sha256", "source_api_url"])
            writer.writeheader()
            writer.writerow(dict(run_id=10, attempt=1, created_at="2026-09-17T05:00:00Z", head_sha="a" * 40,
                                 event="schedule", conclusion="cancelled", status="preserved",
                                 archive_bytes=self.archive.stat().st_size,
                                 sha256=hashlib.sha256(self.archive.read_bytes()).hexdigest(), source_api_url=""))
        (self.root / "10-attempt-1-jobs.json").write_text(json.dumps({"total_count": 2, "jobs": [
            {"id": 12, "run_id": 10, "run_attempt": 1, "name": "timing-leak nightly (features=sm4-bitsliced)", "conclusion": "cancelled"},
            {"id": 11, "run_id": 10, "run_attempt": 1, "name": "timing-leak nightly (features=default)", "conclusion": "success"}]}))
        self.out = self.root / "out"

    def test_join_by_feature_not_zip_or_api_order_and_keep_cancelled_job(self):
        stats = extract(self.manifest, self.root, self.out)
        self.assertEqual(stats.get("jobs"), 2)
        jobs = list(csv.DictReader(io.StringIO((self.out / "v1.15-nightly-corpus.csv").read_text())))
        self.assertEqual(jobs[0]["job_id"], "11")
        self.assertEqual(jobs[0].get("ct_fp_invert_tau_5"), "-0.71175")
        self.assertEqual(jobs[1].get("ct_fp_invert_tau_5"), "")
        self.assertIn("missing_target:noise_twin_class_split", jobs[0]["issues"])
        self.assertEqual(jobs[0]["rustc"], "rustc 1.98.1 (actual-compiler)")
        self.assertEqual(jobs[1]["job_id"], "12")
        self.assertIn("missing_log", jobs[1]["issues"])
        samples = list(csv.DictReader(io.StringIO((self.out / "v1.15-nightly-samples.csv").read_text())))
        self.assertEqual(len(samples), 5)
        self.assertEqual({r["job_id"] for r in samples}, {"11"})
        self.assertEqual(samples[0]["max_tau"], "-0.71175")

    def test_changed_archive_fails_before_output(self):
        with self.archive.open("ab") as f:
            f.write(b"tampering")
        with self.assertRaisesRegex(ValueError, "archive integrity"):
            extract(self.manifest, self.root, self.out)
        self.assertFalse(self.out.exists())

    def test_unmatched_log_is_not_silently_dropped(self):
        data = json.loads((self.root / "10-attempt-1-jobs.json").read_text())
        data["jobs"][1]["name"] = "timing-leak nightly (features=other)"
        (self.root / "10-attempt-1-jobs.json").write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "unmatched logs"):
            extract(self.manifest, self.root, self.out)


if __name__ == "__main__":
    unittest.main()
