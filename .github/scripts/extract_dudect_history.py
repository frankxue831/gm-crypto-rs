#!/usr/bin/env python3
"""Extract descriptive historical dudect evidence; never derives or activates gates."""
import argparse
import ast
import csv
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path
from collections import Counter

TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT\S+Z ")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
PASS = re.compile(r"=== dudect run (\d+)/(\d+) \(features=(.*)\) ===$")
NUMBER = r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?"
RESULT = re.compile(
    rf"bench (\w+)\s+\.\.\. : n == ({NUMBER})M, max t = ({NUMBER}), "
    rf"max tau = ({NUMBER}), .*$"
)
GATE = re.compile(r"^(?:OK|FAIL|SENTINEL(?: FAIL)?|NOISE-TWIN):\s+(\w+) .*?runs=(\[.*?\])")
SEED = re.compile(r"bench (\w+)\s+seeded with (0x[0-9a-fA-F]+)$")


def parse_job(text):
    """Preserve printed precision/signs; flag incomplete or ambiguous output."""
    meta, rows, issues = {}, [], []
    section, image_group = "", False
    gate_lists = []
    pass_id, features = 0, ""
    passes, counts, seeds = Counter(), Counter(), {}
    for raw in text.splitlines():
        line = ANSI.sub("", TIMESTAMP.sub("", raw)).strip()
        if line.startswith("##["):
            section = ""
            image_group = line == "##[group]Runner Image"
        if line.startswith("=== ") and line.endswith(" ==="):
            section = line
        if image_group:
            if line.startswith("Image: "):
                meta["image"] = line.removeprefix("Image: ")
            elif line.startswith("Version: "):
                meta["image_version"] = line.removeprefix("Version: ")
        if section == "=== Rust ===":
            if line.startswith("rustc "):
                meta["rustc"] = line
            elif line.startswith("cargo "):
                meta["cargo"] = line
        if section == "=== CPU ===" and line.startswith("Model name:"):
            meta["cpu_env"] = line.split(":", 1)[1].strip()
        if section == "=== Kernel ===" and line.startswith("Linux "):
            # Exclude the ephemeral hostname, retain kernel release and machine.
            words = line.split()
            meta["kernel"] = words[2]
        if line.startswith("RUNNER-CPU: "):
            meta["cpu_gate"] = line.removeprefix("RUNNER-CPU: ")
        budget = re.fullmatch(r"DUDECT_SAMPLES: (\d+)", line)
        if budget:
            if meta.get("sample_budget", budget[1]) != budget[1]:
                issues.append("inconsistent_sample_budget")
            meta["sample_budget"] = budget[1]
        match = PASS.fullmatch(line)
        if match:
            pass_id, expected = int(match[1]), int(match[2])
            features = match[3]
            passes[pass_id] += 1
            if expected != 5 or pass_id not in range(1, 6):
                issues.append(f"unexpected_pass:{pass_id}/{expected}")
            if passes[pass_id] > 1:
                issues.append(f"duplicate_pass:{pass_id}")
        gate = GATE.search(line)
        if gate:
            gate_lists.append((gate[1], ast.literal_eval(gate[2])))
        match = SEED.fullmatch(line)
        if match:
            seeds[pass_id, match[1]] = match[2]
        match = RESULT.fullmatch(line)
        if match:
            target, n, t, tau = match.groups()
            counts[pass_id, target] += 1
            if counts[pass_id, target] > 1:
                issues.append(f"duplicate_result:{pass_id}:{target}")
            if not pass_id:
                issues.append(f"result_outside_pass:{target}")
            rows.append({"pass": pass_id, "features": features, "target": target,
                         "n_millions": n, "max_t": t, "max_tau": tau,
                         "seed": seeds.get((pass_id, target), "")})
        elif line.startswith("bench ") and "..." in line:
            issues.append(f"malformed_result:{pass_id}:{line.split()[1]}")
    missing = sorted(set(range(1, 6)) - passes.keys())
    if missing:
        issues.append("missing_passes:" + ",".join(map(str, missing)))
    for target in sorted({row["target"] for row in rows}):
        if any(counts[i, target] != 1 for i in range(1, 6)):
            issues.append(f"incomplete_target:{target}")
    for target, values in gate_lists:
        reported = [f"{abs(float(r['max_tau'])):.4f}" for r in rows if r["target"] == target]
        if reported != values:
            issues.append(f"gate_values_mismatch:{target}")
    meta["gate_targets_checked"] = len(gate_lists)
    return meta, rows, sorted(set(issues))


JOB_FIELDS = [
    "run_id", "attempt", "created_at", "head_sha", "event", "run_conclusion",
    "job_id", "job_conclusion", "matrix_features", "bench_features", "cpu_env",
    "cpu_gate", "image", "image_version", "kernel", "rustc", "cargo",
    "sample_budget", "sample_rows", "gate_targets_checked", "issues", "archive_sha256", "jobs_metadata_sha256", "log_sha256",
    "job_url",
]
CORPUS_TARGETS = ("ct_fn_invert", "ct_fp_invert", "ct_sign_k_class", "ct_hmac_sm3",
                  "noise_twin_class_split", "ct_sm4_cbc_decrypt_fanout", "negative_control")
TAU_FIELDS = [f"{target}_tau_{i}" for target in CORPUS_TARGETS for i in range(1, 6)]
JOB_FIELDS += TAU_FIELDS
SAMPLE_FIELDS = ["job_id", "pass", "target", "seed", "n_millions", "max_t", "max_tau"]
FEATURES = re.compile(r"features=(.*)\)(?:\.txt)?$")
REPO = "https://github.com/frankxue831/gm-crypto-rs"


def extract(manifest, archives, output):
    """Read checksummed archives plus matching attempt job metadata, entirely offline.

    Output is allowlisted CSV. Missing logs/metadata remain explicit; archive or
    association ambiguity aborts before writing any output. No calibration fit.
    """
    with Path(manifest).open(newline="") as f:
        runs = list(csv.DictReader(f))
    jobs_out, samples = [], []
    seen_runs, seen_jobs = set(), set()
    for run in sorted(runs, key=lambda r: (r["created_at"], int(r["run_id"]), int(r["attempt"]))):
        run_id, attempt = int(run["run_id"]), int(run["attempt"])
        key = run_id, attempt
        if key in seen_runs:
            raise ValueError(f"duplicate run attempt: {key}")
        seen_runs.add(key)
        stem = f"{run_id}-attempt-{attempt}"
        raw_zip = (Path(archives) / (stem + ".zip")).read_bytes()
        digest = hashlib.sha256(raw_zip).hexdigest()
        if digest != run["sha256"] or len(raw_zip) != int(run["archive_bytes"]):
            raise ValueError(f"archive integrity mismatch: {stem}")
        raw_jobs = (Path(archives) / (stem + "-jobs.json")).read_bytes()
        job_digest = hashlib.sha256(raw_jobs).hexdigest()
        job_data = json.loads(raw_jobs)
        if job_data["total_count"] != len(job_data["jobs"]):
            raise ValueError(f"incomplete job metadata: {stem}")
        logs = {}
        with zipfile.ZipFile(io.BytesIO(raw_zip)) as z:
            for name in z.namelist():
                if "/" in name or not name.endswith(".txt"):
                    continue
                match = FEATURES.search(name)
                if not match or match[1] in logs:
                    raise ValueError(f"ambiguous log entry: {stem}: {name}")
                logs[match[1]] = z.read(name)
        for job in sorted(job_data["jobs"], key=lambda j: j["id"]):
            job_id = job["id"]
            if job_id in seen_jobs or job["run_id"] != run_id or job["run_attempt"] != attempt:
                raise ValueError(f"ambiguous job identity: {job_id}")
            seen_jobs.add(job_id)
            match = FEATURES.search(job["name"])
            if not match:
                raise ValueError(f"unrecognized job: {job_id}")
            matrix_features = match[1]
            raw_log = logs.pop(matrix_features, None)
            if raw_log is None:
                meta, rows, issues = {}, [], ["missing_log"]
                log_digest = ""
            else:
                meta, rows, issues = parse_job(raw_log.decode("utf-8"))
                log_digest = hashlib.sha256(raw_log).hexdigest()
            feature_sets = sorted({row["features"] for row in rows})
            expected_features = ("" if matrix_features == "default" else matrix_features + ",") + "crypto-bigint-scalar"
            if feature_sets and feature_sets != [expected_features]:
                issues.append("bench_features_mismatch")
            for field in ("cpu_env", "image_version", "kernel", "rustc", "cargo", "sample_budget"):
                if not meta.get(field):
                    issues.append(f"missing_metadata:{field}")
            if meta.get("cpu_gate") and meta.get("cpu_env") and meta["cpu_gate"] != meta["cpu_env"]:
                issues.append("cpu_metadata_mismatch")
            compact = {}
            for target in CORPUS_TARGETS:
                if not any(r["target"] == target for r in rows):
                    issues.append(f"missing_target:{target}")
                for i in range(1, 6):
                    # Preserve duplicates, rather than silently choosing a winner.
                    values = [r["max_tau"] for r in rows if r["target"] == target and r["pass"] == i]
                    compact[f"{target}_tau_{i}"] = "|".join(values)
            jobs_out.append(dict(
                run_id=run_id, attempt=attempt, created_at=run["created_at"], head_sha=run["head_sha"],
                event=run["event"], run_conclusion=run["conclusion"], job_id=job_id,
                job_conclusion=job["conclusion"], matrix_features=matrix_features,
                bench_features=";".join(feature_sets), **meta, **compact, sample_rows=len(rows),
                issues=";".join(sorted(set(issues))), archive_sha256=digest,
                jobs_metadata_sha256=job_digest, log_sha256=log_digest,
                job_url=f"{REPO}/actions/runs/{run_id}/job/{job_id}",
            ))
            for row in rows:
                samples.append({"job_id": job_id, **{k: v for k, v in row.items() if k != "features"}})
        if logs:
            raise ValueError(f"unmatched logs: {stem}: {sorted(logs)}")
    stats = {"runs": len(runs), "jobs": len(jobs_out), "samples": len(samples),
             "jobs_with_issues": sum(bool(j["issues"]) for j in jobs_out),
             "run_events": dict(sorted(Counter(r["event"] for r in runs).items())),
             "run_conclusions": dict(sorted(Counter(r["conclusion"] for r in runs).items())),
             "job_conclusions": dict(sorted(Counter(j["job_conclusion"] for j in jobs_out).items())),
             "actual_rustc": dict(sorted(Counter(j.get("rustc", "unknown") for j in jobs_out).items()))}
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for filename, fields, rows in (("v1.15-nightly-corpus.csv", JOB_FIELDS, jobs_out), ("v1.15-nightly-samples.csv", SAMPLE_FIELDS, samples)):
        with (output / filename).open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
    stats["output_sha256"] = {name: hashlib.sha256((output / name).read_bytes()).hexdigest()
                              for name in ("v1.15-nightly-corpus.csv", "v1.15-nightly-samples.csv")}
    (output / "v1.15-nightly-summary.json").write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n")
    return stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(extract(args.manifest, args.archives, args.output), sort_keys=True))


if __name__ == "__main__":
    main()
