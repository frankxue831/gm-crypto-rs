#!/usr/bin/env python3
"""One native qualification draw; no calibration, retries, or study routing.

The existing assurance checker audits its original workflow and parser before
we execute that parser verbatim. No protected fingerprint is regenerated here.
Release correctness and bench timing use separate executables, with the same
source, effective toolchain, locked graph, features and default profile inputs.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
LEGS = (
    "sm4-bitsliced-simd",
    "sm4-bitsliced-simd,sm4-aead,sm4-xts,sm2-key-exchange,tlcp",
)
DETECTOR = "sm4::sbox_x32::tests::gfni_path_present_when_expected"
MILLION = "sm4::cipher::tests::gbt32907_one_million_rounds"
REQUIRED_TESTS = (
    DETECTOR,
    "sm4::sbox_x4::tests::gfni_lane_position_sweep",
    "sm4::sbox_x4::tests::gfni_matches_scalar_on_distinct_inputs",
    "sm4::sbox_x32::tests::gfni_lane_position_sweep",
    "sm4::sbox_x32::tests::gfni_matches_scalar_on_distinct_inputs",
    "dispatch_pin_00010203",
    "dispatch_mixed_distinct_bytes",
    "sm4::cipher::tests::gbt32907_single_block",
    "sm4::cipher::tests::sbox_ct_matches_lut",
    "sm4::cipher::tests::tau_simd_matches_four_bitsliced_sboxes",
    "sm4::cbc_streaming::tests::cbc_decrypt_simd_batch_boundary_sweep",
    "sm4::cbc_streaming::tests::cbc_decrypt_simd_chunked_update_sweep",
    "encrypt_blocks_matches_per_block_at_every_length",
    "decrypt_blocks_matches_per_block_at_every_length",
    "round_trip_encrypt_then_decrypt_is_identity",
    "batch_boundary_named_lengths_round_trip",
    "ctr_equals_ecb_keystream_xor_plaintext_at_counter_zero",
    "ctr_matches_ecb_across_simd_batches_and_counter_carries",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reviewed_programs(root=ROOT):
    """Import performs the unchanged full assurance audit and mutation suite.

    Do not catch SystemExit: a rejected fingerprint must stop qualification.
    The extraction is the checker's own implementation, not a second parser.
    """
    spec = importlib.util.spec_from_file_location(
        "qualification_assurance", root / ".github/scripts/check_assurance_policy.py"
    )
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    full = policy.job(policy.DUDECT_NIGHTLY, "full")
    parser = policy.reviewed_python_heredoc(policy.step_named(full, "Parse and gate"))
    if parser is None:
        raise ValueError("reviewed nightly parser unavailable")
    guard = policy.literal_run_body(policy.step_named(full, "Verify effective dudect toolchain"))
    if not guard:
        raise ValueError("reviewed toolchain guard unavailable")
    return guard, parser[0], parser[1]


def python_preflight(output, root=ROOT):
    """Record the interpreter and audit protected source with its pinned AST format."""
    runtime = {"executable": sys.executable, "version": sys.version,
               "version_info": list(sys.version_info),
               "implementation": sys.implementation.name}
    (output / "python-runtime.json").write_text(json.dumps(runtime, indent=2) + "\n")
    if sys.implementation.name != "cpython" or sys.version_info[:4] != (3, 14, 8, "final"):
        raise ValueError("qualification requires CPython 3.14.8; see python-runtime.json")
    with (output / "assurance-policy.log").open("w") as audit_log, contextlib.redirect_stdout(audit_log):
        return reviewed_programs(root)


def require_tests(log, names):
    passed = re.findall(r"^test (\S+) \.\.\. ok$", log, re.M)
    for name in names:
        if passed.count(name) != 1:
            raise ValueError(f"required test did not execute exactly once: {name}")


def parse_logs(source, directory, env):
    # Original parser accepts any nonempty number of logs; qualification must
    # additionally reject partial/stale passes before applying unchanged gates.
    expected = {f"dudect-nightly-{i}.log" for i in range(1, 6)}
    if {p.name for p in directory.glob("dudect-nightly-*.log")} != expected:
        raise ValueError("qualification requires exactly five numbered timing logs")
    return subprocess.run([sys.executable, "-c", source], cwd=directory,
                          env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def qualify(output, env):
    output.mkdir(parents=True, exist_ok=False)  # Never mix attempts or stale logs.
    result = {"status": "NOT QUALIFIED", "stage": "preflight", "commands": []}
    lock_hash = None

    def save():
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")

    def run(args, name, cwd=ROOT):
        result["commands"].append(args)
        save()
        with (output / name).open("w") as log:
            proc = subprocess.Popen(args, cwd=cwd, env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for line in proc.stdout:
                print(line, end="", flush=True)
                log.write(line)
            code = proc.wait()
        if lock_hash is not None and digest(ROOT / "Cargo.lock") != lock_hash:
            raise ValueError("dependency lock changed during qualification")
        if code:
            raise ValueError(f"{name}: command exited {code}")
        return (output / name).read_text()

    try:
        save()
        leg = env.get("MATRIX_FEATURES")
        if leg not in LEGS:
            raise ValueError("unsupported qualification feature configuration")
        if env.get("GITHUB_EVENT_NAME") != "workflow_dispatch" or env.get("GITHUB_RUN_ATTEMPT") != "1":
            raise ValueError("requires one explicitly dispatched first attempt; no automatic reruns")
        features = leg + ",crypto-bigint-scalar"
        result.update(features=features, samples=100000, runs=5,
                      provenance={k: env.get(k) for k in (
                          "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_REF",
                          "GITHUB_REPOSITORY", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA",
                          "RUNNER_NAME", "RUNNER_ARCH", "ImageOS", "ImageVersion", "RUSTUP_TOOLCHAIN")})
        # No env/profile/runner override can change the reviewed build shape.
        overrides = [k for k in env if k.startswith(("CARGO_PROFILE_", "CARGO_TARGET_", "CARGO_BUILD_")) or k in (
            "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
            "RUSTC")]
        if overrides:
            raise ValueError(f"unexpected build overrides: {overrides}")
        os_release = Path("/etc/os-release").read_text()
        (output / "os-release").write_text(os_release)
        if 'ID=ubuntu\n' not in os_release or 'VERSION_ID="24.04"\n' not in os_release:
            raise ValueError("qualification requires Ubuntu 24.04")
        run(["uname", "-a"], "kernel.log")
        run(["lscpu"], "cpu.log")
        run(["bash", "-c", "for f in /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor /sys/devices/system/cpu/intel_pstate/no_turbo; do if [ -r \"$f\" ]; then printf '%s: ' \"$f\"; cat \"$f\"; fi; done"], "cpu-policy.log")
        sha = run(["git", "rev-parse", "HEAD"], "source.log").strip()
        if sha != env.get("GITHUB_SHA"):
            raise ValueError("checkout differs from dispatched candidate")
        if run(["git", "status", "--porcelain", "--untracked-files=no"], "worktree.log").strip():
            raise ValueError("tracked source is dirty")
        result["stage"] = "Python runtime and assurance preflight"
        guard, parser, ast_hash = python_preflight(output)
        (output / "reviewed-parser.py").write_text(parser)
        result["parser_ast_sha256"] = ast_hash
        result["source_sha256"] = {p: digest(ROOT / p) for p in (
            "Cargo.toml", "crates/gmcrypto-core/Cargo.toml", "crates/gmcrypto-simd/Cargo.toml",
            "crates/gmcrypto-core/benches/timing_leaks.rs", ".github/workflows/dudect-nightly.yml",
            ".github/scripts/check_assurance_policy.py", ".github/scripts/native_gfni.py")}
        result["stage"] = "effective Rust toolchain and locked graph"
        run(["bash", "-euo", "pipefail", "-c", guard], "toolchain.log")
        run(["cargo", "generate-lockfile"], "resolve.log")
        lock_hash = digest(ROOT / "Cargo.lock")
        result["lock_sha256"] = lock_hash
        (output / "Cargo.lock").write_bytes((ROOT / "Cargo.lock").read_bytes())
        run(["cargo", "metadata", "--locked", "--format-version", "1", "--features", features], "cargo-metadata.json")
        env.update(GMCRYPTO_SIMD_EXPECT_GFNI="1", DUDECT_SAMPLES="100000")
        base = ["cargo", "test", "--release", "--locked", "-p", "gmcrypto-core", "-p", "gmcrypto-simd", "--features", features]
        result["stage"] = "native detector (missing GFNI is NOT QUALIFIED)"
        detector = run(base + ["--lib", DETECTOR, "--", "--exact", "--format", "pretty"], "detector.log")
        require_tests(detector, (DETECTOR,))
        result["native_has_gfni_avx2"] = True
        result["stage"] = "release output correctness"
        # No lib-only selector or name filter: includes ALL four batch API
        # integrations, CTR/CBC composition and the complete core/backend suites.
        correctness = run(base + ["--", "--format", "pretty"], "correctness.log")
        require_tests(correctness, REQUIRED_TESTS)
        # These names are shared by the x4/x16/x32 integration executables.
        # Require each executable's table-oracle dispatch sweep explicitly.
        for suite in ("lane_position_x4", "lane_position_x16", "lane_position_x32"):
            block = re.search(r"Running tests/" + suite + r"\.rs [^\n]*\n(.*?)(?=\n\s*(?:Running |Doc-tests )|\Z)", correctness, re.S)
            if block is None:
                raise ValueError(f"missing integration executable: {suite}")
            require_tests(block[1], ("dispatch_lane_position_sweep", "dispatch_sequential_fill_sweep"))
        million = run(base + ["--lib", MILLION, "--", "--exact", "--ignored", "--format", "pretty"], "million-round.log")
        require_tests(million, (MILLION,))
        result["stage"] = "timing (100K x 5, unchanged nightly gates)"
        for i in range(1, 6):
            run(["cargo", "bench", "--locked", "--bench", "timing_leaks", "--features", features], f"dudect-nightly-{i}.log")
        gate = parse_logs(parser, output, env)
        (output / "gate.log").write_text(gate.stdout)
        print(gate.stdout, end="", flush=True)
        if gate.returncode:
            raise ValueError("unchanged nightly timing gate failed")
        result["executables_sha256"] = {
            p.name: digest(p) for p in (ROOT / "target/release/deps").iterdir()
            if p.is_file() and os.access(p, os.X_OK) and not p.is_symlink()
        }
        result.update(status="QUALIFIED", stage="complete")
    except (ValueError, OSError, SystemExit) as error:
        result["reason"] = (f"assurance checker rejected protected policy (exit {error.code}); see assurance-policy.log"
                            if isinstance(error, SystemExit) else str(error))
    finally:
        save()
        summary = f"Native GFNI: {result['status']} — {result['stage']}\n{result.get('reason', '')}\n"
        print(summary, flush=True)
        if env.get("GITHUB_STEP_SUMMARY"):
            with Path(env["GITHUB_STEP_SUMMARY"]).open("a") as stream:
                stream.write(summary)
    return 0 if result["status"] == "QUALIFIED" else 1


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    sys.exit(qualify(args.output.resolve(), dict(os.environ)))
