#!/usr/bin/env python3
"""Produce replayable v1.15 evidence; prepare alone NEVER executes timing code.

No workflow calls this yet. A reviewed freeze and calibration window are required
for run-pass; build-only preparation can construct the identities for that review.
Leaky controls and confirmation dispatches have their own protocol/runner.
"""
import argparse
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys

LEGS = ('default', 'sm4-bitsliced', 'sm4-bitsliced-simd',
        'sm4-bitsliced-simd,sm4-aead,sm4-xts,sm2-key-exchange,tlcp')
IDENTITY_FILES = {'source-manifest.json', 'Cargo.lock', 'resolution.json',
                  'toolchain.json', 'build-config.json', 'capture-source.py'}
TARGET = 'x86_64-unknown-linux-gnu'
LOCK_SHA = 'e2800837c468ba45d21e759d50e94dc115e3f72eb3139c579305a908b60ed1c8'
SOURCE_SHA = '375f80441fa49a6fcbb2eca0381a7a907ed166aea31f1ad420b569ab621256b6'


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_bytes(canonical(value))
    temporary.replace(path)


def features(leg):
    if leg not in LEGS:
        raise ValueError('unknown feature leg')
    return 'crypto-bigint-scalar' if leg == 'default' else leg + ',crypto-bigint-scalar'


def source_inventory(root):
    paths = [root / 'Cargo.toml', root / 'rust-toolchain.toml']
    for name in ('crates', '.cargo'):
        parent = root / name
        if parent.is_symlink():
            raise ValueError('symlinked input directory')
        if parent.exists():
            paths.extend(parent.rglob('*'))
    records = []
    for path in sorted(paths):
        if path.is_symlink():
            raise ValueError('symlinked build input')
        if path.is_file():
            data = path.read_bytes()
            records.append(dict(path=path.relative_to(root).as_posix(), bytes=len(data), sha256=digest(data)))
        elif path.name in ('Cargo.toml', 'rust-toolchain.toml'):
            raise ValueError('missing root build input')
    return records


def normalized_resolution(metadata, root):
    """Retain package sources, dependency edges/kinds and resolved feature sets."""
    root = root.resolve()
    names = {}
    for package in metadata['packages']:
        source = package['source']
        if source is None:
            try:
                source = 'workspace/' + Path(package['manifest_path']).resolve().parent.relative_to(root).as_posix()
            except ValueError as error:
                raise ValueError('external path dependency') from error
        names[package['id']] = (package['name'], package['version'], source)
    if len(set(names.values())) != len(names):
        raise ValueError('ambiguous normalized package identity')
    nodes = []
    for node in metadata['resolve']['nodes']:
        dependencies = [dict(name=dep['name'], package=names[dep['pkg']],
                             kinds=sorted(dep['dep_kinds'], key=lambda item: json.dumps(item, sort_keys=True)))
                        for dep in node['deps']]
        nodes.append(dict(package=names[node['id']], features=sorted(node['features']),
                          dependencies=sorted(dependencies, key=lambda item: (item['name'], item['package']))))
    return dict(packages=sorted(names.values()), nodes=sorted(nodes, key=lambda item: item['package']),
                workspace_members=sorted(names[name] for name in metadata['workspace_members']))


def build_environment(env):
    if env.get('RUSTUP_TOOLCHAIN') != '1.95.0':
        raise ValueError('effective RUSTUP_TOOLCHAIN must be 1.95.0')
    banned = []
    for key, value in env.items():
        if key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'RUSTC', 'RUSTDOC',
                   'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'LD_PRELOAD', 'LD_LIBRARY_PATH'):
            banned.append(key)
        elif key.startswith(('CARGO_PROFILE_', 'CARGO_BUILD_', 'CARGO_TARGET_')) and key != 'CARGO_TARGET_DIR':
            banned.append(key)
        elif key == 'CARGO_INCREMENTAL' and value != '0':
            banned.append(key)
    if banned:
        raise ValueError('unfrozen build overrides: ' + ','.join(sorted(banned)))
    return dict(toolchain='1.95.0', target=TARGET, profile='bench',
                rustflags=None, encoded_rustflags=None, build_target=None,
                incremental=env.get('CARGO_INCREMENTAL'))


def check_external_config(root, env):
    # Cargo searches ancestors and CARGO_HOME; root .cargo is in source inventory.
    candidates = [parent / '.cargo' / name for parent in root.parents for name in ('config', 'config.toml')]
    cargo_home = Path(env.get('CARGO_HOME', str(Path.home() / '.cargo')))
    candidates.extend(cargo_home / name for name in ('config', 'config.toml'))
    if any(path.exists() for path in candidates):
        raise ValueError('external Cargo configuration is not frozen')


def command_output(command, root):
    return subprocess.check_output(command, cwd=root, text=True).strip()


def snapshot(root, directory, leg, env, *, offline=False):
    directory.mkdir(exist_ok=True)
    config = build_environment(env)
    config['features'] = features(leg)
    check_external_config(root, env)
    inventory = (json.dumps(source_inventory(root), indent=2) + '\n').encode()
    (directory / 'source-manifest.json').write_bytes(inventory)
    lock = (root / 'Cargo.lock').read_bytes()
    (directory / 'Cargo.lock').write_bytes(lock)
    if digest(inventory) != SOURCE_SHA or digest(lock) != LOCK_SHA:
        raise ValueError('source or lock differs from structural-control freeze')
    rustc = command_output(['rustc', '-Vv'], root)
    cargo = command_output(['cargo', '-V'], root)
    active = command_output(['rustup', 'show', 'active-toolchain'], root)
    if not (rustc.startswith('rustc 1.95.0 (') and 'release: 1.95.0' in rustc.splitlines()
            and 'host: ' + TARGET in rustc.splitlines() and cargo.startswith('cargo 1.95.0 (')
            and active.split()[0] == '1.95.0-' + TARGET):
        raise ValueError('effective compiler identity differs')
    (directory / 'toolchain.json').write_bytes(canonical(dict(rustc=rustc, cargo=cargo, active_toolchain=active)))
    raw = subprocess.check_output(['cargo', 'metadata', '--locked', '--features', features(leg),
                                   '--filter-platform', TARGET, '--format-version', '1'] + (['--offline'] if offline else []),
                                  cwd=root, env=env)
    resolution = normalized_resolution(json.loads(raw), root)
    if (root / 'Cargo.lock').read_bytes() != lock:
        raise ValueError('metadata changed lock resolution')
    (directory / 'resolution.json').write_bytes(canonical(resolution))
    (directory / 'build-config.json').write_bytes(canonical(config))
    (directory / 'capture-source.py').write_bytes(Path(__file__).read_bytes())
    return {path.name: digest(path.read_bytes()) for path in sorted(directory.iterdir())}


def seal(evidence, capture):
    files = {}
    for path in sorted(evidence.rglob('*')):
        if path.is_symlink():
            raise ValueError('symlink in capture evidence')
        if path.is_file() and path.name not in ('capture.json', 'capture.json.tmp'):
            files[path.relative_to(evidence).as_posix()] = digest(path.read_bytes())
    capture['files'] = files
    save(evidence / 'capture.json', capture)


def read_cpu():
    return next(line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                if line.startswith('model name'))


def prepare(root, evidence, leg, lock_path, metadata_path, freeze):
    if evidence.exists():
        raise ValueError('refuse to replace existing evidence')
    evidence.mkdir(parents=True)
    capture = dict(schema=1, metadata={}, processes=[], status='preparing', measurement_enabled=False)
    try:
        features(leg)
        env = os.environ.copy()
        build_environment(env)
        metadata = json.loads(metadata_path.read_text())
        for key in ('run_id', 'job_id', 'run_attempt'):
            if type(metadata.get(key)) is not int or metadata[key] <= 0:
                raise ValueError('positive Actions identity required')
        sha = command_output(['git', 'rev-parse', 'HEAD'], root)
        if metadata.get('head_sha') != sha or metadata.get('feature_leg') != leg:
            raise ValueError('job metadata does not match checkout/feature leg')
        model = read_cpu()
        capture['metadata'] = {key: metadata.get(key) for key in
                               ('run_id', 'job_id', 'run_attempt', 'head_sha', 'feature_leg', 'event', 'started_at')}
        capture['metadata'].update(cpu=model, image_version=env.get('ImageVersion'), kernel=os.uname().release)
        frozen_lock = lock_path.read_bytes()
        if digest(frozen_lock) != LOCK_SHA:
            raise ValueError('wrong frozen research lock')
        lock = root / 'Cargo.lock'
        if lock.exists() and lock.read_bytes() != frozen_lock:
            raise ValueError('existing lock drift; do not overwrite or regenerate')
        if not lock.exists():
            lock.write_bytes(frozen_lock)
        identity = snapshot(root, evidence / 'before', leg, env)
        capture['identity_sha256'] = identity
        if freeze is not None and freeze.get('identity_sha256_by_leg', {}).get(leg) != identity:
            raise ValueError('before-build identity does not match reviewed freeze')
        capture['measurement_enabled'] = freeze is not None
        if freeze is not None:
            (evidence / 'freeze.json').write_bytes(canonical(freeze))
            capture['freeze_sha256'] = digest(canonical(freeze))
        seal(evidence, capture)
        command = ['cargo', 'bench', '--no-run', '--locked', '--bench', 'timing_leaks',
                   '--features', features(leg), '--message-format=json']
        with (evidence / 'build.json').open('wb') as out, (evidence / 'build.stderr').open('wb') as err:
            subprocess.run(command, cwd=root, env=env, stdout=out, stderr=err, check=True)
        artifacts = [item for line in (evidence / 'build.json').read_text().splitlines()
                     if (item := json.loads(line)).get('reason') == 'compiler-artifact'
                     and item.get('target', {}).get('name') == 'timing_leaks' and item.get('executable')]
        if len(artifacts) != 1:
            raise ValueError('expected one optimized harness executable')
        shutil.copyfile(artifacts[0]['executable'], evidence / 'timing.bin')
        (evidence / 'timing.bin').chmod(0o755)
        capture['binary_before_sha256'] = digest((evidence / 'timing.bin').read_bytes())
        # Freeze hashable build inputs after compilation as well, before any pass.
        postbuild = snapshot(root, evidence / 'after', leg, env, offline=True)
        if postbuild != identity:
            raise ValueError('build inputs changed during compilation')
        capture['binary_after_sha256'] = capture['binary_before_sha256']
        capture['status'] = 'prepared-no-timing-run'
    except Exception as error:
        capture.update(status='preparation-failed', error=str(error), measurement_enabled=False)
        raise
    finally:
        seal(evidence, capture)
    return capture


def authorize_pass(capture, freeze, evidence, number, now):
    if capture.get('measurement_enabled') is not True:
        raise ValueError('build-only preparation cannot authorize timing')
    if capture.get('freeze_sha256') != digest(canonical(freeze)):
        raise ValueError('freeze changed after preparation')
    metadata = capture['metadata']
    leg = metadata['feature_leg']
    identity = capture.get('identity_sha256')
    if (not isinstance(identity, dict) or set(identity) != IDENTITY_FILES
            or any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value) for value in identity.values())
            or freeze.get('identity_sha256_by_leg', {}).get(leg) != identity):
        raise ValueError('reviewed build identity required')
    try:
        start = date.fromisoformat(freeze['calibration_start'])
        end = date.fromisoformat(freeze['calibration_end'])
        started = datetime.fromisoformat(metadata['started_at'].replace('Z', '+00:00'))
    except (KeyError, ValueError, TypeError) as error:
        raise ValueError('declared calibration dates and job timestamp required') from error
    if (end != start + timedelta(days=42) or started.utcoffset() != timedelta(0)
            or now.utcoffset() != timedelta(0) or not start <= started.date() < end
            or now < started or metadata.get('event') != 'schedule' or metadata.get('run_attempt') != 1):
        raise ValueError('not an authorized first scheduled calibration attempt')
    # Leave two minutes for snapshot/seal/upload and five seconds for termination.
    remaining = 40 * 60 - 120 - 5 - (now - started).total_seconds()
    if remaining <= 0:
        raise ValueError('production job time budget exhausted')
    processes = capture['processes']
    if type(number) is not int or not 1 <= number <= 5 or len(processes) != number - 1:
        raise ValueError('pass order or repeated attempt')
    if any(p.get('status') != 'completed' or p.get('returncode') != 0 for p in processes):
        raise ValueError('previous pass failed or incomplete; no retry')
    if digest((evidence / 'timing.bin').read_bytes()) != capture['binary_before_sha256']:
        raise ValueError('timing binary changed')
    return remaining


def launch(command, **kwargs):
    return subprocess.run(command, **kwargs).returncode


def record_pass(root, evidence, capture, number, timeout, launcher=launch):
    """Caller authorizes and snapshots first. Persist started state BEFORE launch."""
    leg = capture['metadata']['feature_leg']
    entry = dict(pass_number=number, sample_budget=100000, features=features(leg),
                 binary_sha256=digest((evidence / 'timing.bin').read_bytes()), status='started')
    entry['pass'] = entry.pop('pass_number')
    capture['processes'].append(entry)
    capture['status'] = 'timing-in-progress'
    capture['final_snapshot_status'] = 'invalidated'
    seal(evidence, capture)
    output = root / f'dudect-nightly-{number}.log'
    if output.exists():
        raise ValueError('refuse to overwrite existing pass output')
    header = f'=== dudect run {number}/5 (features={features(leg)}) ===\n'.encode()
    with (evidence / 'output.log').open('ab') as combined:
        combined.write(header)
    env = os.environ.copy()
    env['DUDECT_SAMPLES'] = '100000'
    result = None
    try:
        with output.open('xb') as out:
            result = launcher([str(evidence / 'timing.bin'), '--bench'], cwd=root, env=env,
                              stdout=out, stderr=subprocess.STDOUT, timeout=timeout)
        entry.update(status='completed' if result == 0 else 'failed', returncode=result)
        return result
    except Exception as error:
        entry.update(status='failed', error=str(error))
        raise
    finally:
        if output.exists():
            data = output.read_bytes()
            (evidence / output.name).write_bytes(data)
            with (evidence / 'output.log').open('ab') as combined:
                combined.write(data)
            sys.stdout.buffer.write(header + data)
            sys.stdout.buffer.flush()
        capture['status'] = 'pass-recorded' if result == 0 else 'pass-failed'
        capture['binary_after_sha256'] = digest((evidence / 'timing.bin').read_bytes())
        seal(evidence, capture)


def finalize(root, evidence, capture):
    # Never reuse files from a previous post-build/pre-pass/final snapshot.
    attempts = capture.setdefault('final_snapshot_attempts', [])
    relative = f'snapshot-attempts/final-{len(attempts) + 1:04d}'
    attempt = dict(path=relative, status='started')
    attempts.append(attempt)
    capture.update(status='finalizing', final_snapshot_status='started')
    seal(evidence, capture)
    try:
        directory = evidence / relative
        directory.parent.mkdir(exist_ok=True)
        directory.mkdir()  # A prior, unrecorded attempt must not be overwritten.
        identity = snapshot(root, directory, capture['metadata']['feature_leg'], os.environ.copy(), offline=True)
        if identity != capture.get('identity_sha256'):
            raise ValueError('final build input drift')
        capture['binary_after_sha256'] = digest((evidence / 'timing.bin').read_bytes())
        if capture['binary_after_sha256'] != capture.get('binary_before_sha256'):
            raise ValueError('final binary drift')
        for name in IDENTITY_FILES:
            shutil.copyfile(directory / name, evidence / 'after' / name)
        attempt['status'] = 'complete'
        capture.update(status='finalized', final_snapshot_status='complete')
    except Exception as error:
        attempt.update(status='failed', error=str(error))
        capture.update(status='finalization-failed', final_snapshot_status='failed', finalization_error=str(error))
        raise
    finally:
        seal(evidence, capture)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'run-pass', 'finalize'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--leg', choices=LEGS)
    parser.add_argument('--lock', type=Path)
    parser.add_argument('--metadata', type=Path)
    parser.add_argument('--freeze', type=Path)
    parser.add_argument('--pass-number', type=int)
    args = parser.parse_args()
    root, evidence = args.root.resolve(), args.evidence.resolve()
    freeze = json.loads(args.freeze.read_text()) if args.freeze else None
    if args.action == 'prepare':
        if not all((args.leg, args.lock, args.metadata)):
            parser.error('prepare requires --leg, --lock, --metadata')
        prepare(root, evidence, args.leg, args.lock, args.metadata, freeze)
    else:
        capture = json.loads((evidence / 'capture.json').read_text())
        if args.action == 'finalize':
            finalize(root, evidence, capture)
        else:
            if freeze is None or args.pass_number is None:
                parser.error('run-pass requires --freeze and --pass-number')
            try:
                authorize_pass(capture, freeze, evidence, args.pass_number, datetime.now(timezone.utc))
                capture.update(status='pass-authorizing', final_snapshot_status='invalidated')
                seal(evidence, capture)
                current = snapshot(root, evidence / 'after', capture['metadata']['feature_leg'], os.environ.copy(), offline=True)
                if current != capture['identity_sha256']:
                    raise ValueError('pre-pass build identity changed')
                # Metadata collection time is part of the same 40-minute job budget.
                remaining = authorize_pass(capture, freeze, evidence, args.pass_number, datetime.now(timezone.utc))
                code = record_pass(root, evidence, capture, args.pass_number, remaining)
            except Exception as error:
                capture.update(status='pass-refused-or-failed', error=str(error))
                seal(evidence, capture)
                raise
            raise SystemExit(code)


if __name__ == '__main__':
    main()
