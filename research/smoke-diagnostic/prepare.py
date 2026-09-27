"""Prepare and qualify disposable diagnostic builds; never execute timing benches."""
from pathlib import Path
import difflib
import hashlib
import json
import re
import shutil
import subprocess
import sys

from patch_exporter import patch

FEATURES = 'sm4-bitsliced-simd,sm4-aead,sm4-xts,sm2-key-exchange,tlcp,crypto-bigint-scalar'
LOCK_HASH = 'e2800837c468ba45d21e759d50e94dc115e3f72eb3139c579305a908b60ed1c8'
SOURCE = 'a832884a95a83488d853233da7cde5e37fc6b845'
HERE = Path(__file__).resolve().parent


def run(args, cwd, output=None):
    if output:
        with output.open('w') as out:
            subprocess.run(args, cwd=cwd, stdout=out, check=True)
    else:
        subprocess.run(args, cwd=cwd, check=True)


def metadata(root, path):
    run(['cargo', 'metadata', '--locked', '--features', FEATURES,
         '--filter-platform', 'x86_64-unknown-linux-gnu', '--format-version', '1'], root, path)
    return json.loads(path.read_text())


def main(source, work, evidence):
    source, work, evidence = source.resolve(), work.resolve(), evidence.resolve()
    work.mkdir()
    evidence.mkdir(exist_ok=True)
    sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
    if sha != SOURCE:
        raise ValueError('wrong source checkout')
    frozen = (HERE / 'frozen.lock').read_bytes()
    if hashlib.sha256(frozen).hexdigest() != LOCK_HASH:
        raise ValueError('frozen lock mismatch')
    (source / 'Cargo.lock').write_bytes(frozen)
    original_meta = metadata(source, evidence / 'original-metadata.json')
    package = next(p for p in original_meta['packages'] if p['name'] == 'dudect-bencher')
    if package['version'] != '0.7.0':
        raise ValueError('wrong dudect version')
    upstream = Path(package['manifest_path']).parent
    vendor = work / 'dudect'
    shutil.copytree(upstream, vendor, ignore=shutil.ignore_patterns('target', '.git'))
    # Standalone synthetic qualification only; its lock is separate from timing builds.
    with (vendor / 'Cargo.toml').open('a') as f:
        f.write('\n[workspace]\n')
    originals = {name: (vendor / 'src' / name).read_text() for name in ('stats.rs', 'ctbench.rs')}
    patch(vendor)
    with (vendor / 'src/ctbench.rs').open('a') as f:
        f.write((HERE / 'export-regression.rs').read_text())
    # A qualification failure stops preparation before either timing binary is built.
    run(['cargo', 'test', '--manifest-path', str(vendor / 'Cargo.toml'), '--lib'], work,
        evidence / 'synthetic-tests.log')
    patch_text = ''
    for name, old in originals.items():
        new = (vendor / 'src' / name).read_text()
        patch_text += ''.join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                                  fromfile='upstream/'+name, tofile='diagnostic/'+name))
    (evidence / 'exporter.patch').write_text(patch_text)
    expected = {(p['name'], p['version'], p['source']) for p in original_meta['packages']
                if p['name'] != 'dudect-bencher'}
    lock = frozen.decode()
    block = re.search(r'(?ms)^\[\[package\]\]\nname = "dudect-bencher"\n.*?(?=^\[\[package\]\]|\Z)', lock)
    if not block:
        raise ValueError('missing dudect lock entry')
    replacement = re.sub(r'(?m)^(source|checksum) = .*\n', '', block.group())
    patched_lock = lock[:block.start()] + replacement + lock[block.end():]
    for mode in ('baseline', 'diagnostic'):
        root = work / mode
        shutil.copytree(source, root, ignore=shutil.ignore_patterns('.git', 'target', 'evidence'))
        with (root / 'Cargo.toml').open('a') as f:
            f.write('\n[patch.crates-io]\ndudect-bencher = { path = "../dudect" }\n')
        (root / 'Cargo.lock').write_text(patched_lock)
        p = root / 'crates/gmcrypto-core/benches/timing_leaks.rs'
        old = p.read_text()
        marker = '    let opts = BenchOpts {'
        if old.count(marker) != 1:
            raise ValueError('bench registry changed')
        new = old.replace(marker, '''    let seed_text = std::env::var("DIAGNOSTIC_SEED").expect("DIAGNOSTIC_SEED");
    let seed = u64::from_str_radix(seed_text.trim_start_matches("0x"), 16).expect("hex seed");
    for bench in &mut benches { bench.seed = Some(seed); }

''' + marker)
        if mode == 'diagnostic':
            begin = new.index('fn ct_sm4_key_schedule(')
            end = new.index('\n}\n', begin)
            piece = new[begin:end]
            marker = '    for _ in 0..sample_count() {'
            if piece.count(marker) != 1:
                raise ValueError('key schedule target changed')
            piece = piece.replace(marker, '''    let pair = match std::env::var("DIAGNOSTIC_MODE").expect("DIAGNOSTIC_MODE").as_str() {
        "original" => (key_left, key_right),
        "swapped" => (key_right, key_left),
        "same-left" => (key_left, key_left),
        "same-right" => (key_right, key_right),
        _ => panic!("unknown diagnostic mode"),
    };
    let key_left = std::hint::black_box(pair.0);
    let key_right = std::hint::black_box(pair.1);
''' + marker)
            new = new[:begin] + piece + new[end:]
        p.write_text(new)
        (evidence / (mode + '-harness.patch')).write_text(''.join(difflib.unified_diff(
            old.splitlines(True), new.splitlines(True), fromfile='base/timing_leaks.rs',
            tofile=mode+'/timing_leaks.rs')))
        meta = metadata(root, evidence / (mode + '-metadata.json'))
        actual = {(p['name'], p['version'], p['source']) for p in meta['packages']
                  if p['name'] != 'dudect-bencher'}
        if actual != expected:
            raise ValueError('non-dudect dependency drift')
        if (root / 'Cargo.lock').read_text() != patched_lock:
            raise ValueError('generated lock drift')
        shutil.copyfile(root / 'Cargo.lock', evidence / (mode + '-lock.txt'))
        build = evidence / (mode + '-build.json')
        run(['cargo', 'bench', '--locked', '--no-run', '--bench', 'timing_leaks',
             '--features', FEATURES, '--message-format=json'], root, build)
        paths = [x['executable'] for line in build.read_text().splitlines()
                 if (x := json.loads(line)).get('reason') == 'compiler-artifact'
                 and x.get('target', {}).get('name') == 'timing_leaks' and x.get('executable')]
        if len(paths) != 1:
            raise ValueError('expected one timing binary')
        binary = evidence / (mode + '.bin')
        shutil.copyfile(paths[0], binary)
        binary.chmod(0o755)
        run(['objdump', '-d', '-C', str(binary)], root, evidence / (mode + '.asm'))
    shutil.copyfile(HERE / 'PROTOCOL.md', evidence / 'PROTOCOL.md')
    for name in ('prepare.py', 'patch_exporter.py', 'execute.py', 'export-regression.rs', 'frozen.lock'):
        shutil.copyfile(HERE / name, evidence / name)
    (evidence / 'qualified.json').write_text(json.dumps({
        'source': sha, 'original_lock_sha256': LOCK_HASH,
        'binaries': {mode: hashlib.sha256((evidence / (mode+'.bin')).read_bytes()).hexdigest()
                     for mode in ('baseline', 'diagnostic')}
    }, indent=2)+'\n')


if __name__ == '__main__':
    main(*(Path(x) for x in sys.argv[1:]))
