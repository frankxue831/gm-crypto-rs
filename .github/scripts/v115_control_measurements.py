"""Fixed control process order and partial-measurement output qualification.

No command execution, dispatch, authenticity claim or table outcome. A caller
must independently bind the Actions job, reviewed producer, control build and
retained binary before these numerical results can become usable evidence.
"""
from datetime import date, timedelta
import hashlib
import math
import re

from v115_evidence import (ANSI, TIMESTAMP, SEED, RESULT, DEMOTED, FEATURE_LEGS,
                          qualify_outputs, qualify_filtered_outputs)
from v115_gate_rules import LEAKY

VARIANTS = ('filtered', 'sham') + LEAKY
SHA256 = re.compile(r'[0-9a-f]{64}')


def dispatch_day(start, index):
    if type(start) is not date or type(index) is not int or not 0 <= index < 12:
        raise ValueError('UTC start and dispatch index 0 through 11 required')
    return start + timedelta(days=7 * (index // 2) + (1 if index % 2 == 0 else 4))


def remaining_seconds(started, now):
    """90-minute whole-job budget, including setup; reserve 120s upload + 5s kill."""
    if (any(type(x) not in (int, float) or not math.isfinite(x) for x in (started, now))
            or now < started or now - started >= 5400 - 125):
        raise ValueError('no remaining control measurement allowance')
    return 5400 - 125 - (now - started)


def process_plan(dispatch_index, feature_leg):
    """Full baseline first; zero-based target/variant rotations; no optional draws."""
    dispatch_day(date(2000, 1, 1), dispatch_index)  # Validate the fixed 12-dispatch cap.
    if feature_leg not in FEATURE_LEGS:
        raise ValueError('exact feature leg required')
    features = 'crypto-bigint-scalar' if feature_leg == 'default' else feature_leg + ',crypto-bigint-scalar'
    rows = []
    def add(target, variant, number, role):
        binary = 'baseline' if variant in ('full', 'filtered') else target + '/' + variant
        argv = ['--bench'] if role == 'full' else ['--bench', '--filter', target if role == 'target' else 'negative_control']
        rows.append(dict(sequence=len(rows), target=target, variant=variant, pass_number=number,
                         role=role, binary_key=binary, argv_tail=argv, features=features, sample_budget=100000,
                         stdout_path=f'processes/{len(rows):03d}.stdout'))
    for number in range(1, 6):
        add('full', 'full', number, 'full')
    offset = dispatch_index % len(DEMOTED)
    for target in DEMOTED[offset:] + DEMOTED[:offset]:
        for number in range(1, 6):
            offset = (number - 1) % len(VARIANTS)
            for variant in VARIANTS[offset:] + VARIANTS[:offset]:
                add(target, variant, number, 'target')
                add(target, variant, number, 'negative_control')
    return rows


def validate_prefix(plan, processes):
    """A partial ledger is a prefix of the recorded plan; no substitution/retry."""
    if not isinstance(processes, list) or len(processes) > len(plan):
        raise ValueError('bounded process ledger required')
    for expected, observed in zip(plan, processes):
        if not isinstance(observed, dict):
            raise ValueError('process record required')
        if any(type(observed.get(key)) is not int for key in ('sequence', 'pass_number', 'sample_budget')):
            raise ValueError('integer process identities required')
        if any(observed.get(key) != value for key, value in expected.items()):
            raise ValueError('process ledger differs from predeclared order')


def _single_inventory(text, name):
    """The current bench filter is substring-based: verify what actually ran."""
    seeds, results = [], []
    for raw in text.splitlines():
        line = ANSI.sub('', TIMESTAMP.sub('', raw)).strip()
        seed, result = SEED.fullmatch(line), RESULT.fullmatch(line)
        if seed:
            seeds.append(seed[1])
        elif result:
            results.append(result[1])
        elif line.startswith('bench ') or line.startswith('=== dudect run '):
            return False
    return seeds == [name] and results == [name]


def qualify_measurement(*, dispatch_index, feature_leg, target, variant,
                        processes, files, cpu, binary_sha256):
    """Validate one five-pass measurement independently of later failures.

    binary_sha256 is the independently reviewed binary identity for this exact
    target/variant. Before calling, the enclosing binder verifies the actual
    retained build, source/recipe and workflow; hash strings alone authenticate
    neither a producer nor execution. This helper returns no qualified=True
    flag for the final numerical kernel. Measurement timestamps, process/job
    deadlines, build snapshots and full artifact provenance remain caller duties.
    """
    if target not in DEMOTED or variant not in ('full',) + VARIANTS:
        raise ValueError('predeclared measurement required')
    if not isinstance(binary_sha256, str) or not SHA256.fullmatch(binary_sha256):
        raise ValueError('independently reviewed binary SHA-256 required')
    plan = process_plan(dispatch_index, feature_leg)
    validate_prefix(plan, processes)
    expected = [row for row in plan if (row['variant'] == 'full' if variant == 'full'
                else row['target'] == target and row['variant'] == variant)]
    issues, text, retained = [], '', []
    features = expected[0]['features']
    by_pass = {number: [] for number in range(1, 6)}
    for row in expected:
        sequence = row['sequence']
        if sequence >= len(processes):
            issues.append('missing-process:' + str(sequence))
            continue
        process = processes[sequence]
        retained.append(sequence)
        if (process.get('status') != 'completed' or type(process.get('returncode')) is not int
                or process['returncode'] != 0):
            issues.append('unsuccessful-process:' + str(sequence))
        for field in ('binary_sha256_before', 'binary_sha256_after'):
            if process.get(field) != binary_sha256:
                issues.append('binary-identity:' + str(sequence) + ':' + field)
        path = process.get('stdout_path')
        if (not isinstance(path, str) or path.startswith('/') or '\\' in path
                or any(part in ('', '.', '..') for part in path.split('/'))):
            issues.append('invalid-output-path:' + str(sequence))
            continue
        raw = files.get(path)
        if (not isinstance(raw, bytes) or process.get('stdout_sha256') != hashlib.sha256(raw).hexdigest()):
            issues.append('missing-or-drifted-output:' + str(sequence))
            continue
        try:
            output = raw.decode('utf-8')
        except UnicodeDecodeError:
            issues.append('unreadable-output:' + str(sequence))
            continue
        if variant != 'full' and not _single_inventory(output, target if row['role'] == 'target' else 'negative_control'):
            issues.append('wrong-process-target-inventory:' + str(sequence))
        by_pass[row['pass_number']].append(output)
    for number in range(1, 6):
        text += f'=== dudect run {number}/5 (features={features}) ===\n'
        text += '\n'.join(by_pass[number]) + '\n'
    kwargs = dict(feature_leg=feature_leg, sample_budget=100000, cpu=cpu)
    parsed = qualify_outputs(text, **kwargs) if variant == 'full' else qualify_filtered_outputs(text, target=target, **kwargs)
    issues += ['output:' + issue for issue in parsed['issues']]
    return dict(measurement_complete=not issues, issues=sorted(set(issues)),
                target=target, variant=variant, process_sequences=retained,
                tau=parsed['tau'].get(target), negative_control=parsed['tau'].get('negative_control'),
                output=parsed, authentication_required=True)
