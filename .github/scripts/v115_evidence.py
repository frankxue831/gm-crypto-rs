"""Selection and output qualification for accepted protocol 05035d5.

These are offline components, not a study launcher or an evidence-authenticity
verifier. The collector must supply the complete Actions job census, preserve
its provenance and bind each raw log/budget/CPU to verified capture/build
identities. ``outputs_valid`` does NOT mean code/build/environment eligible.
Do not derive candidates until that independent identity qualification passes.
Missing ordering metadata raises rather than silently selecting a replacement.
"""
from collections import Counter
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
import hashlib
import re

from v115_gate_rules import median_five, normalize_cpu

FEATURE_LEGS = (
    'default', 'sm4-bitsliced', 'sm4-bitsliced-simd',
    'sm4-bitsliced-simd,sm4-aead,sm4-xts,sm2-key-exchange,tlcp',
)
DEMOTED = ('ct_fn_invert', 'ct_fp_invert', 'ct_sign_k_class', 'ct_hmac_sm3')
LOW = ('ct_mul_g', 'ct_mul_var', 'ct_sign', 'ct_sm4_key_schedule',
       'ct_sm4_encrypt_block', 'ct_sm4_ctr_encrypt', 'ct_sm2_decrypt', 'ct_pkcs8_decrypt')
TELEMETRY = 'noise_twin_class_split'
PASS = re.compile(r'=== dudect run (\d+)/(\d+) \(features=(.*)\) ===')
SEED = re.compile(r'bench (\w+)\s+seeded with (0x[0-9a-fA-F]+)')
# Capture tokens even when invalid; never make nonfinite results disappear.
RESULT = re.compile(r'bench (\w+)\s+\.\.\. : n == (\S+)M, max t = (\S+), max tau = (\S+), .*')
NUMBER = re.compile(r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?')
TIMESTAMP = re.compile(r'^\d{4}-\d\d-\d\dT\S+Z ')
ANSI = re.compile(r'\x1b\[[0-9;]*m')


def _utc(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z', value):
        raise ValueError('unambiguous UTC job started_at required')
    return datetime.fromisoformat(value.removesuffix('Z') + '+00:00')


def select_scheduled_jobs(jobs, start):
    """Retain every supplied job; select before inspecting evidence or verdicts.

    Date is the UTC job-start date; ordering within it is start, run ID, job ID.
    All fields originate in the Actions census, not measurement output. Missing
    ordering identity in a scheduled first attempt, or stratum identity inside
    the window, is unresolved census
    evidence: the caller must retain it and repair provenance before deriving
    any table, not drop it and retry this function on a favorable subset.
    """
    if type(start) is not date:
        raise ValueError('UTC window start date required')
    end = start + timedelta(days=42)
    rows, candidates, seen = [], [], set()
    for job in jobs:
        if not isinstance(job, dict):
            raise ValueError('job metadata object required')
        for key in ('run_id', 'job_id', 'run_attempt'):
            if type(job.get(key)) is not int or job[key] <= 0:
                raise ValueError('positive integer ' + key + ' required')
        identity = job['job_id']
        if identity in seen:
            raise ValueError('duplicate job identity')
        seen.add(identity)
        if not isinstance(job.get('event'), str) or not job['event']:
            raise ValueError('event provenance required')
        row = dict(job, selection=None, utc_date=None)
        rows.append(row)
        if job['event'] != 'schedule':
            row['selection'] = 'manual-or-other-event'
        elif job['run_attempt'] != 1:
            row['selection'] = 'rerun'
        else:
            timestamp = _utc(job.get('started_at'))
            day = timestamp.date()
            row['utc_date'] = day.isoformat()
            if not start <= day < end:
                row['selection'] = 'outside-window'
            else:
                if job.get('feature_leg') not in FEATURE_LEGS:
                    raise ValueError('exact feature leg required for first-attempt selection')
                candidates.append((timestamp, job['run_id'], job['job_id'], row))
    chosen = set()
    for _, _, _, row in sorted(candidates, key=lambda item: item[:3]):
        cell = (row['utc_date'], row['feature_leg'])
        row['selection'] = 'later-attempt' if cell in chosen else 'selected'
        chosen.add(cell)
    # Output order is deterministic even for excluded rows with no start time.
    return sorted(rows, key=lambda row: (row.get('started_at') or '', row['run_id'], row['job_id']))


def required_bounds(feature_leg, cpu):
    """Mirror current nightly policy; no candidate override is accepted here."""
    if feature_leg not in FEATURE_LEGS:
        raise ValueError('unknown feature leg')
    normalize_cpu(cpu)  # Validate; existing SKU policy tests the original CPU string.
    bounds = dict.fromkeys(LOW, Decimal('0.20'))
    bounds.update(dict.fromkeys(DEMOTED, Decimal('0.55')))
    if 'sm4-bitsliced-simd' in feature_leg:
        bounds['ct_sm4_encrypt_block_bitsliced_simd'] = Decimal('0.20')
        bounds['ct_sm4_cbc_decrypt_fanout'] = Decimal('0.55' if 'EPYC 9V74' in cpu else '0.20')
    if 'sm4-aead' in feature_leg:
        bounds.update(dict.fromkeys(('ct_sm4_gcm_decrypt', 'ct_sm4_ccm_decrypt',
                                     'ct_sm4_gcm_decrypt_buffered'), Decimal('0.20')))
    if 'sm4-xts' in feature_leg:
        bounds['ct_sm4_xts_decrypt'] = Decimal('0.20')
    if 'sm2-key-exchange' in feature_leg:
        bounds['ct_sm2_key_exchange'] = Decimal('0.20')
    if 'tlcp' in feature_leg:
        bounds['ct_tlcp_cbc_deprotect'] = Decimal('0.20')
    return bounds


def _finite(token):
    try:
        return bool(NUMBER.fullmatch(token)) and Decimal(token).is_finite()
    except (InvalidOperation, TypeError):
        return False


def qualify_outputs(text, *, feature_leg, sample_budget, cpu):
    """Preserve all raw results; qualify required outputs, without hiding reds.

    sample_budget is the declared per-process budget from capture metadata, NOT
    the rounded selected crop printed as n. A small crop is retained verbatim.
    The caller must verify metadata and all process identities before using
    these outputs. This function neither trusts an exit status nor interprets
    gate-summary rounding as the five-decimal study observable.
    """
    bounds = required_bounds(feature_leg, cpu)
    required = set(bounds) | {'negative_control', TELEMETRY}
    return _qualify_outputs(text, feature_leg, sample_budget, cpu, bounds, required, False)


def qualify_filtered_outputs(text, *, target, feature_leg, sample_budget, cpu):
    """Exactly one demoted target and negative control in each of five passes.

    This validates output only. Independent build, process, source and Actions
    provenance qualification is still required before using a control result.
    """
    if target not in DEMOTED:
        raise ValueError('predeclared control target required')
    bounds = required_bounds(feature_leg, cpu)
    return _qualify_outputs(text, feature_leg, sample_budget, cpu,
                            {target: bounds[target]}, {target, 'negative_control'}, True)


def _qualify_outputs(text, feature_leg, sample_budget, cpu, bounds, required, strict):
    compiled_features = ('crypto-bigint-scalar' if feature_leg == 'default'
                         else feature_leg + ',crypto-bigint-scalar')
    issues, observations = [], []
    passes, counts, seed_counts, seeds = Counter(), Counter(), Counter(), {}
    pass_id = 0
    pass_order = []
    if type(sample_budget) is not int or sample_budget != 100000:
        issues.append('wrong-declared-sample-budget')
    for raw in text.splitlines():
        line = ANSI.sub('', TIMESTAMP.sub('', raw)).strip()
        match = PASS.fullmatch(line)
        if match:
            pass_id, total, features = int(match[1]), int(match[2]), match[3]
            passes[pass_id] += 1
            pass_order.append(pass_id)
            if total != 5 or pass_id not in range(1, 6):
                issues.append('unexpected-pass:' + str(pass_id))
            if features != compiled_features:
                issues.append('wrong-features:' + str(pass_id))
            continue
        if line.startswith('=== dudect run '):
            issues.append('malformed-pass-header')
            pass_id = 0
        match = SEED.fullmatch(line)
        if match:
            if strict and match[1] not in required:
                issues.append('unexpected-filtered-target:' + match[1])
            key = (pass_id, match[1])
            seed_counts[key] += 1
            seeds[key] = match[2]
            if match[1] in required and pass_id not in range(1, 6):
                issues.append('seed-outside-pass:' + match[1])
            continue
        match = RESULT.fullmatch(line)
        if not match:
            if line.startswith('bench ') and len(line.split()) >= 2:
                target = line.split()[1]
                if target in required:
                    issues.append('malformed-result:' + target)
                elif strict:
                    issues.append('unexpected-filtered-target:' + target)
                observations.append(dict(pass_number=pass_id, target=target, raw=line, malformed=True))
            continue
        target, n, t, tau = match.groups()
        key = (pass_id, target)
        counts[key] += 1
        observations.append(dict(pass_number=pass_id, target=target, seed=seeds.get(key),
                                 n_millions=n, max_t=t, max_tau=tau))
        if target not in required:
            if strict:
                issues.append('unexpected-filtered-target:' + target)
            continue
        if pass_id not in range(1, 6):
            issues.append('result-outside-pass:' + target)
        if not _finite(n) or Decimal(n) < 0 or not _finite(t):
            issues.append('nonfinite-or-invalid-statistic:' + target)
        if seeds.get(key) is None:
            issues.append('seed-missing-before-result:' + target)
        try:
            median_five([tau] * 5)
        except ValueError:
            issues.append('invalid-five-decimal-tau:' + target)
    if pass_order != list(range(1, 6)):
        issues.append('wrong-pass-order')
    if passes != Counter({i: 1 for i in range(1, 6)}):
        issues.append('missing-or-duplicate-passes')
    values = {}
    for target in sorted(required):
        for i in range(1, 6):
            if counts[i, target] != 1:
                issues.append(f'result-count:{i}:{target}:{counts[i,target]}')
            if seed_counts[i, target] != 1:
                issues.append(f'seed-count:{i}:{target}:{seed_counts[i,target]}')
        result = [row for row in observations if row['target'] == target]
        if len(result) == 5 and {row['pass_number'] for row in result} == set(range(1, 6)) and all('max_tau' in row for row in result):
            candidate = [row['max_tau'] for row in sorted(result, key=lambda row: row['pass_number'])]
            try:
                median_five(candidate)
                values[target] = candidate
            except ValueError:
                pass  # Raw invalid tokens remain above, alongside explicit issues.
    negative = values.get('negative_control')
    if negative is None or any(Decimal(x).copy_abs() <= 1 for x in negative):
        issues.append('negative-control-liveness')
    medians = {target: median_five(tau) for target, tau in values.items()}
    breaches = [target for target, bound in bounds.items()
                if target in medians and medians[target] > bound]
    return dict(outputs_valid=not issues, issues=sorted(set(issues)),
                cpu=normalize_cpu(cpu), feature_leg=feature_leg,
                log_sha256=hashlib.sha256(text.encode('utf-8')).hexdigest(),
                observations=observations, tau=values,
                medians={target: str(value) for target, value in medians.items()},
                existing_gate_breaches=sorted(breaches))


IDENTITY_FILES = ('source-manifest.json', 'Cargo.lock', 'resolution.json',
                  'toolchain.json', 'build-config.json', 'capture-source.py')
SHA256 = re.compile(r'[0-9a-f]{64}')


def qualify_capture(job, frozen, capture, files):
    """Bind output qualification to an independently frozen capture contract.

    ``files`` maps archive-relative names to exact bytes, after the collector
    verifies the GitHub artifact digest and associates it with this API job.
    ``frozen`` is the reviewed manifest, never values inferred from this job.
    The capture producer must snapshot inputs before and after execution; its
    reviewed source is itself frozen. Byte hashes verify retained snapshots,
    not the authenticity of an arbitrary self-authored archive. The caller
    still owes authenticated run/artifact provenance and first-attempt selection.

    The contract is implemented here for offline replay. A capture producer,
    real frozen identity files and workflow integration are separate prerequisites;
    this function does not claim that they exist or set C0.
    """
    issues = []
    for field in ('run_id', 'run_attempt', 'job_id'):
        if type(job.get(field)) is not int or job[field] <= 0:
            raise ValueError('positive integer job provenance required')
    if not isinstance(job.get('head_sha'), str) or not re.fullmatch(r'[0-9a-f]{40}', job['head_sha']):
        raise ValueError('exact source commit provenance required')
    leg = job.get('feature_leg')
    if leg not in FEATURE_LEGS:
        raise ValueError('known feature leg required')
    identities = frozen.get('identity_sha256_by_leg', {}).get(leg)
    if not isinstance(identities, dict) or set(identities) != set(IDENTITY_FILES):
        raise ValueError('complete independently frozen build identity required')
    if any(not isinstance(digest, str) or not SHA256.fullmatch(digest) for digest in identities.values()):
        raise ValueError('invalid frozen SHA-256')
    if capture.get('schema') != 1 or type(capture.get('schema')) is not int:
        issues.append('unknown-capture-schema')
    if capture.get('status') != 'finalized' or capture.get('final_snapshot_status') != 'complete':
        issues.append('final-snapshot-incomplete')
    attempts = capture.get('final_snapshot_attempts')
    if (not isinstance(attempts, list) or not attempts
            or any(not isinstance(attempt, dict) or attempt.get('status') != 'complete' for attempt in attempts)):
        issues.append('final-snapshot-attempt-failed-or-missing')
    metadata = capture.get('metadata', {})
    if not isinstance(metadata, dict):
        metadata = {};issues.append('malformed-capture-metadata')
    for field in ('run_id', 'run_attempt', 'job_id', 'head_sha', 'feature_leg'):
        if field not in job or metadata.get(field) != job[field] or type(metadata.get(field)) is not type(job[field]):
            issues.append('provenance-mismatch:' + field)
    manifest = capture.get('files')
    if not isinstance(manifest, dict):
        manifest = {};issues.append('missing-file-manifest')
    if set(manifest) != set(files):
        issues.append('file-inventory-mismatch')
    for name, data in files.items():
        if not isinstance(name, str) or name.startswith('/') or '..' in name.split('/'):
            issues.append('invalid-file-name')
        if not isinstance(data, bytes):
            raise ValueError('exact artifact bytes required')
        if hashlib.sha256(data).hexdigest() != manifest.get(name):
            issues.append('file-digest-mismatch:' + str(name))
    for phase in ('before', 'after'):
        for name, expected in identities.items():
            data = files.get(phase + '/' + name)
            if data is None or hashlib.sha256(data).hexdigest() != expected:
                issues.append('build-identity-mismatch:' + phase + '/' + name)
    binary = files.get('timing.bin')
    if binary is None or not binary:
        issues.append('missing-timing-binary');binary_digest = None
    else:
        binary_digest = hashlib.sha256(binary).hexdigest()
    for field in ('binary_before_sha256', 'binary_after_sha256'):
        if binary_digest is None or capture.get(field) != binary_digest:
            issues.append('binary-identity-mismatch:' + field)
    for field in ('cpu', 'image_version', 'kernel'):
        value = metadata.get(field)
        if not isinstance(value, str) or not value.strip() or value.strip().lower() in ('unknown', '<unset>', 'n/a', 'none'):
            issues.append('missing-environment:' + field)
    processes = capture.get('processes')
    if not isinstance(processes, list):
        processes = [];issues.append('missing-process-ledger')
    if len(processes) != 5 or any(not isinstance(p, dict) for p in processes):
        issues.append('invalid-process-ledger')
    else:
        for number, process in enumerate(processes, 1):
            expected_features = 'crypto-bigint-scalar' if leg == 'default' else leg + ',crypto-bigint-scalar'
            if (process.get('status') != 'completed' or type(process.get('returncode')) is not int
                    or process.get('returncode') != 0
                    or type(process.get('pass')) is not int or process.get('pass') != number
                    or type(process.get('sample_budget')) is not int or process.get('sample_budget') != 100000
                    or process.get('features') != expected_features
                    or binary_digest is None or process.get('binary_sha256') != binary_digest):
                issues.append('process-identity-mismatch:' + str(number))
    raw = files.get('output.log')
    result = None
    if raw is None:
        issues.append('missing-output-log')
    else:
        try:
            result = qualify_outputs(raw.decode('utf-8'), feature_leg=leg,
                                     sample_budget=100000, cpu=metadata.get('cpu'))
        except (UnicodeDecodeError, ValueError):
            issues.append('unreadable-output-or-cpu')
    if result is not None and not result['outputs_valid']:
        issues.extend('output:' + issue for issue in result['issues'])
    return dict(capture_qualified=not issues and result is not None,
                issues=sorted(set(issues)), output=result,
                binary_sha256=binary_digest,
                # Preserve metadata and declared inventory even for rejected captures.
                metadata=metadata, file_manifest=manifest)
