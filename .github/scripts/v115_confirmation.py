#!/usr/bin/env python3
"""Replay ordinary prospective draws against an independently frozen candidate.

No network, timing execution, candidate fitting or gate activation. The CLI
recomputes calibration from its authenticated collection; both input freezes
must be independently reviewed. Control binding and final outcome are separate.
"""
import argparse
from datetime import date, datetime, timedelta, timezone
import json
from pathlib import Path
import re

from v115_capture_binding import canonical, digest, validate_freeze
from v115_evidence import DEMOTED, FEATURE_LEGS
from v115_gate_rules import confirmation_cell, normalize_cpu, RULE_VERSION
from v115_replay import calibration_report, qualified_window, timestamp, verified_collection, write_census_csv

EVALUATORS = ('v115_confirmation.py', 'v115_replay.py', 'v115_collect.py',
              'v115_capture_binding.py', 'v115_evidence.py', 'v115_gate_rules.py')
SHA256 = re.compile(r'[0-9a-f]{64}')


def evaluator_hashes():
    return {name: digest((Path(__file__).parent/name).read_bytes()) for name in EVALUATORS}


def candidate_contract(calibration, calibration_freeze, frozen, now):
    """Validate the separately reviewed candidate/confirmation execution freeze.

    Hashes bind reviewed inputs; they do not authenticate a caller-invented
    approval. The CLI supplies a freshly reproduced calibration report, not a
    caller's eligibility flags or hand-picked rows.
    """
    validate_freeze(calibration_freeze)
    validate_freeze(frozen)
    if now.utcoffset() != timedelta(0):
        raise ValueError('UTC evaluation time required')
    if (frozen.get('phase') != 'confirmation'
            or calibration.get('window_complete') is not True
            or calibration.get('status') != 'candidate-review-required'
            or calibration.get('rule_version') != RULE_VERSION):
        raise ValueError('completed calibration with a proposed set and confirmation phase required')
    if (frozen.get('calibration_freeze_sha256') != digest(canonical(calibration_freeze))
            or frozen.get('candidate_report_sha256') != digest(canonical(calibration))
            or calibration.get('freeze_sha256') != digest(canonical(calibration_freeze))):
        raise ValueError('candidate report or calibration freeze differs from reviewed identity')
    if frozen.get('evaluator_sha256') != evaluator_hashes():
        raise ValueError('evaluator differs from independently reviewed freeze')
    if not isinstance(frozen.get('control_build_manifest_sha256'), str) or not SHA256.fullmatch(frozen['control_build_manifest_sha256']):
        raise ValueError('reviewed control-build manifest identity required')
    for key in ('repository', 'workflow_id', 'workflow_path', 'job_names_by_leg'):
        if frozen[key] != calibration_freeze[key]:
            raise ValueError('confirmation workflow strata differ from calibration')
    for leg in FEATURE_LEGS:
        for name, expected in calibration_freeze['identity_sha256_by_leg'][leg].items():
            if name != 'capture-source.py' and frozen['identity_sha256_by_leg'][leg][name] != expected:
                raise ValueError('confirmation source/build identity differs from calibration')
    # A separately reviewed producer may authorize confirmation, but the actual
    # crypto, harness, lock, resolution, compiler and build flags must not drift.
    start = date.fromisoformat(frozen['confirmation_start'])
    end = date.fromisoformat(frozen['confirmation_end'])
    accepted = timestamp(frozen['candidate_accepted_at'])
    ready = timestamp(frozen['confirmation_ready_at'])
    calibration_end = date.fromisoformat(calibration_freeze['calibration_end'])
    if (end != start + timedelta(days=42)
            or frozen.get('t0') != start.isoformat() + 'T00:00:00Z'
            or accepted.date() < calibration_end
            or start != max(accepted.date(), ready.date()) + timedelta(days=1)
            or now < max(accepted, ready)):
        raise ValueError('prospective T0 must follow completed calibration, acceptance and readiness')
    proposed = calibration.get('proposed')
    if not isinstance(proposed, list) or not proposed or proposed != [c for c in calibration['cells'] if c['status'] == 'proposed-tightening']:
        raise ValueError('complete nonempty frozen proposed set required')
    seen = set()
    for cell in proposed:
        key = (cell['target'], cell['feature_leg'], cell['cpu'])
        if (key in seen or key[0] not in DEMOTED or key[1] not in FEATURE_LEGS
                or normalize_cpu(key[2]) != key[2]):
            raise ValueError('unique exact candidate cells required')
        seen.add(key)
        confirmation_cell(start, cell['bound'], [])  # Validate fixed numerical grid.
    return start, end, proposed


def confirmation_report(collection, files, frozen, corpus_hash, calibration, calibration_freeze, now):
    """Evaluate ordinary coverage only; injected controls cannot be bypassed."""
    start, end, proposed = candidate_contract(calibration, calibration_freeze, frozen, now)
    census, groups, _ = qualified_window(collection, files, frozen, start, end, now)
    environments = {(date.fromisoformat(j['utc_date']), j['feature_leg'], j['cpu']):
                    (j['image_version'], j['kernel']) for j in census['jobs'] if j['eligible']}
    cells, breaches = [], []
    for cell in proposed:
        target, leg, cpu = cell['target'], cell['feature_leg'], cell['cpu']
        observations = [(day, values, *environments[(day, leg, cpu)])
                        for day, values in groups.get((target, leg, cpu), [])]
        result = confirmation_cell(start, cell['bound'], observations)
        cells.append(dict(target=target, feature_leg=leg, cpu=cpu, bound=cell['bound'],
                          provisional=not census['window_complete'], **result))
        breaches.extend(dict(utc_date=day, target=target, feature_leg=leg, cpu=cpu, bound=cell['bound'])
                        for day in result['breach_dates'])
    breaches.sort(key=lambda row: (row['utc_date'], row['feature_leg'], row['cpu'], row['target']))
    ordinary = ('window-incomplete' if not census['window_complete'] else
                'rejected' if breaches else
                'insufficient-evidence' if any(c['status'] != 'covered' for c in cells) else 'covered')
    return dict(schema=1, phase='confirmation', rule_version=RULE_VERSION,
                corpus_sha256=corpus_hash, freeze_sha256=digest(canonical(frozen)),
                candidate_report_sha256=digest(canonical(calibration)), evaluator_sha256=evaluator_hashes(),
                confirmation_start=start.isoformat(), confirmation_end=end.isoformat(),
                **census, cells=cells, candidate_breaches=breaches, ordinary_status=ordinary,
                # Keep all candidate rows, exclusions and fallbacks from the frozen report.
                calibration_cells=calibration['cells'], fallback=calibration['fallback'],
                ordinary_validated_environments=[dict(target=c['target'], feature_leg=c['feature_leg'], cpu=c['cpu'],
                    image_version=g['image_version'], kernel=g['kernel'])
                    for c in cells if census['window_complete'] and c['status'] == 'covered' for g in c['subgroups']],
                control_evidence_status='not-evaluated', table_outcome=None,
                activation_authorized=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--calibration-collection', required=True, type=Path)
    parser.add_argument('--calibration-freeze', required=True, type=Path)
    parser.add_argument('--calibration-isolation', type=Path)
    parser.add_argument('--collection', required=True, type=Path)
    parser.add_argument('--freeze', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    now = datetime.now(timezone.utc)
    c, files, h = verified_collection(args.calibration_collection)
    calibration_freeze = json.loads(args.calibration_freeze.read_text())
    calibration = calibration_report(c, files, calibration_freeze, h, now,
        isolation=json.loads(args.calibration_isolation.read_text()) if args.calibration_isolation else None)
    c, files, h = verified_collection(args.collection)
    frozen = json.loads(args.freeze.read_text())
    report = confirmation_report(c, files, frozen, h, calibration, calibration_freeze, now)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output/'confirmation.json').write_bytes(canonical(report))
    write_census_csv(report, args.output)
    print(json.dumps(dict(ordinary_status=report['ordinary_status'], cells=len(report['cells']),
                          candidate_breaches=len(report['candidate_breaches']),
                          control_evidence_status=report['control_evidence_status'], table_outcome=None)))


if __name__ == '__main__':
    main()
