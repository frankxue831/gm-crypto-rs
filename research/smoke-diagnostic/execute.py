"""Bounded D1 execution and descriptive analysis; never clear the original alarm."""
from collections import defaultdict
import csv
from decimal import Decimal, InvalidOperation
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time

SEEDS = ['0xe8c9e38888bda9cf', '0x8b6bd04cb0283e17', '0x3b2c93b5a01386fb']
ORDERS = [('original', 'swapped', 'same-left', 'same-right'),
          ('swapped', 'same-right', 'original', 'same-left'),
          ('same-left', 'original', 'same-right', 'swapped')]
TARGET = 'ct_sm4_key_schedule'
FIELDS = 'bench,crop,threshold,n_left,n_right,mean_left,mean_right,var_left,var_right,t,tau,selected'


def median_three(values):
    if len(values) != 3 or any(x is None for x in values):
        return None
    try:
        xs = [abs(Decimal(x)) for x in values]
    except (InvalidOperation, ValueError, TypeError):
        return None
    if not all(x.is_finite() for x in xs):
        return None
    value = sorted(xs)[1]
    return {'median_abs_tau': str(value), 'alarm': value > Decimal('0.20')}


def manifest(root, name):
    records = [{ 'path': str(p.relative_to(root)), 'bytes': p.stat().st_size,
                 'sha256': hashlib.sha256(p.read_bytes()).hexdigest() }
               for p in sorted(root.rglob('*')) if p.is_file() and p.name != name]
    (root / name).write_text(json.dumps(records, indent=2)+'\n')


def validate(directory):
    raw = defaultdict(lambda: ([], []))
    with (directory / 'raw.csv').open() as f:
        for row in csv.DictReader(f):
            if row['class'] not in ('0', '1'):
                raise ValueError('invalid class label')
            value = int(row['runtime'])
            if value < 0:
                raise ValueError('negative elapsed time')
            raw[row['benchname']][int(row['class'])].append(value)
    crops = defaultdict(list)
    with (directory / 'crops.csv').open() as f:
        for row in csv.DictReader(f):
            crops[row['bench']].append(row)
    summaries = defaultdict(list)
    pattern = r'bench (\S+) +\.\.\. : n == (\S+)M, max t = (\S+), max tau = (\S+),'
    for name, n, t, tau in re.findall(pattern, (directory / 'stdout.log').read_text()):
        summaries[name].append((n, t, tau))
    if not raw or raw.keys() != crops.keys() or raw.keys() != summaries.keys():
        raise ValueError('raw/crop/summary target sets differ')
    result = {}
    for name, (left, right) in raw.items():
        if len(left)+len(right) != 10000 or not left or not right:
            raise ValueError(f'{name}: incomplete raw samples')
        rows = crops[name]
        if len(rows) != 101 or sorted(int(x['crop']) for x in rows) != list(range(101)):
            raise ValueError(f'{name}: incomplete/duplicate crop indices')
        if len(summaries[name]) != 1:
            raise ValueError(f'{name}: duplicate summaries')
        for row in rows:
            threshold = float(row['threshold'])
            if math.isnan(threshold):
                raise ValueError(f'{name}: invalid threshold')
            counts = (sum(x < threshold for x in left), sum(x < threshold for x in right))
            if counts != (int(row['n_left']), int(row['n_right'])):
                raise ValueError(f'{name}: crop counts disagree with raw samples')
            if row['selected'] not in ('true', 'false'):
                raise ValueError(f'{name}: invalid selected flag')
        selected = [x for x in rows if x['selected'] == 'true']
        if len(selected) != 1:
            raise ValueError(f'{name}: expected one selected crop')
        selected = selected[0]
        _, t, tau = summaries[name][0]
        valid = all(math.isfinite(float(x)) for x in (t, tau, selected['t'], selected['tau']))
        if valid:
            if abs(float(t)-float(selected['t'])) > 0.0000051 or abs(float(tau)-float(selected['tau'])) > 0.0000051:
                raise ValueError(f'{name}: printed statistic does not match selected crop')
            selected_n = int(selected['n_left'])+int(selected['n_right'])
            if selected_n <= 0 or abs(float(selected['tau'])-float(selected['t'])/math.sqrt(selected_n)) > 1e-12:
                raise ValueError(f'{name}: selected tau normalization mismatch')
        result[name] = {'valid': valid, 'signed_t': t, 'signed_tau': tau,
                        'selected': selected, 'uncropped': next(x for x in rows if x['crop'] == '0')}
    return result


def main(root):
    root = root.resolve()
    qualified = json.loads((root / 'qualified.json').read_text())
    for mode, digest in qualified['binaries'].items():
        if hashlib.sha256((root / (mode+'.bin')).read_bytes()).hexdigest() != digest:
            raise ValueError('qualified binary hash mismatch')
    plan = []
    for block, (seed, modes) in enumerate(zip(SEEDS, ORDERS), 1):
        for mode in ('baseline',) + modes:
            plan.append({'block': block, 'seed': seed, 'mode': mode, 'status': 'pending'})
    ledger = root / 'run-ledger.json'
    ledger.write_text(json.dumps(plan, indent=2)+'\n')
    manifest(root, 'before-timing-manifest.json')
    deadline = time.monotonic()+720
    for index, item in enumerate(plan):
        remaining = deadline-time.monotonic()
        if remaining <= 1:
            break
        directory = root / f"measurement-{index+1:02d}-{item['mode']}"
        directory.mkdir()
        (directory / 'crops.csv').write_text(FIELDS+'\n')
        binary = root / ('baseline.bin' if item['mode'] == 'baseline' else 'diagnostic.bin')
        command = [str(binary), '--out', str(directory / 'raw.csv')]
        if item['mode'] != 'baseline':
            command += ['--filter', TARGET]
        env = os.environ.copy()
        env.update(DUDECT_SAMPLES='10000', DIAGNOSTIC_SEED=item['seed'],
                   DIAGNOSTIC_MODE=item['mode'], DUDECT_CROP_OUT=str(directory / 'crops.csv'))
        item.update(status='running', directory=directory.name, command=command)
        ledger.write_text(json.dumps(plan, indent=2)+'\n')
        try:
            with (directory / 'stdout.log').open('w') as out:
                proc = subprocess.run(command, env=env, stdout=out, stderr=subprocess.STDOUT,
                                      timeout=min(180, remaining), check=False)
            item.update(status='completed', exit_code=proc.returncode)
            if proc.returncode != 0:
                item['error'] = 'nonzero benchmark exit'
            else:
                item['targets'] = validate(directory)
                expected = {TARGET} if item['mode'] != 'baseline' else {TARGET, 'negative_control'}
                if not expected <= item['targets'].keys():
                    raise ValueError('required diagnostic target missing')
        except subprocess.TimeoutExpired:
            item.update(status='timeout', error='process time limit reached; no replacement')
        except (ValueError, OSError, KeyError) as error:
            item['error'] = str(error)
        ledger.write_text(json.dumps(plan, indent=2)+'\n')
    by_mode = {}
    for mode in ('baseline', 'original', 'swapped', 'same-left', 'same-right'):
        entries = [x for x in plan if x['mode'] == mode]
        values = []
        for item in entries:
            target = item.get('targets', {}).get(TARGET, {})
            values.append(target.get('signed_tau') if item.get('exit_code') == 0 and
                          not item.get('error') and target.get('valid') else None)
        by_mode[mode] = {'signed_tau': values, 'descriptive_gate': median_three(values)}
    liveness_values = []
    for item in plan:
        if item['mode'] == 'baseline':
            target = item.get('targets', {}).get('negative_control', {})
            liveness_values.append(target.get('signed_tau') if item.get('exit_code') == 0 and
                                   not item.get('error') and target.get('valid') else None)
    liveness = len(liveness_values) == 3 and all(x is not None and abs(Decimal(x)) > 1 for x in liveness_values)
    result = {'original_alarm': 'cause unresolved; this diagnostic cannot clear it',
              'negative_control_signed_tau': liveness_values, 'liveness': liveness,
              'modes': by_mode, 'complete': all(x['status'] == 'completed' and x.get('exit_code') == 0 and not x.get('error') for x in plan)}
    (root / 'diagnostic-result.json').write_text(json.dumps(result, indent=2)+'\n')
    manifest(root, 'after-timing-manifest.json')
    print(json.dumps(result, indent=2))
    if not result['complete'] or not liveness:
        raise SystemExit(1)


if __name__ == '__main__':
    main(Path(sys.argv[1]))
