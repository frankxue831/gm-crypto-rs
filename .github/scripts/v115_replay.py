#!/usr/bin/env python3
"""Replay a preserved calibration census into exclusions and a candidate table.

No network, timing execution or gate activation. The input must be a locally
preserved, authenticated v115_collect snapshot and independently reviewed freeze.
"""
import argparse
import csv
from datetime import date, datetime, timedelta, timezone
import json
from pathlib import Path
import re
import tempfile

from v115_capture_binding import bind_capture, canonical, digest, validate_freeze, WORKFLOW
from v115_collect import Collector, ApiError, REPOSITORY
from v115_evidence import select_scheduled_jobs, FEATURE_LEGS, DEMOTED
from v115_gate_rules import candidate_cell, normalize_cpu, RULE_VERSION


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z', value):
        raise ValueError('UTC timestamp required')
    return datetime.fromisoformat(value[:-1] + '+00:00')


class ReplayCollector(Collector):
    # The original raw inventory is verified once below. Avoid rehashing every
    # earlier response on every replayed request; no network is available here.
    def save(self):
        pass


def verified_collection(root):
    root = Path(root)
    index_bytes = (root / 'collection.json').read_bytes()
    original = json.loads(index_bytes)
    if (original.get('schema') != 1 or original.get('repository') != REPOSITORY
            or original.get('status') != 'complete'
            or not re.fullmatch(r'\.github/workflows/[A-Za-z0-9_-]+\.ya?ml',original.get('workflow_path',''))):
        raise ValueError('complete authenticated workflow collection required')
    files = {}
    if (root / 'raw').is_symlink() or not (root / 'raw').is_dir():
        raise ValueError('regular raw response directory required')
    for path in sorted((root / 'raw').rglob('*')):
        if path.is_symlink() or not path.is_file():
            raise ValueError('unexpected directory or symlink in raw evidence')
        name = path.relative_to(root).as_posix()
        if not re.fullmatch(r'raw/\d{6,}\.bin', name):
            raise ValueError('unexpected raw response path')
        files[name] = path.read_bytes()
    if {name:digest(data) for name,data in files.items()} != original.get('files'):
        raise ValueError('raw response inventory or digest mismatch')
    requests = original.get('requests')
    if not isinstance(requests, list):
        raise ValueError('request ledger required')
    used, index = set(), 0
    def get(endpoint):
        nonlocal index
        if index == len(requests):
            raise ValueError('missing preserved API request')
        request = requests[index];index += 1
        if endpoint != 'repos/' + REPOSITORY + request.get('endpoint', ''):
            raise ValueError('preserved API request sequence mismatch')
        timestamp(request.get('requested_at'))
        if request.get('status') == 'unavailable' and request.get('http_status') in (404,410):
            raise ApiError(request['http_status'],request.get('error','unavailable'))
        name = request.get('path')
        if request.get('status') != 'received' or name not in files or name in used:
            raise ValueError('invalid or reused response identity')
        data = files[name]
        if digest(data) != request.get('sha256'):
            raise ValueError('response does not match its request digest')
        used.add(name)
        return data
    with tempfile.TemporaryDirectory(prefix='v115-replay-') as scratch:
        rebuilt = ReplayCollector(Path(scratch)/'copy', get).collect(Path(original['workflow_path']).name)
    if index != len(requests) or used != set(files):
        raise ValueError('unreplayed requests or response files')
    for field in ('repository','workflow_id','workflow_path','runs','attempts','artifacts','sources'):
        if original.get(field) != rebuilt[field]:
            raise ValueError('collection index differs from raw API responses: ' + field)
    started, finished = timestamp(original.get('started_at')), timestamp(original.get('finished_at'))
    if finished < started or any(not started <= timestamp(r['requested_at']) <= finished for r in requests):
        raise ValueError('inconsistent collection timestamps')
    rebuilt.update(started_at=original['started_at'], finished_at=original['finished_at'])
    return rebuilt, files, digest(index_bytes)


def calibration_report(collection, files, frozen, corpus_hash, now):
    """Use only verified_collection output; no caller eligibility flags are read."""
    validate_freeze(frozen)
    start = date.fromisoformat(frozen['calibration_start'])
    end = date.fromisoformat(frozen['calibration_end'])
    if end != start + timedelta(days=42):
        raise ValueError('exact 42-day calibration interval required')
    if collection['workflow_id'] != frozen['workflow_id'] or collection['workflow_path'] != WORKFLOW:
        raise ValueError('collection workflow differs from execution freeze')
    if now.utcoffset() != timedelta(0):
        raise ValueError('UTC evaluation time required')
    finished = timestamp(collection['finished_at'])
    if now < finished:
        raise ValueError('collection timestamp is in the future')
    sources = {}
    import base64
    for source in collection['sources']:
        if source['status'] == 'received':
            body = json.loads(files[source['response_path']])
            sources[source['head_sha'],source['path']] = base64.b64decode(body['content'])
    artifacts_by_run = {}
    # Artifact API lists are authoritative; reconstructed artifact records only
    # identify downloaded bytes and explicit unavailable/digest statuses.
    # Rebuilt requests retain the exact endpoint ledger from Collector.fetch.
    for request in collection['requests']:
        match = re.fullmatch(r'/actions/runs/(\d+)/artifacts\?per_page=100&page=\d+', request['endpoint'])
        if match and request['status'] == 'received':
            artifacts_by_run.setdefault(int(match[1]),[]).extend(json.loads(files[request['path']])['artifacts'])
    archives = {a['artifact_id']:files[a['archive_path']] for a in collection['artifacts'] if a.get('archive_path') in files}
    names = {name:leg for leg,name in frozen['job_names_by_leg'].items()}
    rows, actual, no_jobs = [], {}, []
    for attempt in collection['attempts']:
        run = attempt['metadata']
        if not attempt['jobs']:
            no_jobs.append(dict(run_id=run['id'],run_attempt=run['run_attempt'],event=run.get('event'),reason='no-jobs-in-api-attempt'))
        for job in attempt['jobs']:
            row = dict(run_id=run['id'],run_attempt=run['run_attempt'],job_id=job['id'],event=run.get('event'),
                       started_at=job.get('started_at'),feature_leg=names.get(job.get('name')),
                       job_name=job.get('name'),head_sha=run['head_sha'])
            rows.append(row);actual[job['id']] = run,job
    # This call precedes any archive validity check, including for failed draws.
    selected = select_scheduled_jobs(rows, start)
    job_records, passes, groups, observed, breaches = [], [], {}, set(), []
    for row in selected:
        run,job = actual[row['job_id']]
        if row['feature_leg'] is None:
            # Other-event and known outside-window jobs remain descriptive.
            # Unknown in-window strata already raised before archive inspection.
            binding = dict(binding_qualified=False,issues=['unknown-descriptive-stratum'],capture=None,artifact_id=None)
        else:
            binding = bind_capture(run,job,artifacts_by_run.get(run['id'],[]),archives,sources,frozen)
        capture = binding['capture']
        metadata = capture['metadata'] if capture else {}
        output = capture.get('output') if capture else None
        eligible = row['selection'] == 'selected' and binding['binding_qualified']
        cpu = None
        try:
            cpu = normalize_cpu(metadata.get('cpu'))
        except ValueError:
            pass
        record = dict(row,artifact_id=binding['artifact_id'],binding_qualified=binding['binding_qualified'],eligible=eligible,
                      issues=binding['issues'],cpu=cpu,raw_cpu=metadata.get('cpu'),image_version=metadata.get('image_version'),
                      kernel=metadata.get('kernel'),job_status=job.get('status'),job_conclusion=job.get('conclusion'))
        job_records.append(record)
        if row['utc_date'] and start <= date.fromisoformat(row['utc_date']) < end and cpu is not None:
            observed.add((row['feature_leg'],cpu))
        if output:
            for observation in output['observations']:
                passes.append(dict(run_id=row['run_id'],job_id=row['job_id'],run_attempt=row['run_attempt'],
                                   feature_leg=row['feature_leg'],utc_date=row['utc_date'],cpu=cpu,
                                   image_version=metadata.get('image_version'),kernel=metadata.get('kernel'),
                                   selection=row['selection'],eligible=eligible,**observation))
            if eligible:
                day = date.fromisoformat(row['utc_date'])
                for target in DEMOTED:
                    groups.setdefault((target,row['feature_leg'],cpu),[]).append((day,output['tau'][target]))
                for target in output['existing_gate_breaches']:
                    breaches.append(dict(job_id=row['job_id'],utc_date=row['utc_date'],target=target,feature_leg=row['feature_leg'],cpu=cpu))
    present = {(r['utc_date'],r['feature_leg']) for r in selected if r['selection']=='selected'}
    absent = [dict(utc_date=(start+timedelta(days=i)).isoformat(),feature_leg=leg,reason='no-attempted-job')
              for i in range(42) for leg in FEATURE_LEGS if ((start+timedelta(days=i)).isoformat(),leg) not in present]
    deadline = datetime.combine(end,datetime.min.time(),tzinfo=timezone.utc)
    pending = [r['job_id'] for r in job_records if r['selection']=='selected' and r['job_status']!='completed']
    window_complete = finished >= deadline and now >= deadline and not pending
    cells = []
    for leg,cpu in sorted(observed):
        for target in DEMOTED:
            result = candidate_cell(start,groups.get((target,leg,cpu),[])) if window_complete else {'status':'window-incomplete'}
            cells.append(dict(target=target,feature_leg=leg,cpu=cpu,**result))
    proposed = [c for c in cells if c['status']=='proposed-tightening']
    fallback = [dict(target=target,feature_leg=leg,cpu=None,current_bound='0.55',status='unknown-or-unobserved-cpu-fallback')
                for leg in FEATURE_LEGS for target in DEMOTED]
    fallback += [dict(target='ct_sm4_cbc_decrypt_fanout',feature_leg=leg,status='unchanged',
                      policy='0.55 only when raw CPU contains EPYC 9V74; 0.20 otherwise')
                 for leg in FEATURE_LEGS if 'sm4-bitsliced-simd' in leg]
    environments = sorted({(r['feature_leg'],r['cpu'],r['image_version'],r['kernel']) for r in job_records if r['eligible']})
    extractors = {name:digest((Path(__file__).parent/name).read_bytes()) for name in
                  ('v115_replay.py','v115_collect.py','v115_capture_binding.py','v115_evidence.py','v115_gate_rules.py')}
    return dict(schema=1,extractor_sha256=extractors,environment_manifest=[dict(feature_leg=leg,cpu=cpu,image_version=image,kernel=kernel)
                for leg,cpu,image,kernel in environments],rule_version=RULE_VERSION,corpus_sha256=corpus_hash,freeze_sha256=digest(canonical(frozen)),
                calibration_start=start.isoformat(),calibration_end=end.isoformat(),window_complete=window_complete,
                status='window-incomplete' if not window_complete else 'candidate-review-required' if proposed else 'insufficient evidence',
                pending_selected_jobs=pending,no_job_attempts=no_jobs,missing_dates=absent,jobs=job_records,passes=passes,
                cells=cells,proposed=proposed,fallback=fallback,existing_gate_breaches=breaches,
                activation_authorized=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collection',required=True,type=Path)
    parser.add_argument('--freeze',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args = parser.parse_args()
    collection,files,corpus_hash = verified_collection(args.collection)
    frozen = json.loads(args.freeze.read_text())
    report = calibration_report(collection,files,frozen,corpus_hash,datetime.now(timezone.utc))
    args.output.mkdir(parents=True,exist_ok=False)
    (args.output/'calibration.json').write_bytes(canonical(report))
    columns=('run_id','job_id','run_attempt','feature_leg','utc_date','cpu','image_version','kernel',
             'selection','eligible','pass_number','target','seed','n_millions','max_t','max_tau','malformed')
    with (args.output/'passes.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=columns,extrasaction='ignore');writer.writeheader();writer.writerows(report['passes'])
    job_columns=('run_id','job_id','run_attempt','event','head_sha','started_at','utc_date','feature_leg','cpu','raw_cpu',
                 'image_version','kernel','artifact_id','job_status','job_conclusion','selection','binding_qualified','eligible','issues')
    with (args.output/'jobs.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=job_columns,extrasaction='ignore');writer.writeheader()
        writer.writerows(dict(row,issues=';'.join(row['issues'])) for row in report['jobs'])
    exclusions=[dict(row,reason=';'.join([row['selection']]+row['issues'])) for row in report['jobs'] if not row['eligible']]
    exclusions+=report['missing_dates']+report['no_job_attempts']
    with (args.output/'exclusions.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=('run_id','job_id','run_attempt','utc_date','feature_leg','reason'),extrasaction='ignore')
        writer.writeheader();writer.writerows(exclusions)
    print(json.dumps(dict(status=report['status'],jobs=len(report['jobs']),cells=len(report['cells']),proposed=len(report['proposed']))))


if __name__=='__main__':
    main()
