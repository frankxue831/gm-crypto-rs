#!/usr/bin/env python3
"""Run the unchanged v1.15 producer on pinned sources, with separate API provenance."""
import argparse
import base64
from datetime import date, datetime, timedelta
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

WORKFLOW = '.github/workflows/dudect-nightly.yml'
HELPER = '.github/scripts/v115_isolated.py'
REPOSITORY = 'frankxue831/gm-crypto-rs'
NIGHTLY_SHA = '9304fbebfadcc72b02550908f8c7e2046293dfd98886d43988308c008734a74c'


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checkout_head(root):
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()


def verify(control, root, amendment):
    frozen = json.loads((root/'docs/v1.15-execution-freeze.json').read_text())
    if (amendment.get('schema') != 1 or amendment.get('repository') != REPOSITORY
            or amendment.get('workflow_path') != WORKFLOW
            or amendment.get('workflow_id') != frozen.get('workflow_id')
            or amendment.get('freeze_sha256') != digest(canonical(frozen))
            or checkout_head(root) != amendment.get('source_sha')):
        raise ValueError('source checkout or original freeze differs from isolation amendment')
    for path, expected in ((WORKFLOW, amendment['workflow_sha256']), (HELPER, amendment['helper_sha256'])):
        if digest((control/path).read_bytes()) != expected:
            raise ValueError('unreviewed study launcher: ' + path)
    original = root/'.github/scripts/v115_nightly.py'
    if digest(original.read_bytes()) != NIGHTLY_SHA:
        raise ValueError('original capture helper changed')
    spec = importlib.util.spec_from_file_location('frozen_nightly', original)
    nightly = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(nightly)
    nightly.verify_sources(root, frozen)
    return frozen, nightly


def metadata(control, root, amendment, frozen, leg, env, get):
    run_id, attempt = int(env['GITHUB_RUN_ID']), int(env['GITHUB_RUN_ATTEMPT'])
    run = get(f'/actions/runs/{run_id}/attempts/{attempt}')
    head = checkout_head(control)
    event = env['GITHUB_EVENT_NAME']
    if (run_id <= 0 or attempt <= 0 or env.get('GITHUB_REPOSITORY') != REPOSITORY
            or run.get('repository', {}).get('full_name') != REPOSITORY
            or run.get('head_repository', {}).get('full_name') != REPOSITORY
            or run.get('id') != run_id or run.get('run_attempt') != attempt
            or run.get('head_sha') != head or run.get('workflow_id') != frozen['workflow_id']
            or run.get('path') != WORKFLOW or run.get('event') != event
            or event not in ('schedule', 'workflow_dispatch')
            or (event == 'schedule' and run.get('head_branch') != 'main')):
        raise ValueError('Actions launcher provenance mismatch')
    jobs = []
    page = 1
    while True:
        batch = get(f'/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100&page={page}')['jobs']
        jobs.extend(batch)
        if len(batch) < 100:
            break
        page += 1
        if page > 100:
            raise ValueError('unexpected job pagination')
    matches = [job for job in jobs if job.get('name') == frozen['job_names_by_leg'].get(leg)]
    if len(matches) != 1:
        raise ValueError('exactly one frozen feature-leg job required')
    job = matches[0]
    if (type(job.get('id')) is not int or job['id'] <= 0 or job.get('run_id') != run_id
            or job.get('run_attempt') != attempt):
        raise ValueError('job attempt mismatch')
    started = datetime.fromisoformat(job['started_at'].replace('Z', '+00:00'))
    if started.utcoffset() != timedelta(0):
        raise ValueError('UTC job start required')
    source = checkout_head(root)
    if source != amendment['source_sha']:
        raise ValueError('measured source checkout drift')
    return dict(run_id=run_id, run_attempt=attempt, job_id=job['id'], head_sha=source,
                feature_leg=leg, event=event, started_at=job['started_at']), head


def route(control, root, amendment, frozen, nightly, leg, env, get):
    job, run_head = metadata(control, root, amendment, frozen, leg, env, get)
    start, end = nightly.window(frozen)
    day = date.fromisoformat(job['started_at'][:10])
    selected = job['event'] == 'schedule' and job['run_attempt'] == 1 and start <= day < end
    mode = 'capture' if selected else 'preflight' if job['event'] == 'workflow_dispatch' else 'skip'
    routing = dict(route=mode, freeze_sha256=digest(canonical(frozen)), metadata=job,
                   run_head_sha=run_head, source_sha=job['head_sha'], isolation_sha256=digest(canonical(amendment)))
    (root/'capture-job.json').write_bytes(canonical(job))
    (root/'v115-route.json').write_bytes(canonical(routing))
    if env.get('GITHUB_OUTPUT'):
        with Path(env['GITHUB_OUTPUT']).open('a') as out:
            out.write(f'route={mode}\ncapture_artifact=v115-capture-{job["job_id"]}\n')
    return routing


def preflight(root, frozen, nightly, routing, env):
    """Manual dispatch compiles and seals all identities; it never runs timing."""
    lock = nightly.request_json('/contents/research/control-builds/frozen.lock?ref='+nightly.RESEARCH)
    data = base64.b64decode(lock['content'])
    if lock.get('encoding') != 'base64' or digest(data) != nightly.LOCK_SHA:
        raise ValueError('research lock digest mismatch')
    lock_path = root/'v115-frozen.lock'
    lock_path.write_bytes(data)
    evidence = root/'v115-capture'
    common = [sys.executable, str(root/nightly.PRODUCER)]
    args = ['--root', str(root), '--evidence', str(evidence)]
    process_env = dict(env, CARGO_INCREMENTAL='0')
    try:
        subprocess.run(common+['prepare']+args+['--leg', routing['metadata']['feature_leg'],
                       '--lock', str(lock_path), '--metadata', str(root/'capture-job.json')],
                       cwd=root, env=process_env, check=True)
        capture = json.loads((evidence/'capture.json').read_text())
        if capture['identity_sha256'] != frozen['identity_sha256_by_leg'][routing['metadata']['feature_leg']]:
            raise ValueError('build-only identity differs from study freeze')
    finally:
        if (evidence/'capture.json').exists():
            subprocess.run(common+['finalize']+args, cwd=root, env=process_env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--control-root', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--leg', required=True)
    args = parser.parse_args()
    control, root = args.control_root.resolve(), args.root.resolve()
    amendment = json.loads((control/'docs/v1.15-isolation.json').read_text())
    frozen, nightly = verify(control, root, amendment)
    if args.leg not in nightly.LEGS:
        raise ValueError('unknown study feature leg')
    routing = route(control, root, amendment, frozen, nightly, args.leg, os.environ, nightly.request_json)
    if routing['route'] == 'capture':
        nightly.capture(root, root/'docs/v1.15-execution-freeze.json', routing, os.environ)
    elif routing['route'] == 'preflight':
        preflight(root, frozen, nightly, routing, os.environ)
    print(routing['route'])


if __name__ == '__main__':
    main()
