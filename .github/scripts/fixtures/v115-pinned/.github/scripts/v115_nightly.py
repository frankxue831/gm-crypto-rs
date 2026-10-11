#!/usr/bin/env python3
"""Route declared calibration draws into frozen capture; never retry measurements."""
import argparse
import base64
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

REPOSITORY = 'frankxue831/gm-crypto-rs'
RESEARCH = '69ee2c2f7fe79fe6be9d7760b4b1247186eb23f7'
LOCK_SHA = 'e2800837c468ba45d21e759d50e94dc115e3f72eb3139c579305a908b60ed1c8'
CAPTURE_SHA = '0be0294a79969ddc525d4ca74ae55530158cdffc96276dba6ae1bd1ec1180d43'
WORKFLOW = '.github/workflows/dudect-nightly.yml'
PRODUCER = '.github/scripts/v115_capture.py'
LEGS = ('default','sm4-bitsliced','sm4-bitsliced-simd','sm4-bitsliced-simd,sm4-aead,sm4-xts,sm2-key-exchange,tlcp')


def canonical(value):
    return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def request_json(endpoint):
    if os.environ.get('GITHUB_REPOSITORY') != REPOSITORY:
        raise ValueError('unexpected repository')
    request = urllib.request.Request('https://api.github.com/repos/'+REPOSITORY+endpoint,
                                    headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],
                                             'Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(request,timeout=30) as response:
        return json.load(response)


def window(frozen):
    if 'calibration_start' not in frozen or 'calibration_end' not in frozen:
        raise ValueError('explicit calibration date fields required')
    start,end=frozen['calibration_start'],frozen['calibration_end']
    if start is None and end is None:
        return None
    if not isinstance(start,str) or not isinstance(end,str):
        raise ValueError('both calibration dates must be declared together')
    start,end=date.fromisoformat(start),date.fromisoformat(end)
    if end != start+timedelta(days=42):
        raise ValueError('exact 42-day calibration interval required')
    return start,end


def verify_sources(root,frozen):
    if frozen.get('repository') != REPOSITORY or frozen.get('workflow_path') != WORKFLOW:
        raise ValueError('execution freeze repository/workflow mismatch')
    if digest((root/WORKFLOW).read_bytes()) != frozen.get('workflow_sha256'):
        raise ValueError('workflow differs from execution freeze')
    if digest((root/PRODUCER).read_bytes()) != CAPTURE_SHA:
        raise ValueError('unreviewed capture implementation')
    identities=frozen.get('identity_sha256_by_leg',{})
    if set(identities)!=set(LEGS) or any(identities[leg].get('capture-source.py')!=CAPTURE_SHA for leg in LEGS):
        raise ValueError('all reviewed producer identities required')


def job_metadata(root,frozen,leg,env,get=request_json):
    run_id,attempt=int(env['GITHUB_RUN_ID']),int(env['GITHUB_RUN_ATTEMPT'])
    if run_id<=0 or attempt<=0 or env.get('GITHUB_REPOSITORY')!=REPOSITORY:
        raise ValueError('positive Actions identity and expected repository required')
    run=get(f'/actions/runs/{run_id}/attempts/{attempt}')
    head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
    if (run.get('id')!=run_id or run.get('run_attempt')!=attempt or run.get('head_sha')!=head
            or run.get('workflow_id')!=frozen.get('workflow_id') or run.get('path')!=WORKFLOW
            or run.get('event')!='schedule' or run.get('head_branch')!='main'):
        raise ValueError('API run does not match frozen scheduled checkout')
    expected=frozen.get('job_names_by_leg',{}).get(leg)
    if not expected:
        raise ValueError('exact frozen job name required')
    jobs=[]
    for retry in range(4):
        jobs=[];page=1
        while True:
            body=get(f'/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100&page={page}')
            batch=body['jobs'];jobs.extend(batch)
            if len(batch)<100:break
            page+=1
            if page>100:raise ValueError('unexpected job pagination')
        matches=[j for j in jobs if j.get('name')==expected]
        if len(matches)==1:break
        if retry<3:time.sleep(2)
    if len(matches)!=1:
        raise ValueError('cannot identify exactly one Actions job')
    job=matches[0]
    if (type(job.get('id')) is not int or job['id']<=0 or job.get('run_id')!=run_id
            or job.get('run_attempt')!=attempt):
        raise ValueError('job attempt identity mismatch')
    started=datetime.fromisoformat(job['started_at'].replace('Z','+00:00'))
    if started.utcoffset()!=timedelta(0):raise ValueError('UTC job start required')
    return dict(run_id=run_id,job_id=job['id'],run_attempt=attempt,event='schedule',head_sha=head,
                feature_leg=leg,started_at=job['started_at'])


def route(root,frozen,leg,env,get=request_json):
    if leg not in LEGS:raise ValueError('unknown feature leg')
    interval=window(frozen)
    result=dict(route='legacy',freeze_sha256=digest(canonical(frozen)))
    if interval is None or env.get('GITHUB_EVENT_NAME')!='schedule' or env.get('GITHUB_RUN_ATTEMPT')!='1':
        return result
    # Resolve the actual job start, not the clock at this later step.
    metadata=job_metadata(root,frozen,leg,env,get)
    day=date.fromisoformat(metadata['started_at'][:10])
    if not interval[0]<=day<interval[1]:return result
    result.update(route='capture',metadata=metadata)
    (root/'capture-job.json').write_bytes(canonical(metadata))
    if env.get('GITHUB_OUTPUT'):
        with Path(env['GITHUB_OUTPUT']).open('a') as out:
            out.write(f'capture_artifact=v115-capture-{metadata["job_id"]}\n')
    # A matching scheduled draw cannot silently fall back after a drift failure.
    verify_sources(root,frozen)
    return result


def capture(root,freeze_path,routing,env,invoke=subprocess.run,get=request_json):
    frozen=json.loads(freeze_path.read_text())
    if routing.get('route')!='capture' or routing.get('freeze_sha256')!=digest(canonical(frozen)):
        raise ValueError('capture routing or freeze changed')
    metadata=routing['metadata']
    if metadata['event']!='schedule' or metadata['run_attempt']!=1 or metadata['feature_leg'] not in LEGS:
        raise ValueError('not a first scheduled calibration draw')
    verify_sources(root,frozen)
    lock=get('/contents/research/control-builds/frozen.lock?ref='+RESEARCH)
    data=base64.b64decode(lock['content'])
    if lock.get('encoding')!='base64' or digest(data)!=LOCK_SHA:
        raise ValueError('research lock digest mismatch')
    lock_path=root/'v115-frozen.lock'
    if lock_path.exists() and lock_path.read_bytes()!=data:
        raise ValueError('refuse to replace drifted research lock')
    lock_path.write_bytes(data)
    evidence=root/'v115-capture'
    producer=[sys.executable,str(root/PRODUCER)]
    common=['--root',str(root),'--evidence',str(evidence)]
    process_env=dict(env,CARGO_INCREMENTAL='0')
    try:
        invoke(producer+['prepare']+common+['--leg',metadata['feature_leg'],'--lock',str(lock_path),
               '--metadata',str(root/'capture-job.json'),'--freeze',str(freeze_path)],cwd=root,env=process_env,check=True)
        for number in range(1,6):
            invoke(producer+['run-pass']+common+['--freeze',str(freeze_path),'--pass-number',str(number)],
                   cwd=root,env=process_env,check=True)
    finally:
        if (evidence/'capture.json').exists():
            invoke(producer+['finalize']+common,cwd=root,env=process_env,check=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('route','capture'))
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--freeze',type=Path,required=True)
    parser.add_argument('--leg',choices=LEGS)
    args=parser.parse_args();root=args.root.resolve();freeze=args.freeze.resolve()
    routing_path=root/'v115-route.json'
    if args.action=='route':
        if args.leg is None:parser.error('route requires --leg')
        result=route(root,json.loads(freeze.read_text()),args.leg,os.environ)
        routing_path.write_bytes(canonical(result))
        print(result['route'])
    else:
        capture(root,freeze,json.loads(routing_path.read_text()),os.environ)


if __name__=='__main__':
    main()
