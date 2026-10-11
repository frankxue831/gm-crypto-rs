"""Synthetic binding tests: no real workflow or timing executable is launched."""
import copy
import json
import unittest

from test_v115_collect import archive
from test_v115_evidence import captured
from v115_capture_binding import bind_capture, canonical, digest, WORKFLOW, PRODUCER
from v115_evidence import FEATURE_LEGS
from v115_collect import REPOSITORY


def fixture():
    j,_,capture,files=captured()
    head=j['head_sha'];workflow=b'synthetic reviewed workflow';producer=files['before/capture-source.py']
    identity={n.removeprefix('before/'):digest(b) for n,b in files.items() if n.startswith('before/')}
    frozen=dict(repository=REPOSITORY,workflow_path=WORKFLOW,workflow_id=7,workflow_sha256=digest(workflow),
                job_names_by_leg={leg:'nightly-'+str(i) for i,leg in enumerate(FEATURE_LEGS)},
                identity_sha256_by_leg={leg:identity.copy() for leg in FEATURE_LEGS})
    run=dict(id=j['run_id'],run_attempt=j['run_attempt'],head_sha=head,repository={'full_name':REPOSITORY},
             head_repository={'full_name':REPOSITORY},head_branch='main',event='schedule',workflow_id=7,path=WORKFLOW)
    job=dict(id=j['job_id'],run_id=run['id'],run_attempt=run['run_attempt'],name='nightly-0',started_at='2030-01-01T05:00:00Z',conclusion='failure')
    capture['metadata'].update(event='schedule',started_at=job['started_at'])
    files['freeze.json']=canonical(frozen)
    capture['files']={n:digest(b) for n,b in files.items()}
    def repack():
        data=archive({'v115-capture/'+n:b for n,b in files.items()}|{'v115-capture/capture.json':canonical(capture)})
        artifact=dict(id=123,name='v115-capture-'+str(job['id']),expired=False,digest='sha256:'+digest(data),workflow_run={'id':run['id'],'head_sha':head})
        return [artifact],{123:data}
    artifacts,archives=repack()
    sources={(head,WORKFLOW):workflow,(head,PRODUCER):producer}
    return [run,job,artifacts,archives,sources,frozen],capture,files,repack


class BindingTests(unittest.TestCase):
    def test_exact_binding_keeps_valid_observations_even_when_workflow_gate_failed(self):
        args,_,_,_=fixture();r=bind_capture(*args)
        self.assertTrue(r['binding_qualified'],r['issues'])
        self.assertTrue(r['capture']['output']['outputs_valid'])
        self.assertEqual(r['job']['feature_leg'],'default')
        self.assertEqual(r['artifact_id'],123)

    def test_unreviewed_workflow_or_producer_source_cannot_be_supplied_by_archive(self):
        for path in (WORKFLOW,PRODUCER):
            args,_,_,_=fixture();args[4][(args[0]['head_sha'],path)]+=b'drift'
            self.assertFalse(bind_capture(*args)['binding_qualified'])
            del args[4][(args[0]['head_sha'],path)]
            self.assertFalse(bind_capture(*args)['binding_qualified'])

    def test_manual_rerun_fork_and_other_workflow_remain_ineligible(self):
        for field,value in [('event','workflow_dispatch'),('run_attempt',2),('head_branch','feature'),
                            ('head_repository',{'full_name':'someone/fork'}),('workflow_id',8),('path','.github/workflows/other.yml')]:
            args,_,_,_=fixture();args[0][field]=value
            with self.subTest(field=field):self.assertFalse(bind_capture(*args)['binding_qualified'])

    def test_job_attempt_and_capture_timestamp_bound_to_api(self):
        args,_,_,_=fixture();args[1]['run_id']+=1
        self.assertFalse(bind_capture(*args)['binding_qualified'])
        for field,value in [('started_at','2030-01-02T05:00:00Z'),('event','workflow_dispatch')]:
            args,c,_,repack=fixture();c['metadata'][field]=value;args[2],args[3]=repack()
            self.assertFalse(bind_capture(*args)['binding_qualified'])

    def test_missing_duplicate_expired_or_wrong_job_artifact_excluded(self):
        for mode in ('missing','duplicate','expired','name','run','head','bytes','digest'):
            args,_,_,_=fixture();a=args[2][0]
            if mode=='missing':args[3].clear()
            elif mode=='duplicate':args[2].append(copy.deepcopy(a))
            elif mode=='expired':a['expired']=True
            elif mode=='name':a['name']='v115-capture-other'
            elif mode=='run':a['workflow_run']['id']+=1
            elif mode=='head':a['workflow_run']['head_sha']='b'*40
            elif mode=='bytes':args[3][123]+=b'changed'
            else:a['digest']='sha256:'+'f'*64
            with self.subTest(mode=mode):self.assertFalse(bind_capture(*args)['binding_qualified'])

    def test_captured_freeze_must_equal_reviewed_freeze(self):
        args,c,files,repack=fixture();files['freeze.json']=b'{}'
        c['files']['freeze.json']=digest(files['freeze.json']);args[2],args[3]=repack()
        r=bind_capture(*args);self.assertFalse(r['binding_qualified']);self.assertIn('captured-freeze-mismatch',r['issues'])

    def test_self_consistent_archive_cannot_redefine_frozen_identity(self):
        args,c,files,repack=fixture()
        for phase in ('before','after'):
            name=phase+'/Cargo.lock';files[name]=b'new lock';c['files'][name]=digest(files[name])
        args[2],args[3]=repack();self.assertFalse(bind_capture(*args)['binding_qualified'])

    def test_unknown_stratum_or_incomplete_freeze_raises_before_census_filtering(self):
        args,_,_,_=fixture();args[1]['name']='unknown'
        with self.assertRaisesRegex(ValueError,'stratum'):bind_capture(*args)
        args,_,_,_=fixture();del args[-1]['identity_sha256_by_leg'][FEATURE_LEGS[-1]]
        with self.assertRaisesRegex(ValueError,'four'):bind_capture(*args)

    def test_malformed_archive_or_capture_is_retained_as_exclusion(self):
        for data in (b'not zip',archive({'v115-capture/capture.json':b'[]'}),archive({'other':b'missing capture'})):
            args,_,_,_=fixture();args[3][123]=data;args[2][0]['digest']='sha256:'+digest(data)
            r=bind_capture(*args);self.assertFalse(r['binding_qualified']);self.assertEqual(r['artifact_id'],123)

    def test_isolated_capture_binds_source_separately_from_actions_head(self):
        args,c,files,repack=fixture()
        launcher=b'reviewed isolated launcher'; helper=b'reviewed isolation helper'
        source='b'*40
        amendment=dict(schema=1, repository=REPOSITORY, workflow_path=WORKFLOW,
                       workflow_id=7, source_sha=source, freeze_sha256=digest(canonical(args[-1])),
                       workflow_sha256=digest(launcher), helper_sha256=digest(helper))
        args[4][(args[0]['head_sha'],WORKFLOW)]=launcher
        args[4][(args[0]['head_sha'],'.github/scripts/v115_isolated.py')]=helper
        c['metadata']['head_sha']=source
        args[2],args[3]=repack()
        r=bind_capture(*args,isolation=amendment)
        self.assertTrue(r['binding_qualified'],r['issues'])
        self.assertEqual(r['job']['head_sha'],source)
        self.assertEqual(r['run_head_sha'],args[0]['head_sha'])
        # Neither a different measured commit nor an unreviewed launcher is eligible.
        for field in ('source_sha','workflow_sha256','helper_sha256','freeze_sha256'):
            bad=copy.deepcopy(amendment);bad[field]='c'*len(bad[field])
            with self.subTest(field=field):
                try:r=bind_capture(*args,isolation=bad)
                except ValueError:continue
                self.assertFalse(r['binding_qualified'])

    def test_isolation_does_not_reinterpret_old_capture_or_waive_provenance(self):
        args,_,_,_=fixture()
        amendment=dict(schema=1, repository=REPOSITORY, workflow_path=WORKFLOW,
                       workflow_id=7, source_sha='b'*40, freeze_sha256=digest(canonical(args[-1])),
                       workflow_sha256='c'*64,helper_sha256='d'*64)
        self.assertTrue(bind_capture(*args,isolation=amendment)['binding_qualified'])
        args[0]['event']='workflow_dispatch'
        self.assertFalse(bind_capture(*args,isolation=amendment)['binding_qualified'])


if __name__=='__main__':unittest.main()
