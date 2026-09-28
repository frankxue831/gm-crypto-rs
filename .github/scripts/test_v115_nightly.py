"""Nightly routing/orchestration tests never launch timing or compilation."""
import base64
from datetime import date
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import v115_nightly as nightly


def fixture(root):
    producer=b'synthetic producer';workflow=b'synthetic workflow';lock=b'synthetic frozen lock'
    (root/nightly.PRODUCER).parent.mkdir(parents=True)
    (root/nightly.PRODUCER).write_bytes(producer)
    (root/nightly.WORKFLOW).parent.mkdir(parents=True)
    (root/nightly.WORKFLOW).write_bytes(workflow)
    sha=nightly.digest(producer)
    f=dict(repository=nightly.REPOSITORY,workflow_id=7,workflow_path=nightly.WORKFLOW,
           workflow_sha256=nightly.digest(workflow),calibration_start='2030-01-01',calibration_end='2030-02-12',
           job_names_by_leg={leg:'nightly-'+leg for leg in nightly.LEGS},
           identity_sha256_by_leg={leg:{'capture-source.py':sha} for leg in nightly.LEGS})
    env=dict(GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_NAME='schedule',GITHUB_REPOSITORY=nightly.REPOSITORY,
             GITHUB_OUTPUT=str(root/'outputs'),RUSTUP_TOOLCHAIN='1.95.0')
    run=dict(id=1,run_attempt=1,head_sha='a'*40,workflow_id=7,path=nightly.WORKFLOW,event='schedule',head_branch='main')
    job=dict(id=2,run_id=1,run_attempt=1,name='nightly-default',started_at='2030-01-01T05:00:00Z')
    def get(endpoint):
        if '/contents/' in endpoint:return dict(encoding='base64',content=base64.b64encode(lock).decode())
        if '/jobs?' in endpoint:return dict(jobs=[job],total_count=1)
        return run
    return f,env,get,sha,lock,job,run


class NightlyTests(unittest.TestCase):
    def test_explicit_disabled_dates_do_not_contact_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);f,e,get,*_=fixture(root);f.update(calibration_start=None,calibration_end=None)
            with patch.object(nightly,'job_metadata',side_effect=AssertionError('must not call')):
                self.assertEqual(nightly.route(root,f,'default',e)['route'],'legacy')

    def test_partial_missing_or_wrong_length_dates_are_not_silent_fallback(self):
        for f in ({},{'calibration_start':None,'calibration_end':'2030-02-12'},
                  {'calibration_start':'2030-01-01','calibration_end':'2030-02-13'}):
            with self.assertRaises(ValueError):nightly.window(f)

    def test_manual_and_rerun_use_legacy_without_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);f,e,get,*_=fixture(root)
            for field,value in [('GITHUB_EVENT_NAME','workflow_dispatch'),('GITHUB_RUN_ATTEMPT','2')]:
                env=dict(e);env[field]=value
                with patch.object(nightly,'job_metadata',side_effect=AssertionError('must not call')):
                    self.assertEqual(nightly.route(root,f,'default',env)['route'],'legacy')

    def test_actual_api_start_selects_window_and_job_specific_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);f,e,get,sha,_,job,_=fixture(root)
            with patch.object(nightly,'CAPTURE_SHA',sha),patch.object(nightly.subprocess,'check_output',return_value='a'*40):
                r=nightly.route(root,f,'default',e,get)
                self.assertEqual(r['route'],'capture');self.assertEqual(r['metadata']['job_id'],2)
                self.assertEqual((root/'outputs').read_text(),'capture_artifact=v115-capture-2\n')
                self.assertEqual(json.loads((root/'capture-job.json').read_text())['started_at'],job['started_at'])
                job['started_at']='2030-02-12T00:00:00Z'
                self.assertEqual(nightly.route(root,f,'default',e,get)['route'],'legacy')

    def test_source_drift_fails_scheduled_draw_without_legacy_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);f,e,get,sha,*_=fixture(root);(root/nightly.WORKFLOW).write_bytes(b'drift')
            with patch.object(nightly,'CAPTURE_SHA',sha),patch.object(nightly.subprocess,'check_output',return_value='a'*40):
                with self.assertRaisesRegex(ValueError,'workflow differs'):nightly.route(root,f,'default',e,get)
            self.assertTrue((root/'capture-job.json').exists())
            self.assertIn('capture_artifact=',(root/'outputs').read_text())

    def test_api_checkout_workflow_and_job_attempt_must_match(self):
        for field,value in [('head_sha','b'*40),('workflow_id',8),('event','workflow_dispatch'),('head_branch','feature')]:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);f,e,get,sha,_,_,run=fixture(root);run[field]=value
                with patch.object(nightly.subprocess,'check_output',return_value='a'*40),self.assertRaises(ValueError):
                    nightly.route(root,f,'default',e,get)

    def test_five_passes_finalize_and_exact_lock_with_no_timing_in_test(self):
        self.exercise_capture(None,['prepare']+['run-pass']*5+['finalize'])

    def test_failed_pass_finalizes_and_is_never_retried(self):
        self.exercise_capture(2,['prepare','run-pass','run-pass','finalize'])

    def exercise_capture(self,fail_pass,expected):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);f,e,get,sha,lock,*_=fixture(root)
            with patch.object(nightly,'CAPTURE_SHA',sha),patch.object(nightly,'LOCK_SHA',nightly.digest(lock)),patch.object(nightly.subprocess,'check_output',return_value='a'*40):
                r=nightly.route(root,f,'default',e,get);freeze=root/'freeze.json';freeze.write_bytes(nightly.canonical(f));calls=[]
                def invoke(command,**kwargs):
                    action=command[2];calls.append(action)
                    self.assertTrue(kwargs['check']);self.assertEqual(kwargs['env']['CARGO_INCREMENTAL'],'0')
                    if action=='prepare':
                        evidence=root/'v115-capture';evidence.mkdir();(evidence/'capture.json').write_text('{}')
                    if action=='run-pass' and int(command[-1])==fail_pass:raise subprocess.CalledProcessError(7,command)
                if fail_pass:
                    with self.assertRaises(subprocess.CalledProcessError):nightly.capture(root,freeze,r,e,invoke,get)
                else:nightly.capture(root,freeze,r,e,invoke,get)
                self.assertEqual(calls,expected);self.assertEqual((root/'v115-frozen.lock').read_bytes(),lock)

    def test_changed_freeze_and_wrong_lock_refuse_before_prepare(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);f,e,get,sha,lock,*_=fixture(root)
            with patch.object(nightly,'CAPTURE_SHA',sha),patch.object(nightly.subprocess,'check_output',return_value='a'*40):
                r=nightly.route(root,f,'default',e,get);freeze=root/'freeze.json';freeze.write_bytes(nightly.canonical(f))
                with patch.object(nightly.subprocess,'run',side_effect=AssertionError('no launch')):
                    with self.assertRaisesRegex(ValueError,'lock digest'):nightly.capture(root,freeze,r,e,get=get)
                    f['calibration_end']='2030-02-13';freeze.write_bytes(nightly.canonical(f))
                    with self.assertRaisesRegex(ValueError,'freeze changed'):nightly.capture(root,freeze,r,e,get=get)

    def test_workflow_pins_helper_bytes_and_execution_freeze_matches_workflow(self):
        root=Path(__file__).resolve().parents[2]
        workflow=(root/nightly.WORKFLOW).read_text();helper=(root/'.github/scripts/v115_nightly.py').read_bytes()
        self.assertIn(nightly.digest(helper)+'  .github/scripts/v115_nightly.py',workflow)
        f=json.loads((root/'docs/v1.15-execution-freeze.json').read_text())
        nightly.window(f)  # Null disables capture; a later declared window must remain exactly 42 days.
        self.assertEqual(f['workflow_sha256'],nightly.digest(workflow.encode()))
        nightly.verify_sources(root,f)


if __name__=='__main__':unittest.main()
