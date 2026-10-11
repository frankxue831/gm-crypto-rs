"""Isolation boundary tests; no compilation or timing process runs."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import v115_isolated as isolated
import v115_nightly as nightly
from test_v115_nightly import fixture


class IsolationTests(unittest.TestCase):
    def test_route_keeps_launcher_and_source_distinct_and_never_measures_manual_or_rerun(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);f,env,get,_,_,job,run=fixture(root)
            run.update(repository={'full_name':isolated.REPOSITORY},head_repository={'full_name':isolated.REPOSITORY})
            amendment={'source_sha':'b'*40}
            control=root/'control'
            def head(path):return 'a'*40 if path==control else 'b'*40
            with patch.object(isolated,'checkout_head',side_effect=head):
                result=isolated.route(control,root,amendment,f,nightly,'default',env,get)
                self.assertEqual(result['route'],'capture')
                self.assertEqual(result['run_head_sha'],'a'*40)
                self.assertEqual(result['metadata']['head_sha'],'b'*40)
                env['GITHUB_EVENT_NAME']=run['event']='workflow_dispatch'
                self.assertEqual(isolated.route(control,root,amendment,f,nightly,'default',env,get)['route'],'preflight')
                env['GITHUB_EVENT_NAME']=run['event']='schedule'
                env['GITHUB_RUN_ATTEMPT']='2';run['run_attempt']=job['run_attempt']=2
                self.assertEqual(isolated.route(control,root,amendment,f,nightly,'default',env,get)['route'],'skip')
                env['GITHUB_RUN_ATTEMPT']='1';run['run_attempt']=job['run_attempt']=1
                job['started_at']='2030-02-12T00:00:00Z'
                self.assertEqual(isolated.route(control,root,amendment,f,nightly,'default',env,get)['route'],'skip')

    def test_wrong_api_head_branch_fork_workflow_or_source_refuses(self):
        for field,value in [('head_sha','f'*40),('head_branch','feature'),('workflow_id',8),
                            ('head_repository',{'full_name':'fork/repo'})]:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);f,env,get,_,_,_,run=fixture(root)
                run.update(repository={'full_name':isolated.REPOSITORY},head_repository={'full_name':isolated.REPOSITORY})
                run[field]=value
                with patch.object(isolated,'checkout_head',return_value='a'*40):
                    with self.assertRaises(ValueError):
                        isolated.metadata(root,root,{'source_sha':'a'*40},f,'default',env,get)

    def test_job_listing_lag_is_retried_then_refused(self):
        for visible_after,expect in ((2,'ok'),(None,'refuse')):
            with self.subTest(visible_after=visible_after),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);f,env,base,_,_,job,run=fixture(root)
                run.update(repository={'full_name':isolated.REPOSITORY},head_repository={'full_name':isolated.REPOSITORY})
                listings=[]
                def get(endpoint):
                    if '/jobs?' in endpoint:
                        listings.append(endpoint)
                        shown=visible_after is not None and len(listings)>visible_after
                        return dict(jobs=[job] if shown else [],total_count=int(shown))
                    return base(endpoint)
                with patch.object(isolated,'checkout_head',return_value='a'*40),\
                        patch.object(isolated.time,'sleep') as sleep:
                    if expect=='ok':
                        meta,_=isolated.metadata(root,root,{'source_sha':'a'*40},f,'default',env,get)
                        self.assertEqual(meta['job_id'],job['id'])
                        self.assertEqual((len(listings),sleep.call_count),(3,2))
                    else:
                        with self.assertRaisesRegex(ValueError,'exactly one frozen feature-leg job'):
                            isolated.metadata(root,root,{'source_sha':'a'*40},f,'default',env,get)
                        self.assertEqual((len(listings),sleep.call_count),(4,3))

    def test_verified_launcher_rejects_workflow_helper_freeze_or_source_drift(self):
        repository=Path(__file__).resolve().parents[2]
        import subprocess
        amendment=json.loads((repository/'docs/v1.15-isolation.json').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'source';control=Path(tmp)/'control'
            paths=(isolated.WORKFLOW,'.github/scripts/v115_capture.py','.github/scripts/v115_nightly.py','docs/v1.15-execution-freeze.json')
            for name in paths:
                dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True)
                dest.write_bytes((repository/'.github/scripts/fixtures/v115-pinned'/name).read_bytes())
            for name in (isolated.WORKFLOW,isolated.HELPER):
                dest=control/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes((repository/name).read_bytes())
            with patch.object(isolated,'checkout_head',return_value=amendment['source_sha']):
                isolated.verify(control,root,amendment)
                for base,name in ((control,isolated.WORKFLOW),(control,isolated.HELPER),(root,'docs/v1.15-execution-freeze.json')):
                    dest=base/name;original=dest.read_bytes();dest.write_bytes(b'{}')
                    with self.assertRaises(ValueError):isolated.verify(control,root,amendment)
                    dest.write_bytes(original)
            with patch.object(isolated,'checkout_head',return_value='f'*40):
                with self.assertRaises(ValueError):isolated.verify(control,root,amendment)

    def test_development_cargo_config_cannot_reach_frozen_sibling(self):
        from v115_capture import check_external_config
        with tempfile.TemporaryDirectory() as tmp:
            workspace=Path(tmp)
            control=workspace/'orchestration';source=workspace/'study-source'
            (control/'.cargo').mkdir(parents=True);source.mkdir()
            (control/'.cargo/config.toml').write_text('[build]\nrustflags = ["--cfg", "new_feature"]\n')
            env={'CARGO_HOME':str(workspace/'cargo-home')}
            check_external_config(source,env)
            # The original nested layout would expose development configuration.
            with self.assertRaisesRegex(ValueError,'external Cargo configuration'):
                check_external_config(control/'study-source',env)


if __name__=='__main__':unittest.main()
