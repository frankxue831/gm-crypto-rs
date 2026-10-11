"""Synthetic authenticated-transport fixtures; no credentials or timing execution."""
import base64
import hashlib
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from v115_collect import Collector, ApiError, REPOSITORY, PRODUCER, unpack_zip, gh_get

BASE='repos/'+REPOSITORY
WORKFLOW='synthetic.yml'
PATH='.github/workflows/'+WORKFLOW
HEAD='a'*40


def archive(files):
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w') as z:
        for n,b in files.items():z.writestr(n,b)
    return out.getvalue()


def fixture():
    run=dict(id=1,workflow_id=7,head_sha=HEAD,run_attempt=2,event='schedule',updated_at='2030-01-01T06:00:00Z',repository={'full_name':REPOSITORY})
    data=archive({'evidence/capture.json':b'{}','evidence/partial.log':b'partial evidence'})
    artifact=dict(id=9,name='capture-job-12',digest='sha256:'+hashlib.sha256(data).hexdigest(),expired=False,workflow_run={'id':1,'head_sha':HEAD})
    responses={
        '/actions/workflows/'+WORKFLOW:{'id':7,'path':PATH},
        '/actions/workflows/7/runs?per_page=100&page=1':{'total_count':1,'workflow_runs':[run]},
        '/actions/runs/1/artifacts?per_page=100&page=1':{'total_count':1,'artifacts':[artifact]},
        '/actions/artifacts/9/zip':data,
    }
    for path in (PATH,PRODUCER):
        responses['/contents/'+path+'?ref='+HEAD]={'type':'file','path':path,'encoding':'base64','content':base64.b64encode(b'synthetic source').decode()}
    for attempt in (1,2):
        endpoint=f'/actions/runs/1/attempts/{attempt}'
        responses[endpoint]=dict(run,run_attempt=attempt)
        responses[endpoint+'/jobs?per_page=100&page=1']={'total_count':1,'jobs':[dict(id=10+attempt,run_id=1,run_attempt=attempt,name='capture-0',started_at=f'2030-01-01T0{attempt}:00:00Z',conclusion='failure' if attempt==1 else 'success')]}
        responses[endpoint+'/logs']=archive({'job.txt':f'attempt {attempt}'.encode()})
    return responses


def fake_get(responses):
    def get(endpoint):
        if not endpoint.startswith(BASE):raise AssertionError(endpoint)
        relative=endpoint[len(BASE):]
        if relative.startswith('/contents/.github/scripts/v115_isolated.py?ref=') and relative not in responses:
            raise ApiError(404,'helper absent on legacy revision')
        value=responses[relative]
        if isinstance(value,Exception):raise value
        return value if isinstance(value,bytes) else json.dumps(value).encode()
    return get


class CollectorTests(unittest.TestCase):
    def test_complete_census_retains_failed_first_attempt_and_successful_rerun(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'collection';r=Collector(root,fake_get(fixture())).collect(WORKFLOW)
            self.assertEqual(r['status'],'complete')
            self.assertEqual([a['jobs'][0]['conclusion'] for a in r['attempts']],['failure','success'])
            self.assertEqual([a['run_attempt'] for a in r['attempts']],[1,2])
            self.assertEqual(r['artifacts'][0]['status'],'verified')
            self.assertEqual(len(r['sources']),3)
            for path,sha in r['files'].items():self.assertEqual(hashlib.sha256((root/path).read_bytes()).hexdigest(),sha)
            self.assertNotIn('capture_qualified',r)

    def test_missing_logs_and_expired_artifact_are_explicit_without_losing_jobs(self):
        f=fixture();f['/actions/runs/1/attempts/1/logs']=ApiError(404,'gone')
        f['/actions/runs/1/artifacts?per_page=100&page=1']['artifacts'][0]['expired']=True
        with tempfile.TemporaryDirectory() as tmp:
            r=Collector(Path(tmp)/'out',fake_get(f)).collect(WORKFLOW)
            self.assertEqual(r['status'],'complete');self.assertEqual(len(r['attempts']),2)
            self.assertEqual(r['attempts'][0]['log_status'],'missing')
            self.assertEqual(r['artifacts'][0]['status'],'expired')
            self.assertTrue(any(q.get('http_status')==404 for q in r['requests']))

    def test_auth_or_server_errors_are_not_treated_as_missing_evidence(self):
        for status in (401,403,429,500,None):
            f=fixture();f['/actions/runs/1/attempts/1/logs']=ApiError(status,'unavailable')
            with self.subTest(status=status),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)/'out'
                with self.assertRaises(ApiError):Collector(root,fake_get(f)).collect(WORKFLOW)
                r=json.loads((root/'collection.json').read_text())
                self.assertEqual(r['status'],'incomplete');self.assertEqual(len(r['attempts']),1)

    def test_corrupt_or_unverifiable_artifacts_are_retained_but_not_verified(self):
        for mode,expected in [('mismatch','digest-mismatch'),('absent','missing-github-digest'),('unsafe','invalid-archive'),('provenance','provenance-mismatch')]:
            f=fixture();a=f['/actions/runs/1/artifacts?per_page=100&page=1']['artifacts'][0]
            if mode=='mismatch':a['digest']='sha256:'+'f'*64
            elif mode=='absent':a.pop('digest')
            elif mode=='provenance':a['workflow_run']['head_sha']='b'*40
            else:
                data=archive({'../escape':b'bad'});f['/actions/artifacts/9/zip']=data
                a['digest']='sha256:'+hashlib.sha256(data).hexdigest()
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)/'out';r=Collector(root,fake_get(f)).collect(WORKFLOW)
                self.assertEqual(r['artifacts'][0]['status'],expected)
                if mode!='provenance':self.assertTrue((root/r['artifacts'][0]['archive_path']).exists())

    def test_truncated_duplicate_and_over_cap_censuses_fail_closed(self):
        for mode in ('truncated','duplicate','cap'):
            f=fixture();page=f['/actions/workflows/7/runs?per_page=100&page=1']
            if mode=='truncated':page['total_count']=2
            elif mode=='duplicate':page['workflow_runs']*=2;page['total_count']=2
            else:page['total_count']=1000
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)/'out'
                with self.assertRaises(ValueError):Collector(root,fake_get(f)).collect(WORKFLOW)
                self.assertEqual(json.loads((root/'collection.json').read_text())['status'],'incomplete')
                self.assertTrue(list((root/'raw').iterdir()))

    def test_pagination_covers_all_pages_and_rejects_total_changes(self):
        for changed in (False,True):
            f={'/list?per_page=100&page=1':{'total_count':101,'jobs':[{'id':n} for n in range(1,101)]},
               '/list?per_page=100&page=2':{'total_count':102 if changed else 101,'jobs':[{'id':101}]}}
            with tempfile.TemporaryDirectory() as tmp:
                c=Collector(Path(tmp)/'out',fake_get(f))
                if changed:
                    with self.assertRaisesRegex(ValueError,'changed'):c.pages('/list','jobs')
                else:self.assertEqual(len(c.pages('/list','jobs')),101)

    def test_new_attempt_during_collection_invalidates_census(self):
        f=fixture();get=fake_get(f);seen=0
        def changing(endpoint):
            nonlocal seen
            if '/workflows/7/runs?' in endpoint:
                seen+=1
                if seen==2:
                    f['/actions/workflows/7/runs?per_page=100&page=1']['workflow_runs'][0]['run_attempt']=3
            return get(endpoint)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'out'
            with self.assertRaisesRegex(ValueError,'census changed'):Collector(root,changing).collect(WORKFLOW)
            self.assertEqual(json.loads((root/'collection.json').read_text())['status'],'incomplete')

    def test_wrong_attempt_job_or_repository_identity_refused(self):
        for mode in ('attempt','job','repository'):
            f=fixture()
            if mode=='attempt':f['/actions/runs/1/attempts/1']['run_attempt']=2
            elif mode=='job':f['/actions/runs/1/attempts/1/jobs?per_page=100&page=1']['jobs'][0]['run_id']=9
            else:f['/actions/workflows/7/runs?per_page=100&page=1']['workflow_runs'][0]['repository']['full_name']='wrong/repo'
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(ValueError):Collector(Path(tmp)/'out',fake_get(f)).collect(WORKFLOW)

    def test_existing_collection_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileExistsError):Collector(Path(tmp))

    def test_archive_rejects_symlinks_ambiguous_names_and_bad_crc(self):
        for name in ('../escape','/absolute','foo/./bar','foo//bar','windows\\path'):
            with self.subTest(name=name),self.assertRaises(ValueError):unpack_zip(archive({name:b'x'}))
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as z:
            entry=zipfile.ZipInfo('link');entry.external_attr=(stat.S_IFLNK|0o777)<<16;z.writestr(entry,'target')
        with self.assertRaises(ValueError):unpack_zip(out.getvalue())
        data=archive({'file':b'crc-data'}).replace(b'crc-data',b'bad-data')
        with self.assertRaises(zipfile.BadZipFile):unpack_zip(data)

    def test_gh_transport_is_get_only_and_fixed_repository(self):
        with patch('v115_collect.subprocess.run') as run:
            run.return_value.stdout=b'bytes';run.return_value.returncode=0
            self.assertEqual(gh_get(BASE+'/actions/runs'),b'bytes')
            self.assertEqual(run.call_args.args[0],['gh','api','--hostname','github.com','--method','GET',BASE+'/actions/runs'])
            with self.assertRaises(ValueError):gh_get('repos/other/repo/actions/runs')
            self.assertEqual(run.call_count,1)


if __name__=='__main__':unittest.main()
