"""Full synthetic transport -> binding -> selection -> calibration replay."""
import base64
import copy
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_v115_capture_binding import fixture as binding_fixture
from test_v115_collect import archive, fake_get
from v115_capture_binding import canonical, digest, WORKFLOW, PRODUCER
from v115_collect import Collector
from v115_replay import verified_collection, calibration_report

START='2030-01-01'
END='2030-02-12'
SNAPSHOT='2030-02-13T00:00:00Z'
NOW=datetime(2030,2,13,1,tzinfo=timezone.utc)


def study(specs):
    """Each spec describes one scheduled default-leg job; other legs stay missing."""
    template,capture_template,files_template,_=binding_fixture()
    frozen=copy.deepcopy(template[-1]);frozen.update(calibration_start=START,calibration_end=END)
    sources=template[4];runs=[];responses={}
    responses['/actions/workflows/dudect-nightly.yml']={'id':7,'path':WORKFLOW}
    for number,spec in enumerate(specs,1):
        run=copy.deepcopy(template[0]);job=copy.deepcopy(template[1])
        started=spec.get('started','2030-01-01T05:00:00Z')
        run.update(id=number,updated_at=started,event=spec.get('event','schedule'),status='completed')
        job.update(id=100+number,run_id=number,started_at=started,status=spec.get('status','completed'),conclusion=spec.get('conclusion','success'))
        capture=copy.deepcopy(capture_template);files=files_template.copy()
        capture['metadata'].update(run_id=number,job_id=job['id'],event=run['event'],started_at=started)
        if spec.get('invalid'):capture['final_snapshot_status']='failed'
        if spec.get('breach'):files['output.log']=files['output.log'].replace(b'max tau = -0.10000',b'max tau = 0.60000')
        files['freeze.json']=canonical(frozen);capture['files']={n:digest(b) for n,b in files.items()}
        data=archive({'v115-capture/'+n:b for n,b in files.items()}|{'v115-capture/capture.json':canonical(capture)})
        artifact=dict(id=1000+number,name='v115-capture-'+str(job['id']),expired=False,digest='sha256:'+digest(data),workflow_run={'id':number,'head_sha':run['head_sha']})
        endpoint=f'/actions/runs/{number}/attempts/1'
        responses[endpoint]=run
        responses[endpoint+'/jobs?per_page=100&page=1']={'total_count':1,'jobs':[job]}
        responses[endpoint+'/logs']=archive({'job.txt':b'synthetic raw log'})
        artifacts=[] if spec.get('missing') else [artifact]
        responses[f'/actions/runs/{number}/artifacts?per_page=100&page=1']={'total_count':len(artifacts),'artifacts':artifacts}
        responses[f'/actions/artifacts/{artifact["id"]}/zip']=data
        runs.append(run)
    responses['/actions/workflows/7/runs?per_page=100&page=1']={'total_count':len(runs),'workflow_runs':runs}
    for (head,path),source in sources.items():
        responses['/contents/'+path+'?ref='+head]={'type':'file','path':path,'encoding':'base64','content':base64.b64encode(source).decode()}
    return responses,frozen


def specs_for_20_dates():
    return [dict(started=f'2030-01-{day:02d}T05:00:00Z') for day in range(1,11)]+[
           dict(started=f'2030-02-{day:02d}T05:00:00Z') for day in range(1,11)]


def report(root,specs,when=SNAPSHOT,now=NOW):
    responses,frozen=study(specs)
    with patch('v115_collect.utc_now',return_value=when):
        Collector(root,fake_get(responses)).collect('dudect-nightly.yml')
    c,files,h=verified_collection(root)
    return calibration_report(c,files,frozen,h,now)


class ReplayTests(unittest.TestCase):
    def test_transport_binding_selection_and_candidate_are_reproducible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'c';r=report(root,specs_for_20_dates())
            self.assertTrue(r['window_complete']);self.assertEqual(r['status'],'candidate-review-required')
            self.assertEqual(len(r['proposed']),4)
            self.assertTrue(all(c['bound']=='0.20' and c['dates']==20 for c in r['proposed']))
            self.assertEqual(len(r['missing_dates']),168-20)
            c,f,h=verified_collection(root);_,freeze=study(specs_for_20_dates())
            self.assertEqual(r,calibration_report(c,f,freeze,h,NOW))
            self.assertFalse(r['activation_authorized']);self.assertEqual(len(r['environment_manifest']),1)

    def test_invalid_first_draw_cannot_be_replaced_by_successful_later_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=report(Path(tmp)/'c',[dict(invalid=True),dict(started='2030-01-01T06:00:00Z')])
            self.assertEqual([j['selection'] for j in r['jobs']],['selected','later-attempt'])
            self.assertFalse(any(j['eligible'] for j in r['jobs']))
            self.assertTrue(r['jobs'][1]['binding_qualified'])
            self.assertTrue(all(c['dates']==0 for c in r['cells']))

    def test_missing_first_artifact_and_manual_success_do_not_supply_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=report(Path(tmp)/'c',[dict(missing=True),dict(event='workflow_dispatch',started='2030-01-02T05:00:00Z')])
            self.assertEqual(len(r['jobs']),2);self.assertFalse(any(j['eligible'] for j in r['jobs']))
            self.assertIn('missing-or-duplicate-job-artifact',r['jobs'][0]['issues'])
            self.assertEqual(r['status'],'insufficient evidence')

    def test_existing_gate_failure_remains_eligible_and_investigation_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=report(Path(tmp)/'c',[dict(breach=True,conclusion='failure')])
            self.assertTrue(r['jobs'][0]['eligible']);self.assertTrue(r['existing_gate_breaches'])
            self.assertTrue(all(c['status']=='investigation-required' for c in r['cells']))
            self.assertEqual(r['status'],'insufficient evidence')

    def test_no_early_derivation_even_with_sufficient_dates(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=report(Path(tmp)/'c',specs_for_20_dates(),when='2030-02-11T23:59:59Z')
            self.assertFalse(r['window_complete']);self.assertEqual(r['status'],'window-incomplete')
            self.assertEqual(r['proposed'],[])
            self.assertTrue(all('bound' not in c for c in r['cells']))

    def test_pending_selected_job_prevents_final_derivation(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=report(Path(tmp)/'c',[dict(status='in_progress')])
            self.assertEqual(r['pending_selected_jobs'],[101]);self.assertFalse(r['window_complete'])

    def test_index_tampering_and_response_tampering_are_rejected(self):
        for kind in ('index','bytes','omitted-request','incomplete'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)/'c';report(root,[{}]);p=root/'collection.json';record=json.loads(p.read_text())
                if kind=='index':record['attempts'][0]['jobs']=[]
                elif kind=='bytes':
                    path=root/next(iter(record['files']));path.write_bytes(path.read_bytes()+b'drift')
                elif kind=='omitted-request':record['requests'].pop()
                else:record['status']='incomplete'
                p.write_text(json.dumps(record))
                with self.assertRaises(ValueError):verified_collection(root)

    def test_missing_ordering_or_unknown_first_attempt_stratum_refuses_derivation(self):
        for field,value in [('started_at',None),('name','unexpected-stratum')]:
            responses,frozen=study([{}]);responses['/actions/runs/1/attempts/1/jobs?per_page=100&page=1']['jobs'][0][field]=value
            with self.subTest(field=field),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)/'c'
                with patch('v115_collect.utc_now',return_value=SNAPSHOT):Collector(root,fake_get(responses)).collect('dudect-nightly.yml')
                c,files,h=verified_collection(root)
                with self.assertRaises(ValueError):calibration_report(c,files,frozen,h,NOW)

    def test_historical_unknown_job_name_stays_excluded_in_complete_replay(self):
        responses, frozen = study([dict(started='2029-12-31T05:00:00Z')] + specs_for_20_dates())
        name = 'timing-leak nightly (100K samples, |tau|<0.20)'
        responses['/actions/runs/1/attempts/1/jobs?per_page=100&page=1']['jobs'][0]['name'] = name
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'c'
            with patch('v115_collect.utc_now', return_value=SNAPSHOT):
                Collector(root, fake_get(responses)).collect('dudect-nightly.yml')
            c, files, h = verified_collection(root)
            result = calibration_report(c, files, frozen, h, NOW)
            old = result['jobs'][0]
            self.assertEqual(old['selection'], 'outside-window')
            self.assertEqual(old['job_name'], name)
            self.assertFalse(old['eligible'])
            self.assertIn('unknown-descriptive-stratum', old['issues'])
            self.assertEqual(len(result['jobs']), 21)
            self.assertEqual(len(result['proposed']), 4)
            self.assertTrue(all(row['dates'] == 20 and row['bound'] == '0.20' for row in result['proposed']))

    def test_empty_completed_window_keeps_every_missing_date_and_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=report(Path(tmp)/'c',[])
            self.assertTrue(r['window_complete']);self.assertEqual(len(r['missing_dates']),168)
            self.assertEqual(r['status'],'insufficient evidence');self.assertEqual(len(r['fallback']),18)


if __name__=='__main__':unittest.main()
