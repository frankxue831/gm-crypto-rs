"""Synthetic authenticated corpora only; no real confirmation dates or timing."""
import copy
import csv
import io
import json
from contextlib import redirect_stdout
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_v115_collect import fake_get
from test_v115_replay import study, specs_for_20_dates, SNAPSHOT, NOW
from v115_collect import Collector
from v115_capture_binding import canonical, digest
from v115_replay import verified_collection, calibration_report
from v115_confirmation import confirmation_report, candidate_contract, evaluator_hashes, main

START = date(2030, 2, 14)
END = START + timedelta(days=42)
FINISHED = END.isoformat() + 'T01:00:00Z'
EVALUATED = datetime.combine(END, datetime.min.time(), tzinfo=timezone.utc) + timedelta(hours=2)


def prospective_specs():
    return [dict(started=(START + timedelta(days=offset)).isoformat() + 'T05:00:00Z')
            for offset in list(range(10)) + list(range(28, 38))]


def collect(root, responses, when):
    with patch('v115_collect.utc_now', return_value=when):
        Collector(root, fake_get(responses)).collect('dudect-nightly.yml')
    return verified_collection(root)


def setup_candidate(root):
    responses, cf = study(specs_for_20_dates())
    c, files, h = collect(root/'calibration', responses, SNAPSHOT)
    candidate = calibration_report(c, files, cf, h, NOW)
    frozen = copy.deepcopy(cf)
    frozen.update(phase='confirmation', confirmation_start=START.isoformat(), confirmation_end=END.isoformat(),
                  t0=START.isoformat() + 'T00:00:00Z', candidate_accepted_at='2030-02-13T02:00:00Z',
                  confirmation_ready_at='2030-02-13T03:00:00Z', calibration_freeze_sha256=digest(canonical(cf)),
                  candidate_report_sha256=digest(canonical(candidate)), evaluator_sha256=evaluator_hashes(),
                  control_build_manifest_sha256='f'*64)
    return candidate, cf, frozen


def report(root, specs, when=FINISHED):
    candidate, cf, frozen = setup_candidate(root)
    responses, _ = study(specs, frozen)
    c, files, h = collect(root/'confirmation', responses, when)
    return confirmation_report(c, files, frozen, h, candidate, cf, EVALUATED)


class ConfirmationTests(unittest.TestCase):
    def test_covered_ordinary_corpus_cannot_bypass_controls_or_activate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);r=report(root, prospective_specs())
            self.assertEqual(r['ordinary_status'], 'covered')
            self.assertEqual(len(r['cells']), 4)
            self.assertTrue(all(c['dates'] == 20 and c['bound'] == '0.20' for c in r['cells']))
            self.assertEqual(len(r['ordinary_validated_environments']), 4)
            self.assertEqual(len(r['missing_dates']), 148)
            self.assertEqual(r['control_evidence_status'], 'not-evaluated')
            self.assertIsNone(r['table_outcome']);self.assertFalse(r['activation_authorized'])

    def test_cli_recomputes_candidate_and_writes_reproducible_census_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);candidate,cf,frozen=setup_candidate(root)
            responses,_=study(prospective_specs(),frozen)
            c,files,h=collect(root/'confirmation',responses,FINISHED)
            expected=confirmation_report(c,files,frozen,h,candidate,cf,EVALUATED)
            (root/'calibration-freeze.json').write_bytes(canonical(cf))
            (root/'confirmation-freeze.json').write_bytes(canonical(frozen))
            argv=['v115_confirmation.py','--calibration-collection',str(root/'calibration'),
                  '--calibration-freeze',str(root/'calibration-freeze.json'),
                  '--collection',str(root/'confirmation'),'--freeze',str(root/'confirmation-freeze.json'),
                  '--output',str(root/'result')]
            with patch('sys.argv',argv),patch('v115_confirmation.datetime') as clock,redirect_stdout(io.StringIO()):
                clock.now.return_value=EVALUATED
                main()
            self.assertEqual((root/'result/confirmation.json').read_bytes(),canonical(expected))
            for filename,count in [('jobs.csv',20),('passes.csv',1400),('exclusions.csv',148)]:
                with (root/'result'/filename).open() as stream:
                    rows=list(csv.DictReader(stream))
                self.assertEqual(len(rows),count)
            self.assertEqual(rows[0]['reason'],'no-attempted-job')

    def test_candidate_breach_rejects_without_refitting_bound(self):
        specs=prospective_specs();specs[0]['tau_by_target']={'ct_fn_invert':'0.25000'}
        with tempfile.TemporaryDirectory() as tmp:
            r=report(Path(tmp), specs)
            self.assertEqual(r['ordinary_status'], 'rejected')
            self.assertEqual([b['target'] for b in r['candidate_breaches']], ['ct_fn_invert'])
            self.assertTrue(all(c['bound'] == '0.20' for c in r['cells']))

    def test_equality_passes_and_low_target_breach_outside_A_is_preserved(self):
        specs=prospective_specs();specs[0]['tau_by_target']={'ct_fn_invert':'0.20000','ct_mul_g':'0.60000'}
        with tempfile.TemporaryDirectory() as tmp:
            r=report(Path(tmp), specs)
            self.assertEqual(r['ordinary_status'], 'covered')
            self.assertEqual([b['target'] for b in r['existing_gate_breaches']], ['ct_mul_g'])
            self.assertIsNone(r['table_outcome']);self.assertFalse(r['activation_authorized'])

    def test_sparse_new_image_is_not_dropped(self):
        specs=prospective_specs();specs[-1]['image_version']='new-image'
        with tempfile.TemporaryDirectory() as tmp:
            r=report(Path(tmp), specs)
            self.assertEqual(r['ordinary_status'], 'insufficient-evidence')
            self.assertTrue(all(sorted(g['dates'] for g in c['subgroups']) == [1,19] for c in r['cells']))
            self.assertEqual(r['ordinary_validated_environments'], [])

    def test_invalid_first_draw_cannot_be_replaced_or_reject_from_its_tau(self):
        specs=prospective_specs();specs[0].update(invalid=True,tau_by_target={'ct_fn_invert':'0.60000'})
        specs.append(dict(started=START.isoformat()+'T06:00:00Z'))
        with tempfile.TemporaryDirectory() as tmp:
            r=report(Path(tmp), specs)
            self.assertEqual(r['ordinary_status'], 'insufficient-evidence')
            self.assertEqual(r['candidate_breaches'], [])
            self.assertEqual([j['selection'] for j in r['jobs'][:2]], ['selected','later-attempt'])
            self.assertTrue(all(c['dates'] == 19 for c in r['cells']))

    def test_manual_missing_or_new_CPU_cannot_supply_changed_cell_coverage(self):
        for change in (dict(event='workflow_dispatch'),dict(missing=True),dict(cpu='A different CPU')):
            specs=prospective_specs();specs[0].update(change)
            with self.subTest(change=change),tempfile.TemporaryDirectory() as tmp:
                r=report(Path(tmp), specs)
                self.assertEqual(r['ordinary_status'], 'insufficient-evidence')
                self.assertEqual(len(r['jobs']),20)
                self.assertTrue(all(c['dates'] == 19 for c in r['cells']))
                self.assertTrue(r['fallback'])

    def test_no_complete_verdict_or_environment_before_endpoint_or_last_job(self):
        for when,pending in (((END-timedelta(days=1)).isoformat()+'T23:59:59Z',False),(FINISHED,True)):
            specs=prospective_specs()
            if pending: specs[-1]['status']='in_progress'
            with self.subTest(when=when),tempfile.TemporaryDirectory() as tmp:
                r=report(Path(tmp), specs, when)
                self.assertEqual(r['ordinary_status'],'window-incomplete')
                self.assertTrue(all(c['provisional'] for c in r['cells']))
                self.assertEqual(r['ordinary_validated_environments'],[])

    def test_tampered_candidate_subset_dates_evaluator_or_build_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate,cf,frozen=setup_candidate(Path(tmp))
            for mutation in ('report','subset','empty','dates','acceptance','evaluator','build','phase','control-manifest'):
                c,f=copy.deepcopy(candidate),copy.deepcopy(frozen)
                if mutation=='report':c['proposed'][0]['bound']='0.25'
                elif mutation=='subset':
                    c['proposed']=c['proposed'][:-1];f['candidate_report_sha256']=digest(canonical(c))
                elif mutation=='empty':
                    c['proposed']=[];f['candidate_report_sha256']=digest(canonical(c))
                elif mutation=='dates':f['confirmation_end']=(END+timedelta(days=1)).isoformat()
                elif mutation=='acceptance':f['candidate_accepted_at']=START.isoformat()+'T01:00:00Z'
                elif mutation=='evaluator':f['evaluator_sha256']['v115_gate_rules.py']='0'*64
                elif mutation=='build':f['identity_sha256_by_leg']['default']['Cargo.lock']='0'*64
                elif mutation=='phase':f['phase']='calibration'
                else:f.pop('control_build_manifest_sha256')
                with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                    candidate_contract(c,cf,f,EVALUATED)


if __name__=='__main__':unittest.main()
