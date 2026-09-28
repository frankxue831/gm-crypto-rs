"""Synthetic evidence only; these tests do not begin either study window."""
from copy import deepcopy
from datetime import date
import hashlib
import unittest

from v115_evidence import FEATURE_LEGS, select_scheduled_jobs, qualify_outputs, required_bounds

START = date(2030, 1, 1)


def job(run=1, job_id=10, start='2030-01-01T05:00:00Z', **extra):
    return dict(run_id=run, job_id=job_id, run_attempt=1, event='schedule',
                started_at=start, feature_leg='default', **extra)


def output(targets=None, feature='default'):
    # Complete production-required inventory, including nonblocking twin.
    targets = targets or ['ct_mul_g', 'ct_mul_var', 'ct_sign', 'ct_sm4_key_schedule',
                         'ct_sm4_encrypt_block', 'ct_sm4_ctr_encrypt', 'ct_sm2_decrypt',
                         'ct_pkcs8_decrypt', 'ct_fn_invert', 'ct_fp_invert',
                         'ct_sign_k_class', 'ct_hmac_sm3', 'noise_twin_class_split',
                         'negative_control']
    compiled = 'crypto-bigint-scalar' if feature == 'default' else feature + ',crypto-bigint-scalar'
    text = ''
    for i in range(1, 6):
        text += f'=== dudect run {i}/5 (features={compiled}) ===\n'
        for target in targets:
            tau = '1.00001' if target == 'negative_control' else '-0.10000'
            text += f'bench {target} seeded with 0x1234\n'
            text += f'bench {target} ... : n == 0.099M, max t = -1.50000, max tau = {tau}, (test)\n'
    return text


class SelectionTests(unittest.TestCase):
    def test_first_invalid_draw_is_selected_before_looking_at_validity(self):
        early = job(conclusion='failure', capture=None)
        late = job(2, 20, '2030-01-01T06:00:00Z', conclusion='success')
        rows = select_scheduled_jobs([late, early], START)
        self.assertEqual([(r['job_id'], r['selection']) for r in rows], [(10, 'selected'), (20, 'later-attempt')])

    def test_manual_and_rerun_cannot_replace_first_attempt(self):
        manual = job(1, 10);manual['event'] = 'workflow_dispatch'
        retry = job(2, 20);retry['run_attempt'] = 2
        scheduled = job(3, 30)
        rows = select_scheduled_jobs([manual, retry, scheduled], START)
        self.assertEqual({r['job_id']: r['selection'] for r in rows}, {10:'manual-or-other-event',20:'rerun',30:'selected'})

    def test_tie_break_and_exact_feature_strata(self):
        a, b, c = job(3, 30), job(2, 21), job(2, 20)
        d = job(4, 40);d['feature_leg'] = FEATURE_LEGS[1]
        rows = select_scheduled_jobs([a,b,c,d], START)
        self.assertEqual([r['job_id'] for r in rows if r['selection']=='selected'], [20,40])

    def test_fixed_window_boundaries_and_utc_only(self):
        rows=select_scheduled_jobs([job(start='2029-12-31T23:59:59Z'),job(2,20,'2030-02-11T23:59:59Z'),job(3,30,'2030-02-12T00:00:00Z')], START)
        self.assertEqual([r['job_id'] for r in rows if r['selection']=='selected'],[20])
        with self.assertRaises(ValueError):select_scheduled_jobs([job(start='2030-01-01T05:00:00')], START)

    def test_ambiguous_order_missing_leg_and_duplicate_ids_refuse_selection(self):
        for rows in ([job(start=None)], [job(),job()], [dict(job(),feature_leg='unknown')], [dict(job(),run_id=True)]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):select_scheduled_jobs(rows, START)

    def test_selection_does_not_mutate_evidence(self):
        raw=[job()];saved=deepcopy(raw);select_scheduled_jobs(raw,START);self.assertEqual(raw,saved)


class OutputTests(unittest.TestCase):
    def qualify(self, text=None, **kwargs):
        return qualify_outputs(text if text is not None else output(), feature_leg='default', sample_budget=100000, cpu='AMD EPYC 9V74', **kwargs)

    def test_valid_outputs_preserve_signed_values_and_seeds(self):
        r=self.qualify();self.assertTrue(r['outputs_valid'],r['issues'])
        self.assertEqual(r['tau']['ct_fn_invert'],['-0.10000']*5)
        self.assertEqual(r['observations'][0]['seed'],'0x1234')
        self.assertEqual(r['log_sha256'],hashlib.sha256(output().encode()).hexdigest())

    def test_duplicate_pass_target_or_seed_invalid_even_if_values_match(self):
        text=output()
        for bad in (text+text.splitlines()[0]+'\n',text+text.splitlines()[-1]+'\n',text.replace('bench ct_mul_g seeded with 0x1234','bench ct_mul_g seeded with 0x1234\nbench ct_mul_g seeded with 0x1234',1)):
            r=self.qualify(bad);self.assertFalse(r['outputs_valid'])

    def test_unrecognized_extra_required_bench_line_cannot_hide_a_duplicate(self):
        for line in ('bench ct_mul_g .. : malformed', 'bench ct_mul_g seeded with nonsense'):
            result = self.qualify(output() + line + '\n')
            self.assertFalse(result['outputs_valid'])
            self.assertTrue(result['observations'][-1]['malformed'])

    def test_missing_whole_target_and_seed_are_explicit(self):
        for target_line in ('bench ct_hmac_sm3', 'bench ct_mul_g seeded'):
            r=self.qualify('\n'.join(l for l in output().splitlines() if not l.startswith(target_line)))
            self.assertFalse(r['outputs_valid']);self.assertTrue(r['issues'])

    def test_nonfinite_malformed_or_wrong_precision_not_silently_dropped(self):
        for value in ('NaN','inf','1e-3','0.1000','0.100000'):
            r=self.qualify(output().replace('max tau = -0.10000','max tau = '+value,1))
            self.assertFalse(r['outputs_valid'],value)
            self.assertEqual(len(r['observations']),70)

    def test_nonfinite_max_t_or_crop_invalid(self):
        for old,new in [('max t = -1.50000','max t = NaN'),('n == 0.099M','n == infM')]:
            self.assertFalse(self.qualify(output().replace(old,new,1))['outputs_valid'])

    def test_negative_control_each_pass_and_strict_boundary(self):
        for value in ('1.00000','-1.00000','0.99999'):
            self.assertFalse(self.qualify(output().replace('1.00001',value,1))['outputs_valid'])
        self.assertTrue(self.qualify(output().replace('1.00001','-1.00001'))['outputs_valid'])

    def test_pass_order_matches_the_process_ledger(self):
        text = output().replace('run 1/5', 'run TEMP/5').replace('run 2/5', 'run 1/5').replace('run TEMP/5', 'run 2/5')
        self.assertFalse(self.qualify(text)['outputs_valid'])

    def test_existing_fanout_policy_uses_raw_cpu_while_cells_normalize_it(self):
        target = 'ct_sm4_cbc_decrypt_fanout'
        self.assertEqual(str(required_bounds(FEATURE_LEGS[2], 'AMD EPYC  9V74')[target]), '0.20')
        self.assertEqual(str(required_bounds(FEATURE_LEGS[2], 'AMD EPYC(TM) 9V74')[target]), '0.20')
        self.assertEqual(str(required_bounds(FEATURE_LEGS[2], 'AMD EPYC 9V74')[target]), '0.55')

    def test_budget_and_exact_feature_order(self):
        self.assertFalse(qualify_outputs(output(),feature_leg='default',sample_budget=10000,cpu='CPU')['outputs_valid'])
        self.assertFalse(self.qualify(output().replace('features=crypto-bigint-scalar','features=default,crypto-bigint-scalar'))['outputs_valid'])

    def test_gate_breach_does_not_make_an_observation_ineligible(self):
        r=self.qualify(output().replace('max tau = -0.10000','max tau = -0.55001'))
        self.assertTrue(r['outputs_valid'],r['issues'])
        self.assertIn('ct_fn_invert',r['existing_gate_breaches'])
        self.assertNotIn('noise_twin_class_split',r['existing_gate_breaches'])

    def test_optional_feature_targets_required_and_fanout_sku_rule_preserved(self):
        targets=['ct_mul_g','ct_mul_var','ct_sign','ct_sm4_key_schedule','ct_sm4_encrypt_block','ct_sm4_ctr_encrypt','ct_sm2_decrypt','ct_pkcs8_decrypt','ct_fn_invert','ct_fp_invert','ct_sign_k_class','ct_hmac_sm3','noise_twin_class_split','negative_control','ct_sm4_encrypt_block_bitsliced_simd','ct_sm4_cbc_decrypt_fanout']
        feature=FEATURE_LEGS[2];text=output(targets,feature).replace('bench ct_sm4_cbc_decrypt_fanout ... : n == 0.099M, max t = -1.50000, max tau = -0.10000','bench ct_sm4_cbc_decrypt_fanout ... : n == 0.099M, max t = -1.50000, max tau = 0.30000')
        for cpu,breach in [('AMD EPYC 9V74',False),('AMD EPYC 7763',True)]:
            r=qualify_outputs(text,feature_leg=feature,sample_budget=100000,cpu=cpu)
            self.assertTrue(r['outputs_valid'],r['issues']);self.assertEqual('ct_sm4_cbc_decrypt_fanout' in r['existing_gate_breaches'],breach)
        self.assertFalse(qualify_outputs(output(feature=feature),feature_leg=feature,sample_budget=100000,cpu='CPU')['outputs_valid'])

    def test_extra_probe_nonfinite_is_retained_but_cannot_supply_required_output(self):
        extra='bench probe_extra seeded with 0xab\nbench probe_extra ... : n == 0.000M, max t = NaN, max tau = NaN, (probe)\n'
        r=self.qualify(output()+extra)
        self.assertTrue(r['outputs_valid'],r['issues']);self.assertEqual(r['observations'][-1]['max_tau'],'NaN')
        self.assertNotIn('probe_extra',r['tau'])


from v115_evidence import IDENTITY_FILES, qualify_capture


def captured():
    h=lambda b:hashlib.sha256(b).hexdigest()
    identities={name: ('synthetic-' + name).encode() for name in IDENTITY_FILES}
    frozen={'identity_sha256_by_leg':{'default':{n:h(b) for n,b in identities.items()}}}
    files={phase+'/'+name:data for phase in ('before','after') for name,data in identities.items()}
    files.update({'timing.bin':b'synthetic-binary-never-executed', 'output.log':output().encode()})
    j=dict(job(),head_sha='a'*40)
    metadata={k:j[k] for k in ('run_id','run_attempt','job_id','head_sha','feature_leg')}
    metadata.update(cpu='AMD EPYC 9V74',image_version='synthetic-image',kernel='synthetic-kernel')
    binary=h(files['timing.bin'])
    capture={'schema':1,'status':'finalized','final_snapshot_status':'complete','metadata':metadata,'files':{n:h(b) for n,b in files.items()},
             'binary_before_sha256':binary,'binary_after_sha256':binary,
             'final_snapshot_attempts':[{'path':'snapshot-attempts/final-0001','status':'complete'}],
             'processes':[{'pass':i,'status':'completed','returncode':0,'sample_budget':100000,'features':'crypto-bigint-scalar','binary_sha256':binary} for i in range(1,6)]}
    return j,frozen,capture,files


class CaptureTests(unittest.TestCase):
    def test_complete_capture_and_signed_outputs(self):
        r=qualify_capture(*captured());self.assertTrue(r['capture_qualified'],r['issues'])

    def test_failed_or_unfinished_process_cannot_qualify_complete_looking_output(self):
        for status,code in [('failed',7),('failed',0),('started',None),('completed',7),('completed',False)]:
            j,f,c,files=captured()
            c['processes'][-1].update(status=status,returncode=code)
            with self.subTest(status=status,code=code):
                self.assertFalse(qualify_capture(j,f,c,files)['capture_qualified'])

    def test_input_drift_even_when_archive_manifest_is_consistent(self):
        for phase in ('before','after'):
            for name in IDENTITY_FILES:
                j,f,c,files=captured();path=phase+'/'+name;files[path]+=b'drift';c['files'][path]=hashlib.sha256(files[path]).hexdigest()
                with self.subTest(path=path):self.assertFalse(qualify_capture(j,f,c,files)['capture_qualified'])

    def test_missing_frozen_identity_cannot_bootstrap_from_observed_capture(self):
        for frozen in ({},{'identity_sha256_by_leg':{'default':{}}}):
            j,_,c,files=captured()
            with self.assertRaises(ValueError):qualify_capture(j,frozen,c,files)

    def test_artifact_byte_tampering_or_absence_is_invalid(self):
        for path in ('output.log','timing.bin','before/Cargo.lock'):
            j,f,c,files=captured();files[path]+=b'tamper'
            self.assertFalse(qualify_capture(j,f,c,files)['capture_qualified'])
            j,f,c,files=captured();del files[path]
            self.assertFalse(qualify_capture(j,f,c,files)['capture_qualified'])

    def test_run_job_attempt_commit_leg_provenance_mismatch(self):
        for key in ('run_id','job_id','run_attempt','head_sha','feature_leg'):
            j,f,c,files=captured();c['metadata'][key]='wrong'
            with self.subTest(key=key):self.assertFalse(qualify_capture(j,f,c,files)['capture_qualified'])

    def test_missing_environment_or_binary_mutation_or_wrong_per_process_budget(self):
        for field in ('cpu','image_version','kernel'):
            j,f,c,files=captured();c['metadata'][field]='unknown'
            self.assertFalse(qualify_capture(j,f,c,files)['capture_qualified'])
        j,f,c,files=captured();c['binary_after_sha256']='0'*64
        self.assertFalse(qualify_capture(j,f,c,files)['capture_qualified'])
        j,f,c,files=captured();c['processes'][2]['sample_budget']=10000
        self.assertFalse(qualify_capture(j,f,c,files)['capture_qualified'])

    def test_process_number_and_feature_duplicates_invalid(self):
        for key,value in [('pass',2),('features','default'),('binary_sha256','f'*64)]:
            j,f,c,files=captured();c['processes'][2][key]=value
            self.assertFalse(qualify_capture(j,f,c,files)['capture_qualified'])

    def test_failure_conclusion_does_not_suppress_complete_breach(self):
        j,f,c,files=captured();j['conclusion']='failure'
        files['output.log']=files['output.log'].replace(b'max tau = -0.10000',b'max tau = -0.55001')
        c['files']['output.log']=hashlib.sha256(files['output.log']).hexdigest()
        r=qualify_capture(j,f,c,files);self.assertTrue(r['capture_qualified'],r['issues'])
        self.assertIn('ct_fn_invert',r['output']['existing_gate_breaches'])


if __name__ == '__main__':
    unittest.main()
