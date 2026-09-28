import importlib.util
from pathlib import Path
import unittest
import tempfile
import csv
import time
import contextlib
import hashlib
import io
import json
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('diagnostic_execute', Path(__file__).with_name('execute.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class DecisionTests(unittest.TestCase):
    def test_missing_or_invalid_pass_cannot_produce_median(self):
        self.assertIsNone(m.median_three(['0.01', '0.02']))
        self.assertIsNone(m.median_three(['0.01', None, '0.02']))
        self.assertIsNone(m.median_three(['0.01', 'NaN', '0.02']))
        self.assertIsNone(m.median_three(['0.01', 'Infinity', '0.02']))
        self.assertIsNone(m.median_three(['0.01', '0.02', '0.03', '0.04']))

    def test_existing_strict_bound_and_signed_absolute_statistic(self):
        self.assertEqual(m.median_three(['-0.20000', '0.19999', '0.30000']),
                         {'median_abs_tau': '0.20000', 'alarm': False})
        self.assertEqual(m.median_three(['0.00001', '-0.20001', '0.30000']),
                         {'median_abs_tau': '0.20001', 'alarm': True})

class EvidenceTests(unittest.TestCase):
    def fixture(self, directory):
        with (directory / 'raw.csv').open('w') as f:
            f.write('benchname,class,runtime\n')
            f.write('fixture,0,1\n'*5000 + 'fixture,1,2\n'*5000)
        with (directory / 'crops.csv').open('w') as f:
            f.write(m.FIELDS+'\n')
            for i in range(101):
                f.write(f'fixture,{i},inf,5000,5000,1,2,0,0,-inf,-inf,{str(i == 0).lower()}\n')
        (directory / 'stdout.log').write_text('bench fixture ... : n == +0.010M, max t = -inf, max tau = -inf,\n')

    def test_nonfinite_selected_statistics_remain_invalid(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root)
            result = m.validate(root)
            self.assertFalse(result['fixture']['valid'])
            self.assertEqual(result['fixture']['signed_tau'], '-inf')

    def test_mislabeled_samples_do_not_qualify(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root)
            p = root / 'raw.csv'
            p.write_text(p.read_text().replace('fixture,1,', 'fixture,0,'))
            with self.assertRaisesRegex(ValueError, 'incomplete raw samples'):
                m.validate(root)

    def test_duplicate_crop_or_wrong_counts_do_not_qualify(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root)
            p = root / 'crops.csv'
            original = p.read_text()
            p.write_text(original.replace('fixture,100,', 'fixture,99,'))
            with self.assertRaisesRegex(ValueError, 'duplicate crop'):
                m.validate(root)
            p.write_text(original.replace('inf,5000,5000', 'inf,4999,5001'))
            with self.assertRaisesRegex(ValueError, 'counts disagree'):
                m.validate(root)

class ControllerTests(unittest.TestCase):
    names = """negative_control ct_mul_g ct_mul_var ct_sign ct_sign_k_class
        ct_fn_invert ct_fp_invert noise_floor_fn_invert noise_floor_fp_invert
        noise_twin_class_split ct_sm4_key_schedule ct_sm4_encrypt_block
        ct_sm4_ctr_encrypt ct_hmac_sm3 ct_sm2_decrypt ct_pkcs8_decrypt
        ct_sm4_encrypt_block_bitsliced_simd ct_sm4_cbc_decrypt_fanout
        ct_sm4_gcm_decrypt ct_sm4_ccm_decrypt ct_sm4_gcm_decrypt_buffered
        ct_sm4_xts_decrypt ct_sm2_key_exchange ct_tlcp_cbc_deprotect""".split()

    def exercise(self, fault):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for mode in ('baseline', 'diagnostic'):
                (root / (mode+'.bin')).write_bytes(b'fixture')
            digest = hashlib.sha256(b'fixture').hexdigest()
            (root / 'qualified.json').write_text(json.dumps({'binaries': {'baseline': digest, 'diagnostic': digest}}))
            def evidence(path):
                baseline = path.name.endswith('baseline')
                names = self.names if baseline else [m.TARGET]
                if fault == 'missing' and baseline:
                    names = [m.TARGET, 'negative_control']
                if fault == 'extra' and not baseline:
                    names = [m.TARGET, 'negative_control']
                return {name: {'valid': not (fault == 'invalid' and name == m.TARGET),
                               'signed_tau': '1.2' if name == 'negative_control' else 'NaN' if fault == 'invalid' else '.01'} for name in names}
            with patch.dict(m.os.environ, {'D1_JOB_STARTED_AT': str(time.time())}), patch.object(m, 'validate', side_effect=evidence), patch.object(m.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), contextlib.redirect_stdout(io.StringIO()):
                try:
                    m.main(root)
                    code = 0
                except SystemExit as e:
                    code = e.code
            result = json.loads((root / 'diagnostic-result.json').read_text())
            return code, result

    def test_invalid_selected_results_cannot_complete_successfully(self):
        code, result = self.exercise('invalid')
        self.assertEqual(code, 1)
        self.assertFalse(result['complete'])

    def test_incomplete_baseline_cannot_complete_successfully(self):
        code, result = self.exercise('missing')
        self.assertEqual(code, 1)
        self.assertFalse(result['complete'])

    def test_extra_filtered_target_cannot_complete_successfully(self):
        code, result = self.exercise('extra')
        self.assertEqual(code, 1)
        self.assertFalse(result['complete'])

class BudgetTests(unittest.TestCase):
    def test_late_start_preserves_plan_without_attempting_measurement(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for mode in ('baseline', 'diagnostic'):
                (root / (mode+'.bin')).write_bytes(b'fixture')
            digest = hashlib.sha256(b'fixture').hexdigest()
            (root / 'qualified.json').write_text(json.dumps({'binaries': {'baseline': digest, 'diagnostic': digest}}))
            with patch.dict(m.os.environ, {'D1_JOB_STARTED_AT': str(time.time()-701)}):
                with self.assertRaises(SystemExit):
                    m.main(root)
            self.assertTrue((root / 'measurement-refused.json').exists())
            plan = json.loads((root / 'run-ledger.json').read_text())
            self.assertEqual(len(plan), 15)
            self.assertTrue(all(x['status'] == 'pending' for x in plan))
            self.assertEqual(list(root.glob('measurement-*/*')), [])

if __name__ == '__main__':
    unittest.main()
