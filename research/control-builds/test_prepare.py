"""Independent checks that partial/wrong control counts cannot qualify a build."""
import json
from pathlib import Path
import tempfile
import unittest
from prepare import verify_probe, parse_probe, validate_record


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'untimed.log'
        self.outputs={'left':[1,2],'right':[3,4]}
        self.baseline=(self.outputs,{'left':[0,0,0,5],'right':[0,0,0,5]})

    def write(self,left,right):
        self.path.write_text(f'OUTPUT left [1, 2]\nCOUNTS left {left}\nOUTPUT right [3, 4]\nCOUNTS right {right}\n')

    def test_hmac_counts_actual_compression_not_just_update_calls(self):
        self.write([1,0,1,6],[1,1,0,5]);verify_probe('ct_hmac_sm3','modest-left',self.path,self.baseline)
        self.write([1,0,1,5],[1,1,0,5])
        with self.assertRaises(ValueError):verify_probe('ct_hmac_sm3','modest-left',self.path,self.baseline)

    def test_both_signing_retries_must_contribute_exact_work(self):
        self.write([2,0,0,5],[2,2,2048,5]);verify_probe('ct_sign_k_class','gross-right',self.path,self.baseline)
        self.write([2,0,0,5],[2,2,1024,5])
        with self.assertRaises(ValueError):verify_probe('ct_sign_k_class','gross-right',self.path,self.baseline)

    def test_sham_preserves_predicate_evaluation_with_no_work(self):
        self.write([1,0,0,5],[1,1,0,5]);verify_probe('ct_fp_invert','sham',self.path,self.baseline)
        self.write([0,0,0,5],[0,0,0,5])
        with self.assertRaises(ValueError):verify_probe('ct_fp_invert','sham',self.path,self.baseline)

    def test_wrong_direction_and_changed_crypto_output_fail(self):
        self.write([1,0,0,5],[1,1,16,5])
        with self.assertRaises(ValueError):verify_probe('ct_fn_invert','modest-left',self.path,self.baseline)
        self.write([1,0,16,5],[1,1,0,5]);s=self.path.read_text().replace('OUTPUT left [1, 2]','OUTPUT left [9, 9]');self.path.write_text(s)
        with self.assertRaisesRegex(ValueError,'crypto output'):verify_probe('ct_fn_invert','modest-left',self.path,self.baseline)

    def test_failed_validation_is_not_recorded_as_qualified(self):
        record={'status':'probe-executed-validation-pending'}
        ledger=Path(self.tmp.name)/'ledger.json'
        def fail(): raise ValueError('wrong operation count')
        with self.assertRaises(ValueError):validate_record(record,fail,[record],ledger)
        self.assertEqual(json.loads(ledger.read_text())[0]['status'],'validation-failed')
        self.assertIn('wrong operation count',record['error'])

    def test_missing_and_duplicate_classes_fail(self):
        for text in ('OUTPUT left [1, 2]\nCOUNTS left [0,0,0,5]\n',
                     'OUTPUT left [1,2]\nOUTPUT left [1,2]\n'):
            self.path.write_text(text)
            with self.assertRaises(ValueError):parse_probe(self.path)


if __name__=='__main__':unittest.main()
