import importlib.util
from pathlib import Path
import unittest

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

if __name__ == '__main__':
    unittest.main()
