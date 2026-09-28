"""Numerical boundary tests for accepted protocol 05035d5; synthetic data only."""
from datetime import date, timedelta
from decimal import Decimal, localcontext
import unittest

from v115_gate_rules import (
    Measurement, candidate_cell, confirmation_cell, control_job, median_five,
    normalize_cpu, table_outcome,
)

C0 = date(2030, 1, 1)  # Synthetic dates, never the actual study start.


def observations(value='0.10000', offsets=range(0, 40, 2)):
    return [(C0 + timedelta(days=i), [value] * 5) for i in offsets]


def usable(value='0.10000', **kwargs):
    return Measurement([value] * 5, ['1.00001'] * 5, True, **kwargs)


def controls():
    return {name: usable('0.20000' if name in ('full', 'filtered', 'sham') else '0.20001')
            for name in ('full', 'filtered', 'sham', 'modest-left', 'modest-right',
                         'gross-left', 'gross-right')}


class PrecisionTests(unittest.TestCase):
    def test_five_decimal_signed_median_not_rounded_gate_list(self):
        self.assertEqual(median_five(['-0.20001', '+0.20000', '0.20002', '-0.00000', '1.00000']), Decimal('0.20001'))

    def test_missing_duplicate_count_nonfinite_and_wrong_precision_refused(self):
        for values in (['0.10000'] * 4, ['0.10000'] * 6, ['NaN'] * 5,
                       ['Infinity'] * 5, ['0.1'] * 5, [0.1] * 5):
            with self.subTest(values=values), self.assertRaises(ValueError):
                median_five(values)

    def test_ambient_decimal_precision_does_not_move_boundaries(self):
        with localcontext() as ctx:
            ctx.prec = 1
            self.assertEqual(candidate_cell(C0, observations('0.12501'))['bound'], '0.30')
            self.assertEqual(control_job('0.20', controls())['status'], 'covered')

    def test_cpu_model_identity_preserves_all_but_literal_marks_and_whitespace(self):
        self.assertEqual(normalize_cpu(' Intel(R)  Xeon(TM) 8573C '), 'Intel Xeon 8573C')
        self.assertNotEqual(normalize_cpu('AMD EPYC 9V74'), normalize_cpu('AMD EPYC 7763'))
        self.assertEqual(normalize_cpu('Intel(r) Xeon'), 'Intel(r) Xeon')
        with self.assertRaises(ValueError): normalize_cpu(' ')


class CandidateTests(unittest.TestCase):
    def test_floor_and_half_coverage(self):
        result = candidate_cell(C0, observations())
        self.assertEqual(result['status'], 'proposed-tightening')
        self.assertEqual(result['bound'], '0.20')
        self.assertEqual(result['half_dates'], [11, 9])

    def test_nearest_rank_not_interpolated_and_decimal_upward_grid(self):
        rows = observations('0.12501')
        rows[-2:] = [(day, ['0.20000'] * 5) for day, _ in rows[-2:]]
        result = candidate_cell(C0, rows)
        self.assertEqual(result['q90'], '0.12501')
        self.assertEqual(result['bound'], '0.30')

    def test_equality_passes_candidate_and_existing_bound(self):
        rows = observations();rows[-1] = (rows[-1][0], ['0.20000'] * 5)
        self.assertEqual(candidate_cell(C0, rows)['status'], 'proposed-tightening')
        self.assertEqual(candidate_cell(C0, observations('0.55000'))['status'], 'unchanged')

    def test_breach_precedes_sparse_coverage(self):
        self.assertEqual(candidate_cell(C0, observations('0.55001', [0]))['status'], 'investigation-required')

    def test_minimum_dates_and_each_half(self):
        self.assertEqual(candidate_cell(C0, observations(offsets=range(19)))['status'], 'insufficient-calibration')
        self.assertEqual(candidate_cell(C0, observations(offsets=range(20)))['status'], 'insufficient-calibration')
        self.assertEqual(candidate_cell(C0, observations(offsets=list(range(16)) + list(range(21, 25))))['status'], 'insufficient-calibration')

    def test_fitted_bound_not_clamped_and_outlier_not_absorbed(self):
        self.assertEqual(candidate_cell(C0, observations('0.27501'))['status'], 'unchanged')
        rows = observations();rows[-1] = (rows[-1][0], ['0.20001'] * 5)
        self.assertEqual(candidate_cell(C0, rows)['status'], 'candidate-rejected')

    def test_duplicate_dates_and_outside_fixed_interval_refused(self):
        for rows in (observations() + observations(offsets=[0]), observations(offsets=[-1]), observations(offsets=[42])):
            with self.assertRaises(ValueError): candidate_cell(C0, rows)
        self.assertEqual(candidate_cell(C0, observations(offsets=[41]))['status'], 'insufficient-calibration')


class ControlTests(unittest.TestCase):
    def test_all_four_directions_detect_at_strict_boundary(self):
        self.assertEqual(control_job('0.20', controls())['status'], 'covered')
        for name in ('modest-left', 'modest-right', 'gross-left', 'gross-right'):
            rows=controls();rows[name]=usable('0.20000')
            self.assertEqual(control_job('0.20', rows)['status'], 'rejected')

    def test_baseline_or_sham_breach_rejects_even_with_other_missing(self):
        for name in ('full', 'filtered', 'sham'):
            rows=controls();rows[name]=usable('0.20001');del rows['gross-right']
            self.assertEqual(control_job('0.20', rows)['status'], 'rejected')

    def test_usable_escape_rejects_even_with_other_variant_missing(self):
        rows=controls();rows['modest-left']=usable('0.20000');del rows['gross-right']
        self.assertEqual(control_job('0.20', rows)['status'], 'rejected')

    def test_unusable_context_blocks_sensitivity_conclusion(self):
        rows=controls();del rows['full'];rows['modest-left']=usable('0.00000')
        self.assertEqual(control_job('0.20', rows)['status'], 'incomplete')

    def test_unusable_high_baseline_does_not_reject(self):
        bad = [Measurement(['0.90000']*5, ['1.00000']*5, True),
               Measurement(['0.90000']*5, ['2.00000']*5, False),
               Measurement(['0.90000']*4, ['2.00000']*5, True),
               Measurement(['NaN']*5, ['2.00000']*5, True)]
        for value in bad:
            rows=controls();rows['full']=value
            self.assertEqual(control_job('0.20', rows)['status'], 'incomplete')

    def test_missing_variant_does_not_earn_coverage(self):
        rows=controls();del rows['gross-right']
        self.assertEqual(control_job('0.20', rows)['status'], 'incomplete')

    def test_incompatible_bound_and_unknown_variant_refused(self):
        for bound in ('0.55', '0.19', '0.21', 'NaN'):
            with self.assertRaises(ValueError): control_job(bound, controls())
        rows=controls();rows['replacement']=usable()
        with self.assertRaises(ValueError): control_job('0.20', rows)


class ConfirmationTests(unittest.TestCase):
    def rows(self):
        return [(day, values, 'image1', 'kernel1') for day, values in observations()]

    def test_coverage_is_per_image_and_kernel(self):
        rows=self.rows();self.assertEqual(confirmation_cell(C0, '0.20', rows)['status'], 'covered')
        rows[-1]=(*rows[-1][:2], 'image1', 'kernel2')
        self.assertEqual(confirmation_cell(C0, '0.20', rows)['status'], 'insufficient-evidence')
        rows[-3:]=[(*r[:2], 'image1', 'kernel2') for r in rows[-3:]]
        self.assertEqual(confirmation_cell(C0, '0.20', rows)['status'], 'covered')

    def test_breach_precedes_missing_coverage(self):
        self.assertEqual(confirmation_cell(C0, '0.20', [(C0, ['0.20001']*5, 'image1', 'kernel1')])['status'], 'rejected')

    def test_invalid_identity_and_duplicate_date_refused(self):
        for rows in ([(C0, ['0.10000']*5, '', 'kernel1')], self.rows()+self.rows()[:1]):
            with self.assertRaises(ValueError): confirmation_cell(C0, '0.20', rows)

    def test_final_precedence_and_unresolved_alarm(self):
        self.assertEqual(table_outcome(has_candidates=True, rejected=True, coverage_complete=False, unresolved_gate=True), 'rejected')
        for flag in ('has_candidates', 'coverage_complete'):
            kw=dict(has_candidates=True, rejected=False, coverage_complete=True, unresolved_gate=False);kw[flag]=False
            self.assertEqual(table_outcome(**kw), 'insufficient evidence')
        self.assertEqual(table_outcome(has_candidates=True, rejected=False, coverage_complete=True, unresolved_gate=True), 'insufficient evidence')
        self.assertEqual(table_outcome(has_candidates=True, rejected=False, coverage_complete=True, unresolved_gate=False), 'eligible for activation review')


if __name__ == '__main__': unittest.main()
