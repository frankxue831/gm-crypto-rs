"""Synthetic API censuses only: no dispatch, timing or authentication claim."""
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
import unittest

from v115_collect import REPOSITORY
from v115_control_census import control_census
from v115_control_measurements import dispatch_day
from v115_evidence import FEATURE_LEGS

START = date(2030, 1, 1)
HEAD = 'a' * 40
NAMES = {leg: 'control (' + leg + ')' for leg in FEATURE_LEGS}
FREEZE = dict(repository=REPOSITORY, workflow_id=42,
              workflow_path='.github/workflows/dudect-nightly.yml',
              research_branch='codex/frozen-controls', research_head=HEAD,
              confirmation_start=START.isoformat(), job_names_by_leg=NAMES)


def stamp(value):
    return value.isoformat().replace('+00:00', 'Z')


def fixture(indices=(0,), duration=3600):
    collection = dict(repository=REPOSITORY, status='complete', workflow_id=42,
                      workflow_path=FREEZE['workflow_path'], finished_at='2030-02-13T00:00:00Z',
                      runs=[], attempts=[])
    for i in indices:
        add_run(collection, i + 1, dispatch_day(START, i), duration=duration)
    return collection


def add_run(c, identifier, day, duration=3600, attempt_count=1):
    created = datetime.combine(day, datetime.min.time(), timezone.utc)
    run = dict(id=identifier, head_branch=FREEZE['research_branch'], head_sha=HEAD,
               path=FREEZE['workflow_path'], workflow_id=42, event='workflow_dispatch',
               created_at=stamp(created), status='completed', run_attempt=attempt_count,
               repository=dict(full_name=REPOSITORY), head_repository=dict(full_name=REPOSITORY))
    c['runs'].append(run)
    for number in range(1, attempt_count + 1):
        metadata = deepcopy(run);metadata['run_attempt'] = number
        jobs = []
        for j, leg in enumerate(FEATURE_LEGS):
            start = created + timedelta(minutes=5 * number)
            jobs.append(dict(id=identifier * 100 + number * 10 + j, run_id=identifier,
                             run_attempt=number, name=NAMES[leg], status='completed',
                             conclusion='success', started_at=stamp(start),
                             completed_at=stamp(start + timedelta(seconds=duration))))
        c['attempts'].append(dict(run_id=identifier, run_attempt=number, metadata=metadata, jobs=jobs))
    return run


class CensusTests(unittest.TestCase):
    def test_exact_twelve_dispatches_at_cap(self):
        r = control_census(fixture(range(12), duration=5400), FREEZE)
        self.assertEqual((r['dispatches'], r['attempts'], r['job_count']), (12, 12, 48))
        self.assertEqual(r['runtime_microseconds_lower_bound'], 72 * 3600 * 1000000)
        self.assertTrue(r['budget_conformant']);self.assertTrue(r['window_complete'])
        self.assertEqual(r['issues'], [])
        self.assertTrue(all(j['selected_for_binding'] for j in r['jobs']))
        self.assertTrue(all(not s['missing_legs'] for s in r['slots']))
        self.assertTrue(r['authentication_required']);self.assertFalse(r['activation_authorized'])

    def test_failed_wrong_source_first_draw_cannot_be_replaced(self):
        c = fixture(); c['runs'][0]['head_sha'] = 'b' * 40
        c['attempts'][0]['metadata']['head_sha'] = 'b' * 40
        for j in c['attempts'][0]['jobs']:j['conclusion'] = 'failure'
        later = add_run(c, 2, dispatch_day(START, 0))
        later['created_at'] = '2030-01-02T00:01:00Z'
        c['runs'].reverse();c['attempts'].reverse()
        r = control_census(c, FREEZE)
        self.assertEqual(r['slots'][0]['run_id'], 1)
        self.assertEqual([j['run_id'] for j in r['jobs'] if j['selected_for_binding']], [1] * 4)
        self.assertFalse(r['budget_conformant'])
        self.assertIn('run-1:research-run-identity-mismatch', r['issues'])
        self.assertIn('run-2:extra-dispatch-on-planned-date', r['issues'])

    def test_failed_job_conclusion_does_not_remove_partial_measurements(self):
        c = fixture()
        for j in c['attempts'][0]['jobs']:j['conclusion'] = 'failure'
        r = control_census(c, FREEZE)
        self.assertTrue(r['budget_conformant'])
        self.assertTrue(all(j['selected_for_binding'] for j in r['jobs']))

    def test_rerun_budget_counts_but_first_attempt_stays_selected(self):
        c = fixture(indices=()); add_run(c, 1, dispatch_day(START, 0), attempt_count=2)
        r = control_census(c, FREEZE)
        self.assertEqual((r['dispatches'], r['attempts'], r['job_count']), (1, 2, 8))
        self.assertEqual(r['runtime_microseconds_lower_bound'], 8 * 3600 * 1000000)
        self.assertEqual([j['run_attempt'] for j in r['jobs'] if j['selected_for_binding']], [1] * 4)
        self.assertIn('run-1:automatic-or-manual-rerun', r['issues'])

    def test_unplanned_early_late_extra_and_nonmanual_all_accounted(self):
        c = fixture(range(12), duration=5400)
        add_run(c, 20, START)
        add_run(c, 21, START + timedelta(days=42))
        c['runs'][0]['event'] = 'push'
        r = control_census(c, FREEZE)
        self.assertEqual((r['dispatches'], r['job_count']), (14, 56))
        for issue in ('more-than-12-dispatches', 'more-than-48-jobs', 'more-than-72-runner-hours',
                      'run-20:unplanned-dispatch-date', 'run-21:unplanned-dispatch-date', 'run-1:not-manual-dispatch'):
            self.assertIn(issue, r['issues'])
        self.assertEqual(sum(j['selected_for_binding'] for j in r['jobs']), 48)

    def test_before_window_and_other_branches_are_explicit_exclusions(self):
        c = fixture()
        add_run(c, 20, START - timedelta(days=1))
        add_run(c, 21, START)['head_branch'] = 'main'
        r = control_census(c, FREEZE)
        self.assertEqual(r['dispatches'], 1)
        self.assertEqual(r['excluded_runs'], [dict(run_id=20, reason='completed-before-confirmation'),
                                             dict(run_id=21, reason='other-branch')])

    def test_queued_cross_midnight_uses_dispatch_date_and_actual_job_date(self):
        c = fixture()
        c['runs'][0]['created_at'] = '2030-01-02T23:59:00Z'
        for j in c['attempts'][0]['jobs']:
            j.update(started_at='2030-01-03T00:02:00Z', completed_at='2030-01-03T00:12:00Z')
        r = control_census(c, FREEZE)
        self.assertTrue(r['budget_conformant'])
        self.assertEqual(r['slots'][0]['dispatch_date'], '2030-01-02')
        self.assertEqual({j['measurement_date'] for j in r['jobs']}, {'2030-01-03'})
        for j in c['attempts'][0]['jobs']:
            j.update(started_at='2030-02-12T00:02:00Z', completed_at='2030-02-12T00:12:00Z')
        self.assertTrue(all('job-start-outside-confirmation' in j['issues'] for j in control_census(c, FREEZE)['jobs']))

    def test_unknown_duplicate_and_missing_legs_are_not_substituted(self):
        for kind in ('unknown', 'duplicate', 'missing', 'empty'):
            c = fixture();jobs = c['attempts'][0]['jobs']
            if kind == 'unknown': jobs[0]['name'] = 'other'
            if kind == 'duplicate': jobs[0]['name'] = jobs[1]['name']
            if kind == 'missing': jobs.pop()
            if kind == 'empty': jobs.clear()
            r = control_census(c, FREEZE)
            self.assertFalse(r['budget_conformant'])
            self.assertTrue(r['slots'][0]['missing_legs'])
            self.assertIn('run-1:attempt-1-not-four-exact-legs', r['issues'])
            self.assertEqual(r['job_count'], len(jobs))

    def test_running_job_counts_elapsed_lower_bound_and_blocks_completion(self):
        c = fixture();c['finished_at'] = '2030-01-02T00:35:00Z'
        c['runs'][0]['status'] = 'in_progress';c['attempts'][0]['metadata']['status'] = 'in_progress'
        for j in c['attempts'][0]['jobs']:j.update(status='in_progress', completed_at=None)
        r = control_census(c, FREEZE)
        self.assertEqual(r['runtime_microseconds_lower_bound'], 4 * 1800 * 1000000)
        self.assertFalse(r['runtime_complete']);self.assertFalse(r['all_observed_completed'])
        self.assertFalse(r['window_complete']);self.assertFalse(r['budget_conformant'])

    def test_missing_timestamps_never_imply_zero_known_consumption(self):
        for field in ('started_at', 'completed_at'):
            c = fixture();c['attempts'][0]['jobs'][0][field] = None
            r = control_census(c, FREEZE)
            self.assertFalse(r['runtime_complete']);self.assertFalse(r['budget_conformant'])
            self.assertEqual(r['job_count'], 4)

    def test_job_overrun_does_not_erase_first_draw(self):
        c = fixture(duration=5400.000001)
        r = control_census(c, FREEZE)
        self.assertFalse(r['budget_conformant'])
        self.assertTrue(all('job-exceeds-90-minutes' in j['issues'] for j in r['jobs']))
        self.assertTrue(all(j['selected_for_binding'] for j in r['jobs']))

    def test_missing_or_ambiguous_census_is_refused(self):
        cases = [lambda c: c['attempts'].clear(),
                 lambda c: c['runs'].append(deepcopy(c['runs'][0])),
                 lambda c: c['attempts'].append(deepcopy(c['attempts'][0])),
                 lambda c: c['attempts'][0]['jobs'].append(deepcopy(c['attempts'][0]['jobs'][0])),
                 lambda c: c['runs'][0].pop('created_at'),
                 lambda c: c['runs'][0].update(created_at='2030-02-14T00:00:00Z'),
                 lambda c: c['attempts'][0]['jobs'][0].update(started_at='2030-01-01T23:59:00Z'),
                 lambda c: c['attempts'][0]['jobs'][0].update(completed_at='2030-01-02T00:04:59Z'),
                 lambda c: c['attempts'][0]['jobs'][0].update(id=True),
                 lambda c: c.update(status='incomplete')]
        for mutate in cases:
            c = fixture();mutate(c)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): control_census(c, FREEZE)

    def test_unfinished_window_and_missing_slots_are_visible_without_fabricated_jobs(self):
        c = fixture();c['finished_at'] = '2030-01-03T00:00:00Z'
        r = control_census(c, FREEZE)
        self.assertFalse(r['window_complete']);self.assertTrue(r['budget_conformant'])
        self.assertEqual(sum(s['run_id'] is None for s in r['slots']), 11)
        self.assertEqual(r['job_count'], 4)

    def test_pre_window_run_rerun_cannot_hide_budget_overflow(self):
        c = fixture(range(12), duration=5400)
        add_run(c, 20, START - timedelta(days=1), duration=5400, attempt_count=2)
        for j in c['attempts'][-1]['jobs']:
            j.update(started_at='2030-01-02T00:05:00Z', completed_at='2030-01-02T01:35:00Z')
        r = control_census(c, FREEZE)
        self.assertEqual((r['dispatches'], r['attempts'], r['job_count']), (13, 13, 52))
        self.assertEqual(r['runtime_microseconds_lower_bound'], 78 * 3600 * 1000000)
        self.assertFalse(r['budget_conformant'])
        self.assertEqual(len(r['excluded_jobs']), 4)
        self.assertEqual(sum(j['selected_for_binding'] for j in r['jobs']), 48)
        for issue in ('more-than-48-jobs', 'more-than-72-runner-hours',
                      'run-20:pre-confirmation-run-with-unexcluded-attempt'):
            self.assertIn(issue, r['issues'])

    def test_pre_window_queue_overlap_and_ambiguous_jobs_remain_accounted(self):
        for times in [dict(started_at='2030-01-01T00:05:00Z', completed_at='2030-01-01T01:05:00Z'),
                      dict(started_at='2029-12-31T23:30:00Z', completed_at='2030-01-01T00:30:00Z'),
                      dict(started_at=None, completed_at=None)]:
            c = fixture(indices=());add_run(c, 20, START - timedelta(days=1))
            # Mixed attempt: three demonstrably pre-window jobs, one relevant.
            c['attempts'][0]['jobs'][0].update(**times)
            r = control_census(c, FREEZE)
            self.assertEqual((r['dispatches'], r['attempts'], r['job_count']), (1, 1, 1))
            self.assertEqual(len(r['excluded_jobs']), 3)
            self.assertFalse(r['budget_conformant'])
            self.assertFalse(r['jobs'][0]['selected_for_binding'])
            self.assertTrue(all(s['run_id'] is None for s in r['slots']))

    def test_pre_window_empty_or_incomplete_attempt_needs_timing_proof(self):
        c = fixture(indices=());add_run(c, 20, START - timedelta(days=1))
        c['attempts'][0]['jobs'].clear()
        r = control_census(c, FREEZE)
        self.assertEqual(r['attempts'], 1);self.assertFalse(r['budget_conformant'])
        c['attempts'][0]['metadata']['updated_at'] = '2029-12-31T23:59:59Z'
        r = control_census(c, FREEZE)
        self.assertEqual(r['attempts'], 0);self.assertEqual(len(r['excluded_attempts']), 1)
        c['attempts'].clear()
        with self.assertRaises(ValueError):control_census(c, FREEZE)

    def test_freeze_requires_isolated_exact_identity(self):
        for key, value in [('research_branch', 'main'), ('research_head', 'a'),
                           ('confirmation_start', None), ('workflow_id', True),
                           ('workflow_path', '../other.yml'), ('job_names_by_leg', {})]:
            f = deepcopy(FREEZE);f[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): control_census(fixture(), f)


if __name__ == '__main__':
    unittest.main()
