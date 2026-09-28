"""Account for control dispatches before inspecting any measurement outcomes.

Input collections must come from v115_replay.verified_collection. This module
neither authenticates arbitrary input dictionaries nor qualifies measurements.
Every study-branch attempt/job consumes budget, including invalid extra draws.
"""
from datetime import date, datetime, time, timedelta, timezone
import re

from v115_collect import REPOSITORY, positive
from v115_control_measurements import dispatch_day
from v115_evidence import FEATURE_LEGS
from v115_replay import timestamp


def control_census(collection, frozen):
    """Select the first dispatch on each planned UTC date, before validity.

    frozen is the independently reviewed control execution declaration. This
    interface requires its confirmation_start, research_branch, research_head,
    workflow_id/path and job_names_by_leg. The enclosing binder must additionally
    bind that declaration to the accepted candidate, confirmation and build freeze.
    A budget violation prevents coverage approval, but never removes an earlier
    selected job from binding or erases its independently usable rejection.
    """
    if (frozen.get('repository') != REPOSITORY
            or collection.get('repository') != REPOSITORY
            or collection.get('status') != 'complete'):
        raise ValueError('complete verified repository census required')
    positive(frozen.get('workflow_id'))
    path = frozen.get('workflow_path')
    if not isinstance(path, str) or not re.fullmatch(r'\.github/workflows/[A-Za-z0-9_-]+\.ya?ml', path):
        raise ValueError('exact research workflow required')
    if any(collection.get(k) != frozen.get(k) for k in ('workflow_id', 'workflow_path')):
        raise ValueError('collection differs from control workflow')
    branch, head = frozen.get('research_branch'), frozen.get('research_head')
    if (not isinstance(branch, str) or not branch.strip() or branch == 'main'
            or not isinstance(head, str) or not re.fullmatch(r'[0-9a-f]{40}', head)):
        raise ValueError('isolated research branch and immutable head required')
    raw_start = frozen.get('confirmation_start')
    if not isinstance(raw_start, str) or not re.fullmatch(r'\d{4}-\d\d-\d\d', raw_start):
        raise ValueError('declared confirmation UTC date required')
    start = date.fromisoformat(raw_start)
    begin = datetime.combine(start, time(), timezone.utc)
    end = begin + timedelta(days=42)
    finished = timestamp(collection.get('finished_at'))
    names = frozen.get('job_names_by_leg')
    if (not isinstance(names, dict) or set(names) != set(FEATURE_LEGS)
            or any(not isinstance(n, str) or not n.strip() for n in names.values())
            or len(set(names.values())) != 4):
        raise ValueError('four unambiguous feature job names required')
    by_name = {name: leg for leg, name in names.items()}
    slots = [dict(dispatch_index=i, dispatch_date=dispatch_day(start, i).isoformat(),
                  run_id=None, missing_legs=list(FEATURE_LEGS)) for i in range(12)]
    by_date = {s['dispatch_date']: s for s in slots}
    runs = collection.get('runs')
    attempts = collection.get('attempts')
    if not isinstance(runs, list) or not isinstance(attempts, list):
        raise ValueError('full run and attempt census required')
    run_ids, attempt_map = set(), {}
    for run in runs:
        identifier = positive(run.get('id'))
        if identifier in run_ids:
            raise ValueError('duplicate run identity')
        run_ids.add(identifier)
    for attempt in attempts:
        key = (positive(attempt.get('run_id')), positive(attempt.get('run_attempt')))
        if key in attempt_map or key[0] not in run_ids:
            raise ValueError('duplicate or orphan attempt')
        attempt_map[key] = attempt
    exclusions, excluded_attempts, excluded_jobs, study = [], [], [], []
    for run in runs:
        if run.get('head_branch') != branch:
            exclusions.append(dict(run_id=run['id'], reason='other-branch'))
            continue
        created = timestamp(run.get('created_at'))
        if created > finished:
            raise ValueError('run created after census snapshot')
        count = positive(run.get('run_attempt'))
        if sorted(a for r, a in attempt_map if r == run['id']) != list(range(1, count + 1)):
            raise ValueError('missing or extra study attempt')
        relevant = []
        for number in range(1, count + 1):
            attempt = attempt_map[run['id'], number]
            metadata, jobs = attempt.get('metadata', {}), attempt.get('jobs')
            if (metadata.get('id') != run['id'] or metadata.get('run_attempt') != number
                    or metadata.get('head_sha') != run.get('head_sha') or not isinstance(jobs, list)):
                raise ValueError('complete matching attempt metadata/jobs required')
            retained = []
            for job in jobs:
                # Original run creation does not date its reruns or queued jobs.
                # Exclude only a completed job demonstrably wholly before T0.
                before = False
                if created < begin and job.get('status') == 'completed':
                    left, right = job.get('started_at'), job.get('completed_at')
                    if left is not None and right is not None:
                        before = created <= timestamp(left) <= timestamp(right) <= begin
                if before:
                    excluded_jobs.append(dict(run_id=run['id'], run_attempt=number,
                                              job_id=positive(job.get('id')), reason='completed-before-confirmation'))
                else:
                    retained.append(job)
            proved_empty_before = (not jobs and metadata.get('status') == 'completed'
                                   and metadata.get('updated_at') is not None
                                   and timestamp(metadata['updated_at']) <= begin)
            if (created < begin and not retained and metadata.get('status') == 'completed'
                    and (jobs or proved_empty_before)):
                excluded_attempts.append(dict(run_id=run['id'], run_attempt=number,
                                              reason='completed-before-confirmation'))
            else:
                relevant.append((number, dict(attempt, jobs=retained)))
        if not relevant:
            exclusions.append(dict(run_id=run['id'], reason='completed-before-confirmation'))
            continue
        study.append((created, run['id'], run, relevant))
    study.sort(key=lambda row: row[:2])
    issues, run_rows, job_rows, seen_jobs = [], [], [], set()
    total_us, incomplete, unknown_time, attempt_count = 0, False, False, 0
    for created, run_id, run, relevant in study:
        slot = by_date.get(created.date().isoformat()) if created >= begin else None
        selected = slot is not None and slot['run_id'] is None
        if selected:
            slot['run_id'] = run_id
        run_issues = []
        if created < begin:
            run_issues.append('pre-confirmation-run-with-unexcluded-attempt')
        elif slot is None:
            run_issues.append('unplanned-dispatch-date')
        elif not selected:
            run_issues.append('extra-dispatch-on-planned-date')
        if run.get('event') != 'workflow_dispatch':
            run_issues.append('not-manual-dispatch')
        if (run.get('head_sha') != head or run.get('path') != path
                or run.get('workflow_id') != frozen['workflow_id']
                or run.get('repository', {}).get('full_name') != REPOSITORY
                or run.get('head_repository', {}).get('full_name') != REPOSITORY):
            run_issues.append('research-run-identity-mismatch')
        count = positive(run.get('run_attempt'))
        if count > 1:
            run_issues.append('automatic-or-manual-rerun')
        if run.get('status') != 'completed':
            incomplete = True
        for number, attempt in relevant:
            attempt_count += 1
            metadata = attempt.get('metadata', {})
            if (metadata.get('id') != run_id or metadata.get('run_attempt') != number
                    or metadata.get('head_sha') != run.get('head_sha')):
                raise ValueError('attempt metadata identity mismatch')
            if metadata.get('status') != 'completed':
                incomplete = True
            jobs = attempt.get('jobs')
            if not isinstance(jobs, list):
                raise ValueError('complete attempt jobs required')
            legs = [by_name.get(job.get('name')) for job in jobs]
            if sorted(leg for leg in legs if leg is not None) != sorted(FEATURE_LEGS) or None in legs:
                run_issues.append('attempt-' + str(number) + '-not-four-exact-legs')
            if selected and number == 1:
                slot['missing_legs'] = [leg for leg in FEATURE_LEGS if legs.count(leg) != 1]
            for job, leg in zip(jobs, legs):
                job_id = positive(job.get('id'))
                if (job_id in seen_jobs or job.get('run_id') != run_id
                        or job.get('run_attempt') != number):
                    raise ValueError('duplicate job or job-attempt mismatch')
                seen_jobs.add(job_id)
                reasons, elapsed = [], None
                if job.get('status') != 'completed':
                    incomplete = True
                started_raw, completed_raw = job.get('started_at'), job.get('completed_at')
                started = timestamp(started_raw) if started_raw is not None else None
                completed = timestamp(completed_raw) if completed_raw is not None else None
                if started is None:
                    # Even cancelled unstarted jobs count toward the 48-job cap;
                    # absent timestamps do not prove zero runner consumption.
                    unknown_time = True
                    reasons.append('missing-job-start')
                else:
                    if not created <= started <= finished:
                        raise ValueError('job start outside dispatch/snapshot interval')
                    if not begin <= started < end:
                        reasons.append('job-start-outside-confirmation')
                    stop = completed if completed is not None else finished
                    if not started <= stop <= finished:
                        raise ValueError('job completion outside start/snapshot interval')
                    delta = stop - started
                    elapsed = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
                    total_us += elapsed
                    if completed is None:
                        unknown_time = True
                        reasons.append('unclosed-job-runtime')
                    if elapsed > 5400 * 1000000:
                        reasons.append('job-exceeds-90-minutes')
                if completed is not None and job.get('status') != 'completed':
                    raise ValueError('completion time on unfinished job')
                if leg is None:
                    reasons.append('unknown-feature-leg')
                elif legs.count(leg) != 1:
                    reasons.append('duplicate-feature-leg')
                first = selected and number == 1 and leg is not None and legs.count(leg) == 1
                job_rows.append(dict(run_id=run_id, run_attempt=number, job_id=job_id,
                                     feature_leg=leg, dispatch_index=slot['dispatch_index'] if slot else None,
                                     selected_for_binding=first, started_at=started_raw,
                                     measurement_date=started.date().isoformat() if started else None,
                                     runtime_microseconds=elapsed, issues=sorted(set(reasons))))
                issues.extend('job-' + str(job_id) + ':' + reason for reason in reasons)
        run_rows.append(dict(run_id=run_id, dispatch_index=slot['dispatch_index'] if slot else None,
                             selected=selected, created_at=run['created_at'], attempts=len(relevant), total_run_attempts=count,
                             issues=sorted(set(run_issues))))
        issues.extend('run-' + str(run_id) + ':' + reason for reason in run_issues)
    if len(study) > 12:
        issues.append('more-than-12-dispatches')
    if len(job_rows) > 48:
        issues.append('more-than-48-jobs')
    if total_us > 72 * 3600 * 1000000:
        issues.append('more-than-72-runner-hours')
    return dict(schema=1, confirmation_start=start.isoformat(), confirmation_end=end.date().isoformat(),
                slots=slots, runs=run_rows, jobs=job_rows, excluded_runs=exclusions,
                excluded_attempts=excluded_attempts, excluded_jobs=excluded_jobs,
                dispatches=len(study), attempts=attempt_count, job_count=len(job_rows),
                runtime_microseconds_lower_bound=total_us, runtime_complete=not unknown_time,
                all_observed_completed=not incomplete,
                window_complete=finished >= end and not incomplete,
                budget_conformant=not issues and not incomplete and not unknown_time,
                issues=sorted(set(issues)), authentication_required=True,
                activation_authorized=False)
