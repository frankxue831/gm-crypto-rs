"""Bind authenticated API records and exact archive bytes to a reviewed freeze.

Callers obtain records/source responses through v115_collect, retain the complete
census, and select first attempts before this function. This module performs no
network requests, timing execution, candidate derivation, or gate activation.
"""
import hashlib
import json
import re
import zipfile

from v115_collect import REPOSITORY, PRODUCER, unpack_zip
from v115_evidence import FEATURE_LEGS, IDENTITY_FILES, qualify_capture

WORKFLOW = '.github/workflows/dudect-nightly.yml'
SHA256 = re.compile(r'[0-9a-f]{64}')


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def validate_freeze(frozen):
    if (frozen.get('repository') != REPOSITORY or frozen.get('workflow_path') != WORKFLOW
            or type(frozen.get('workflow_id')) is not int or frozen['workflow_id'] <= 0
            or not isinstance(frozen.get('workflow_sha256'), str)
            or not SHA256.fullmatch(frozen['workflow_sha256'])):
        raise ValueError('reviewed repository and workflow identity required')
    names = frozen.get('job_names_by_leg')
    if (not isinstance(names, dict) or set(names) != set(FEATURE_LEGS)
            or any(not isinstance(name, str) or not name for name in names.values())
            or len(set(names.values())) != len(FEATURE_LEGS)):
        raise ValueError('unambiguous complete frozen job-name mapping required')
    identities = frozen.get('identity_sha256_by_leg')
    if not isinstance(identities, dict) or set(identities) != set(FEATURE_LEGS):
        raise ValueError('all four frozen feature identities required')
    for identity in identities.values():
        if (not isinstance(identity, dict) or set(identity) != set(IDENTITY_FILES)
                or any(not isinstance(h, str) or not SHA256.fullmatch(h) for h in identity.values())):
            raise ValueError('all six frozen input hashes required')


def bind_capture(run, job, artifacts, archives, source_contents, frozen):
    """Return binding/qualification result, preserving issues and parsed observations.

    run is the exact attempt API response; job comes from that attempt's full job
    census. artifacts is the complete run artifact listing. archives maps artifact
    IDs to downloaded bytes; absent values remain missing evidence. source_contents
    maps (API head SHA, path) to decoded bytes from authenticated contents responses.
    Neither this interface nor a local SHA hash authenticates caller-invented API
    records. The caller must use the read-only collector's preserved provenance.
    """
    validate_freeze(frozen)
    issues = []
    names = frozen['job_names_by_leg']
    legs = [leg for leg, name in names.items() if name == job.get('name')]
    if len(legs) != 1:
        raise ValueError('unresolved job stratum; do not drop it from the census')
    leg = legs[0]
    head = run.get('head_sha')
    for label, record, key in [('run', run, 'id'), ('attempt', run, 'run_attempt'), ('job', job, 'id')]:
        if type(record.get(key)) is not int or record[key] <= 0:
            raise ValueError('unresolved ' + label + ' identity')
    api_job = dict(run_id=run['id'], run_attempt=run['run_attempt'], job_id=job['id'],
                   head_sha=head, feature_leg=leg, event=run.get('event'), started_at=job.get('started_at'))
    if not isinstance(head, str) or not re.fullmatch(r'[0-9a-f]{40}', head):
        raise ValueError('unresolved API source identity')
    if (run.get('repository', {}).get('full_name') != REPOSITORY
            or run.get('head_repository', {}).get('full_name') != REPOSITORY
            or run.get('head_branch') != 'main' or run.get('event') != 'schedule'
            or run['run_attempt'] != 1):
        issues.append('not-first-scheduled-main-attempt')
    if run.get('workflow_id') != frozen['workflow_id'] or run.get('path') != WORKFLOW:
        issues.append('workflow-identity-mismatch')
    if job.get('run_id') != run['id'] or job.get('run_attempt') != run['run_attempt']:
        issues.append('job-attempt-mismatch')
    identities = frozen['identity_sha256_by_leg'][leg]
    for path, expected in [(WORKFLOW, frozen['workflow_sha256']), (PRODUCER, identities['capture-source.py'])]:
        data = source_contents.get((head, path))
        if not isinstance(data, bytes) or digest(data) != expected:
            issues.append('executed-source-mismatch:' + path)
    matches = [a for a in artifacts if a.get('name') == f'v115-capture-{job["id"]}']
    result, artifact_id = None, None
    if len(matches) != 1:
        issues.append('missing-or-duplicate-job-artifact')
    else:
        artifact = matches[0]
        artifact_id = artifact.get('id')
        if type(artifact_id) is not int or artifact_id <= 0:
            issues.append('invalid-artifact-id')
        provenance = artifact.get('workflow_run', {})
        if provenance.get('id') != run['id'] or provenance.get('head_sha') != head:
            issues.append('artifact-provenance-mismatch')
        data = archives.get(artifact_id)
        if artifact.get('expired') is not False or not isinstance(data, bytes):
            issues.append('artifact-expired-or-missing')
        elif artifact.get('digest') != 'sha256:' + digest(data):
            issues.append('artifact-digest-mismatch')
        else:
            try:
                files = unpack_zip(data)
                capture = json.loads(files['v115-capture/capture.json'])
                if not isinstance(capture, dict):
                    raise ValueError('capture object required')
                prefix = 'v115-capture/'
                captured_files = {name[len(prefix):]:value for name,value in files.items()
                                  if name.startswith(prefix) and name != prefix+'capture.json'}
                if captured_files.get('freeze.json') != canonical(frozen):
                    issues.append('captured-freeze-mismatch')
                metadata = capture.get('metadata', {})
                if not isinstance(metadata, dict):
                    raise ValueError('capture metadata object required')
                for field in ('event', 'started_at'):
                    if metadata.get(field) != api_job[field] or not isinstance(api_job[field], str):
                        issues.append('api-metadata-mismatch:' + field)
                result = qualify_capture(api_job, frozen, capture, captured_files)
                if not result['capture_qualified']:
                    issues.extend(result['issues'])
            except (ValueError, KeyError, TypeError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
                issues.append('malformed-capture-archive:' + str(error))
    return dict(binding_qualified=not issues and result is not None, issues=sorted(set(issues)),
                job=api_job, artifact_id=artifact_id, capture=result)
