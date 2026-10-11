#!/usr/bin/env python3
"""Preserve a complete Actions census and raw v1.15 evidence via authenticated gh.

Read-only network operations. Never execute downloaded code or timing binaries.
This transport archive is not a calibration eligibility or gate decision.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import subprocess
import zipfile

REPOSITORY = 'frankxue831/gm-crypto-rs'
PRODUCER = '.github/scripts/v115_capture.py'
SHA = re.compile(r'[0-9a-f]{40}')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def positive(value):
    if type(value) is not int or value <= 0:
        raise ValueError('positive API identity/count required')
    return value


def unpack_zip(data):
    """Inspect archive bytes without writing untrusted paths to the filesystem."""
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) > 32768 or sum(e.file_size for e in entries) > 256 * 1024 * 1024:
            raise ValueError('archive exceeds preservation inspection limit')
        names, result = set(), {}
        for entry in entries:
            name = entry.filename
            if (not name or name in names or '\\' in name or name.startswith('/')
                    or any(p in ('', '.', '..') for p in name.rstrip('/').split('/'))
                    or stat.S_ISLNK(entry.external_attr >> 16)):
                raise ValueError('ambiguous or unsafe archive path')
            names.add(name)
            if not entry.is_dir():
                result[name] = archive.read(entry)  # Includes ZIP CRC validation.
        return result


class ApiError(RuntimeError):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


def gh_get(endpoint):
    """Only GET fixed-repository github.com API endpoints; gh handles auth/redirects."""
    if not endpoint.startswith('repos/' + REPOSITORY + '/'):
        raise ValueError('unexpected repository endpoint')
    result = subprocess.run(['gh', 'api', '--hostname', 'github.com', '--method', 'GET', endpoint],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if result.returncode:
        message = result.stderr.decode('utf-8', errors='replace')
        match = re.search(r'\(HTTP (\d{3})\)', message)
        raise ApiError(int(match[1]) if match else None, message)
    return result.stdout


class Collector:
    def __init__(self, output, get=gh_get, *, schema=2):
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=False)
        (self.output / 'raw').mkdir()
        self.get = get
        self.record = dict(schema=schema, repository=REPOSITORY, started_at=utc_now(),
                           status='collecting', requests=[], runs=[], attempts=[], artifacts=[], sources=[])
        self.save()

    def save(self):
        files = {p.relative_to(self.output).as_posix(): sha256(p.read_bytes())
                 for p in sorted((self.output / 'raw').iterdir()) if p.is_file()}
        self.record['files'] = files
        tmp = self.output / 'collection.json.tmp'
        tmp.write_text(json.dumps(self.record, indent=2, sort_keys=True) + '\n')
        tmp.replace(self.output / 'collection.json')

    def fetch(self, endpoint, *, missing_ok=False):
        relative = f'raw/{len(self.record["requests"]) + 1:06d}.bin'
        request = dict(endpoint=endpoint, requested_at=utc_now(), path=relative, status='started')
        self.record['requests'].append(request)
        self.save()
        try:
            data = self.get('repos/' + REPOSITORY + endpoint)
            if not isinstance(data, bytes):
                raise ValueError('exact API response bytes required')
            (self.output / relative).write_bytes(data)
            request.update(status='received', sha256=sha256(data))
            return data, relative
        except ApiError as error:
            request.update(status='unavailable', http_status=error.status, error=str(error))
            if missing_ok and error.status in (404, 410):
                return None, None
            raise
        except Exception as error:
            request.update(status='failed', error=str(error))
            raise
        finally:
            self.save()

    def json(self, endpoint):
        data, _ = self.fetch(endpoint)
        return json.loads(data)

    def pages(self, endpoint, field):
        """Reject truncation, duplicate pages, or a census that changed mid-fetch."""
        records, seen, expected = [], set(), None
        for page in range(1, 10002):
            separator = '&' if '?' in endpoint else '?'
            body = self.json(endpoint + separator + f'per_page=100&page={page}')
            count = body.get('total_count')
            if type(count) is not int or count < 0:
                raise ValueError('missing API total_count')
            if field == 'workflow_runs' and count >= 1000:
                raise ValueError('workflow census reaches API cap; partitioned census required')
            if expected is None:
                expected = count
            if expected != count:
                raise ValueError('API census changed during pagination; retain and recollect')
            batch = body.get(field)
            if not isinstance(batch, list) or len(batch) > 100:
                raise ValueError('malformed API page')
            for row in batch:
                identifier = positive(row.get('id'))
                if identifier in seen:
                    raise ValueError('duplicate API identity across pages')
                seen.add(identifier)
            records.extend(batch)
            if len(batch) < 100:
                if len(records) != expected:
                    raise ValueError('truncated API census')
                return records
        raise ValueError('pagination bound reached')

    def source(self, head, path):
        if not isinstance(head, str) or not SHA.fullmatch(head):
            raise ValueError('exact run source SHA required')
        key = dict(head_sha=head, path=path)
        if any(all(row.get(k) == v for k, v in key.items()) for row in self.record['sources']):
            return
        row = dict(key, status='pending')
        self.record['sources'].append(row)
        raw, location = self.fetch('/contents/' + path + '?ref=' + head, missing_ok=True)
        if raw is None:
            row['status'] = 'missing'
            return
        body = json.loads(raw)
        if body.get('type') != 'file' or body.get('path') != path or body.get('encoding') != 'base64':
            raise ValueError('unexpected source content response')
        decoded = base64.b64decode(body['content'], validate=False)
        row.update(status='received', response_path=location, sha256=sha256(decoded))

    def artifact(self, run, artifact):
        row = dict(artifact_id=positive(artifact['id']), run_id=run['id'], name=artifact['name'],
                   digest=artifact.get('digest'), expired=artifact.get('expired'), status='pending')
        self.record['artifacts'].append(row)
        provenance = artifact.get('workflow_run', {})
        if provenance.get('id') != run['id'] or provenance.get('head_sha') != run['head_sha']:
            row['status'] = 'provenance-mismatch'
            return
        if artifact.get('expired') is True:
            row['status'] = 'expired'
            return
        data, location = self.fetch('/actions/artifacts/' + str(artifact['id']) + '/zip', missing_ok=True)
        if data is None:
            row['status'] = 'missing'
            return
        row.update(archive_path=location, observed_sha256=sha256(data))
        if not isinstance(row['digest'], str) or not DIGEST.fullmatch(row['digest']):
            row['status'] = 'missing-github-digest'
        elif row['digest'] != 'sha256:' + sha256(data):
            row['status'] = 'digest-mismatch'
        else:
            try:
                files = unpack_zip(data)
                row.update(status='verified', files={n: sha256(b) for n, b in files.items()})
            except (ValueError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
                row.update(status='invalid-archive', error=str(error))

    def collect(self, workflow):
        if not re.fullmatch(r'[A-Za-z0-9_-]+\.ya?ml', workflow):
            raise ValueError('workflow filename required')
        try:
            identity = self.json('/actions/workflows/' + workflow)
            workflow_id = positive(identity.get('id'))
            path = '.github/workflows/' + workflow
            if identity.get('path') != path:
                raise ValueError('workflow path mismatch')
            self.record.update(workflow_id=workflow_id, workflow_path=path)
            # No event/conclusion/date filter: delayed starts and failed attempts remain.
            runs = self.pages('/actions/workflows/' + str(workflow_id) + '/runs', 'workflow_runs')
            self.record['runs'] = runs
            self.save()
            job_ids = set()
            for run in runs:
                run_id = positive(run['id'])
                if run.get('workflow_id') != workflow_id:
                    raise ValueError('run workflow identity mismatch')
                if run.get('repository', {}).get('full_name') != REPOSITORY:
                    raise ValueError('run repository identity mismatch')
                self.source(run['head_sha'], path)
                self.source(run['head_sha'], PRODUCER)
                if self.record['schema'] >= 2:
                    self.source(run['head_sha'], '.github/scripts/v115_isolated.py')
                for attempt in range(1, positive(run.get('run_attempt')) + 1):
                    endpoint = f'/actions/runs/{run_id}/attempts/{attempt}'
                    metadata = self.json(endpoint)
                    if (metadata.get('id') != run_id or metadata.get('run_attempt') != attempt
                            or metadata.get('head_sha') != run['head_sha']):
                        raise ValueError('attempt identity mismatch')
                    jobs = self.pages(endpoint + '/jobs', 'jobs')
                    row = dict(run_id=run_id, run_attempt=attempt, metadata=metadata, jobs=jobs)
                    self.record['attempts'].append(row)
                    for job in jobs:
                        if (job.get('run_id') != run_id or job.get('run_attempt') != attempt
                                or job['id'] in job_ids):
                            raise ValueError('job identity mismatch or duplication')
                        job_ids.add(job['id'])
                    logs, location = self.fetch(endpoint + '/logs', missing_ok=True)
                    row.update(log_status='missing' if logs is None else 'received', log_path=location)
                    if logs is not None:
                        try:
                            row['log_files'] = {n: sha256(b) for n, b in unpack_zip(logs).items()}
                        except (ValueError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
                            row.update(log_status='invalid-archive', log_error=str(error))
                    self.save()
                for artifact in self.pages(f'/actions/runs/{run_id}/artifacts', 'artifacts'):
                    self.artifact(run, artifact)
                self.save()
            # Guard against runs or rerun attempts added while collecting this snapshot.
            current = self.pages('/actions/workflows/' + str(workflow_id) + '/runs', 'workflow_runs')
            keys = lambda rows: sorted((r['id'], r['run_attempt'], r['updated_at']) for r in rows)
            if keys(current) != keys(runs):
                raise ValueError('run census changed during collection; retain and recollect')
            self.record['status'] = 'complete'
        except Exception as error:
            self.record.update(status='incomplete', error=str(error))
            raise
        finally:
            self.record['finished_at'] = utc_now()
            self.save()
        return self.record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workflow', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = Collector(args.output).collect(args.workflow)
    print(json.dumps(dict(status=result['status'], runs=len(result['runs']),
                          attempts=len(result['attempts']), artifacts=len(result['artifacts']))))


if __name__ == '__main__':
    main()
