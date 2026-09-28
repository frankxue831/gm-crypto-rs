"""Reserve upload time including elapsed setup; execute only the fixed preparer."""
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def remaining_seconds(start, now):
    if not all(math.isfinite(x) for x in (start,now)) or now<start or now-start>=4790:
        raise ValueError('insufficient time for preparation and ten-minute evidence reserve')
    return 4790-(now-start)


def main(evidence,command):
    out=Path(evidence)/'preparation-budget.json'
    record={'status':'not-started'}
    try:
        remaining=remaining_seconds(float(os.environ['V115_BUILD_STARTED_AT']),time.time())
        record.update(status='running',allowed_seconds=remaining)
        out.write_text(json.dumps(record,indent=2)+'\n')
        proc=subprocess.Popen(command,start_new_session=True)
        try:
            code=proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid,signal.SIGTERM)
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            # The parent may exit before a child; kill any remaining members of
            # the process group created above, leaving no writer after hashing.
            try:os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            proc.wait()
            record.update(status='timeout',error='preparation budget exhausted; no timing performed')
            raise SystemExit(1)
        record.update(status='success' if code==0 else 'failed',exit_code=code)
        if code:raise SystemExit(code)
    except (ValueError,OSError,KeyError) as error:
        record.update(status='refused-or-failed',error=str(error))
        raise
    finally:
        out.write_text(json.dumps(record,indent=2)+'\n')


if __name__=='__main__':main(sys.argv[1],sys.argv[2:])
