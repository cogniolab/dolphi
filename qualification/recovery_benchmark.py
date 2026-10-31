#!/usr/bin/env python3
"""Measure synthetic encrypted recovery; no production RPO/RTO claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['server', 'control', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--size', choices=['small', 'large'], default='small')
    args = parser.parse_args()
    server, control = args.server.resolve(), args.control.resolve()
    with tempfile.TemporaryDirectory(prefix='dolphi-storage-benchmark-') as temporary:
        root = Path(temporary)
        key = root / 'database.key'
        subprocess.run([str(server), 'keygen', str(key)], check=True, capture_output=True)
        mode = 'recovery-benchmark' + ('-large' if args.size == 'large' else '')
        start = time.monotonic()
        # Reap this exact process: RUSAGE_CHILDREN can include earlier children
        # from a shell that exec'd this runner, contaminating its peak RSS.
        with (root / 'output').open('w+') as output, (root / 'errors').open('w+') as errors:
            process = subprocess.Popen(
                [str(control), mode, str(root / 'memory.db'), str(key)],
                stdout=output, stderr=errors,
            )
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                if time.monotonic() - start > 240:
                    process.kill()
                    _, status, _ = os.wait4(process.pid, 0)
                    process.returncode = os.waitstatus_to_exitcode(status)
                    raise SystemExit('synthetic recovery timed out')
                time.sleep(0.05)
            if process.returncode:
                errors.seek(0)
                raise SystemExit('synthetic recovery failed: ' + errors.read()[-1000:])
            output.seek(0)
            report = json.load(output)
        assert report['tables_verified'] == 10
        assert report['recovery_samples_match'] and report['durable_receipts_replayed']
        if args.size == 'large':
            assert report['oversize_rejected_without_publication']
        report.update(
            status='passed', end_to_end_seconds=round(time.monotonic() - start, 3),
            child_peak_rss_kib=usage.ru_maxrss,
            memory_measurement='wait4 rusage of the recovery process only; Linux KiB',
            release_binary_sha256=hashlib.sha256(server.read_bytes()).hexdigest(),
            control_binary_sha256=hashlib.sha256(control.read_bytes()).hexdigest(),
            scope='single synthetic Linux run; not a production SLA',
            physical_power_loss_tested=False, live_installations_touched=False,
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
