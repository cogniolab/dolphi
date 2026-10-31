#!/usr/bin/env python3
"""Measure >64 MiB streaming export/restore using synthetic data only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def measured(command, root, label):
    start=time.monotonic()
    with (root/(label+'.out')).open('w+') as output, (root/(label+'.err')).open('w+') as errors:
        process=subprocess.Popen(list(map(str,command)),stdout=output,stderr=errors)
        while True:
            pid,status,usage=os.wait4(process.pid,os.WNOHANG)
            if pid:
                process.returncode=os.waitstatus_to_exitcode(status);break
            if time.monotonic()-start>600:
                process.kill();_,status,_=os.wait4(process.pid,0);process.returncode=os.waitstatus_to_exitcode(status)
                raise RuntimeError('synthetic_benchmark_timeout')
            time.sleep(0.05)
        errors.seek(0)
        assert process.returncode==0, errors.read()[-1000:]
        output.seek(0); result=json.load(output)
    return dict(seconds=round(time.monotonic()-start,3),peak_process_rss_kib=usage.ru_maxrss,result=result)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server',type=Path,required=True)
    parser.add_argument('--seed',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();server=args.server.resolve();seed=args.seed.resolve();os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='dolphi-operations-large-') as temporary:
        root=Path(temporary);source=root/'source.db';key=root/'database.key'
        subprocess.run([str(server),'init',str(source),str(key),str(root/'owner.token')],check=True,capture_output=True)
        seeded=measured([seed,'seed',source,key],root,'seed')
        assert seeded['result']['logical_value_bytes']>64*1024*1024
        for name in ['backup.key','recovered.key']:
            subprocess.run([str(server),'keygen',str(root/name)],check=True,capture_output=True)
        exported=measured([server,'migration-export-stream',source,key,root/'snapshot.mimi',root/'backup.key'],root,'export')
        restored=measured([server,'migration-import',root/'snapshot.mimi',root/'backup.key',root/'recovered.db',root/'recovered.key',root/'report.json'],root,'restore')
        assert restored['result']['snapshot_version']==3 and len(restored['result']['tables'])==10
        checked=measured([seed,'check',root/'recovered.db',root/'recovered.key'],root,'samples')
        report=dict(status='passed',rows=seeded['result']['rows'],logical_value_bytes=seeded['result']['logical_value_bytes'],
            encrypted_backup_bytes=(root/'snapshot.mimi').stat().st_size,seed=seeded,export=exported,restore=restored,samples=checked,
            server_sha256=hashlib.sha256(server.read_bytes()).hexdigest(),physical_power_loss_tested=False,live_installations_touched=False)
        cgroup=Path('/proc/self/cgroup').read_text().split('0::',1)[-1].strip()
        directory=Path('/sys/fs/cgroup')/cgroup.lstrip('/')
        if (directory/'memory.max').exists():
            report['cgroup_memory_limit']=(directory/'memory.max').read_text().strip()
            report['cgroup_memory_peak']=(directory/'memory.peak').read_text().strip()
            report['cgroup_memory_events']=(directory/'memory.events').read_text().strip()
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ['status','rows','logical_value_bytes','encrypted_backup_bytes']}))


if __name__=='__main__':main()
