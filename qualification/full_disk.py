#!/usr/bin/env python3
"""Actual ENOSPC in a private 2 MiB tmpfs mount. Invoke via a new mount namespace."""
import argparse
import errno
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from storage_faults import Fixture
from dolphi import DolphiError

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['server','control','interposer','output']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    if os.geteuid()!=0:raise SystemExit('requires a private root mount namespace')
    if os.readlink('/proc/self/ns/mnt')==os.readlink('/proc/1/ns/mnt'):raise SystemExit('refusing the host mount namespace')
    results=[]
    with tempfile.TemporaryDirectory(prefix='dolphi-storage-') as temporary:
        root=Path(temporary);mount=root/'database';mount.mkdir()
        subprocess.run(['mount','-t','tmpfs','-o','size=2M,nr_inodes=256,mode=0700','dolphi-synthetic-full',str(mount)],check=True)
        f=None
        try:
            # Keep metadata, keys and test controls outside the small filesystem.
            f=Fixture(root,a.server.resolve(),a.control.resolve(),a.interposer.resolve())
            filler=mount/'filler';observed=False
            with filler.open('wb',buffering=0) as output:
                try:
                    while True:output.write(b'F'*(64*1024))
                except OSError as error:
                    if error.errno!=errno.ENOSPC:raise
                    observed=True
            assert observed
            try:f.agent.remember('candidate','full disk synthetic '*3000,operation_id='real-full');ack=True
            except DolphiError:ack=False
            assert not ack,'disk-full write unexpectedly succeeded without allocation'
            f.stop(abrupt=True);filler.unlink();f.restart();f.preserved()
            committed=f.agent.operation_status('real-full') is not None
            check=f.check();assert check['candidate_memories']==int(committed)
            f.agent.remember('candidate','full disk synthetic '*3000,operation_id='real-full')
            f.agent.remember('candidate','full disk synthetic '*3000,operation_id='real-full')
            f.check()
            result={'status':'passed','filesystem':'private tmpfs','size_bytes':2*1024*1024,'actual_enospc_observed':True,'write_not_falsely_acknowledged':True,'previous_acknowledged_data_and_receipts_preserved':True,'same_id_retry_after_free_space':True,'host_mount_namespace_unchanged':True,'physical_power_loss_tested':False}
            results.append(dict(result,case='database-full'))
        finally:
            if f:f.stop(abrupt=True)
            subprocess.run(['umount',str(mount)],check=True)
    for case in ['backup-full','restore-full','report-full','backup-inodes-full']:
        with tempfile.TemporaryDirectory(prefix='dolphi-storage-') as temporary:
            root=Path(temporary)
            folder='backup' if case.startswith('backup') else ('restore' if case=='restore-full' else 'report')
            mount=root/folder;mount.mkdir()
            subprocess.run(['mount','-t','tmpfs','-o','size=2M,nr_inodes=256,mode=0700','dolphi-synthetic-full',str(mount)],check=True)
            f=None
            try:
                f=Fixture(root,a.server.resolve(),a.control.resolve(),a.interposer.resolve());f.stop()
                before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'database').iterdir() if p.is_file()}
                backup_key=root/'backup.key';new_key=root/'new.key'
                assert f.run(['keygen',backup_key]).returncode==0 and f.run(['keygen',new_key]).returncode==0
                snapshot=root/'backup/snapshot.mimi';destination=root/'restore/target.db';report=root/'report/result.json'
                if case not in ['backup-full','backup-inodes-full']:
                    assert f.run(['migration-export',f.db,f.key,snapshot,backup_key]).returncode==0
                created=[]
                try:
                    if case=='backup-inodes-full':
                        for i in range(1024):
                            path=mount/f'filler-{i}';path.touch();created.append(path)
                        raise AssertionError('inode cap was not exhausted')
                    else:
                        path=mount/'filler';created.append(path)
                        with path.open('wb',buffering=0) as output:
                            while True:output.write(b'F'*(64*1024))
                except OSError as error:
                    assert error.errno==errno.ENOSPC
                if case.startswith('backup'):
                    args=['migration-export',f.db,f.key,snapshot,backup_key]
                else:args=['migration-import',snapshot,backup_key,destination,new_key,report]
                failed=f.run(args);assert failed.returncode!=0
                if case=='report-full':
                    assert destination.exists() and b'created and verified' in failed.stderr.encode()
                    checked=subprocess.run([str(a.control.resolve()),'check',str(destination),str(new_key)],capture_output=True,text=True)
                    assert checked.returncode==0
                elif case=='restore-full':assert not destination.exists()
                else:assert not snapshot.exists()
                assert before=={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'database').iterdir() if p.is_file()}
                for path in created:path.unlink()
                if case=='report-full':
                    # Preserve the verified destination; use a new target for retry.
                    args=['migration-import',snapshot,backup_key,root/'restore/retry.db',new_key,report]
                assert f.run(args).returncode==0
                f.restart();f.preserved();f.check()
                results.append({'case':case,'actual_enospc_observed':True,'source_bytes_preserved':True,'operation_failed_without_false_success':True,'retry_after_free_space_passed':True,'verified_destination_retained_after_report_failure':case=='report-full','status':'passed'})
            finally:
                if f:f.stop(abrupt=True)
                subprocess.run(['umount',str(mount)],check=True)
    summary={'status':'passed','cases':results,'case_count':len(results),'private_mount_namespace':True,'bounded_tmpfs_bytes_per_case':2*1024*1024,'live_installations_touched':False,'physical_power_loss_tested':False,'release_binary_sha256':hashlib.sha256(a.server.resolve().read_bytes()).hexdigest()}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(summary,indent=2)+'\n')
    if os.environ.get('SUDO_UID'):os.chown(a.output,int(os.environ['SUDO_UID']),int(os.environ['SUDO_GID']))
    print(json.dumps(summary))

if __name__=='__main__':main()
