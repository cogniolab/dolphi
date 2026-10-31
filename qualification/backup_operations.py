#!/usr/bin/env python3
"""Synthetic operations acceptance; no live installation is opened."""
import argparse
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import uuid

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT/'deploy'))
import backup_operations as operations
import backup_remote as support


def cli(config, command, success=True):
    result = subprocess.run(['python3', '-I', str(PROJECT/'deploy/backup_operations.py'), command,
                             '--config', str(config)], capture_output=True, text=True, timeout=150)
    if success:
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)
    assert result.returncode != 0
    return result


def write_config(path, config):
    path.write_text(json.dumps(config)); path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--systemd', action='store_true')
    args = parser.parse_args(); os.umask(0o077)
    cases = []
    with tempfile.TemporaryDirectory(prefix='dolphi-operations-test-') as temporary:
        root = Path(temporary); server = args.server.resolve()
        support.run(server, 'init', root/'source.db', root/'database.key', root/'owner.token')
        support.run(server, 'keygen', root/'backup.key')
        config = dict(schema=1, server=str(server), source=dict(database=str(root/'source.db'),
            database_key=str(root/'database.key'), coordination=dict(mode='lock',path=str(root/'source.control.lock'),wait_seconds=0)),
            spool=str(root/'spool'), backup_key=dict(id='test-key',path=str(root/'backup.key')),
            destination=dict(transport='local',host=None,root=str(root/'repository'),vault_key=str(root/'vault/key')),
            policy=dict(interval_seconds=300,snapshot_timeout_seconds=30,rpo_seconds=900,rto_seconds=60,retention_days=7,
                        minimum_verified=3,repository_max_bytes=128*1024*1024,accepted=False))
        path = root/'config.json'; write_config(path, config)
        assert cli(path,'health',False).returncode == 2
        cases.append('no_verified_backup_alert')
        distinct=config['backup_key']['path'];config['backup_key']['path']=config['source']['database_key'];write_config(path,config)
        assert 'independent_backup_key_required' in cli(path,'provision',False).stderr
        config['backup_key']['path']=distinct;write_config(path,config)
        cases.append('database_key_reuse_as_backup_key_rejected')
        cli(path,'provision')
        # Existing writer lock is held by the actual caller, so a second process
        # must fail rather than snapshot a concurrently modified DB.
        with (root/'source.control.lock').open('w') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            cli(path,'run',False)
        assert not list((root/'repository').glob('objects/*.mimi'))
        cases.append('writer_lock_prevents_unsafe_export')
        marker=root/'snapshot-child-started'
        controller_code='''import sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import backup_operations as o, backup_remote as s
c=o.read_config(Path(sys.argv[2]))
with o.writers_stopped(c) as fds:
 s.run(sys.executable,'-c',"from pathlib import Path;import time;Path("+repr(sys.argv[3])+").touch();time.sleep(2)",pass_fds=fds)
'''
        controller=subprocess.Popen([sys.executable,'-I','-c',controller_code,str(PROJECT/'deploy'),str(path),str(marker)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            deadline=time.monotonic()+5
            while not marker.exists() and time.monotonic()<deadline:time.sleep(0.02)
            assert marker.exists()
            controller.kill();controller.wait(timeout=5)
            with (root/'source.control.lock').open('r+') as lock:
                try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:pass
                else:raise AssertionError('controller_death_released_snapshot_child_lock')
                deadline=time.monotonic()+5
                while True:
                    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                    except BlockingIOError:
                        assert time.monotonic()<deadline
                        time.sleep(0.02)
        finally:
            if controller.poll() is None:controller.kill();controller.wait()
        cases.append('snapshot_child_holds_writer_lock_after_controller_death')
        first=cli(path,'run'); assert first['health']['status']=='healthy'
        state_path=root/'spool/status.json'; saved=json.loads(state_path.read_text())
        assert saved['last_verified']['service']['namespace_isolation']
        assert saved['last_verified']['original_database_key_used'] is False
        cases.append('full_restore_credentials_and_service_verification')
        key=root/'vault/key'; retained=key.read_bytes();key.unlink()
        cli(path,'run',False)
        pending=json.loads((root/'spool/pending.json').read_text())
        assert json.loads(state_path.read_text())['last_verified']==saved['last_verified']
        assert 'last_backup_attempt_failed' in json.loads(cli(path,'health',False).stdout)['issues']
        cases.append('missing_recovery_key_never_promotes_failed_backup')
        key.write_bytes(retained);key.chmod(0o600)
        # A pending immutable snapshot is retried while source writers hold their
        # lock; success proves retry did not take another source snapshot.
        with (root/'source.control.lock').open('w') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            retried=cli(path,'run')
        assert retried['backup_id']==pending['id']
        cases.append('same_backup_id_retry_without_resnapshot')
        latest=json.loads(state_path.read_text())
        changed=json.loads(json.dumps(latest));changed['last_verified']['metadata']['snapshot_started_at']=support.stamp(support.now()-dt.timedelta(seconds=901))
        support.atomic_json(state_path,changed)
        assert 'verified_backup_stale' in json.loads(cli(path,'health',False).stdout)['issues']
        cases.append('rpo_uses_snapshot_point_not_transfer_completion')
        changed['last_verified']['metadata']['snapshot_started_at']=support.stamp(support.now()+dt.timedelta(minutes=2));support.atomic_json(state_path,changed)
        assert 'clock_skew' in json.loads(cli(path,'health',False).stdout)['issues']
        support.atomic_json(state_path,latest);cases.append('future_clock_rejected')
        key.write_bytes(os.urandom(32));cli(path,'run',False)
        assert json.loads(state_path.read_text())['last_verified']==latest['last_verified']
        cases.append('wrong_recovery_key_keeps_last_verified_receipt')
        key.write_bytes(retained);cli(path,'run')
        endpoint=operations.Endpoint(config);endpoint.server=server
        metadata=json.loads(state_path.read_text())['last_verified']['metadata']
        snapshot=root/'spool'/(metadata['id']+'.mimi')
        bad=root/'truncated';bad.write_bytes(snapshot.read_bytes()[:-17]);bad.chmod(0o600)
        candidate=dict(metadata,id='truncated-'+uuid.uuid4().hex)
        try:
            with bad.open('rb') as source:endpoint.call('receive','--metadata',json.dumps(candidate),source=source)
        except RuntimeError as error:assert str(error)=='transfer_incomplete_or_corrupted'
        else:raise AssertionError('truncated_transfer_published')
        assert not (root/'repository/objects'/(candidate['id']+'.mimi')).exists()
        assert not list((root/'repository/objects').glob('.partial-*'))
        cases.append('incomplete_transfer_never_published')
        try:
            with snapshot.open('rb') as source:endpoint.call('receive','--metadata',json.dumps(dict(metadata,id='quota-'+uuid.uuid4().hex)),'--quota','1',source=source)
        except RuntimeError as error:assert str(error)=='repository_capacity_exceeded'
        else:raise AssertionError('quota_not_enforced')
        cases.append('repository_quota_preserves_verified_objects')
        for _ in range(2):cli(path,'run')
        receipts=sorted((root/'repository/receipts').glob('*.json'))
        assert len(receipts)>=5
        for receipt in receipts:
            value=json.loads(receipt.read_text());value['metadata']['snapshot_started_at']=support.stamp(support.now()-dt.timedelta(days=8));support.atomic_json(receipt,value)
        pruned=endpoint.call('prune','--days','7','--minimum','3')
        assert len(list((root/'repository/receipts').glob('*.json')))==3 and len(pruned['removed'])==len(receipts)-3
        cases.append('retention_keeps_three_verified_fallbacks')
        kept=next((root/'repository/objects').glob('*.mimi'));data=kept.read_bytes();kept.write_bytes(data[:-1])
        try:endpoint.call('prune','--days','7','--minimum','3')
        except RuntimeError as error:assert str(error)=='retention_requires_intact_verified_objects'
        else:raise AssertionError('corrupt_fallback_counted_as_verified')
        kept.write_bytes(data);cases.append('retention_refuses_corrupted_fallbacks')
        if args.systemd:
            unit='dolphi-operations-fixture-'+uuid.uuid4().hex[:10]+'.service'
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
            definition=root/unit
            definition.write_text('[Unit]\nDescription=Synthetic Dolphi backup coordination fixture\n[Service]\nType=exec\nKillSignal=SIGINT\nTimeoutStopSec=10s\nExecStart='+str(server)+' serve '+str(root/'source.db')+' '+str(root/'database.key')+' '+str(port)+'\n')
            subprocess.run(['systemctl','--user','link','--runtime',str(definition)],capture_output=True,timeout=30,check=True)
            started=subprocess.run(['systemctl','--user','start',unit],capture_output=True,timeout=30)
            assert started.returncode==0
            try:
                config['source']['coordination']=dict(mode='systemd',unit=unit,scope='user',health_url=f'http://127.0.0.1:{port}/health')
                # Use a fresh repository because retention tests intentionally
                # edited the prior catalog's timestamps.
                config['spool']=str(root/'service-spool');config['destination']['root']=str(root/'service-repository')
                write_config(path,config);cli(path,'provision');cli(path,'run')
                assert subprocess.check_output(['systemctl','--user','is-active',unit],text=True).strip()=='active'
                cases.append('real_service_stopped_and_resumed_for_snapshot')
                original_key=config['source']['database_key'];config['source']['database_key']=str(root/'missing.key');write_config(path,config)
                cli(path,'run',False)
                assert subprocess.check_output(['systemctl','--user','is-active',unit],text=True).strip()=='active'
                config['source']['database_key']=original_key
                cases.append('real_service_resumed_after_export_failure')
                write_config(path,config)
                subprocess.run(['systemctl','--user','stop',unit],capture_output=True,timeout=30,check=True)
                support.atomic_json(Path(config['spool'])/'resume.json',dict(coordination=config['source']['coordination'],recorded_at=support.stamp()))
                assert cli(path,'resume')['resumed']
                assert subprocess.check_output(['systemctl','--user','is-active',unit],text=True).strip()=='active'
                assert not (Path(config['spool'])/'resume.json').exists()
                cases.append('persisted_resume_marker_recovers_interrupted_controller')
                job='dolphi-interrupted-backup-'+uuid.uuid4().hex[:10]+'.service'
                crash=root/'interrupted.py'
                crash.write_text('import sys,time\nfrom pathlib import Path\nsys.path.insert(0,'+repr(str(PROJECT/'deploy'))+')\nimport backup_operations as o\nc=o.read_config(Path('+repr(str(path))+'))\nwith o.writers_stopped(c): time.sleep(60)\n')
                job_definition=root/job
                job_definition.write_text('[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -I '+str(crash)+'\nExecStopPost=/usr/bin/python3 -I '+str(PROJECT/'deploy/backup_operations.py')+' resume --config '+str(path)+'\nTimeoutStartSec=15s\nTimeoutStopSec=40s\n')
                subprocess.run(['systemctl','--user','link','--runtime',str(job_definition)],capture_output=True,timeout=30,check=True)
                try:
                    subprocess.run(['systemctl','--user','start','--no-block',job],capture_output=True,timeout=30,check=True)
                    deadline=time.monotonic()+10
                    while subprocess.run(['systemctl','--user','is-active',unit],capture_output=True,text=True).stdout.strip()!='inactive':
                        assert time.monotonic()<deadline;time.sleep(0.05)
                    assert (Path(config['spool'])/'resume.json').exists()
                    subprocess.run(['systemctl','--user','kill','--kill-whom=main','--signal=KILL',job],capture_output=True,timeout=30,check=True)
                    deadline=time.monotonic()+30
                    while (Path(config['spool'])/'resume.json').exists():
                        assert time.monotonic()<deadline;time.sleep(0.05)
                    assert subprocess.check_output(['systemctl','--user','is-active',unit],text=True).strip()=='active'
                    cases.append('exec_stop_post_resumes_source_after_controller_sigkill')
                finally:
                    subprocess.run(['systemctl','--user','stop',job],capture_output=True,timeout=45)
                    subprocess.run(['systemctl','--user','disable','--runtime',job],capture_output=True,timeout=30)
                    subprocess.run(['systemctl','--user','reset-failed',job],capture_output=True,timeout=30)
            finally:
                subprocess.run(['systemctl','--user','stop',unit],capture_output=True,timeout=30)
                subprocess.run(['systemctl','--user','disable','--runtime',unit],capture_output=True,timeout=30)
                subprocess.run(['systemctl','--user','daemon-reload'],capture_output=True,timeout=30)
                subprocess.run(['systemctl','--user','reset-failed',unit],capture_output=True,timeout=30)
    summary=dict(status='passed',cases=cases,case_count=len(cases),live_installations_touched=False,
                 server_sha256=support.digest(args.server.resolve()),systemd_coordination_tested=args.systemd)
    summary['sources_sha256']={name:support.digest(PROJECT/name) for name in ['deploy/backup_operations.py','deploy/backup_remote.py','qualification/backup_operations.py']}
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary))


if __name__=='__main__':main()
