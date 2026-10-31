#!/usr/bin/env python3
"""Synthetic scheduled-backup protocol over verified SSH to a second host."""
import argparse
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import uuid

PROJECT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PROJECT/'deploy'))
import backup_remote as support
import backup_operations as operations


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server',type=Path,required=True)
    parser.add_argument('--host',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();os.umask(0o077)
    identity=uuid.uuid4().hex
    remote=Path('/tmp/dolphi-operations-offhost-'+identity)
    vault=Path('/tmp/dolphi-vault-offhost-'+identity)
    with tempfile.TemporaryDirectory(prefix='dolphi-operations-offhost-') as temporary:
        root=Path(temporary);server=args.server.resolve()
        support.run(server,'init',root/'source.db',root/'database.key',root/'owner.token')
        support.run(server,'keygen',root/'backup.key')
        Client,_=support.load_sdk()
        process=subprocess.Popen([str(server),'serve',str(root/'source.db'),str(root/'database.key'),'0'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=support.clean_env())
        try:
            import selectors
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ);assert selector.select(10)
            url=process.stdout.readline().decode().split(' at ',1)[1].split(' ',1)[0]
            owner=Client(url,support.read_private(root/'owner.token').decode())
            for number in range(2):
                registration=owner.create_agent(300);agent=Client(url,registration['secret'])
                for row in range(32):agent.remember(f'key-{row}',f'agent-{number}-value-{row}',operation_id=f'memory-{row}')
            before=len(owner.audit(limit=1000))
        finally:
            process.send_signal(signal.SIGINT)
            process.communicate(timeout=20)
        source_before={p.name:support.digest(p) for p in root.glob('source.db*')}
        config=dict(schema=1,server=str(server),source=dict(database=str(root/'source.db'),database_key=str(root/'database.key'),
                    coordination=dict(mode='lock',path=str(root/'source.control.lock'),wait_seconds=0)),spool=str(root/'spool'),
                    backup_key=dict(id='synthetic-offhost',path=str(root/'backup.key')),
                    destination=dict(transport='ssh',host=args.host,root=str(remote),vault_key=str(vault/'backup.key')),
                    policy=dict(interval_seconds=300,snapshot_timeout_seconds=60,rpo_seconds=900,rto_seconds=1800,retention_days=7,
                                minimum_verified=3,repository_max_bytes=64*1024**3,accepted=False))
        path=root/'config.json';path.write_text(json.dumps(config));path.chmod(0o600)
        endpoint=operations.Endpoint(operations.read_config(path))
        try:
            endpoint.provision();result=operations.backup(config)
            assert result['health']['status']=='healthy'
            state=json.loads((root/'spool/status.json').read_text());receipt=state['last_verified']
            tables={table['table']:table['rows'] for table in receipt['tables']}
            assert tables['memories']==64 and tables['operations']==64 and tables['audit']==before
            assert receipt['original_database_key_used'] is False and all(receipt['service'].values())
            assert source_before=={p.name:support.digest(p) for p in root.glob('source.db*')}
            inspect='import json,pathlib,sys; r=pathlib.Path(sys.argv[1]); print(json.dumps(dict(temporary_restores_removed=not list(r.glob(".restore-drill-*")),objects=len(list((r/"objects").glob("*.mimi"))),receipts=len(list((r/"receipts").glob("*.json"))))))'
            command=endpoint.command([])[:-1]+[shlex.join(['python3','-I','-c',inspect,str(remote)])]
            actual=json.loads(subprocess.check_output(command,timeout=30));assert actual==dict(temporary_restores_removed=True,objects=1,receipts=1)
            report=dict(status='passed',transport='strict_host_key_verified_ssh',destination_host=args.host,
                server_sha256=support.digest(server),source_bytes_preserved=True,source_database_key_transferred=False,
                receipt=receipt,remote_cleanup_checks=actual,physical_power_loss_tested=False,production_qualified=False,
                sources_sha256={name:support.digest(PROJECT/name) for name in ['deploy/backup_operations.py','deploy/backup_remote.py','qualification/offhost_operations.py']})
        finally:
            cleanup='import pathlib,shutil,sys; a,b=map(pathlib.Path,sys.argv[1:3]); assert a.parent==b.parent==pathlib.Path("/tmp") and a.name=="dolphi-operations-offhost-"+sys.argv[3] and b.name=="dolphi-vault-offhost-"+sys.argv[3]; shutil.rmtree(a,ignore_errors=True);shutil.rmtree(b,ignore_errors=True)'
            # Explicit argument positions avoid deleting any prior fixture or live repository.
            subprocess.run(endpoint.command([])[:-1]+[shlex.join(['python3','-I','-c',cleanup,str(remote),str(vault),identity])],capture_output=True,timeout=30,check=True)
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(status='passed',tables=tables,restore_and_service_seconds=receipt['restore_and_service_seconds'])))


if __name__=='__main__':main()
