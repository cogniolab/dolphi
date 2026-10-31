#!/usr/bin/env python3
"""Coordinated snapshot, off-host verification, retention and age monitoring."""
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
import time
import uuid
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backup_remote as support


def read_config(path):
    config = json.loads(support.read_private(path))
    required = {'schema', 'server', 'source', 'spool', 'backup_key', 'destination', 'policy'}
    if set(config) != required or config['schema'] != 1:
        raise ValueError('invalid_operations_config')
    if set(config['source']) != {'database', 'database_key', 'coordination'}:
        raise ValueError('invalid_source_config')
    if set(config['backup_key']) != {'id', 'path'} or not support.IDENTIFIER.fullmatch(config['backup_key']['id']):
        raise ValueError('invalid_key_id')
    destination = config['destination']
    if set(destination) != {'transport', 'host', 'root', 'vault_key'} or destination['transport'] not in {'local', 'ssh'}:
        raise ValueError('invalid_destination_config')
    if destination['transport'] == 'ssh' and (not re.fullmatch('[A-Za-z0-9_.@-]{1,255}', destination['host']) or destination['host'].startswith('-')):
        raise ValueError('invalid_ssh_host')
    for value in [config['server'], config['spool'], config['source']['database'], config['source']['database_key'],
                  config['backup_key']['path'], destination['root'], destination['vault_key']]:
        if not Path(value).is_absolute():
            raise ValueError('absolute_path_required')
    spool=Path(config['spool']).resolve()
    if any(Path(value).resolve().is_relative_to(spool) for value in
           [config['source']['database'],config['source']['database_key'],config['backup_key']['path']]):
        raise ValueError('live_state_and_keys_must_be_outside_spool')
    policy = config['policy']
    if set(policy) != {'interval_seconds', 'snapshot_timeout_seconds', 'rpo_seconds', 'rto_seconds', 'retention_days', 'minimum_verified', 'repository_max_bytes', 'accepted'}:
        raise ValueError('invalid_policy_fields')
    if any(type(policy[k]) is not int for k in policy if k != 'accepted') or type(policy['accepted']) is not bool:
        raise ValueError('invalid_policy_types')
    if not (1 <= policy['interval_seconds'] < policy['rpo_seconds'] <= 7*86400
            and 1 <= policy['rto_seconds'] <= 86400 and 1 <= policy['retention_days'] <= 3650
            and 1 <= policy['snapshot_timeout_seconds'] < policy['rpo_seconds']
            and 2 <= policy['minimum_verified'] <= 1000 and 1024*1024 <= policy['repository_max_bytes'] <= 1024**4):
        raise ValueError('invalid_policy_bounds')
    coordination = config['source']['coordination']
    if coordination.get('mode') == 'lock':
        if set(coordination) != {'mode', 'path', 'wait_seconds'} or not Path(coordination['path']).is_absolute() or not 0 <= coordination['wait_seconds'] <= 600:
            raise ValueError('invalid_writer_lock')
    elif coordination.get('mode') == 'systemd':
        if set(coordination) != {'mode', 'unit', 'scope', 'health_url'} or coordination['scope'] not in {'user', 'system'} or not re.fullmatch(r'[A-Za-z0-9_.@-]+\.service', coordination['unit']):
            raise ValueError('invalid_service_coordination')
        parsed=urllib.parse.urlsplit(coordination['health_url'])
        if parsed.scheme!='http' or parsed.hostname not in {'127.0.0.1','localhost','::1'} or parsed.username or parsed.password or parsed.path!='/health' or parsed.query or parsed.fragment:
            raise ValueError('loopback_health_url_required')
    else:
        raise ValueError('writer_coordination_required')
    return config


class Endpoint:
    def __init__(self, config):
        self.config = config
        self.destination = config['destination']
        self.root = Path(self.destination['root'])
        self.helper = Path(__file__).with_name('backup_remote.py')
        self.server = self.root/'runtime'/('server-'+support.digest(Path(config['server'])))

    def command(self, arguments):
        if self.destination['transport'] == 'local':
            return ['python3', '-I', str(self.helper), *arguments]
        return ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
                '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2', self.destination['host'],
                shlex.join(['python3', '-I', str(self.root/'runtime/backup_remote.py'), *arguments])]

    def call(self, command, *arguments, source=None):
        args = [command, '--root', str(self.root), *map(str, arguments)]
        result = subprocess.run(self.command(args), stdin=source, capture_output=True,
                                timeout=self.config['policy']['rto_seconds']+60)
        if result.returncode:
            try:
                code = json.loads(result.stderr)['code']
            except (ValueError, KeyError):
                code = 'destination_unavailable'
            raise RuntimeError(code)
        return json.loads(result.stdout)

    def provision(self):
        independent_keys(self.config)
        # Initial provisioning is explicit and separate from scheduled backup
        # transfer. Normal receives never carry a recovery key or a source DB key.
        if self.destination['transport'] == 'local':
            support.private_dir(self.root/'runtime')
            self.server = Path(self.config['server'])
        else:
            self.bootstrap(self.helper, self.root/'runtime/backup_remote.py', 0o500)
            self.bootstrap(Path(self.config['server']), self.server, 0o500)
            sdk = next((p for p in [Path(__file__).parents[1]/'sdk/python/dolphi',
                                   Path(__file__).parents[1]/'lib/python/dolphi'] if (p/'__init__.py').exists()), None)
            if sdk is None:
                raise ValueError('source_sdk_unavailable')
            for name in ['__init__.py', 'mcp.py']:
                self.bootstrap(sdk/name, self.root/'runtime/python/dolphi'/name, 0o400)
        with Path(self.config['backup_key']['path']).open('rb') as key:
            return self.call('put-key', '--key', self.destination['vault_key'], source=key)

    def bootstrap(self, local, remote, mode):
        code = '''import hashlib,os,pathlib,sys,tempfile
path=pathlib.Path(sys.argv[1]); root=pathlib.Path(sys.argv[2]); mode=int(sys.argv[3]); expected=sys.argv[4]
assert path.is_relative_to(root) and path.is_absolute()
root.mkdir(parents=True,exist_ok=True,mode=0o700)
assert not root.is_symlink() and root.stat().st_uid==os.geteuid() and root.stat().st_mode&0o077==0
path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
with tempfile.NamedTemporaryFile(dir=path.parent,delete=False) as f:
 name=pathlib.Path(f.name); total=0; h=hashlib.sha256()
 try:
  while data:=sys.stdin.buffer.read(1024*1024):
   total+=len(data); assert total<128*1024*1024; f.write(data); h.update(data)
  assert h.hexdigest()==expected
  f.flush(); os.fsync(f.fileno()); os.chmod(name,mode); os.replace(name,path)
  d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
 finally:name.unlink(missing_ok=True)
'''
        args = ['python3', '-I', '-c', code, str(remote), str(self.root), str(mode), support.digest(local)]
        ssh = self.command([])[:-1] + [shlex.join(args)]
        with local.open('rb') as source:
            result = subprocess.run(ssh, stdin=source, capture_output=True, timeout=120)
        if result.returncode:
            raise RuntimeError('destination_provisioning_failed')


def resume(config):
    marker=Path(config['spool'])/'resume.json'
    if not marker.exists():return dict(resumed=False)
    saved=json.loads(support.read_private(marker))
    coordination=config['source']['coordination']
    if saved['coordination']!=coordination or coordination['mode']!='systemd':
        raise RuntimeError('resume_configuration_mismatch')
    ctl=['systemctl']+(['--user'] if coordination['scope']=='user' else [])
    result=subprocess.run([*ctl,'start',coordination['unit']],capture_output=True,timeout=60)
    if result.returncode:raise RuntimeError('source_service_resume_failed')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args):return None
    client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        try:
            with client.open(coordination['health_url'],timeout=1) as response:
                if json.loads(response.read(1024)).get('status')=='ok':break
        except Exception:pass
        time.sleep(0.1)
    else:raise RuntimeError('source_service_health_failed')
    marker.unlink();support.sync_dir(marker.parent)
    return dict(resumed=True)


def independent_keys(config):
    database=support.read_private(config['source']['database_key'],32)
    backup=support.read_private(config['backup_key']['path'],32)
    if len(database)!=32 or len(backup)!=32 or secrets.compare_digest(database,backup):
        raise ValueError('independent_backup_key_required')


@contextlib.contextmanager
def writers_stopped(config):
    coordination = config['source']['coordination']
    if coordination['mode'] == 'lock':
        fd = os.open(coordination['path'], os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as lock:
            deadline = time.monotonic()+coordination['wait_seconds']
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB); break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('source_writers_busy')
                    time.sleep(0.05)
            # Keep the cooperative lock held by the snapshot child if its
            # controller dies before the child finishes reading the source.
            yield (lock.fileno(),)
    else:
        ctl = ['systemctl'] + (['--user'] if coordination['scope'] == 'user' else [])
        unit = coordination['unit']
        before = subprocess.run([*ctl, 'is-active', unit], capture_output=True, text=True, timeout=30)
        active = before.stdout.strip() == 'active'
        if before.stdout.strip() not in {'active', 'inactive', 'failed'}:
            raise RuntimeError('source_service_state_unknown')
        try:
            if active:
                support.atomic_json(Path(config['spool'])/'resume.json',dict(coordination=coordination,recorded_at=support.stamp()))
                subprocess.run([*ctl, 'stop', unit], capture_output=True, timeout=60, check=True)
            state = subprocess.run([*ctl, 'is-active', unit], capture_output=True, text=True, timeout=30)
            if state.stdout.strip() not in {'inactive', 'failed'}:
                raise RuntimeError('source_service_not_stopped')
            yield ()
        finally:
            if active:
                resume(config)


def status_path(config):
    return Path(config['spool'])/'status.json'


def health(config):
    path = status_path(config)
    state = json.loads(support.read_private(path)) if path.exists() else {}
    receipt = state.get('last_verified')
    issues = []
    age = None
    if not receipt:
        issues.append('no_verified_offhost_backup')
    else:
        age = (support.now()-support.timestamp(receipt['metadata']['snapshot_started_at'])).total_seconds()
        if age < -30:
            issues.append('clock_skew')
        elif age > config['policy']['rpo_seconds']:
            issues.append('verified_backup_stale')
        elif age > config['policy']['rpo_seconds']*2/3:
            issues.append('verified_backup_age_warning')
        if receipt['restore_and_service_seconds'] > config['policy']['rto_seconds']:
            issues.append('restore_time_exceeded')
    if state.get('last_attempt', {}).get('status') == 'failed':
        issues.append('last_backup_attempt_failed')
    if (Path(config['spool'])/'resume.json').exists():issues.append('source_resume_pending')
    return dict(status='healthy' if not issues else 'attention_required', issues=issues,
                verified_snapshot_age_seconds=None if age is None else round(age, 3),
                rpo_target_seconds=config['policy']['rpo_seconds'], rto_target_seconds=config['policy']['rto_seconds'],
                policy_accepted=config['policy']['accepted'], production_qualified=False)


def backup(config):
    spool = support.private_dir(config['spool'])
    lock_fd = os.open(spool/'job.lock', os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, 'w') as job:
        fcntl.flock(job, fcntl.LOCK_EX|fcntl.LOCK_NB)
        path = status_path(config)
        state = json.loads(support.read_private(path)) if path.exists() else {}
        pending_path = spool/'pending.json'
        endpoint = Endpoint(config)
        if config['destination']['transport'] == 'local':
            endpoint.server = Path(config['server'])
        stage='resume_previous_job'
        try:
            resume(config)
            if pending_path.exists():
                stage='reconcile_pending_snapshot'
                metadata = json.loads(support.read_private(pending_path))
                if metadata['backup_key_id'] != config['backup_key']['id']:
                    raise ValueError('pending_backup_requires_previous_key')
                snapshot = spool/(metadata['id']+'.mimi')
                if support.digest(snapshot) != metadata['sha256']:
                    raise ValueError('pending_snapshot_corrupted')
            else:
                identity = support.now().strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex
                snapshot = spool/(identity+'.mimi')
                stage='snapshot_source'
                with writers_stopped(config) as inherited:
                    independent_keys(config)
                    started = support.stamp()
                    output = support.run(config['server'], 'migration-export-stream', config['source']['database'],
                                         config['source']['database_key'], snapshot, config['backup_key']['path'],
                                         timeout=config['policy']['snapshot_timeout_seconds'],pass_fds=inherited)
                    exported = json.loads(output)
                    if not exported['source_files_unchanged']:
                        raise ValueError('source_changed_during_backup')
                # Writers are resumed before network I/O or recovery drills.
                metadata = dict(id=identity, sha256=support.digest(snapshot), bytes=snapshot.stat().st_size,
                    snapshot_started_at=started, backup_key_id=config['backup_key']['id'],
                    server_sha256=support.digest(Path(config['server'])), source_profile=exported['source_profile'])
                support.atomic_json(pending_path, metadata)
            encoded = json.dumps(metadata, sort_keys=True)
            stage='transfer'
            with snapshot.open('rb') as source:
                endpoint.call('receive', '--metadata', encoded, '--quota', config['policy']['repository_max_bytes'], source=source)
            stage='restore_and_service_verification'
            receipt = endpoint.call('verify', '--metadata', encoded, '--server', endpoint.server,
                                    '--key', config['destination']['vault_key'], '--timeout', config['policy']['rto_seconds'])
            if receipt['metadata'] != metadata or receipt['status'] != 'verified':
                raise ValueError('destination_receipt_mismatch')
            state['last_verified'] = receipt
            state['last_attempt'] = dict(status='verified', id=metadata['id'], completed_at=support.stamp())
            support.atomic_json(path, state)
            pending_path.unlink(); support.sync_dir(spool)
            # Keep two local fallback snapshots; remote retention has its own
            # independently verified minimum. Never remove unrelated files.
            snapshots = sorted((p for p in spool.glob('*.mimi') if re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}',p.stem) and not p.is_symlink()), key=lambda p:p.name, reverse=True)
            for old in snapshots[2:]:
                if re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}',old.stem) and not old.is_symlink():
                    old.unlink()
            stage='retention'
            endpoint.call('prune', '--days', config['policy']['retention_days'], '--minimum', config['policy']['minimum_verified'])
            return dict(status='verified', backup_id=metadata['id'], health=health(config))
        except Exception as error:
            message = str(error)
            code = message if re.fullmatch('[a-z_]{1,100}', message) else 'backup_operation_failed'
            state['last_attempt'] = dict(status='failed', code=code, stage=stage, completed_at=support.stamp())
            support.atomic_json(path, state)
            raise RuntimeError(code) from None


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['provision', 'run', 'health', 'resume'])
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args(); config = read_config(args.config)
    if args.command == 'provision':
        if len(support.read_private(config['backup_key']['path'], 32)) != 32:
            raise ValueError('backup_key_size_invalid')
        result = Endpoint(config).provision()
    elif args.command == 'run':
        result = backup(config)
    elif args.command=='resume':
        result=resume(config)
    else:
        result = health(config)
    print(json.dumps(result, sort_keys=True))
    if args.command == 'health' and result['status'] != 'healthy':
        raise SystemExit(2)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        message = str(error)
        code = message if re.fullmatch('[a-z_]{1,100}', message) else 'backup_operation_failed'
        print(json.dumps(dict(status='failed', code=code)), file=sys.stderr)
        raise SystemExit(1)
