#!/usr/bin/env python3
"""Private recovery endpoint. Invoked through trusted SSH; no network listener."""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time

IDENTIFIER = re.compile(r'[A-Za-z0-9_-]{1,100}\Z')
MAX_FILE = 4 * 1024**3


def now():
    return dt.datetime.now(dt.timezone.utc)


def stamp(value=None):
    return (value or now()).isoformat()


def timestamp(value):
    result = dt.datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise ValueError('timestamp_requires_timezone')
    return result


def private_dir(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('absolute_path_required')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if path.is_symlink() or not path.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('private_directory_required')
    return path


def read_private(path, maximum=1024*1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        import stat
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o077:
            raise ValueError('private_regular_file_required')
        result = source.read(maximum+1)
        if len(result) > maximum:
            raise ValueError('file_bound_exceeded')
        return result


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, value):
    path = Path(path)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.status-', delete=False) as target:
        name = Path(target.name)
        try:
            target.write((json.dumps(value, sort_keys=True, indent=2)+'\n').encode())
            target.flush(); os.fsync(target.fileno())
            os.replace(name, path); sync_dir(path.parent)
        finally:
            name.unlink(missing_ok=True)


def digest(path):
    result = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        import stat
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('regular_backup_required')
        for block in iter(lambda: source.read(1024*1024), b''):
            result.update(block)
    return result.hexdigest()


def run(server, *arguments, timeout=1800, pass_fds=()):
    result = subprocess.run([str(server), *map(str, arguments)], capture_output=True, timeout=timeout,
                            env=clean_env(), pass_fds=pass_fds)
    if result.returncode:
        raise RuntimeError('server_operation_failed')
    return result.stdout


def clean_env():
    environment = os.environ.copy()
    for name in ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'OPENSSL_CONF', 'OPENSSL_MODULES', 'OPENSSL_ENGINES']:
        environment.pop(name, None)
    environment['TOKIO_WORKER_THREADS']='2'
    return environment


def load_sdk():
    for path in [Path(__file__).parent/'python', Path(__file__).parents[1]/'lib/python', Path(__file__).parents[1]/'sdk/python']:
        if (path/'dolphi/__init__.py').is_file():
            sys.path.insert(0, str(path))
            from dolphi import Client, DolphiError
            return Client, DolphiError
    raise RuntimeError('private_sdk_unavailable')


def service_drill(server, database, key, root, timeout):
    Client, DolphiError = load_sdk()
    token = root/'owner.token'
    run(server, 'owner-token', database, key, token, timeout=timeout)
    errors = (root/'server.log').open('wb')
    process = subprocess.Popen([str(server), 'serve', str(database), str(key), '0'],
                               stdout=subprocess.PIPE, stderr=errors, env=clean_env())
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(20):
                raise RuntimeError('restored_service_timeout')
        line = process.stdout.readline().decode()
        if ' at http://127.0.0.1:' not in line:
            raise RuntimeError('restored_service_failed')
        url = line.split(' at ', 1)[1].split(' ', 1)[0]
        owner = Client(url, read_private(token, 64).decode())
        assert owner.me()['role'] == 'owner'
        a, b = owner.create_agent(300), owner.create_agent(300)
        agent, peer = Client(url, a['secret']), Client(url, b['secret'])
        agent.remember('drill-private', 'synthetic recovery probe', operation_id='restore-probe')
        assert agent.recall('drill-private') == 'synthetic recovery probe'
        assert peer.recall('drill-private') is None
        low, high = 0, 2**63-1
        while low < high:
            middle = (low+high)//2
            if owner.audit(after=middle, limit=1):
                low = middle+1
            else:
                high = middle
        agent.remember('drill-private', 'synthetic recovery probe', operation_id='restore-probe')
        assert owner.audit(after=low, limit=1) == []
        proposal = agent.propose('drill-shared', 'reviewed')
        try:
            agent.approve(proposal)
        except DolphiError as error:
            assert error.status == 403
        else:
            raise AssertionError('owner_review_bypassed')
        owner.approve(proposal)
        assert peer.read_shared('drill-shared')['value'] == 'reviewed'
        owner.revoke_credential(a['credential_id'])
        try:
            agent.me()
        except DolphiError as error:
            assert error.status == 401
        else:
            raise AssertionError('revoked_credential_accepted')
        return dict(authentication=True, private_memory=True, namespace_isolation=True,
                    retries_without_duplicate_audit=True, owner_review=True, revocation=True)
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
        process.stdout.close(); errors.close()


def checked_metadata(metadata):
    required = {'id', 'sha256', 'bytes', 'snapshot_started_at', 'backup_key_id', 'server_sha256', 'source_profile'}
    if set(metadata) != required or not IDENTIFIER.fullmatch(metadata['id']) or not IDENTIFIER.fullmatch(metadata['backup_key_id']):
        raise ValueError('invalid_backup_metadata')
    if any(not re.fullmatch(r'[a-f0-9]{64}', metadata[field]) for field in ['sha256', 'server_sha256']):
        raise ValueError('invalid_backup_digest')
    if type(metadata['bytes']) is not int or not 1 <= metadata['bytes'] <= MAX_FILE:
        raise ValueError('invalid_backup_size')
    if timestamp(metadata['snapshot_started_at']) > now()+dt.timedelta(seconds=30):
        raise ValueError('source_clock_ahead')


def receive(root, metadata, quota):
    checked_metadata(metadata)
    objects = private_dir(root/'objects')
    destination = objects/(metadata['id']+'.mimi')
    if destination.exists():
        if destination.is_symlink() or destination.stat().st_size != metadata['bytes'] or digest(destination) != metadata['sha256']:
            raise ValueError('backup_id_conflict')
        return dict(received=True, reconciled=True)
    used = sum(p.stat().st_size for p in objects.glob('*.mimi') if not p.is_symlink())
    if used+metadata['bytes'] > quota or shutil.disk_usage(root).free < metadata['bytes']*4+64*1024*1024:
        raise ValueError('repository_capacity_exceeded')
    with tempfile.NamedTemporaryFile(dir=objects, prefix='.partial-', delete=False) as output:
        partial = Path(output.name)
        try:
            count = 0; hashed = hashlib.sha256()
            while block := sys.stdin.buffer.read(1024*1024):
                count += len(block)
                if count > metadata['bytes']:
                    raise ValueError('transfer_size_exceeded')
                output.write(block); hashed.update(block)
            if count != metadata['bytes'] or hashed.hexdigest() != metadata['sha256']:
                raise ValueError('transfer_incomplete_or_corrupted')
            output.flush(); os.fsync(output.fileno())
            os.link(partial, destination, follow_symlinks=False); sync_dir(objects)
        finally:
            partial.unlink(missing_ok=True)
    return dict(received=True, reconciled=False)


def verify(root, metadata, server, vault_key, timeout):
    checked_metadata(metadata)
    if Path(vault_key).is_relative_to(root):
        raise ValueError('recovery_key_must_be_outside_backup_tree')
    if len(read_private(vault_key, 32)) != 32:
        raise ValueError('recovery_key_unavailable')
    if digest(server) != metadata['server_sha256']:
        raise ValueError('recovery_runtime_mismatch')
    snapshot = root/'objects'/(metadata['id']+'.mimi')
    if snapshot.is_symlink() or snapshot.stat().st_size != metadata['bytes'] or digest(snapshot) != metadata['sha256']:
        raise ValueError('backup_object_mismatch')
    receipts = private_dir(root/'receipts'); saved = receipts/(metadata['id']+'.json')
    if saved.exists():
        receipt = json.loads(read_private(saved))
        if receipt['metadata'] != metadata:
            raise ValueError('verification_receipt_conflict')
        return receipt
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='.restore-drill-', dir=root) as temporary:
        drill = Path(temporary); key = drill/'database.key'; database = drill/'memory.db'; report = drill/'tables.json'
        run(server, 'keygen', key, timeout=timeout)
        result = json.loads(run(server, 'migration-import', snapshot, vault_key, database, key, report, timeout=timeout))
        if not result['verified_before_publication'] or len(result['tables']) != 10 or result['snapshot_version'] != 3 or result['target_profile'] != metadata['source_profile']:
            raise ValueError('restore_verification_failed')
        probes = service_drill(server, database, key, drill, timeout)
    elapsed = time.monotonic()-start
    if elapsed > timeout:
        raise ValueError('recovery_objective_exceeded')
    receipt = dict(status='verified', metadata=metadata, verified_at=stamp(),
                   restore_and_service_seconds=round(elapsed, 3), tables=result['tables'],
                   credentials_invalidated=result['credentials_invalidated'], service=probes,
                   original_database_key_used=False)
    atomic_json(saved, receipt)
    return receipt


def prune(root, days, minimum):
    if not 1 <= days <= 3650 or not 2 <= minimum <= 1000:
        raise ValueError('invalid_retention_policy')
    receipts = private_dir(root/'receipts'); objects = private_dir(root/'objects')
    paths = list(receipts.glob('*.json'))
    if len(paths) > 100_000:
        raise ValueError('catalog_bound_exceeded')
    entries = []
    for path in paths:
        record = json.loads(read_private(path))
        checked_metadata(record['metadata'])
        if record.get('status') != 'verified' or path.stem != record['metadata']['id']:
            raise ValueError('invalid_verification_catalog')
        snapshot = objects/(record['metadata']['id']+'.mimi')
        if not snapshot.exists() or snapshot.is_symlink() or snapshot.stat().st_size != record['metadata']['bytes'] or digest(snapshot) != record['metadata']['sha256']:
            raise ValueError('retention_requires_intact_verified_objects')
        entries.append((timestamp(record['metadata']['snapshot_started_at']), path, record))
    entries.sort(key=lambda entry: entry[0], reverse=True)
    removed = []
    for created, path, record in entries[minimum:]:
        if created < now()-dt.timedelta(days=days):
            snapshot = objects/(record['metadata']['id']+'.mimi')
            if snapshot.is_symlink():
                raise ValueError('unsafe_retention_object')
            snapshot.unlink(missing_ok=True); path.unlink(); removed.append(record['metadata']['id'])
    sync_dir(objects); sync_dir(receipts)
    return dict(removed=removed, minimum_verified_retained=minimum)


def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['receive', 'verify', 'prune', 'put-key'])
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--metadata', default='{}')
    parser.add_argument('--server', type=Path)
    parser.add_argument('--key', type=Path)
    parser.add_argument('--quota', type=int, default=64*1024**3)
    parser.add_argument('--timeout', type=int, default=1800)
    parser.add_argument('--days', type=int, default=7)
    parser.add_argument('--minimum', type=int, default=3)
    args = parser.parse_args(); root = private_dir(args.root)
    lock_path = root/'operations.lock'
    fd = os.open(lock_path, os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.command == 'put-key':
            if args.key is None or args.key.is_relative_to(root):
                raise ValueError('separate_key_vault_required')
            private_dir(args.key.parent)
            data = sys.stdin.buffer.read(33)
            if len(data) != 32:
                raise ValueError('recovery_key_size_invalid')
            if args.key.exists():
                if read_private(args.key, 32) != data:
                    raise ValueError('existing_recovery_key_differs')
            else:
                key_fd = os.open(args.key, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
                with os.fdopen(key_fd, 'wb') as target:
                    target.write(data); target.flush(); os.fsync(target.fileno())
                sync_dir(args.key.parent)
            result = dict(key_provisioned=True)
        elif args.command == 'receive':
            result = receive(root, json.loads(args.metadata), args.quota)
        elif args.command == 'verify':
            def deadline(signum, frame):
                raise RuntimeError('recovery_objective_exceeded')
            signal.signal(signal.SIGALRM, deadline)
            signal.signal(signal.SIGTERM, deadline)
            signal.signal(signal.SIGHUP, deadline)
            signal.alarm(args.timeout)
            result = verify(root, json.loads(args.metadata), args.server, args.key, args.timeout)
            signal.alarm(0)
        else:
            result = prune(root, args.days, args.minimum)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Safe, fixed error codes only. Never emit keys, tokens or stderr from a
        # restored process into scheduler logs or an SSH response.
        message = str(error)
        code = message if re.fullmatch('[a-z_]{1,100}', message) else 'recovery_operation_failed'
        print(json.dumps(dict(status='failed', code=code)), file=sys.stderr)
        raise SystemExit(1)
