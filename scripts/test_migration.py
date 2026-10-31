#!/usr/bin/env python3
"""Real two-binary, two-direction migration acceptance test. Synthetic temp data only."""
import argparse
import hashlib
import json
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk/python"))
from dolphi import Client, DolphiError


def run(binary, *args, succeeds=True):
    result = subprocess.run([str(binary), *map(str,args)], capture_output=True, text=True, timeout=30)
    if (result.returncode == 0) != succeeds:
        raise AssertionError("unexpected command outcome: " + args[0])
    return result.stdout


def start(binary, db, key, token):
    process = subprocess.Popen([str(binary),"serve",str(db),str(key),"0"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout,selectors.EVENT_READ)
        if not selector.select(15):
            process.kill(); process.communicate(); raise AssertionError("server startup timed out")
    line = process.stdout.readline().decode()
    if " at " not in line:
        process.kill(); process.communicate(); raise AssertionError("server startup failed")
    url = line.split(" at ",1)[1].split(" ",1)[0]
    return process, Client(url,Path(token).read_text()), url


def stop(process, abrupt=False):
    if abrupt: process.kill()
    else: process.send_signal(signal.SIGINT)
    try: process.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        process.kill();process.communicate();raise AssertionError("server shutdown timed out")


def hashes(db):
    return {suffix:hashlib.sha256(Path(str(db)+suffix).read_bytes()).hexdigest()
            for suffix in ("","-wal","-shm") if Path(str(db)+suffix).exists()}


def unauthorized(client):
    try: client.me()
    except DolphiError as error:
        assert error.status == 401
    else: raise AssertionError("old bearer credential survived migration")


def scenario(source_binary, target_binary, directory):
    directory.mkdir()
    source=directory/"source.db";source_key=directory/"source.key";owner_token=directory/"source.token"
    snapshot=directory/"snapshot.mimi";backup_key=directory/"backup.key";target_key=directory/"target.key"
    target=directory/"target.db";report_path=directory/"verification.json"
    run(source_binary,"init",source,source_key,owner_token)
    process, owner, url = start(source_binary,source,source_key,owner_token)
    try:
        a=owner.create_agent(300);b=owner.create_agent(300);revoked=owner.create_agent(300)
        ac=Client(url,a["secret"]);bc=Client(url,b["secret"])
        text="line1\nÉ café\0🐬 '); DROP TABLE memories; --"
        ac.remember("private",text,operation_id="memory")
        bc.remember("private","agent B",operation_id="memory")
        approved=ac.propose("stock","12",operation_id="approved")
        owner.approve(approved,operation_id="approval")
        pending=bc.propose("next","pending",operation_id="pending")
        rejected=ac.propose("discard","no",operation_id="rejected")
        owner.reject(rejected,operation_id="rejection")
        owner.revoke_agent(revoked["agent_id"],operation_id="revocation")
        receipt=ac.operation_status("approved")
        history=owner.audit(limit=1000)
    finally:
        # All calls completed first; leave committed WAL and stop every writer.
        stop(process,abrupt=True)
    before=hashes(source)
    run(source_binary,"keygen",backup_key);run(target_binary,"keygen",target_key)
    exported=json.loads(run(source_binary,"migration-export",source,source_key,snapshot,backup_key))
    assert exported["source_files_unchanged"] and before==hashes(source)
    assert snapshot.read_bytes().find(text.encode()) == -1

    # Reject wrong export keys, damaged snapshots and existing outputs.
    failed=directory/"failed-export"
    run(source_binary,"migration-export",source,target_key,failed,backup_key,succeeds=False)
    assert not failed.exists() and before==hashes(source)
    run(target_binary,"migration-export",source,source_key,failed,backup_key,succeeds=False)
    assert not failed.exists() and before==hashes(source)
    damaged=directory/"damaged";damaged.write_bytes(snapshot.read_bytes()[:-17])
    for label,backup,key in [("wrong-key",snapshot,target_key),("damaged",damaged,backup_key)]:
        destination=directory/(label+".db");report=directory/(label+".json")
        run(target_binary,"migration-import",backup,key,destination,target_key,report,succeeds=False)
        assert not destination.exists() and not report.exists()
    report_path.write_text("preserve existing report")
    run(target_binary,"migration-import",snapshot,backup_key,target,target_key,report_path,succeeds=False)
    assert not target.exists() and report_path.read_text()=="preserve existing report"
    report_path.unlink()
    report=json.loads(run(target_binary,"migration-import",snapshot,backup_key,target,target_key,report_path))
    assert report==json.loads(report_path.read_text())
    assert report["verified_before_publication"] and len(report["tables"])==10
    assert report["credentials_invalidated"]==4  # initial owner + three agents
    assert before==hashes(source)
    assert target.stat().st_mode & 0o077 == 0
    assert report_path.stat().st_mode & 0o077 == 0
    preserved=hashes(target)
    run(target_binary,"migration-import",snapshot,backup_key,target,target_key,directory/"duplicate.json",succeeds=False)
    assert preserved==hashes(target) and not (directory/"duplicate.json").exists()

    token=directory/"fresh-owner.token"
    run(target_binary,"owner-token",target,target_key,token)
    process, migrated, url = start(target_binary,target,target_key,token)
    try:
        for secret in [owner_token.read_text(),a["secret"],b["secret"],revoked["secret"]]:
            unauthorized(Client(url,secret))
        assert migrated.audit(limit=1000)[:len(history)]==history
        assert migrated.inspect(approved)["status"]=="approved"
        assert migrated.inspect(rejected)["status"]=="rejected"
        assert migrated.inspect(pending)["status"]=="pending"
        new_a=migrated.issue_credential(a["agent_id"],300)
        new_b=migrated.issue_credential(b["agent_id"],300)
        ac=Client(url,new_a["secret"]);bc=Client(url,new_b["secret"])
        assert ac.recall("private")==text and bc.recall("private")=="agent B"
        assert ac.operation_status("approved")==receipt
        assert ac.propose("stock","12",operation_id="approved")==approved
        migrated.approve(approved,operation_id="approval")
        assert migrated.read_shared("stock")["version"]==1
        assert bc.propose("next","pending",operation_id="pending")==pending
        migrated.approve(pending,operation_id="finish-pending")
        assert bc.read_shared("next")["value"]=="pending"
        try: migrated.issue_credential(revoked["agent_id"],300)
        except DolphiError as error: assert error.status==403
        else: raise AssertionError("revoked agent was resurrected")
    finally: stop(process)
    assert before==hashes(source)
    return {"source_profile":exported["source_profile"],"target_profile":report["target_profile"],
            "source_unchanged":True,"tables_verified":len(report["tables"]),
            "old_credentials_rejected":4,"committed_wal_source":True,
            "private_memory_review_receipts_and_revocation_verified":True,
            "failure_cases_verified":6}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--embedded-server",type=Path,required=True)
    parser.add_argument("--encrypted-server",type=Path,required=True)
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="dolphi-cross-migration-") as temporary:
        root=Path(temporary)
        forward=scenario(args.embedded_server.resolve(),args.encrypted_server.resolve(),root/"forward")
        reverse=scenario(args.encrypted_server.resolve(),args.embedded_server.resolve(),root/"reverse")
        print(json.dumps({"forward":forward,"reverse":reverse,"status":"passed"},indent=2))


if __name__=="__main__":main()
