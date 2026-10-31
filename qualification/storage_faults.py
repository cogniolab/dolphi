#!/usr/bin/env python3
"""Real release-binary storage faults, confined to synthetic /tmp databases."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time

PROJECT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PROJECT/'sdk/python'))
from dolphi import Client,DolphiError

class Fixture:
    def __init__(self,root,server,control_binary,interposer):
        self.root=root;self.server=server;self.control_binary=control_binary;self.interposer=interposer
        for name in ['database','backup','restore','report','scratch']:(root/name).mkdir(exist_ok=True)
        self.db=root/'database/memory.db';self.key=root/'database.key';self.token=root/'owner.token'
        self.control=root/'fault-control';self.trace=root/'fault-trace';self.process=None
        assert self.run(['init',self.db,self.key,self.token]).returncode==0
        self.start();self.clients()
        self.registration=self.owner.create_agent(300);self.clients()
        self.baseline={f'baseline-{i}':f'acknowledged-{i}' for i in range(5)}
        for key,value in self.baseline.items():self.agent.remember(key,value,operation_id=key)
        p=self.agent.propose('shared','baseline',operation_id='baseline-proposal')
        self.owner.approve(p,operation_id='baseline-approval');self.history=self.owner.audit(limit=1000)
    def clients(self):
        self.owner=Client(self.url,self.token.read_text())
        if hasattr(self,'registration'):self.agent=Client(self.url,self.registration['secret'])
    def environment(self):
        env=os.environ.copy();env.update({'LD_PRELOAD':str(self.interposer),'DOLPHI_FAULT_ROOT':str(self.root),'DOLPHI_FAULT_CONTROL':str(self.control),'DOLPHI_FAULT_LOG':str(self.trace),'TMPDIR':str(self.root/'scratch')})
        return env
    def run(self,args,fault=False):
        return subprocess.run([str(self.server),*map(str,args)],env=self.environment() if fault else None,capture_output=True,text=True,timeout=30)
    def start(self):
        with (self.root/'server-errors').open('ab') as errors:
            self.process=subprocess.Popen([str(self.server),'serve',str(self.db),str(self.key),'0'],env=self.environment(),stdout=subprocess.PIPE,stderr=errors)
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout,selectors.EVENT_READ)
            if not selector.select(10):raise AssertionError('server readiness timeout')
        line=self.process.stdout.readline().decode()
        if ' at http://' not in line:raise AssertionError('server readiness failed')
        self.url=line.split(' at ',1)[1].split(' ',1)[0]
    def stop(self,abrupt=False):
        if self.process and self.process.poll() is None:
            self.process.kill() if abrupt else self.process.send_signal(signal.SIGINT)
            try:self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait()
        if self.process and self.process.stdout:self.process.stdout.close()
        self.process=None
    def restart(self):self.start();self.clients()
    def arm(self,op,kind,mode,skip=0):self.control.write_text(f'{op} {kind} {mode} {skip}\n')
    def disarm(self):self.control.unlink(missing_ok=True)
    def events(self):return [json.loads(s) for s in self.trace.read_text().splitlines()] if self.trace.exists() else []
    def check(self):
        result=subprocess.run([str(self.control_binary),'check',str(self.db),str(self.key)],capture_output=True,text=True,timeout=30)
        if result.returncode:raise AssertionError('integrity/page-authentication failed: '+result.stderr[-400:])
        return json.loads(result.stdout)
    def preserved(self):
        for key,value in self.baseline.items():
            assert self.agent.recall(key)==value
            assert self.agent.operation_status(key)['status']=='committed'
        assert self.owner.operation_status('baseline-approval')['status']=='committed'
        assert self.owner.audit(limit=1000)[:len(self.history)]==self.history

def transaction_case(root,server,control,interposer,action,op,mode,skip):
    f=Fixture(root,server,control,interposer)
    try:
        pending=f.agent.propose('shared','updated',operation_id='pending') if action=='approve' else None
        victim=f.owner.create_agent(300) if action=='revoke' else None
        operation='fault-operation';value='encrypted synthetic candidate '*1800
        def attempt():
            try:
                if action=='remember':result=f.agent.remember('candidate',value,operation_id=operation)
                elif action=='propose':result=f.agent.propose('candidate',value,operation_id=operation)
                elif action=='approve':result=f.owner.approve(pending,operation_id=operation)
                else:result=f.owner.revoke_credential(victim['credential_id'],operation_id=operation)
                return True,result
            except DolphiError:return False,None
        f.history=f.owner.audit(limit=1000);f.arm(op,'wal',mode,skip);started=time.monotonic()
        if mode in ['pause','tear_pause']:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future=pool.submit(attempt);deadline=time.monotonic()+8
                while not f.events() and time.monotonic()<deadline and not future.done():time.sleep(0.01)
                assert f.events(),'fault boundary not reached'
                f.stop(abrupt=True);acknowledged,result=future.result(timeout=10)
        else:acknowledged,result=attempt();f.stop(abrupt=True)
        events=f.events();assert events,'no fault injected'
        f.disarm();f.restart();recovery_ms=(time.monotonic()-started)*1000
        f.preserved();principal=f.agent if action in ['remember','propose'] else f.owner
        receipt=principal.operation_status(operation);committed=receipt is not None
        if acknowledged:assert committed,'acknowledged commit lost'
        checks=f.check()
        if action=='remember':
            assert f.agent.recall('candidate')==(value if committed else None)
            assert checks['candidate_memories']==int(committed)
            saves=[e for e in f.owner.audit(limit=1000) if e['action']=='memory.saved' and e['subject']=='candidate']
            assert len(saves)==int(committed)
        elif action=='propose':
            assert checks['candidate_proposals']==int(committed)
            if committed:assert f.owner.inspect(receipt['result']['id'])['value']==value
            created=[e for e in f.owner.audit(limit=1000)[len(f.history):] if e['action']=='proposal.created']
            assert len(created)==int(committed)
            if committed:assert created[0]['subject']==receipt['result']['id']
        elif action=='approve':
            assert f.owner.inspect(pending)['status']==('approved' if committed else 'pending')
            assert f.owner.read_shared('shared')['version']==(2 if committed else 1)
            assert len([e for e in f.owner.audit(limit=1000) if e['action']=='proposal.approved' and e['subject']==pending])==int(committed)
        else:
            try:Client(f.url,victim['secret']).me();revoked=False
            except DolphiError as error:assert error.status==401;revoked=True
            assert revoked==committed
            events_for_victim=[e for e in f.owner.audit(limit=1000) if e['action']=='credential.revoked' and e['subject']==victim['credential_id']]
            assert len(events_for_victim)==int(committed)
        first=attempt();assert first[0]
        audit_after_first=f.owner.audit(limit=1000)
        second=attempt();assert second[0] and first[1]==second[1]
        assert f.owner.audit(limit=1000)==audit_after_first,'retry appended a duplicate event'
        assert principal.operation_status(operation) is not None
        checks=f.check()
        if action=='remember':assert checks['candidate_memories']==1
        elif action=='propose':assert checks['candidate_proposals']==1
        return {'case':f'{action}-{op}-{mode}-skip{skip}','acknowledged_before_failure':acknowledged,'recovered_complete_transaction':committed,'fault_events':len(events),'first_event':events[0],'previous_acknowledged_data_preserved':True,'atomic_data_audit_receipt':True,'same_id_retry_reconciled':True,'retry_did_not_duplicate_audit':True,'restart_observation_ms':round(recovery_ms,2),'status':'passed'}
    finally:f.disarm();f.stop(abrupt=True)

def artifact_case(root,server,control,interposer,operation,op,kind,mode,streaming=False):
    f=Fixture(root,server,control,interposer)
    try:
        f.stop();before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'database').iterdir() if p.is_file()}
        backup_key=root/'backup.key';new_key=root/'new.key'
        assert f.run(['keygen',backup_key]).returncode==0 and f.run(['keygen',new_key]).returncode==0
        snapshot=root/'backup/snapshot.mimi';destination=root/'restore/recovered.db';report=root/'report/result.json'
        export='migration-export-stream' if streaming else 'migration-export'
        if operation!='export':assert f.run([export,f.db,f.key,snapshot,backup_key]).returncode==0
        f.arm(op,kind,mode)
        command=[export,f.db,f.key,snapshot,backup_key] if operation=='export' else ['migration-import',snapshot,backup_key,destination,new_key,report]
        process=subprocess.Popen([str(server),*map(str,command)],env=f.environment(),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if mode in ['pause','tear_pause']:
            deadline=time.monotonic()+8
            while not f.events() and time.monotonic()<deadline and process.poll() is None:time.sleep(0.01)
            if not f.events():process.kill();process.communicate();raise AssertionError('artifact fault not reached')
            process.kill()
        stdout,stderr=process.communicate(timeout=30)
        assert process.returncode!=0,'faulted operation reported success'
        assert f.events(),'no artifact fault injected'
        f.disarm()
        assert before=={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'database').iterdir() if p.is_file()}
        if destination.exists():
            checked=subprocess.run([str(control),'check',str(destination),str(new_key)],capture_output=True,text=True,timeout=30)
            assert checked.returncode==0,'published destination invalid'
        if snapshot.exists():
            assert f.run(['migration-import',snapshot,backup_key,root/'restore/retry.db',new_key,root/'report/retry.json']).returncode==0
        f.restart();f.preserved();f.check()
        return {'case':f'{operation}-{op}-{kind}-{mode}','fault_events':len(f.events()),'source_bytes_preserved':True,'published_database_valid':destination.exists(),'snapshot_published':snapshot.exists(),'failure_not_reported_as_success':True,'status':'passed'}
    finally:f.disarm();f.stop(abrupt=True)

def checkpoint_case(root,server,control,interposer,op,kind,mode):
    f=Fixture(root,server,control,interposer)
    try:
        f.stop(abrupt=True)
        assert Path(str(f.db)+'-wal').stat().st_size>32
        f.arm(op,kind,mode)
        process=subprocess.Popen([str(control),'checkpoint',str(f.db),str(f.key)],env=f.environment(),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if mode in ['pause','tear_pause']:
            deadline=time.monotonic()+8
            while not f.events() and process.poll() is None and time.monotonic()<deadline:time.sleep(0.01)
            if not f.events():process.kill();process.communicate();raise AssertionError('checkpoint fault not reached')
            process.kill()
        stdout,stderr=process.communicate(timeout=30)
        assert f.events(),'checkpoint injected no fault'
        if mode=='short':assert process.returncode==0
        else:assert process.returncode!=0
        f.disarm();f.restart();f.preserved();f.stop();f.check()
        retry=subprocess.run([str(control),'checkpoint',str(f.db),str(f.key)],capture_output=True,text=True,timeout=30)
        assert retry.returncode==0
        return {'case':f'checkpoint-{op}-{kind}-{mode}','fault_events':len(f.events()),'acknowledged_data_and_receipts_preserved':True,'checkpoint_retry_passed':True,'status':'passed'}
    finally:f.disarm();f.stop(abrupt=True)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['server','control','interposer','output']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--streaming-artifacts-only',action='store_true',help='Qualify v3 snapshot publication and restore faults only')
    a=p.parse_args();server=a.server.resolve();control=a.control.resolve();interposer=a.interposer.resolve();results=[];calibration=[]
    if a.streaming_artifacts_only:
        cases=[('export','write','backup','full'),('export','sync','backup','eio'),('export','sync','backupdir','eio'),('export','write','copy','eio'),('export','write','backup','pause'),('restore','pwrite','stage','eio'),('restore','sync','stage','eio'),('restore','pwrite','stage','tear_pause'),('restore','sync','restoredir','eio'),('restore','write','report','full'),('restore','sync','report','eio')]
        for operation,op,kind,mode in cases:
            with tempfile.TemporaryDirectory(prefix='dolphi-storage-') as temporary:
                result=artifact_case(Path(temporary),server,control,interposer,operation,op,kind,mode,streaming=True)
                results.append(result);print(result['case']+': passed',flush=True)
        summary=dict(status='passed',case_count=len(results),cases=results,snapshot_version=3,release_binary_sha256=hashlib.sha256(server.read_bytes()).hexdigest(),physical_power_loss_tested=False,live_installations_touched=False)
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(summary,indent=2)+'\n')
        print(json.dumps(dict(status='passed',case_count=len(results))))
        return
    for action in ['remember','propose','approve','revoke']:
        for op,mode,skip in [('pwrite','full',0),('pwrite','eio',0),('pwrite','short',0),('pwrite','short_full',0),('sync','eio',0),('pwrite','tear_pause',2),('sync','pause',0)]:
            with tempfile.TemporaryDirectory(prefix='dolphi-storage-') as temporary:
                result=transaction_case(Path(temporary),server,control,interposer,action,op,mode,skip)
                results.append(result);print(result['case']+': passed',flush=True)
    cases=[('export','write','backup','full'),('export','sync','backup','eio'),('export','sync','backupdir','eio'),('export','write','copy','eio'),('export','write','backup','pause'),('restore','pwrite','stage','eio'),('restore','sync','stage','eio'),('restore','pwrite','stage','tear_pause'),('restore','sync','restoredir','eio'),('restore','write','report','full'),('restore','sync','report','eio')]
    for operation,op,kind,mode in cases:
        with tempfile.TemporaryDirectory(prefix='dolphi-storage-') as temporary:
            result=artifact_case(Path(temporary),server,control,interposer,operation,op,kind,mode)
            results.append(result);print(result['case']+': passed',flush=True)
    for op,kind,mode in [('pwrite','db','eio'),('pwrite','db','short'),('pwrite','db','tear_pause'),('sync','db','eio'),('sync','db','pause'),('truncate','wal','eio')]:
        with tempfile.TemporaryDirectory(prefix='dolphi-storage-') as temporary:
            result=checkpoint_case(Path(temporary),server,control,interposer,op,kind,mode)
            results.append(result);print(result['case']+': passed',flush=True)
    # Calibrate real syscall counts for the same fixture, then fail every
    # later WAL write/sync ordinal. Ordinal zero is covered by the matrix above.
    for action in ['remember','propose','approve','revoke']:
        for op in ['pwrite','sync']:
            with tempfile.TemporaryDirectory(prefix='dolphi-storage-') as temporary:
                traced=transaction_case(Path(temporary),server,control,interposer,action,op,'trace',0)
            total=traced['fault_events'];calibration.append({'action':action,'op':op,'observed_syscalls':total})
            for ordinal in range(1,total):
                with tempfile.TemporaryDirectory(prefix='dolphi-storage-') as temporary:
                    result=transaction_case(Path(temporary),server,control,interposer,action,op,'eio',ordinal)
                    results.append(result);print(result['case']+': passed',flush=True)
    summary={'status':'passed','cases':results,'case_count':len(results),'calibration':calibration,'physical_power_loss_tested':False,'live_installations_touched':False,'release_binary_sha256':hashlib.sha256(server.read_bytes()).hexdigest(),'fault_interposer_sha256':hashlib.sha256(interposer.read_bytes()).hexdigest()}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({'case_count':len(results),'status':'passed'}))

if __name__=='__main__':main()
