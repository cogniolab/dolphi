#!/usr/bin/env python3
"""Privileged synthetic systemd/UID qualification. Never opens an installed DB."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

PROBE=r'''
import json,os,sys
from pathlib import Path
from dolphi import Client,DolphiError
url,token_file,*protected=sys.argv[1:]
token=Path(token_file).read_text().strip()
client=Client(url,token)
denied=[]
for name in protected:
    try:
        with open(name,'rb') as stream:stream.read(1)
    except (PermissionError,ProcessLookupError):denied.append(name)
    else:raise AssertionError('agent read a protected service resource')
client.remember('isolation-canary','synthetic',operation_id='isolated-write')
proposal=client.propose('isolated-shared','synthetic',operation_id='isolated-proposal')
assert client.propose('isolated-shared','synthetic',operation_id='isolated-proposal')==proposal
try:client.approve(proposal)
except DolphiError as error:assert error.status==403
else:raise AssertionError('agent self-approved')
try:client._request('/v1/memory/recall',{'key':'x','agent_id':'owner'})
except DolphiError as error:assert error.status==400
else:raise AssertionError('identity spoof was accepted')
status=Path('/proc/self/status').read_text()
assert 'NoNewPrivs:\t1' in status
assert int(next(line.split()[1] for line in status.splitlines() if line.startswith('CapEff:')),16)==0
print(json.dumps({'agent_uid':os.geteuid(),'protected_reads_denied':len(denied),'private_memory_and_retry_api_pass':True,'owner_api_denied':True,'identity_spoof_denied':True,'proposal_id':proposal}))
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if os.geteuid()!=0:raise SystemExit('run this synthetic fixture with sudo; it creates only a transient unit and temporary data')
    project=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(project/'sdk/python'))
    from dolphi import Client,DolphiError
    unit='dolphi-qualification-'+uuid.uuid4().hex[:12]
    runtime=Path('/run')/unit
    with tempfile.TemporaryDirectory(prefix='dolphi-isolation-') as temporary:
        root=Path(temporary);root.chmod(0o755)
        controller=root/'controller';controller.mkdir(mode=0o700)
        binary=root/'dolphi-server';shutil.copyfile(args.server.resolve(),binary);binary.chmod(0o755)
        lib=root/'python';shutil.copytree(project/'sdk/python/dolphi',lib/'dolphi',ignore=shutil.ignore_patterns('__pycache__'))
        # Source permissions may include restrictive inherited ACLs; make only
        # public synthetic code readable by the isolated identities.
        for path in lib.rglob('*'):path.chmod(0o755 if path.is_dir() else 0o644)
        lib.chmod(0o755)
        subprocess.run([str(binary),'init',str(controller/'seed.db'),str(controller/'database.key'),str(controller/'owner.token')],check=True,capture_output=True)
        bootstrap=root/'bootstrap.py'
        bootstrap.write_text('import os,shutil,sys\nfrom pathlib import Path\np=Path(os.environ["CREDENTIALS_DIRECTORY"])\nr=Path(sys.argv[2])\nshutil.copyfile(p/"initial.db",r/"memory.db")\n(r/"memory.db").chmod(0o600)\nshutil.copyfile(p/"database.key",r/"database.key")\n(r/"database.key").chmod(0o600)\nos.execv(sys.argv[1],[sys.argv[1],"serve",str(r/"memory.db"),str(r/"database.key"),"0"])\n')
        bootstrap.chmod(0o644)
        properties={
            'DynamicUser':'yes','RuntimeDirectory':unit,'RuntimeDirectoryMode':'0700',
            'LoadCredential':f'database.key:{controller}/database.key',
            'UMask':'0077','NoNewPrivileges':'yes','CapabilityBoundingSet':'','AmbientCapabilities':'',
            'ProtectSystem':'strict','ProtectHome':'yes','PrivateTmp':'yes','PrivateDevices':'yes',
            'ProtectKernelTunables':'yes','ProtectKernelModules':'yes','ProtectKernelLogs':'yes',
            'ProtectControlGroups':'yes','ProtectClock':'yes','ProtectHostname':'yes',
            'ProtectProc':'invisible','ProcSubset':'pid','RestrictSUIDSGID':'yes','RestrictRealtime':'yes',
            'RestrictNamespaces':'yes','LockPersonality':'yes','MemoryDenyWriteExecute':'yes',
            'RestrictAddressFamilies':'AF_INET AF_UNIX','IPAddressDeny':'any','IPAddressAllow':'localhost',
            'SystemCallArchitectures':'native','LimitCORE':'0','LimitNOFILE':'1024','TasksMax':'64','MemoryMax':'512M','CPUQuota':'200%',
            'BindReadOnlyPaths':str(root),
        }
        command=['systemd-run','--quiet','--collect','--unit='+unit,'--service-type=exec']
        for key,value in properties.items():command.extend(['--property',key+'='+value])
        command.extend(['--property','LoadCredential=initial.db:'+str(controller/'seed.db')])
        command.extend(['/usr/bin/python3',str(bootstrap),str(binary),str(runtime)])
        try:
            subprocess.run(command,check=True,capture_output=True,text=True)
            deadline=time.monotonic()+20;url=None
            while time.monotonic()<deadline:
                log=subprocess.check_output(['journalctl','-u',unit,'--no-pager','-o','cat'],text=True)
                match=re.search(r'Dolphi listening at (http://127\.0\.0\.1:\d+)',log)
                if match:url=match.group(1);break
                state=subprocess.check_output(['systemctl','show',unit,'--property=ActiveState','--value'],text=True).strip()
                if state not in ['active','activating']:raise RuntimeError('isolated service failed: '+log[-1200:])
                time.sleep(0.1)
            if url is None:raise RuntimeError('isolated service readiness timed out')
            service_uid=runtime.stat().st_uid
            assert service_uid not in [0,65534]
            owner=Client(url,(controller/'owner.token').read_text().strip())
            registration=owner.create_agent(300)
            agent_area=root/'agent';agent_area.mkdir(mode=0o700);os.chown(agent_area,65534,65534)
            token_file=agent_area/'agent.token';token_file.write_text(registration['secret']);token_file.chmod(0o600);os.chown(token_file,65534,65534)
            probe=root/'probe.py';probe.write_text(PROBE);probe.chmod(0o644)
            pid=subprocess.check_output(['systemctl','show',unit,'--property=MainPID','--value'],text=True).strip()
            protected=[str(runtime/'memory.db'),str(runtime/'database.key'),f'/proc/{pid}/root/run/credentials/{unit}.service/database.key',str(controller/'owner.token'),f'/proc/{pid}/environ',f'/proc/{pid}/mem']
            invoke=['setpriv','--reuid=65534','--regid=65534','--clear-groups','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','--no-new-privs','/usr/bin/python3',str(probe),url,str(token_file),*protected]
            result=subprocess.run(invoke,env={'PATH':'/usr/bin:/bin','PYTHONPATH':str(lib)},capture_output=True,text=True,timeout=20)
            if result.returncode:raise RuntimeError('unprivileged probe failed: '+result.stderr[-1200:])
            checked=json.loads(result.stdout)
            owner.approve(checked.pop('proposal_id'))
            # Exercise actual MCP stdio under another DynamicUser, with a file
            # credential delivered by systemd and no bearer token in its env.
            agent_unit=unit+'-agent'
            agent_properties=dict(properties)
            for name in ['CPUQuota','MemoryDenyWriteExecute']:
                agent_properties.pop(name,None)
            agent_properties.update({'RuntimeDirectory':agent_unit,'LoadCredential':'agent.token:'+str(token_file),
                'InaccessiblePaths':str(runtime)+' '+str(controller),'UnsetEnvironment':'DOLPHI_TOKEN PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH'})
            agent_command=['systemd-run','--quiet','--pipe','--wait','--collect','--unit='+agent_unit]
            for key,value in agent_properties.items():agent_command.extend(['--property',key+'='+value])
            bootstrap_code=('import os,sys,shutil;os.umask(0o077);token=os.environ["RUNTIME_DIRECTORY"]+"/agent.token";'
                'shutil.copyfile(os.environ["CREDENTIALS_DIRECTORY"]+"/agent.token",token);os.chmod(token,0o600);'
                'assert "DOLPHI_TOKEN" not in os.environ;'
                'sys.stderr.write("DOLPHI_FIXTURE_UID="+str(os.geteuid())+"\\n");'
                'os.environ["DOLPHI_URL"]='+repr(url)+';os.environ["DOLPHI_TOKEN_FILE"]=token;'
                'sys.path.insert(0,'+repr(str(lib))+');from dolphi.mcp import main;sys.exit(main())')
            agent_command.extend(['/usr/bin/python3','-c',bootstrap_code])
            messages=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18'}},
                {'jsonrpc':'2.0','method':'notifications/initialized'},
                {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'proposal_create','arguments':{'key':'mcp-isolated','value':'synthetic','operation_id':'mcp-isolated'}}},
                {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'operation_status','arguments':{'id':'mcp-isolated'}}}]
            mcp=subprocess.run(agent_command,input='\n'.join(map(json.dumps,messages))+'\n',capture_output=True,text=True,timeout=20)
            if mcp.returncode:raise RuntimeError('isolated MCP failed: '+mcp.stderr[-1000:])
            replies=[json.loads(line) for line in mcp.stdout.splitlines()]
            assert len(replies)==3 and all('result' in reply for reply in replies)
            assert replies[-1]['result']['structuredContent']['operation']['status']=='committed'
            mcp_uid=int(re.search(r'DOLPHI_FIXTURE_UID=(\d+)',mcp.stderr).group(1))
            assert mcp_uid not in [0,service_uid,65534]
            checked.update({'mcp_credential_file_bridge_pass':True,'mcp_agent_uid':mcp_uid,'raw_bearer_environment_absent':True})
            owner.revoke_credential(registration['credential_id'])
            try:Client(url,registration['secret']).operation_status('isolated-proposal')
            except DolphiError as error:assert error.status==401
            else:raise AssertionError('revocation did not invalidate the isolated agent')
            checked.update({'service_uid':service_uid,'different_os_identities':True,'dynamic_user_and_credential_delivery':True,'privilege_escalation_disabled':True,'revoked_token_denied':True,'existing_installations_touched':False,'status':'passed'})
            args.output.parent.mkdir(parents=True,exist_ok=True)
            args.output.write_text(json.dumps(checked,indent=2)+'\n');args.output.chmod(0o600)
            if os.environ.get('SUDO_UID'):os.chown(args.output,int(os.environ['SUDO_UID']),int(os.environ['SUDO_GID']))
            print(json.dumps(checked))
        finally:
            subprocess.run(['systemctl','stop',unit+'-agent'],capture_output=True)
            subprocess.run(['systemctl','reset-failed',unit+'-agent'],capture_output=True)
            subprocess.run(['systemctl','stop',unit],capture_output=True)
            subprocess.run(['systemctl','reset-failed',unit],capture_output=True)


if __name__=='__main__':main()
