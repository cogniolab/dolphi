#!/usr/bin/python3 -I
"""Root-owned stdio launcher: one transient, unprivileged UID per agent session."""
import os
import re
import subprocess
import sys
import uuid

if os.geteuid()!=0 or len(sys.argv)!=2 or re.fullmatch(r'[A-Za-z0-9_-]{1,64}',sys.argv[1]) is None:
    raise SystemExit('usage (trusted operator): run-agent-mcp.py AGENT_NAME')
name=sys.argv[1]
unit='dolphi-agent-'+name+'-'+uuid.uuid4().hex[:12]
properties={
    'DynamicUser':'yes','RuntimeDirectory':unit,'RuntimeDirectoryMode':'0700',
    'LoadCredential':'agent.token:/etc/dolphi/agents/'+name+'.token',
    'UMask':'0077','NoNewPrivileges':'yes','CapabilityBoundingSet':'','AmbientCapabilities':'',
    'ProtectSystem':'strict','ProtectHome':'yes','PrivateTmp':'yes','PrivateDevices':'yes',
    'InaccessiblePaths':'-/var/lib/dolphi -/var/lib/private/dolphi -/etc/dolphi',
    'ProtectKernelTunables':'yes','ProtectKernelModules':'yes','ProtectKernelLogs':'yes',
    'ProtectControlGroups':'yes','ProtectProc':'invisible','ProcSubset':'pid',
    'RestrictSUIDSGID':'yes','RestrictRealtime':'yes','RestrictNamespaces':'yes','LockPersonality':'yes',
    'RestrictAddressFamilies':'AF_INET AF_UNIX','IPAddressDeny':'any','IPAddressAllow':'localhost',
    'SystemCallArchitectures':'native','LimitCORE':'0','LimitNOFILE':'256','TasksMax':'16','MemoryMax':'128M',
    'UnsetEnvironment':'DOLPHI_TOKEN PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH OPENSSL_CONF OPENSSL_MODULES OPENSSL_ENGINES',
}
command=['/usr/bin/systemd-run','--quiet','--pipe','--wait','--collect','--unit='+unit]
for key,value in properties.items():command.extend(['--property',key+'='+value])
command.extend(['/usr/bin/python3','-I','-c',
    'import os,sys,shutil;os.umask(0o077);token=os.environ["RUNTIME_DIRECTORY"]+"/agent.token";shutil.copyfile(os.environ["CREDENTIALS_DIRECTORY"]+"/agent.token",token);os.chmod(token,0o600);os.environ["DOLPHI_URL"]="http://127.0.0.1:8787";os.environ["DOLPHI_TOKEN_FILE"]=token;sys.path.insert(0,"/usr/local/share/dolphi/python");from dolphi.mcp import main;sys.exit(main())'])
raise SystemExit(subprocess.call(command))
