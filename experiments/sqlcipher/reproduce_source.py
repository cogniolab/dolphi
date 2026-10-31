#!/usr/bin/env python3
"""Regenerate the active C/header/license inputs from SQLCipher's signed tag."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

def main():
    root=Path(__file__).resolve().parent
    policy=json.loads((root/'native-provenance.json').read_text())['sqlcipher']
    with tempfile.TemporaryDirectory(prefix='dolphi-source-reproduction-') as directory:
        work=Path(directory);home=work/'gnupg';home.mkdir(mode=0o700)
        env=os.environ.copy();env['GNUPGHOME']=str(home)
        subprocess.run(['gpg','--no-options','--homedir',str(home),'--batch','--import',str(root/'vendor/native-signatures/sqlcipher-key.asc')],capture_output=True,check=True)
        repo=work/'sqlcipher'
        subprocess.run(['git','clone','--quiet','--depth','1','--branch','v4.20.0',policy['repository'],str(repo)],capture_output=True,check=True)
        signed=subprocess.run(['git','-C',str(repo),'verify-tag','--raw','v4.20.0'],env=env,capture_output=True,text=True,errors='replace')
        fingerprints=[line.split()[-1] for line in signed.stderr.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
        if signed.returncode or fingerprints!=[policy['primary_signer']]:raise SystemExit('source signature rejected')
        commit=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
        if commit!=policy['signed_commit']:raise SystemExit('source tag commit changed')
        with (work/'generation.log').open('w') as log:
            subprocess.run(['./configure'],cwd=repo,stdout=log,stderr=subprocess.STDOUT,check=True)
            subprocess.run(['make','sqlite3.c'],cwd=repo,stdout=log,stderr=subprocess.STDOUT,check=True)
        result={}
        for generated,compiled in [('sqlite3.c','sqlcipher.c'),('sqlite3.h','sqlite3.h'),('sqlite3ext.h','sqlite3ext.h'),('LICENSE.md','LICENSE-sqlcipher')]:
            digest=hashlib.sha256((repo/generated).read_bytes()).hexdigest()
            if digest!=policy['reproduced_files'][compiled]['bundled_sha256']:raise SystemExit('generated source differs: '+compiled)
            result[compiled]=digest
        print(json.dumps({'signed_commit':commit,'active_sources_reproduced':result,'status':'passed'},indent=2))

if __name__=='__main__':main()
