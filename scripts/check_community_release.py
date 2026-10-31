#!/usr/bin/env python3
"""Validate the declared public tree without including private development data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.parse
import xml.etree.ElementTree as ET

SKIP={'.git','target','__pycache__','.venv','build','dist'}
PRIVATE_PARTS={'data','state','backups','.ssh','.aws','.codex','.agents'}
PATTERNS=[
    ('personal_home_path',re.compile(rb'/(?:home|Users)/[A-Za-z0-9._-]+')),
    ('private_host_reference',re.compile(rb'\b(?:spark|Moses)\x2d[A-Za-z0-9-]+',re.I)),
    ('private_thread_reference',re.compile(rb'codex'+rb'://')),
    ('private_key',re.compile(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----')),
    ('github_token',re.compile(rb'gh[pousr]_[A-Za-z0-9]{30,}')),
    ('access_key',re.compile(rb'AKIA[0-9A-Z]{16}')),
]


def digest(path):
    value=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):value.update(block)
    return value.hexdigest()


def selected(root):
    policy=json.loads((root/'release/public-files.json').read_text())
    if policy['schema']!=1:raise ValueError('unsupported_public_manifest')
    files=set(policy['files'])
    for directory in policy['directories']:
        start=root/directory
        if not start.is_dir() or start.is_symlink():raise ValueError('missing_or_symlink_public_directory: '+directory)
        for parent,dirs,names in os.walk(start,followlinks=False):
            dirs[:]=sorted(d for d in dirs if d not in SKIP and not d.endswith('.egg-info'))
            for d in dirs:
                if (Path(parent)/d).is_symlink():raise ValueError('symlink_directory_refused')
            for name in names:
                if name.endswith('.pyc'):continue
                files.add(str((Path(parent)/name).relative_to(root)))
    for name in files:
        path=Path(name)
        if path.is_absolute() or '..' in path.parts or not (root/path).is_file() or any(root.joinpath(*path.parts[:i]).is_symlink() for i in range(1,len(path.parts)+1)):
            raise ValueError('invalid_public_file: '+name)
    return sorted(files)


def prose(text):return re.sub(r'(?ms)^```[^\n]*\n.*?^```[ \t]*$','',text)


def local_links(root,name,files):
    text=prose((root/name).read_text());errors=[]
    targets=re.findall(r'(?<!!)\[[^\]]*\]\(([^\s)]+)(?:\s+[^)]*)?\)',text)
    targets+=re.findall(r'!\[[^\]]*\]\(([^\s)]+)\)',text)
    targets+=re.findall(r'(?:href|src)="([^"]+)"',text)
    for target in targets:
        parsed=urllib.parse.urlsplit(target.strip('<>'))
        if parsed.scheme or target.startswith('//'):continue
        base=(root/name).parent
        actual=(base/urllib.parse.unquote(parsed.path)).resolve() if parsed.path else root/name
        if not actual.is_relative_to(root) or not actual.exists():errors.append(name+': missing local link '+target);continue
        relative=str(actual.relative_to(root))
        if actual.is_file() and relative not in files:errors.append(name+': link omitted from public tree '+target)
        if parsed.fragment and actual.suffix=='.md':
            headings=re.findall(r'^#{1,6}\s+(.+?)\s*#*$',prose(actual.read_text()),re.M)
            anchors={re.sub(r'\s+','-',re.sub(r'[^\w\-\s]','',h.lower())) for h in headings}
            if parsed.fragment not in anchors:errors.append(name+': missing heading '+target)
    return errors


def validate(root,strict=False):
    root=root.resolve();files=selected(root);errors=[];large=[]
    for name in files:
        path=root/name
        if PRIVATE_PARTS.intersection(Path(name).parts) or path.suffix.lower() in {'.db','.sqlite','.sqlite3','.key','.token','.mimi','.log','.p12','.pfx'} or path.name=='.env' or path.name.startswith('.env.') or name.endswith(('-wal','-shm')):
            errors.append('private_state_file: '+name)
        size=path.stat().st_size
        if size>=100*1024*1024:errors.append('github_file_limit: '+name)
        elif size>50*1024*1024:large.append(name)
        # Vendored bytes are independently checked against the source ledger.
        if 'vendor' not in Path(name).parts and path.suffix not in {'.gz','.png','.jpg'}:
            data=path.read_bytes()
            for code,pattern in PATTERNS:
                if pattern.search(data):errors.append(code+': '+name)
        if path.suffix=='.md' and 'vendor' not in Path(name).parts:errors.extend(local_links(root,name,set(files)))
        if path.suffix=='.svg':ET.fromstring(path.read_text())
    manifest=root/'PUBLIC_MANIFEST.json'
    allowed=set(files)|{'PUBLIC_MANIFEST.json'}
    if manifest.exists():
        saved=json.loads(manifest.read_text())
        if set(saved['files_sha256'])!=set(files):errors.append('public_manifest_file_set_changed')
        for name,expected in saved['files_sha256'].items():
            if name not in files or digest(root/name)!=expected:errors.append('public_manifest_hash_changed: '+name)
    if (root/'.git').exists():
        result=subprocess.run(['git','-C',str(root),'ls-files','-z'],capture_output=True,check=True)
        tracked={p for p in result.stdout.decode().split('\0') if p}
        errors.extend('unallowlisted_tracked_file: '+p for p in sorted(tracked-allowed))
    if strict:
        actual=set()
        for parent,dirs,names in os.walk(root):
            dirs[:]=[d for d in dirs if d!='.git']
            actual.update(str((Path(parent)/name).relative_to(root)) for name in names)
        errors.extend('unallowlisted_export_file: '+p for p in sorted(actual-allowed))
    native=subprocess.run([sys.executable,str(root/'experiments/sqlcipher/check_build.py'),'--lock',str(root/'Cargo.lock')],capture_output=True,text=True)
    if native.returncode:errors.append('native_source_integrity_failed')
    config=json.loads((root/'release/community.json').read_text());pending=[]
    if not isinstance(config.get('repository'),str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',config['repository']):pending.append('confirm_github_owner_and_repository')
    if not config.get('maintainer_contact'):pending.append('confirm_private_maintainer_contact')
    if not config.get('security_email') and config.get('private_vulnerability_reporting_verified') is not True:pending.append('configure_private_vulnerability_reporting')
    return dict(status='passed' if not errors else 'failed',files_checked=len(files),errors=errors,
        large_pinned_source_files=large,publish_ready=not errors and not pending,publication_setup_pending=pending,
        production_qualified=False,native_source_integrity=native.returncode==0)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--strict-tree',action='store_true');parser.add_argument('--require-publish-ready',action='store_true')
    args=parser.parse_args();report=validate(args.root,args.strict_tree);print(json.dumps(report,indent=2))
    return int(report['status']!='passed' or (args.require_publish_ready and not report['publish_ready']))


if __name__=='__main__':raise SystemExit(main())
