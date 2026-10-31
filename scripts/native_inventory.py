#!/usr/bin/env python3
"""Generate a CycloneDX source inventory for the selected Linux encrypted profile."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cargo',default='cargo')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    metadata=json.loads(subprocess.check_output([args.cargo,'metadata','--locked','--offline','--format-version','1','--no-default-features','--features','sqlcipher-backend','--filter-platform','aarch64-unknown-linux-gnu'],cwd=root,text=True))
    active={node['id'] for node in metadata['resolve']['nodes']}
    packages=[p for p in metadata['packages'] if p['id'] in active]
    policy=json.loads((root/'experiments/sqlcipher/native-provenance.json').read_text())
    source=next(p for p in packages if p['name']=='sqlcipher-src')
    source_dir=Path(source['manifest_path']).parent/'sqlcipher'
    for name,expected in policy['sqlcipher']['reproduced_files'].items():
        if hashlib.sha256((source_dir/name).read_bytes()).hexdigest()!=expected['bundled_sha256']:
            raise SystemExit('compiled native input changed: '+name)
    refs={p['id']:'pkg:cargo/'+p['name']+'@'+p['version'] for p in packages}
    components=[]
    for package in packages:
        component={'type':'library','bom-ref':refs[package['id']],'name':package['name'],'version':package['version']}
        if package.get('license'):component['licenses']=[{'license':{'name':package['license']}}]
        components.append(component)
    for name,version,license_name in [('SQLCipher','4.20.0','BSD-3-Clause'),('SQLite','3.54.1','blessing'),('OpenSSL','3.5.9','Apache-2.0')]:
        components.append({'type':'library','bom-ref':'pkg:generic/'+name+'@'+version,'name':name,'version':version,'licenses':[{'license':{'id':license_name}}]})
    dependencies=[{'ref':refs[node['id']],'dependsOn':[refs[d['pkg']] for d in node['deps'] if d['pkg'] in refs]} for node in metadata['resolve']['nodes'] if node['id'] in refs]
    dependencies.extend([
        {'ref':refs[next(p['id'] for p in packages if p['name']=='sqlcipher-src')],'dependsOn':['pkg:generic/SQLCipher@4.20.0']},
        {'ref':refs[next(p['id'] for p in packages if p['name']=='openssl-src')],'dependsOn':['pkg:generic/OpenSSL@3.5.9']},
        {'ref':'pkg:generic/SQLCipher@4.20.0','dependsOn':['pkg:generic/SQLite@3.54.1','pkg:generic/OpenSSL@3.5.9']}])
    # Merge references that also have normal Cargo edges.
    merged={}
    for item in dependencies:merged.setdefault(item['ref'],set()).update(item['dependsOn'])
    result={'bomFormat':'CycloneDX','specVersion':'1.6','version':1,
        'metadata':{'timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(),'component':{'type':'application','name':'Dolphi Community encrypted Linux ARM64 candidate','version':'0.1.0'}},
        'components':components,'dependencies':[{'ref':key,'dependsOn':sorted(value)} for key,value in merged.items()]}
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':'passed','active_components':len(components),'native_inputs_match_signed_reproduction':True,'output':str(args.output)}))


if __name__=='__main__':main()
