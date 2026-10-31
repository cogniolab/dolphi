#!/usr/bin/env python3
"""Create a fresh allowlisted Community source tree and self-verifying manifest."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_community_release import digest,selected,validate


def export(root,output):
    root=root.resolve();output=output.absolute()
    if output.exists() or output.is_symlink():raise ValueError('export_destination_must_be_new')
    report=validate(root)
    if report['status']!='passed':raise ValueError('public_source_validation_failed: '+json.dumps(report['errors']))
    files=selected(root);output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.dolphi-public-',dir=output.parent) as temporary:
        staging=Path(temporary)/'source';staging.mkdir(mode=0o755)
        for name in files:
            destination=staging/name;destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(root/name,destination);destination.chmod(0o644)
        manifest=dict(schema=1,stage='developer_alpha',created_at_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
            files_sha256={name:digest(staging/name) for name in files},production_qualified=False)
        (staging/'PUBLIC_MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n')
        verified=validate(staging,strict=True)
        if verified['status']!='passed':raise ValueError('export_verification_failed')
        os.rename(staging,output)
    return dict(status='prepared_and_verified',output=str(output),files=len(files),manifest_sha256=digest(output/'PUBLIC_MANIFEST.json'),
        private_operational_evidence_exported=False,publish_ready=verified['publish_ready'],publication_setup_pending=verified['publication_setup_pending'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();print(json.dumps(export(args.root,args.output),indent=2))


if __name__=='__main__':main()
