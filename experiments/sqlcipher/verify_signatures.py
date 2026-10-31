#!/usr/bin/env python3
"""Offline verification against explicitly pinned public release signer identities."""
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    root=Path(__file__).resolve().parent
    native=json.loads((root/'native-provenance.json').read_text())
    provider=root/'vendor/openssl-src'
    with tempfile.TemporaryDirectory(prefix='dolphi-native-signatures-') as directory:
        home=Path(directory);home.chmod(0o700)
        base=['gpg','--no-options','--homedir',directory,'--batch','--no-auto-key-retrieve']
        subprocess.run(base+['--import',str(provider/'pubkeys.asc')],capture_output=True,check=True)
        result=subprocess.run(base+['--status-fd','1','--verify',str(provider/'openssl-3.5.9.tar.gz.asc'),str(provider/'openssl-3.5.9.tar.gz')],capture_output=True,text=True,errors='replace')
        valid=[line.split()[-1] for line in result.stdout.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
        forbidden=('REVKEYSIG','EXPKEYSIG','EXPSIG','BADSIG')
        if result.returncode or valid!=[native['openssl_signer']] or any(word in result.stdout for word in forbidden):
            raise SystemExit('OpenSSL release signature verification FAILED')
        sql=root/'vendor/native-signatures'
        for name,checksum in native['sqlcipher']['signature_files'].items():
            import hashlib
            if hashlib.sha256((sql/name).read_bytes()).hexdigest()!=checksum:
                raise SystemExit('SQLCipher signature input changed')
        subprocess.run(base+['--import',str(sql/'sqlcipher-key.asc')],capture_output=True,check=True)
        result=subprocess.run(base+['--status-fd','1','--verify',str(sql/'sqlcipher-tag.asc'),str(sql/'sqlcipher-tag.payload')],capture_output=True,text=True,errors='replace')
        valid=[line.split()[-1] for line in result.stdout.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
        if result.returncode or valid!=[native['sqlcipher']['primary_signer']] or any(word in result.stdout for word in forbidden):
            raise SystemExit('SQLCipher source-tag signature verification FAILED')
        payload=(sql/'sqlcipher-tag.payload').read_text()
        if not payload.startswith('object '+native['sqlcipher']['signed_commit']+'\n') or '\ntag v4.20.0\n' not in payload:
            raise SystemExit('SQLCipher signed tag points at an unexpected release')
    print('OpenSSL 3.5.9 LTS release signature PASS; primary signer '+native['openssl_signer'])
    print('SQLCipher 4.20.0 source-tag signature PASS; pinned commit '+native['sqlcipher']['signed_commit'])


if __name__=='__main__':main()
