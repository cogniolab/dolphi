#!/usr/bin/env python3
"""Verify the sole binding patch and pinned SQLCipher/provider source identities.

Requires Python 3.11+. Cargo verifies registry downloads against Cargo.lock;
this checks the local path dependency that Cargo cannot verify for us.
This is source integrity, not a signed upstream provenance or native CVE audit.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tomllib

LEDGER_SHA256 = "2e9ecffcbbd17019eaad82d778a55ecc56fc81e8ed37ea2f59e1477d1f909dfd"
SOURCE = (
    "420.0.0+sqlcipher-4.20.0-sqlite-3.54.1-libtomcrypt-1.18.2",
    "fd6b5280ed2593d07b2816ec531821c15c306903bcca224716f1fbcc2bbfedfe",
)
PROVIDER = (
    "300.5.9+3.5.9-mimidb.1",
    None,
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify(root, lock=None):
    vendor = root / "vendor/libsqlite3-sys"
    ledger_bytes = (vendor / "upstream-checksums.json").read_bytes()
    if digest(ledger_bytes) != LEDGER_SHA256:
        raise ValueError("upstream checksum ledger changed")
    ledger = json.loads(ledger_bytes)
    expected_files = set(ledger["files"]) | {"upstream-checksums.json"}
    actual_files = {str(p.relative_to(vendor)) for p in vendor.rglob("*") if p.is_file()}
    if actual_files != expected_files or any(p.is_symlink() for p in vendor.rglob("*")):
        raise ValueError("unexpected vendor files or symlinks")
    for name, checksum in ledger["files"].items():
        data = (vendor / name).read_bytes()
        if name == "Cargo.toml":
            old = b'[build-dependencies.sqlcipher-src]\nversion = "=419.0.6"'
            new = b'[build-dependencies.sqlcipher-src]\nversion = "=420.0.0"'
            if data.count(new) != 1:
                raise ValueError("expected explicit 4.20 source pin")
            data = data.replace(new, old)
        if digest(data) != checksum:
            raise ValueError("unexpected binding modification: " + name)
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    if manifest["patch"]["crates-io"]["libsqlite3-sys"] != {"path": "vendor/libsqlite3-sys"}:
        raise ValueError("local compatibility patch must be active")
    features = manifest["dependencies"]["rusqlite"]["features"]
    if features != ["bundled-sqlcipher-vendored-openssl"]:
        raise ValueError("unexpected native build profile")
    packages = tomllib.loads((lock or root / "Cargo.lock").read_text())["package"]
    for name, expected in [("sqlcipher-src", SOURCE), ("openssl-src", PROVIDER)]:
        found = [p for p in packages if p["name"] == name]
        if len(found) != 1 or (found[0]["version"], found[0].get("checksum")) != expected:
            raise ValueError("unexpected locked source: " + name)
        expected_source = None if name == "openssl-src" else "registry+https://github.com/rust-lang/crates.io-index"
        if found[0].get("source") != expected_source:
            raise ValueError("unexpected source registry: " + name)
    if manifest["patch"]["crates-io"]["openssl-src"] != {"path": "vendor/openssl-src"}:
        raise ValueError("explicit LTS source packaging patch must be active")
    native = json.loads((root / "native-provenance.json").read_text())
    provider_dir = root / "vendor/openssl-src"
    actual = {str(p.relative_to(provider_dir)) for p in provider_dir.rglob("*") if p.is_file()}
    if actual != set(native["openssl_files"]) or any(p.is_symlink() for p in provider_dir.rglob("*")):
        raise ValueError("unexpected OpenSSL packaging files")
    for name, checksum in native["openssl_files"].items():
        if digest((provider_dir/name).read_bytes()) != checksum:
            raise ValueError("modified LTS build input: " + name)
    bindings = [p for p in packages if p["name"] == "libsqlite3-sys"]
    if len(bindings) != 1 or bindings[0]["version"] != "0.39.1" or "source" in bindings[0]:
        raise ValueError("expected the patched local binding, not the registry binding")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--lock", type=Path, help="also supports the main product lockfile")
    args = parser.parse_args()
    try:
        verify(args.root, args.lock)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("SQLCipher build integrity FAILED: " + str(error), file=sys.stderr)
        return 1
    print("SQLCipher build integrity PASS: sole binding change is 419.0.6 -> 420.0.0; sources pinned")
    return 0


if __name__ == "__main__":
    sys.exit(main())
