#!/usr/bin/env python3
"""Fail if the deferred FTS/compression dependency surface is reintroduced.

This complements cargo-audit; it is not a general vulnerability scanner.
Cargo feature unification means downstream consumers must check their own graph.
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument(
        "--manifest-path",
        default=str(Path(__file__).resolve().parents[1] / "Cargo.toml"),
    )
    args = parser.parse_args()
    command = [
        args.cargo, "metadata", "--locked", "--format-version", "1",
        "--manifest-path", args.manifest_path,
    ]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        metadata = json.loads(result.stdout)
        active = {node["id"]: node for node in metadata["resolve"]["nodes"]}
        packages = [p for p in metadata["packages"] if p["id"] in active]
        blocked = {"tantivy", "zstd", "zstd-safe", "lru"}
        violations = []
        for package in packages:
            name = package["name"]
            if name in blocked:
                violations.append(f"deferred dependency: {name} {package['version']}")
            if name in {"turso", "turso_core", "turso_sdk_kit"}:
                if "fts" in active[package["id"]]["features"]:
                    violations.append(f"deferred feature: {name}/fts")
        if violations:
            print("Dependency policy FAILED; security requalification required:", file=sys.stderr)
            print("\n".join(violations), file=sys.stderr)
            return 1
        print(f"Dependency policy PASS: {len(packages)} resolved packages; deferred FTS/compression/cache surface absent")
        return 0
    except (OSError, subprocess.CalledProcessError, ValueError, KeyError, TypeError) as error:
        print(f"Dependency policy could not be verified: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
