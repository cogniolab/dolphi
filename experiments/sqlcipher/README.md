# SQLCipher Community adapter and native inputs

This package supplies the optional encrypted backend to Dolphi. It can also run
as a standalone evaluation harness. It does not require a commercial service.

The selected native profile is SQLCipher 4.20 Community / SQLite 3.54.1 with
OpenSSL 3.5.9 LTS. Source-package hashes, pinned signer identities and generated
source checks are retained in `native-provenance.json`. The local binding patch
changes the selected SQLCipher source version; the local OpenSSL wrapper uses
the pinned signed source archive. Read the retained vendor packaging notes and
licenses before changing these inputs.

```sh
python3 experiments/sqlcipher/check_build.py --lock Cargo.lock
python3 experiments/sqlcipher/verify_signatures.py
cargo test --locked --no-default-features --features sqlcipher-backend --all-targets
```

The build currently targets Linux/GNU tools. It checks expected runtime
encryption configuration and fails rather than silently accepting another
provider. Provenance checks and internal tests do not constitute an independent
cryptographic assessment or production durability qualification.

See [architecture](../../docs/ARCHITECTURE.md),
[development](../../docs/DEVELOPMENT.md), [security](../../SECURITY.md) and
[third-party notices](../../THIRD_PARTY_NOTICES.md).
