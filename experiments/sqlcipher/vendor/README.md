# Local binding compatibility patch

`libsqlite3-sys` is the complete 0.39.1 crates.io archive, verified before
extraction against SHA-256
`14a5f01b87b92705d07b433c06f96cbc764637d81a0bffb5734ce17cf0f9a2b3`.
The upstream MIT license and files are retained. Its sole modified upstream file
is the normalized `Cargo.toml`: `sqlcipher-src = "=419.0.6"` becomes `"=420.0.0"`.
The original manifest remains intact as `Cargo.toml.orig` for comparison.
There are no FFI, C, crypto, compiler-flag or binding source changes.

This is a MimiDB-maintained compatibility patch, not an upstream rusqlite
release or vendor endorsement. It only applies to the standalone candidate.
`../check_build.py` checks every archived file against the recorded baseline,
allowing exactly that pin substitution, and verifies the locked source/provider
versions and hashes. Run `python3 experiments/sqlcipher/check_build.py` from
the repository root. Retire this patch after an upstream binding supports the
selected version and the replacement passes qualification.

The complete archive includes unused plain SQLite sources for upstream package
fidelity. The selected Cargo feature builds SQLCipher from sqlcipher-src 420.0.0,
not those sources. Startup requires SQLCipher 4.20.0 Community / SQLite 3.54.1
with the OpenSSL provider and fails on any other runtime configuration.
