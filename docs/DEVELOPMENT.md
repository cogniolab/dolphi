# Development

## Requirements

Use a current stable Rust toolchain with rustfmt and Clippy, a C build toolchain
and Python 3.11+ for repository checks. The SDK runtime supports Python 3.10+.
The optional SQLCipher/OpenSSL source build also requires Make, Perl and GNU tar.
Source-signature verification uses GnuPG; reproducing SQLCipher sources needs
Git and Tcl development files. Linux ARM64 is the locally exercised platform;
GitHub Linux x86_64 jobs are configured but need a real hosted run after publish.

Typical Debian/Ubuntu development dependencies:

```sh
sudo apt-get install build-essential pkg-config perl python3 python3-venv git gnupg tcl-dev
rustup component add rustfmt clippy
```

## Fast checks

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --doc
cargo build --locked --bin dolphi-server
PYTHONPATH=sdk/python python3 -m unittest discover -s sdk/python/tests -v
python3 scripts/check_dependency_policy.py
python3 scripts/check_community_release.py --root .
```

## SQLCipher profile

```sh
python3 experiments/sqlcipher/check_build.py --lock Cargo.lock
python3 experiments/sqlcipher/verify_signatures.py
cargo clippy --locked --no-default-features --features sqlcipher-backend --all-targets -- -D warnings
cargo test --locked --no-default-features --features sqlcipher-backend --all-targets
cargo test --locked --no-default-features --features sqlcipher-backend --doc
cargo build --locked --no-default-features --features sqlcipher-backend --bin dolphi-server
PYTHONPATH=sdk/python python3 -m unittest discover -s sdk/python/tests -v
```

The SDK suite defaults to `target/debug/dolphi-server`. If using a separate Cargo
target directory, set `DOLPHI_TEST_SERVER` to that built executable.

The native packaging paths are part of the build, not optional documentation.
The binding checker compares the complete vendored file set against its reviewed
baseline. Avoid editors/tools creating extra files under those vendor directories.

## Recovery and deployment checks

Linux software fault injection lives under `qualification/`. Use synthetic
temporary fixtures. Some storage/device/UID tests need explicit local privileges;
never point them at personal databases or a shared live installation.
See [testing](TESTING.md) for scope and [releasing](RELEASING.md) for source export.

CI separates profile tests, cross-profile migration, source integrity, native
isolation and recovery jobs. Hosted results are evidence only after they actually
run. No badge or local report should imply a hosted CI result.
