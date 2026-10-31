# Third-party notices

Dolphi's MIT license applies to its original code. Dependency licenses continue
to apply to their components; the project does not claim ownership or vendor
endorsement of those components.

| Component | Role | License/source information |
|---|---|---|
| Turso 0.8.3 | Default embedded engine | MIT; [upstream](https://github.com/tursodatabase/turso), versions locked in Cargo.lock |
| SQLite | SQL engine foundation | [Public-domain dedication](https://sqlite.org/copyright.html); embedded source notices retained |
| SQLCipher 4.20 Community | Optional encrypted storage | [Retained BSD notice](experiments/sqlcipher/notices/SQLCipher-BSD.txt) |
| OpenSSL 3.5.9 | Optional crypto provider | [Apache 2.0 notice](experiments/sqlcipher/notices/OpenSSL-Apache-2.0.txt); full source license inside the pinned archive |
| libsqlite3-sys wrapper | Rust/native binding packaging | [MIT notice](experiments/sqlcipher/vendor/libsqlite3-sys/LICENSE) |
| openssl-src wrapper | Native provider packaging | [MIT](experiments/sqlcipher/vendor/openssl-src/LICENSE-MIT) / [Apache 2.0](experiments/sqlcipher/vendor/openssl-src/LICENSE-APACHE) |

The complete selected dependency versions and checksums are in `Cargo.lock`.
Native notices, signed-source evidence and local packaging patches are retained
under `experiments/sqlcipher`; all other dependencies retain the notices supplied
in their packages. `scripts/native_inventory.py` generates the native SBOM.

The pinned OpenSSL source archive is included to keep the selected native build
reproducible. Its approximately 51 MiB size is intentional. Do not drop or alter
it without updating provenance checks and requalifying the native build.

Additional retained notices cover the source-packaging crates and components
present in their complete upstream archives. Presence in an archive does not
mean every component is compiled into the selected runtime.
