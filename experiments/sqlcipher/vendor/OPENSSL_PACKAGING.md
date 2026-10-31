# Explicit OpenSSL LTS source packaging

The openssl-src directory is a local package, not a crates.io release. Its
300.5.9+3.5.9-mimidb.1 version accurately identifies the selected native source.
The existing upstream 300.5.5 builder is reused with checksum-verified extraction
of the unmodified official 3.5.9 archive and an artifact bin_dir accessor.
Cargo source selection points here explicitly in both manifests.

The source archive's signature, publisher certificate and exact wrapper/file
hashes are retained and checked through ../native-provenance.json and the
qualification scripts. The full original source license is inside the archive;
wrapper MIT and Apache notices are retained beside it. No native C files are
patched. Linux/GNU tar is the supported build environment for this package.

Review and retire this local package when a maintained upstream wrapper includes
the selected LTS source and passes the same provenance, native and API checks.
