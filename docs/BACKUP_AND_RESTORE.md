# Backup, restore and migration

Protect database files and keys separately. Backups use an independent 32-byte
encryption key. Save and test recovery of that key; losing it loses the backup.

## Export an encrypted snapshot

Stop all source writers first. Offline CLI export copies the source into a
private working directory, validates it and verifies unchanged source fingerprints.
Fingerprints alone are not proof that another writer was excluded.

```sh
umask 077
mkdir -p data/backups data/recovered
chmod 700 data/backups data/recovered
target/debug/dolphi-server keygen data/local/backup.key
target/debug/dolphi-server migration-export-stream data/local/community.db data/local/database.key data/backups/community.mimi data/local/backup.key
```

Use a new snapshot filename for every export. Version 3 is an authenticated
stream, capped at 4 GiB ciphertext and 1 MiB plaintext per frame. These are
refusal bounds, not a claim that the whole range is production-qualified.
The legacy `migration-export` / `Owner::backup` format remains capped at 64 MiB.

The library's `Owner::backup_streaming` coordinates through its store connection
lock. The external CLI still requires stopped/cooperatively excluded writers.
Do not copy a live DB while ignoring WAL or process coordination.

## Restore with a new database key

```sh
target/debug/dolphi-server keygen data/recovered/database.key
target/debug/dolphi-server migration-import data/backups/community.mimi data/local/backup.key data/recovered/community.db data/recovered/database.key data/recovered/verification.json
target/debug/dolphi-server owner-token data/recovered/community.db data/recovered/database.key data/recovered/owner.token
```

Restore verifies all ten application tables, receipt relationships and engine
integrity before publishing a new destination. Imported credentials are revoked.
Use the new owner credential in trusted administration, then issue fresh agent
credentials for preserved agent IDs. Old tokens must not resume access.

Readers recognize v1/v2/v3. Older executables cannot read v3: retain a compatible
recovery executable and source. A failed directory sync can leave a complete
published artifact while returning an error. Report publication can fail after
the database is verified. Preserve and inspect such destinations; do not delete
them on the assumption that an error guarantees absence.

## Changing storage profiles

Build the source and destination profiles separately. Export with the source
profile and import into a new destination with the target profile. Keep the
original files, keys, credentials and runtime available for rollback until the
restored application has been validated. Do not merge diverged histories by
swapping files. A backend change is an explicit migration, never an in-place
file-format conversion.

## Scheduled off-host operations

`deploy/backup_operations.py` and `deploy/backup_remote.py` provide coordinated
snapshots, verified SSH transfer, actual remote restore/service probes,
retention and age monitoring. Configure the private
[example](../deploy/backup-operations.example.json) for your deployment, then:

```sh
python3 -I deploy/backup_operations.py provision --config /absolute/private/backup-config.json
python3 -I deploy/backup_operations.py run --config /absolute/private/backup-config.json
python3 -I deploy/backup_operations.py health --config /absolute/private/backup-config.json
```

Provisioning separately delivers the recovery runtime and backup key. Normal
transfers carry ciphertext and metadata. The source DB key is not delivered.
Keep the vault outside the repository. A separate directory under the same
account is not protection from that account's compromise.

Select a cooperative lock held by every writer, or stop/resume a specific
systemd service. Writers resume before network/restore work. The systemd
templates include an interrupted-job resume hook. Verify a manual run before
enabling timers. Set retention, quota, full-service recovery objectives and
actual alert delivery; the supplied alert template writes to the local journal.
Key escrow/rotation, external paging and production recovery acceptance remain
deployment responsibilities.
