//! Offline migration via authenticated logical snapshots; no in-place conversion.
use crate::{Connection, EncryptionKey, Error, Owner, Result, recovery::TABLES};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Serialize)]
pub struct TableVerification {
    pub table: String,
    pub rows: usize,
    /// Hash of canonical typed rows, after the explicit credential revocation.
    pub sha256: String,
}
#[derive(Debug, Serialize)]
pub struct MigrationReport {
    pub target_profile: &'static str,
    pub snapshot_version: u32,
    pub verified_before_publication: bool,
    pub credentials_invalidated: usize,
    pub tables: Vec<TableVerification>,
}
#[derive(Debug, Serialize)]
pub struct MigrationExport {
    pub source_profile: &'static str,
    pub source_files_unchanged: bool,
    pub files: Vec<SourceFile>,
}
#[derive(Debug, Serialize, PartialEq)]
pub struct SourceFile {
    pub suffix: String,
    pub bytes: u64,
    pub sha256: String,
}

pub(crate) fn profile() -> &'static str {
    #[cfg(feature = "turso-backend")]
    {
        "embedded-turso-0.8.3"
    }
    #[cfg(feature = "sqlcipher-backend")]
    {
        "encrypted-sqlcipher-4.20.0"
    }
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}
fn source_files(path: &Path) -> Result<Vec<SourceFile>> {
    let mut result = Vec::new();
    for suffix in ["", "-wal", "-shm"] {
        let file = sidecar(path, suffix);
        match std::fs::symlink_metadata(&file) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !suffix.is_empty() => {
                continue;
            }
            Err(error) => return Err(error.into()),
            _ => return Err(Error::Configuration),
        }
        let mut reader = std::fs::File::open(&file)?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        let mut bytes = 0;
        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
            bytes += n as u64;
        }
        result.push(SourceFile {
            suffix: suffix.to_owned(),
            bytes,
            sha256: format!("{:x}", hash.finalize()),
        });
    }
    Ok(result)
}

impl Owner {
    /// Caller MUST stop all source writers first. Fingerprint checks detect
    /// observed changes but are not an OS lock or proof of quiescence.
    /// The source is read as bytes only; the engine opens a private working copy.
    pub async fn migration_export(
        source: &Path,
        database_key: &EncryptionKey,
        destination: &Path,
        backup_key: &EncryptionKey,
    ) -> Result<MigrationExport> {
        Self::migration_export_format(source, database_key, destination, backup_key, false).await
    }

    /// Paged version-3 export. All source writers must be stopped, as for the
    /// legacy export. Restores require a reader supporting streaming snapshots.
    pub async fn migration_export_streaming(
        source: &Path,
        database_key: &EncryptionKey,
        destination: &Path,
        backup_key: &EncryptionKey,
    ) -> Result<MigrationExport> {
        Self::migration_export_format(source, database_key, destination, backup_key, true).await
    }

    async fn migration_export_format(
        source: &Path,
        database_key: &EncryptionKey,
        destination: &Path,
        backup_key: &EncryptionKey,
        streaming: bool,
    ) -> Result<MigrationExport> {
        if std::fs::symlink_metadata(destination).is_ok() {
            return Err(Error::Configuration);
        }
        let before = source_files(source)?;
        let work = tempfile::Builder::new()
            .prefix("dolphi-migration-")
            .tempdir()?;
        let copy = work.path().join("source.db");
        for file in &before {
            if file.suffix == "-shm" {
                continue;
            } // Never copy process-specific SHM state.
            let mut input = std::fs::File::open(sidecar(source, &file.suffix))?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut output = options.open(sidecar(&copy, &file.suffix))?;
            std::io::copy(&mut input, &mut output)?;
            output.flush()?;
            output.sync_all()?;
        }
        if source_files(source)? != before {
            return Err(Error::Conflict);
        }
        let copied = source_files(&copy)?;
        if copied.iter().collect::<Vec<_>>()
            != before
                .iter()
                .filter(|file| file.suffix != "-shm")
                .collect::<Vec<_>>()
        {
            return Err(Error::InvalidBackup);
        }
        // Private staging keeps an unsuccessful export from publishing a snapshot.
        let staged = work.path().join("snapshot.mimi");
        let owner = Owner::open_encrypted(
            copy.to_str().ok_or(Error::Configuration)?,
            database_key,
            None,
        )
        .await?;
        {
            let c = owner.store.connection.lock().await;
            validate_export_schema(&c).await?;
            crate::recovery::validate_snapshot(&c).await?;
            let mut rows = c.query("PRAGMA integrity_check", ()).await?;
            if rows
                .next()
                .await?
                .ok_or(Error::InvalidBackup)?
                .get::<String>(0)?
                != "ok"
            {
                return Err(Error::InvalidBackup);
            }
        }
        if streaming {
            owner.backup_streaming(&staged, backup_key).await?;
        } else {
            owner.backup(&staged, backup_key).await?;
        }
        // Explicit close of the working copy is needed before tempdir cleanup.
        #[cfg(feature = "sqlcipher-backend")]
        owner.store.connection.lock().await.close().await?;
        drop(owner);
        if source_files(source)? != before {
            return Err(Error::Conflict);
        }
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut output = tempfile::NamedTempFile::new_in(parent)?;
        std::io::copy(&mut std::fs::File::open(staged)?, output.as_file_mut())?;
        output.as_file().sync_all()?;
        output
            .persist_noclobber(destination)
            .map_err(|e| Error::Io(e.error))?;
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(MigrationExport {
            source_profile: profile(),
            source_files_unchanged: true,
            files: before,
        })
    }
}

async fn validate_export_schema(c: &Connection) -> Result<()> {
    let mut objects = c.query("SELECT name,type FROM sqlite_master", ()).await?;
    while let Some(row) = objects.next().await? {
        let name: String = row.get(0)?;
        let kind: String = row.get(1)?;
        if name.starts_with("sqlite_") {
            continue;
        }
        if kind != "table" || !TABLES.iter().any(|(table, _)| *table == name) {
            return Err(Error::Configuration);
        }
    }
    drop(objects);
    for (table, columns) in TABLES {
        let mut rows = c.query(&format!("PRAGMA table_info({table})"), ()).await?;
        let mut names = Vec::new();
        while let Some(row) = rows.next().await? {
            names.push(row.get::<String>(1)?);
        }
        if names != columns.split(',').collect::<Vec<_>>() {
            return Err(Error::Configuration);
        }
    }
    Ok(())
}

fn canonical(rows: &[Vec<Value>], revoke: bool) -> Result<Vec<Vec<u8>>> {
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let mut row = row.clone();
        if revoke {
            *row.get_mut(4).ok_or(Error::InvalidBackup)? = Value::from(1);
        }
        result.push(serde_json::to_vec(&row).map_err(|_| Error::InvalidBackup)?);
    }
    result.sort_unstable();
    Ok(result)
}

pub(crate) async fn verify_tables(
    c: &Connection,
    expected: &[Vec<Vec<Value>>],
) -> Result<MigrationReport> {
    if expected.len() != TABLES.len() {
        return Err(Error::InvalidBackup);
    }
    let mut tables = Vec::new();
    let mut budget = 0usize;
    let mut credentials_invalidated = 0;
    for ((table, columns), expected) in TABLES.iter().zip(expected) {
        let expected = canonical(expected, *table == "credentials")?;
        let mut actual = Vec::new();
        let mut rows = c
            .query(&format!("SELECT json_array({columns}) FROM {table}"), ())
            .await?;
        while let Some(row) = rows.next().await? {
            let encoded = zeroize::Zeroizing::new(row.get::<String>(0)?);
            budget += encoded.len() + 64;
            if budget > 64 * 1024 * 1024 {
                return Err(Error::Quota);
            }
            let value: Vec<Value> =
                serde_json::from_str(&encoded).map_err(|_| Error::InvalidBackup)?;
            actual.push(serde_json::to_vec(&value).map_err(|_| Error::InvalidBackup)?);
        }
        actual.sort_unstable();
        if actual != expected {
            return Err(Error::InvalidBackup);
        }
        let mut hash = Sha256::new();
        hash.update(table.as_bytes());
        hash.update([0]);
        hash.update(columns.as_bytes());
        for row in &actual {
            hash.update((row.len() as u64).to_be_bytes());
            hash.update(row);
        }
        if *table == "credentials" {
            credentials_invalidated = actual.len();
        }
        tables.push(TableVerification {
            table: table.to_string(),
            rows: actual.len(),
            sha256: format!("{:x}", hash.finalize()),
        });
    }
    Ok(MigrationReport {
        target_profile: profile(),
        snapshot_version: 2,
        verified_before_publication: true,
        credentials_invalidated,
        tables,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn close_source(owner: Owner) {
        #[cfg(feature = "sqlcipher-backend")]
        owner.store.connection.lock().await.close().await.unwrap();
        drop(owner);
    }

    #[tokio::test]
    async fn every_table_mismatch_is_detected_even_with_equal_row_counts() {
        let owner = Owner::open(":memory:").await.unwrap();
        let agent = owner.create_agent().await.unwrap();
        agent
            .remember_once("migration", "key", "é\0🐬")
            .await
            .unwrap();
        let c = owner.store.connection.lock().await;
        let mut expected = Vec::new();
        for (table, columns) in TABLES {
            let mut rows = c
                .query(&format!("SELECT json_array({columns}) FROM {table}"), ())
                .await
                .unwrap();
            let mut table_rows = Vec::new();
            while let Some(row) = rows.next().await.unwrap() {
                table_rows.push(
                    serde_json::from_str::<Vec<Value>>(&row.get::<String>(0).unwrap()).unwrap(),
                );
            }
            expected.push(table_rows);
        }
        assert_eq!(verify_tables(&c, &expected).await.unwrap().tables.len(), 10);
        for index in 0..TABLES.len() {
            let mut altered = expected.clone();
            if let Some(row) = altered[index].first_mut() {
                row[0] = Value::from("changed-with-same-row-count");
            } else {
                altered[index].push(vec![Value::from("unexpected-row")]);
            }
            assert!(
                verify_tables(&c, &altered).await.is_err(),
                "{} mismatch accepted",
                TABLES[index].0
            );
        }
        assert!(verify_tables(&c, &expected[..9]).await.is_err());
    }

    #[tokio::test]
    async fn export_preserves_source_bytes_and_verified_import_preserves_logic() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.db");
        let backup = temp.path().join("snapshot");
        let key = EncryptionKey::generate().unwrap();
        let backup_key = EncryptionKey::generate().unwrap();
        let owner = Owner::open_encrypted(source.to_str().unwrap(), &key, None)
            .await
            .unwrap();
        let a = owner.create_agent().await.unwrap();
        let id = a.id().to_owned();
        a.remember_once("memory", "key", "Unicode é\0🐬")
            .await
            .unwrap();
        let p = a.propose_once("proposal", "stock", "12").await.unwrap();
        owner.approve_once("approve", &p).await.unwrap();
        drop(a);
        close_source(owner).await;
        let before = source_files(&source).unwrap();
        let exported = Owner::migration_export(&source, &key, &backup, &backup_key)
            .await
            .unwrap();
        assert_eq!(before, source_files(&source).unwrap());
        assert!(exported.source_files_unchanged);
        let (restored, report) = Owner::restore_verified(
            &backup,
            &backup_key,
            &temp.path().join("destination.db"),
            &EncryptionKey::generate().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(report.tables.len(), 10);
        assert!(report.verified_before_publication);
        let a = restored.agent(&id).await.unwrap();
        assert_eq!(
            a.recall("key").await.unwrap().as_deref(),
            Some("Unicode é\0🐬")
        );
        assert_eq!(a.propose_once("proposal", "stock", "12").await.unwrap(), p);
        restored.approve_once("approve", &p).await.unwrap();
        assert_eq!(
            restored
                .read_shared("stock")
                .await
                .unwrap()
                .unwrap()
                .version,
            1
        );
    }

    #[tokio::test]
    async fn failed_export_never_publishes_or_overwrites_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.db");
        let snapshot = temp.path().join("snapshot");
        let key = EncryptionKey::generate().unwrap();
        let backup_key = EncryptionKey::generate().unwrap();
        let owner = Owner::open_encrypted(source.to_str().unwrap(), &key, None)
            .await
            .unwrap();
        close_source(owner).await;
        let before = source_files(&source).unwrap();
        assert!(
            Owner::migration_export(
                &source,
                &EncryptionKey::generate().unwrap(),
                &snapshot,
                &backup_key
            )
            .await
            .is_err()
        );
        assert!(!snapshot.exists());
        assert_eq!(source_files(&source).unwrap(), before);
        std::fs::write(&snapshot, b"preserve this file").unwrap();
        assert!(
            Owner::migration_export(&source, &key, &snapshot, &backup_key)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&snapshot).unwrap(), b"preserve this file");
        let missing = temp.path().join("missing.db");
        assert!(
            Owner::migration_export(&missing, &key, &temp.path().join("new"), &backup_key)
                .await
                .is_err()
        );
        assert!(!missing.exists());
    }

    #[tokio::test]
    async fn export_rejects_unmapped_tables_columns_and_triggers() {
        for kind in ["table", "column", "trigger"] {
            let temp = tempfile::tempdir().unwrap();
            let source = temp.path().join("source.db");
            let key = EncryptionKey::generate().unwrap();
            let owner = Owner::open_encrypted(source.to_str().unwrap(), &key, None)
                .await
                .unwrap();
            {
                let c = owner.store.connection.lock().await;
                match kind {
                    "table" => {
                        c.execute("CREATE TABLE sqliteXcustom(value TEXT)", ())
                            .await
                            .unwrap();
                    }
                    "column" => {
                        c.execute("DROP TABLE memories", ()).await.unwrap();
                        c.execute(
                            "CREATE TABLE memories(agent_id TEXT,key TEXT,value TEXT,extra TEXT)",
                            (),
                        )
                        .await
                        .unwrap();
                    }
                    _ => {
                        c.execute("CREATE TRIGGER custom_trigger BEFORE INSERT ON memories BEGIN SELECT RAISE(ABORT,'custom'); END",()).await.unwrap();
                    }
                }
            }
            close_source(owner).await;
            let before = source_files(&source).unwrap();
            let snapshot = temp.path().join("snapshot");
            assert!(
                Owner::migration_export(&source, &key, &snapshot, &key)
                    .await
                    .is_err()
            );
            assert!(!snapshot.exists());
            assert_eq!(source_files(&source).unwrap(), before);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_sources_and_sidecars_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.db");
        let alias = temp.path().join("alias.db");
        let key = EncryptionKey::generate().unwrap();
        let owner = Owner::open_encrypted(source.to_str().unwrap(), &key, None)
            .await
            .unwrap();
        close_source(owner).await;
        std::os::unix::fs::symlink(&source, &alias).unwrap();
        assert!(
            Owner::migration_export(&alias, &key, &temp.path().join("snapshot"), &key)
                .await
                .is_err()
        );
        let wal = sidecar(&source, "-wal");
        if wal.exists() {
            std::fs::remove_file(&wal).unwrap();
        }
        std::os::unix::fs::symlink(&source, wal).unwrap();
        assert!(
            Owner::migration_export(&source, &key, &temp.path().join("snapshot"), &key)
                .await
                .is_err()
        );
    }
}
