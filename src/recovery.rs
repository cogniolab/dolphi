//! Versioned logical snapshots, authenticated encryption, and offline restore.
use super::*;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"MIMIDB-BACKUP-1\0";
const MAX_SNAPSHOT: usize = 64 * 1024 * 1024;
// Names/columns are static code, never supplied by a snapshot.
pub(crate) const TABLES: &[(&str, &str)] = &[
    ("agents", "id"),
    ("revoked_agents", "agent_id"),
    ("memories", "agent_id,key,value"),
    ("shared", "key,value,version"),
    ("proposals", "id,agent_id,key,value,base_version,status"),
    ("audit", "sequence,actor,action,subject,created_at"),
    ("settings", "id,value"),
    ("credentials", "digest,role,agent_id,expires_at,revoked"),
    ("request_windows", "agent_id,window,requests"),
    (
        "operations",
        "role,principal,operation_id,action,fingerprint,result,created_at",
    ),
];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    version: u32,
    tables: Vec<Vec<Vec<serde_json::Value>>>,
}

fn cipher(key: &EncryptionKey) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key.bytes()).map_err(|_| Error::InvalidBackup)
}

impl Owner {
    /// Consistent logical snapshot encrypted with an independent backup key.
    /// Destination must not exist. No plaintext temporary file is written.
    pub async fn backup(&self, destination: &Path, key: &EncryptionKey) -> Result<()> {
        let mut connection = self.store.connection.lock().await;
        let c = connection.transaction().await?;
        let result = async {
            ensure_owner(&c, self).await?;
            let mut snapshot = Snapshot {
                version: 2,
                tables: Vec::new(),
            };
            let mut budget = 0;
            for (table, columns) in TABLES {
                let sql = format!("SELECT json_array({columns}) FROM {table} ORDER BY 1");
                let mut rows = c.query(&sql, ()).await?;
                let mut values = Vec::new();
                while let Some(row) = rows.next().await? {
                    let encoded = Zeroizing::new(row.get::<String>(0)?);
                    budget += encoded.len() + 64;
                    if budget > MAX_SNAPSHOT {
                        return Err(Error::Quota);
                    }
                    values.push(serde_json::from_str(&encoded).map_err(|_| Error::InvalidBackup)?);
                }
                snapshot.tables.push(values);
            }
            let plaintext =
                Zeroizing::new(serde_json::to_vec(&snapshot).map_err(|_| Error::InvalidBackup)?);
            if plaintext.len() > MAX_SNAPSHOT {
                return Err(Error::Quota);
            }
            let random = EncryptionKey::generate()?;
            let nonce = Nonce::from_slice(&random.bytes()[..12]);
            let ciphertext = cipher(key)?
                .encrypt(
                    nonce,
                    Payload {
                        msg: &plaintext,
                        aad: MAGIC,
                    },
                )
                .map_err(|_| Error::InvalidBackup)?;
            let parent = destination
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let mut output = tempfile::NamedTempFile::new_in(parent)?;
            output.write_all(MAGIC)?;
            output.write_all(nonce)?;
            output.write_all(&ciphertext)?;
            output.as_file().sync_all()?;
            // Refuse to overwrite existing backup paths or symlinks.
            output
                .persist_noclobber(destination)
                .map_err(|e| Error::Io(e.error))?;
            sync_directory(parent)?;
            Ok(())
        }
        .await;
        finish(c, result).await
    }

    /// Offline restore to a NEW encrypted database. The destination is published
    /// only after validation/checkpoint. All restored bearer credentials are
    /// invalidated to avoid resurrecting previously revoked/expired access.
    pub async fn restore(
        backup: &Path,
        backup_key: &EncryptionKey,
        destination: &Path,
        database_key: &EncryptionKey,
    ) -> Result<Self> {
        Self::restore_verified(backup, backup_key, destination, database_key)
            .await
            .map(|(owner, _)| owner)
    }

    /// Restore with exact per-table verification before destination publication.
    pub async fn restore_verified(
        backup: &Path,
        backup_key: &EncryptionKey,
        destination: &Path,
        database_key: &EncryptionKey,
    ) -> Result<(Self, crate::MigrationReport)> {
        if !std::fs::symlink_metadata(backup)?.is_file() {
            return Err(Error::InvalidBackup);
        }
        let mut magic = vec![0; crate::streaming::MAGIC.len()];
        let mut probe = std::fs::File::open(backup)?;
        if probe.read_exact(&mut magic).is_ok() && magic == crate::streaming::MAGIC {
            return Self::restore_streaming(
                std::fs::File::open(backup)?,
                backup_key,
                destination,
                database_key,
            )
            .await;
        }
        let mut input = Vec::new();
        std::fs::File::open(backup)?
            .take((MAX_SNAPSHOT + 1024) as u64)
            .read_to_end(&mut input)?;
        let offset = MAGIC.len() + 12;
        if input.len() < offset + 16
            || input.len() > MAX_SNAPSHOT + offset + 16
            || !input.starts_with(MAGIC)
        {
            return Err(Error::InvalidBackup);
        }
        let plaintext = Zeroizing::new(
            cipher(backup_key)?
                .decrypt(
                    Nonce::from_slice(&input[MAGIC.len()..offset]),
                    Payload {
                        msg: &input[offset..],
                        aad: MAGIC,
                    },
                )
                .map_err(|_| Error::InvalidBackup)?,
        );
        let mut snapshot: Snapshot =
            serde_json::from_slice(&plaintext).map_err(|_| Error::InvalidBackup)?;
        if snapshot.version == 1 && snapshot.tables.len() == TABLES.len() - 1 {
            snapshot.tables.push(Vec::new());
        } else if snapshot.version != 2 || snapshot.tables.len() != TABLES.len() {
            return Err(Error::InvalidBackup);
        }
        // Authenticate and parse before creating anything at the destination.
        if destination.exists() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "restore destination exists",
            )));
        }
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let stage = tempfile::Builder::new()
            .prefix(".dolphi-restore-")
            .tempfile_in(parent)?;
        let stage_path = stage
            .path()
            .to_str()
            .ok_or(Error::Configuration)?
            .to_owned();
        let staged = Self::open_encrypted(&stage_path, database_key, None).await?;
        let result = async {
            let mut connection = staged.store.connection.lock().await;
            let c = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .await?;
            let result = async {
                for ((table, columns), rows) in TABLES.iter().zip(&snapshot.tables) {
                    c.execute(&format!("DELETE FROM {table}"), ()).await?;
                    let width = columns.split(',').count();
                    let placeholders = vec!["?"; width].join(",");
                    let sql = format!("INSERT INTO {table}({columns}) VALUES ({placeholders})");
                    for row in rows {
                        if row.len() != width {
                            return Err(Error::InvalidBackup);
                        }
                        let values: Vec<backend::Value> = row
                            .iter()
                            .cloned()
                            .map(|v| match v {
                                serde_json::Value::String(s) => Ok(backend::Value::Text(s)),
                                serde_json::Value::Number(n) => n
                                    .as_i64()
                                    .map(backend::Value::Integer)
                                    .ok_or(Error::InvalidBackup),
                                _ => Err(Error::InvalidBackup),
                            })
                            .collect::<Result<_>>()?;
                        c.execute(&sql, backend::params_from_iter(values)).await?;
                    }
                }
                validate_snapshot(&c).await?;
                c.execute("UPDATE credentials SET revoked = 1", ()).await?;
                Ok(())
            }
            .await;
            finish(c, result).await?;
            let report = crate::migration::verify_tables(&connection, &snapshot.tables).await?;
            let mut rows = connection.query("PRAGMA integrity_check", ()).await?;
            if rows
                .next()
                .await?
                .ok_or(Error::InvalidBackup)?
                .get::<String>(0)?
                != "ok"
            {
                return Err(Error::InvalidBackup);
            }
            drop(rows);
            let mut rows = connection
                .query("PRAGMA wal_checkpoint(TRUNCATE)", ())
                .await?;
            let row = rows.next().await?.ok_or(Error::InvalidBackup)?;
            if row.get::<i64>(0)? != 0 {
                return Err(Error::InvalidBackup);
            }
            Ok(report)
        }
        .await;
        #[cfg(feature = "sqlcipher-backend")]
        let result = {
            // Close even on validation failure before removing staging sidecars.
            let closed = staged.store.connection.lock().await.close().await;
            match (result, closed) {
                (Ok(report), Ok(())) => Ok(report),
                (Err(error), _) => Err(error),
                (_, Err(error)) => Err(Error::from(error)),
            }
        };
        drop(staged);
        // Stage/WAL sidecars are private encrypted files. Cleanup on any outcome.
        for suffix in ["-wal", "-shm"] {
            let path = format!("{stage_path}{suffix}");
            if Path::new(&path).exists() {
                std::fs::remove_file(path)?;
            }
        }
        let report = result?;
        stage.as_file().sync_all()?;
        stage
            .persist_noclobber(destination)
            .map_err(|e| Error::Io(e.error))?;
        sync_directory(parent)?;
        let owner = Self::open_encrypted(
            destination.to_str().ok_or(Error::Configuration)?,
            database_key,
            None,
        )
        .await?;
        Ok((owner, report))
    }
}

pub(crate) fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

pub(crate) async fn validate_snapshot(c: &Connection) -> Result<()> {
    operations::validate(c).await?;
    let config = limits(c).await?;
    if count(c, "SELECT COUNT(*) FROM agents").await? > config.agents
        || count(c, "SELECT COUNT(*) FROM credentials").await? > config.credentials
        || count(c, "SELECT COUNT(*) FROM audit").await?
            > config.audit_events + config.agents + config.credentials
    {
        return Err(Error::InvalidBackup);
    }
    for sql in [
        "SELECT COUNT(*) FROM memories WHERE agent_id NOT IN (SELECT id FROM agents)",
        "SELECT COUNT(*) FROM proposals WHERE agent_id NOT IN (SELECT id FROM agents)",
        "SELECT COUNT(*) FROM revoked_agents WHERE agent_id NOT IN (SELECT id FROM agents)",
        "SELECT COUNT(*) FROM credentials WHERE role NOT IN ('owner','agent') OR (role = 'agent' AND agent_id NOT IN (SELECT id FROM agents)) OR (role = 'owner' AND agent_id != '')",
        "SELECT COUNT(*) FROM shared WHERE version < 1",
    ] {
        if count(c, sql).await? != 0 {
            return Err(Error::InvalidBackup);
        }
    }
    let mut rows = crate::streaming::TableRows::new("agents", "id");
    while let Some(row) = rows.next(c).await? {
        let id = row[0].as_str().ok_or(Error::InvalidBackup)?;
        memory_quota(c, id)
            .await
            .map_err(|_| Error::InvalidBackup)?;
        let mut proposals = c
            .query("SELECT COUNT(*) FROM proposals WHERE agent_id = ?", [id])
            .await?;
        if proposals
            .next()
            .await?
            .ok_or(Error::InvalidBackup)?
            .get::<i64>(0)?
            > config.proposals_per_agent
        {
            return Err(Error::InvalidBackup);
        }
    }
    Ok(())
}

#[cfg(test)]
mod retry_snapshot_tests {
    use super::*;

    fn read_snapshot(path: &Path, key: &EncryptionKey) -> Snapshot {
        let input = std::fs::read(path).unwrap();
        let offset = MAGIC.len() + 12;
        let bytes = cipher(key)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&input[MAGIC.len()..offset]),
                Payload {
                    msg: &input[offset..],
                    aad: MAGIC,
                },
            )
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
    fn write_snapshot(path: &Path, key: &EncryptionKey, snapshot: &Snapshot) {
        let random = EncryptionKey::generate().unwrap();
        let nonce = Nonce::from_slice(&random.bytes()[..12]);
        let bytes = serde_json::to_vec(snapshot).unwrap();
        let encrypted = cipher(key)
            .unwrap()
            .encrypt(
                nonce,
                Payload {
                    msg: &bytes,
                    aad: MAGIC,
                },
            )
            .unwrap();
        let mut output = MAGIC.to_vec();
        output.extend_from_slice(nonce);
        output.extend(encrypted);
        std::fs::write(path, output).unwrap();
    }

    #[tokio::test]
    async fn legacy_nine_table_snapshot_restores_without_inventing_receipts() {
        let temp = tempfile::tempdir().unwrap();
        let backup = temp.path().join("legacy");
        let owner = Owner::open(":memory:").await.unwrap();
        let agent = owner.create_agent().await.unwrap();
        agent.remember("legacy", "value").await.unwrap();
        let key = EncryptionKey::generate().unwrap();
        owner.backup(&backup, &key).await.unwrap();
        let mut snapshot = read_snapshot(&backup, &key);
        snapshot.version = 1;
        snapshot.tables.pop();
        write_snapshot(&backup, &key, &snapshot);
        let restored = Owner::restore(
            &backup,
            &key,
            &temp.path().join("restored.db"),
            &EncryptionKey::generate().unwrap(),
        )
        .await
        .unwrap();
        let agent = restored.agent(agent.id()).await.unwrap();
        assert_eq!(
            agent.recall("legacy").await.unwrap().as_deref(),
            Some("value")
        );
        assert!(agent.operation_status("legacy-id").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn malformed_or_cross_agent_receipts_never_publish_a_restore() {
        let temp = tempfile::tempdir().unwrap();
        let backup = temp.path().join("backup");
        let owner = Owner::open(":memory:").await.unwrap();
        let a = owner.create_agent().await.unwrap();
        let b = owner.create_agent().await.unwrap();
        a.propose_once("restore-retry", "key", "value")
            .await
            .unwrap();
        let key = EncryptionKey::generate().unwrap();
        owner.backup(&backup, &key).await.unwrap();
        for kind in [
            "hash",
            "result",
            "principal",
            "missing-table",
            "unsupported-version",
        ] {
            let mut snapshot = read_snapshot(&backup, &key);
            match kind {
                "hash" => snapshot.tables.last_mut().unwrap()[0][4] = serde_json::json!("bad"),
                "result" => {
                    snapshot.tables.last_mut().unwrap()[0][5] =
                        serde_json::json!(r#"{"secret":"not permitted"}"#)
                }
                "principal" => {
                    snapshot.tables.last_mut().unwrap()[0][1] = serde_json::json!(b.id())
                }
                "missing-table" => {
                    snapshot.tables.pop();
                }
                _ => snapshot.version = 999,
            }
            let altered = temp.path().join(kind);
            write_snapshot(&altered, &key, &snapshot);
            let destination = temp.path().join(format!("{kind}.db"));
            assert!(
                Owner::restore(
                    &altered,
                    &key,
                    &destination,
                    &EncryptionKey::generate().unwrap()
                )
                .await
                .is_err()
            );
            assert!(!destination.exists());
        }
    }
}
