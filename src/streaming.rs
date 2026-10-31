//! Version-3 bounded-memory snapshots. No plaintext spool files.
use crate::{backend, migration, recovery::TABLES, *};
use aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    fs::File,
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

pub(crate) const MAGIC: &[u8] = b"MIMIDB-BACKUP-3\0";
const FRAME: usize = 1024 * 1024;
const MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Row-id keyset pagination never materializes a whole table. Row IDs are not
/// exported: insertion order preserves the sequence for verification instead.
pub(crate) struct TableRows {
    table: &'static str,
    columns: &'static str,
    after: Option<i64>,
    pending: VecDeque<Vec<Value>>,
    done: bool,
}

impl TableRows {
    pub(crate) fn new(table: &'static str, columns: &'static str) -> Self {
        Self {
            table,
            columns,
            after: None,
            pending: VecDeque::new(),
            done: false,
        }
    }
    pub(crate) async fn next(&mut self, c: &Connection) -> Result<Option<Vec<Value>>> {
        if self.pending.is_empty() && !self.done {
            let select = format!(
                "SELECT rowid,json_array({}) FROM {}",
                self.columns, self.table
            );
            let mut rows = if let Some(after) = self.after {
                c.query(
                    &format!("{select} WHERE rowid > ? ORDER BY rowid LIMIT 8"),
                    [after],
                )
                .await?
            } else {
                c.query(&format!("{select} ORDER BY rowid LIMIT 8"), ())
                    .await?
            };
            let mut size = 0;
            while let Some(row) = rows.next().await? {
                let id: i64 = row.get(0)?;
                if self.after.is_some_and(|previous| id <= previous) {
                    return Err(Error::InvalidBackup);
                }
                self.after = Some(id);
                let encoded = Zeroizing::new(row.get::<String>(1)?);
                if encoded.len() > FRAME {
                    return Err(Error::Quota);
                }
                self.pending
                    .push_back(serde_json::from_str(&encoded).map_err(|_| Error::InvalidBackup)?);
                size += 1;
            }
            self.done = size < 8;
        }
        Ok(self.pending.pop_front())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum Record {
    Start { version: u8 },
    Table { index: usize },
    Row { values: Vec<Value> },
    EndTable { rows: usize, sha256: String },
    Complete { tables: usize },
}

fn cipher(key: &EncryptionKey) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key.bytes()).map_err(|_| Error::InvalidBackup)
}

struct Encoder {
    cipher: Option<EncryptorBE32<Aes256Gcm>>,
    context: Vec<u8>,
    bytes: u64,
}

impl Encoder {
    fn new(output: &mut File, master: &EncryptionKey) -> Result<Self> {
        // Every stream gets a fresh 256-bit data key. This avoids relying on
        // the short STREAM-BE32 nonce prefix for uniqueness across backups.
        let data_key = EncryptionKey::generate()?;
        let random = EncryptionKey::generate()?;
        let wrap_nonce = &random.bytes()[..12];
        let prefix = &random.bytes()[12..19];
        let mut aad = MAGIC.to_vec();
        aad.extend_from_slice(prefix);
        let wrapped = cipher(master)?
            .encrypt(
                Nonce::from_slice(wrap_nonce),
                Payload {
                    msg: data_key.bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::InvalidBackup)?;
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(wrap_nonce);
        header.extend_from_slice(prefix);
        header.extend_from_slice(&wrapped);
        output.write_all(&header)?;
        Ok(Self {
            cipher: Some(EncryptorBE32::from_aead(cipher(&data_key)?, prefix.into())),
            context: Sha256::digest(&header).to_vec(),
            bytes: header.len() as u64,
        })
    }
    fn write(&mut self, output: &mut File, record: &Record, last: bool) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(record).map_err(|_| Error::InvalidBackup)?);
        if plain.len() > FRAME {
            return Err(Error::Quota);
        }
        let size = (plain.len() + 16) as u32;
        let mut framing = size.to_be_bytes().to_vec();
        framing.push(u8::from(last));
        let mut aad = self.context.clone();
        aad.extend_from_slice(&framing);
        let payload = Payload {
            msg: &plain,
            aad: &aad,
        };
        let bytes = if last {
            self.cipher
                .take()
                .ok_or(Error::InvalidBackup)?
                .encrypt_last(payload)
        } else {
            self.cipher
                .as_mut()
                .ok_or(Error::InvalidBackup)?
                .encrypt_next(payload)
        }
        .map_err(|_| Error::InvalidBackup)?;
        self.bytes += (framing.len() + bytes.len()) as u64;
        if self.bytes > MAX_BYTES {
            return Err(Error::Quota);
        }
        output.write_all(&framing)?;
        output.write_all(&bytes)?;
        Ok(())
    }
}

struct Decoder {
    file: File,
    cipher: Option<DecryptorBE32<Aes256Gcm>>,
    context: Vec<u8>,
    bytes: u64,
    complete: bool,
}
impl Decoder {
    fn new(mut file: File, master: &EncryptionKey) -> Result<Self> {
        if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_BYTES {
            return Err(Error::InvalidBackup);
        }
        let mut header = vec![0; MAGIC.len() + 12 + 7 + 48];
        file.read_exact(&mut header)
            .map_err(|_| Error::InvalidBackup)?;
        if !header.starts_with(MAGIC) {
            return Err(Error::InvalidBackup);
        }
        let nonce_at = MAGIC.len();
        let prefix_at = nonce_at + 12;
        let wrapped_at = prefix_at + 7;
        let mut aad = MAGIC.to_vec();
        aad.extend_from_slice(&header[prefix_at..wrapped_at]);
        let key = Zeroizing::new(
            cipher(master)?
                .decrypt(
                    Nonce::from_slice(&header[nonce_at..prefix_at]),
                    Payload {
                        msg: &header[wrapped_at..],
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::InvalidBackup)?,
        );
        let key: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidBackup)?;
        let key = EncryptionKey::from_bytes(key);
        let stream =
            DecryptorBE32::from_aead(cipher(&key)?, (&header[prefix_at..wrapped_at]).into());
        Ok(Self {
            file,
            cipher: Some(stream),
            context: Sha256::digest(&header).to_vec(),
            bytes: header.len() as u64,
            complete: false,
        })
    }
    fn read(&mut self) -> Result<(Record, bool)> {
        if self.complete {
            return Err(Error::InvalidBackup);
        }
        let mut framing = [0; 5];
        self.file
            .read_exact(&mut framing)
            .map_err(|_| Error::InvalidBackup)?;
        let size = u32::from_be_bytes(framing[..4].try_into().unwrap()) as usize;
        if !(16..=FRAME + 16).contains(&size) || framing[4] > 1 {
            return Err(Error::InvalidBackup);
        }
        self.bytes += 5 + size as u64;
        if self.bytes > MAX_BYTES {
            return Err(Error::InvalidBackup);
        }
        let mut bytes = vec![0; size];
        self.file
            .read_exact(&mut bytes)
            .map_err(|_| Error::InvalidBackup)?;
        let mut aad = self.context.clone();
        aad.extend_from_slice(&framing);
        let payload = Payload {
            msg: &bytes,
            aad: &aad,
        };
        let last = framing[4] == 1;
        let plain = Zeroizing::new(
            if last {
                self.cipher
                    .take()
                    .ok_or(Error::InvalidBackup)?
                    .decrypt_last(payload)
            } else {
                self.cipher
                    .as_mut()
                    .ok_or(Error::InvalidBackup)?
                    .decrypt_next(payload)
            }
            .map_err(|_| Error::InvalidBackup)?,
        );
        if last {
            self.complete = true;
            let mut trailing = [0];
            if self.file.read(&mut trailing)? != 0 {
                return Err(Error::InvalidBackup);
            }
        }
        Ok((
            serde_json::from_slice(&plain).map_err(|_| Error::InvalidBackup)?,
            last,
        ))
    }
    fn next(&mut self) -> Result<Record> {
        let (record, last) = self.read()?;
        if last {
            return Err(Error::InvalidBackup);
        }
        Ok(record)
    }
}

fn hash_start(table: &str, columns: &str) -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(table);
    hash.update([0]);
    hash.update(columns);
    hash
}
fn hash_row(hash: &mut Sha256, row: &[Value], revoke: bool) -> Result<()> {
    let mut row = row.to_vec();
    if revoke {
        *row.get_mut(4).ok_or(Error::InvalidBackup)? = Value::from(1);
    }
    let bytes = Zeroizing::new(serde_json::to_vec(&row).map_err(|_| Error::InvalidBackup)?);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(&*bytes);
    Ok(())
}

impl Owner {
    /// Version-3 authenticated streaming snapshot, bounded to 4 GiB encrypted
    /// bytes and 1 MiB per frame. Legacy backup() remains version 2.
    pub async fn backup_streaming(&self, destination: &Path, key: &EncryptionKey) -> Result<()> {
        let mut connection = self.store.connection.lock().await;
        let c = connection.transaction().await?;
        let result = async {
            ensure_owner(&c, self).await?;
            let parent = destination
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let mut file = tempfile::NamedTempFile::new_in(parent)?;
            let mut encoder = Encoder::new(file.as_file_mut(), key)?;
            encoder.write(file.as_file_mut(), &Record::Start { version: 3 }, false)?;
            for (index, (table, columns)) in TABLES.iter().enumerate() {
                encoder.write(file.as_file_mut(), &Record::Table { index }, false)?;
                let mut rows = TableRows::new(table, columns);
                let mut count = 0;
                let mut hash = hash_start(table, columns);
                while let Some(row) = rows.next(&c).await? {
                    hash_row(&mut hash, &row, *table == "credentials")?;
                    encoder.write(file.as_file_mut(), &Record::Row { values: row }, false)?;
                    count += 1;
                }
                encoder.write(
                    file.as_file_mut(),
                    &Record::EndTable {
                        rows: count,
                        sha256: format!("{:x}", hash.finalize()),
                    },
                    false,
                )?;
            }
            encoder.write(
                file.as_file_mut(),
                &Record::Complete {
                    tables: TABLES.len(),
                },
                true,
            )?;
            file.as_file().sync_all()?;
            file.persist_noclobber(destination)
                .map_err(|e| Error::Io(e.error))?;
            super::recovery::sync_directory(parent)?;
            Ok(())
        }
        .await;
        finish(c, result).await
    }

    pub(crate) async fn restore_streaming(
        file: File,
        key: &EncryptionKey,
        destination: &Path,
        database_key: &EncryptionKey,
    ) -> Result<(Self, crate::MigrationReport)> {
        // Authenticate the wrapped key and initial frame before creating staging.
        let mut decoder = Decoder::new(file, key)?;
        if !matches!(decoder.next()?, Record::Start { version: 3 }) {
            return Err(Error::InvalidBackup);
        }
        if std::fs::symlink_metadata(destination).is_ok() {
            return Err(Error::Configuration);
        }
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let stage = tempfile::Builder::new()
            .prefix(".dolphi-restore-")
            .tempfile_in(parent)?;
        let path = stage
            .path()
            .to_str()
            .ok_or(Error::Configuration)?
            .to_owned();
        let staged = Self::open_encrypted(&path, database_key, None).await?;
        let result = async {
            let mut connection = staged.store.connection.lock().await;
            let c = connection.transaction_with_behavior(TransactionBehavior::Immediate).await?;
            let imported = async {
                let mut expected = Vec::new();
                for (index,(table,columns)) in TABLES.iter().enumerate() {
                    if !matches!(decoder.next()?,Record::Table {index:i} if i==index) { return Err(Error::InvalidBackup); }
                    c.execute(&format!("DELETE FROM {table}"),()).await?;
                    let width = columns.split(',').count();
                    let sql = format!("INSERT INTO {table}({columns}) VALUES ({})",vec!["?";width].join(","));
                    let mut count=0; let mut hash=hash_start(table,columns);
                    loop {
                        match decoder.next()? {
                            Record::Row {values} => {
                                if values.len()!=width { return Err(Error::InvalidBackup); }
                                hash_row(&mut hash,&values,*table=="credentials")?;
                                let values=values.into_iter().map(|v| match v {
                                    Value::String(v)=>Ok(backend::Value::Text(v)),
                                    Value::Number(v)=>v.as_i64().map(backend::Value::Integer).ok_or(Error::InvalidBackup),
                                    _=>Err(Error::InvalidBackup),
                                }).collect::<Result<Vec<_>>>()?;
                                c.execute(&sql,backend::params_from_iter(values)).await?; count+=1;
                            }
                            Record::EndTable {rows,sha256} => {
                                if rows!=count || sha256!=format!("{:x}",hash.finalize()) { return Err(Error::InvalidBackup); }
                                expected.push((count,sha256)); break;
                            }
                            _=>return Err(Error::InvalidBackup),
                        }
                    }
                }
                if !matches!(decoder.read()?,(Record::Complete {tables},true) if tables==TABLES.len()) { return Err(Error::InvalidBackup); }
                crate::recovery::validate_snapshot(&c).await?;
                c.execute("UPDATE credentials SET revoked=1",()).await?;
                Ok(expected)
            }.await;
            let expected=finish(c,imported).await?;
            let mut tables=Vec::new(); let mut credentials_invalidated=0;
            for ((table,columns),(count,expected)) in TABLES.iter().zip(expected) {
                let mut rows=TableRows::new(table,columns); let mut actual=0; let mut hash=hash_start(table,columns);
                while let Some(row)=rows.next(&connection).await? { hash_row(&mut hash,&row,false)?;actual+=1; }
                let sha256=format!("{:x}",hash.finalize());
                if actual!=count || sha256!=expected { return Err(Error::InvalidBackup); }
                if *table=="credentials" {credentials_invalidated=actual;}
                tables.push(migration::TableVerification {table:table.to_string(),rows:actual,sha256});
            }
            let mut rows=connection.query("PRAGMA integrity_check",()).await?;
            if rows.next().await?.ok_or(Error::InvalidBackup)?.get::<String>(0)?!="ok" {return Err(Error::InvalidBackup);}
            drop(rows);
            let mut rows=connection.query("PRAGMA wal_checkpoint(TRUNCATE)",()).await?;
            if rows.next().await?.ok_or(Error::InvalidBackup)?.get::<i64>(0)?!=0 {return Err(Error::InvalidBackup);}
            Ok(crate::MigrationReport {target_profile:migration::profile(),snapshot_version:3,
                verified_before_publication:true,credentials_invalidated,tables})
        }.await;
        #[cfg(feature = "sqlcipher-backend")]
        let result = match (result, staged.store.connection.lock().await.close().await) {
            (Ok(report), Ok(())) => Ok(report),
            (Err(e), _) => Err(e),
            (_, Err(e)) => Err(e.into()),
        };
        drop(staged);
        for suffix in ["-wal", "-shm"] {
            let sidecar = format!("{path}{suffix}");
            if Path::new(&sidecar).exists() {
                std::fs::remove_file(sidecar)?;
            }
        }
        let report = result?;
        stage.as_file().sync_all()?;
        stage
            .persist_noclobber(destination)
            .map_err(|e| Error::Io(e.error))?;
        crate::recovery::sync_directory(parent)?;
        Ok((
            Self::open_encrypted(
                destination.to_str().ok_or(Error::Configuration)?,
                database_key,
                None,
            )
            .await?,
            report,
        ))
    }
}
