//! SQLCipher engine/worker and standalone synthetic qualification harness.
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use zeroize::Zeroizing;
pub mod worker;
pub use rusqlite;

pub const SCHEMA: &str = include_str!("../../../src/schema.sql");

pub fn open(path: &Path, key: &[u8; 32]) -> rusqlite::Result<Connection> {
    configured(path, Some(key))
}

pub(crate) fn configured(path: &Path, key: Option<&[u8; 32]>) -> rusqlite::Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    // SQLCipher raw-key syntax. Hex is generated from bytes, not caller text.
    if let Some(key) = key {
        let hex = Zeroizing::new(
            key.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
        connection.pragma_update(None, "key", format!("x'{}'", hex.as_str()))?;
    }
    // Fail closed on stale/system libraries, plaintext SQLite or prereleases.
    let version: String = connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
    if version != "4.20.0 community" {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let sqlite: String = connection.query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
    if sqlite != "3.54.1" {
        return Err(rusqlite::Error::InvalidQuery);
    }
    if key.is_some() {
        let provider: String =
            connection.query_row("PRAGMA cipher_provider", [], |row| row.get(0))?;
        if provider != "openssl" {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let provider_version: String =
            connection.query_row("PRAGMA cipher_provider_version", [], |row| row.get(0))?;
        if !provider_version.starts_with("OpenSSL 3.5.9 ") {
            return Err(rusqlite::Error::InvalidQuery);
        }
    }
    connection.pragma_update(None, "cipher_memory_security", "ON")?;
    connection.query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(connection)
}

pub fn initialized(path: &Path, key: &[u8; 32]) -> rusqlite::Result<Connection> {
    let connection = open(path, key)?;
    connection.execute_batch(SCHEMA)?;
    Ok(connection)
}

pub fn metadata(connection: &Connection) -> rusqlite::Result<serde_json::Value> {
    let scalar = |query: &str| connection.query_row(query, [], |row| row.get::<_, String>(0));
    Ok(
        serde_json::json!({"cipher_version":scalar("PRAGMA cipher_version")?,
        "sqlite_version":scalar("SELECT sqlite_version()")?,
        "crypto_provider":scalar("PRAGMA cipher_provider")?,
        "crypto_provider_version":scalar("PRAGMA cipher_provider_version")?,
        "journal_mode":scalar("PRAGMA journal_mode")?,
        "synchronous":connection.query_row("PRAGMA synchronous",[],|row|row.get::<_,i64>(0))?,
        "temp_store":connection.query_row("PRAGMA temp_store",[],|row|row.get::<_,i64>(0))?}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_private_scoping_and_literal_parameters_work() {
        let temp = tempfile::tempdir().unwrap();
        let db = initialized(&temp.path().join("test.db"), &[7; 32]).unwrap();
        for id in ["a", "b"] {
            db.execute("INSERT INTO agents VALUES (?)", [id]).unwrap();
        }
        let injection = "x'; DROP TABLE memories; --";
        db.execute(
            "INSERT INTO memories VALUES (?, ?, ?)",
            ("a", injection, "private-a"),
        )
        .unwrap();
        db.execute(
            "INSERT INTO memories VALUES (?, ?, ?)",
            ("b", injection, "private-b"),
        )
        .unwrap();
        let value: String = db
            .query_row(
                "SELECT value FROM memories WHERE agent_id=? AND key=?",
                ("a", injection),
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(value, "private-a");
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM memories", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn keys_reopen_wrong_key_plaintext_and_corruption_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("test.db");
        let db = initialized(&path, &[9; 32]).unwrap();
        db.execute("INSERT INTO agents VALUES ('stable')", [])
            .unwrap();
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
        drop(db);
        assert!(open(&path, &[8; 32]).is_err());
        let missing = Connection::open(&path).unwrap();
        assert!(
            missing
                .query_row("SELECT COUNT(*) FROM agents", [], |row| row
                    .get::<_, i64>(0))
                .is_err()
        );
        drop(missing);
        let db = open(&path, &[9; 32]).unwrap();
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM agents", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        drop(db);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[256] ^= 0x80;
        let damaged = temp.path().join("damaged.db");
        std::fs::write(&damaged, bytes).unwrap();
        assert!(open(&damaged, &[9; 32]).is_err());
    }

    #[test]
    fn database_and_live_wal_do_not_contain_sentinel() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("test.db");
        let db = initialized(&path, &[11; 32]).unwrap();
        let sentinel = "DOLPHI-QUALIFICATION-SECRET-b827d94753";
        db.execute("INSERT INTO memories VALUES ('a','key',?)", [sentinel])
            .unwrap();
        assert!(Path::new(&format!("{}-wal", path.display())).exists());
        for entry in std::fs::read_dir(temp.path()).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(
                !bytes
                    .windows(sentinel.len())
                    .any(|window| window == sentinel.as_bytes())
            );
        }
        assert_eq!(
            db.query_row("PRAGMA temp_store", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn atomic_approval_rolls_back_when_audit_fails() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("test.db");
        let mut db = initialized(&path, &[12; 32]).unwrap();
        db.execute("INSERT INTO agents VALUES ('a')", []).unwrap();
        db.execute(
            "INSERT INTO proposals VALUES ('p','a','stock','12',0,'pending')",
            [],
        )
        .unwrap();
        db.execute_batch("CREATE TRIGGER deny_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected'); END").unwrap();
        {
            let tx = db.transaction().unwrap();
            tx.execute("INSERT INTO shared VALUES ('stock','12',1)", [])
                .unwrap();
            tx.execute("UPDATE proposals SET status='approved' WHERE id='p'", [])
                .unwrap();
            assert!(tx.execute("INSERT INTO audit(actor,action,subject) VALUES ('owner','proposal.approved','p')",[]).is_err());
        }
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM shared", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT status FROM proposals", [], |row| row
                .get::<_, String>(0))
                .unwrap(),
            "pending"
        );
    }

    #[test]
    fn schema_features_and_json_snapshot_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("test.db");
        let db = initialized(&path, &[13; 32]).unwrap();
        db.execute(
            "INSERT INTO memories VALUES ('a','é',?)",
            ["line1\n🐬\0line2"],
        )
        .unwrap();
        let encoded: String = db
            .query_row(
                "SELECT json_array(agent_id,key,value) FROM memories",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let decoded: Vec<String> = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, vec!["a", "é", "line1\n🐬\0line2"]);
        assert_eq!(
            db.query_row(
                "SELECT length(CAST(value AS BLOB)) FROM memories",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            16
        );
        db.execute(
            "INSERT INTO settings VALUES(1,'first') ON CONFLICT(id) DO NOTHING",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO settings VALUES(1,'second') ON CONFLICT(id) DO NOTHING",
            [],
        )
        .unwrap();
        assert_eq!(
            db.query_row("SELECT value FROM settings", [], |row| row
                .get::<_, String>(0))
                .unwrap(),
            "first"
        );
        let errors: Vec<String> = db
            .prepare("PRAGMA cipher_integrity_check")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(errors.is_empty());
    }

    #[test]
    fn backup_copy_after_checkpoint_reopens_with_same_key() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("test.db");
        let db = initialized(&path, &[14; 32]).unwrap();
        db.execute("INSERT INTO agents VALUES ('recoverable')", [])
            .unwrap();
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
        drop(db);
        let copy = temp.path().join("offline-copy.db");
        std::fs::copy(&path, &copy).unwrap();
        let recovered = open(&copy, &[14; 32]).unwrap();
        assert_eq!(
            recovered
                .query_row("SELECT id FROM agents", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "recoverable"
        );
    }
}
