//! Dolphi Community: local, capability-scoped agent memory.
//!
//! `Owner` is the trusted administrative boundary. Give agents only an
//! `AgentSession`, never an Owner, database path, or raw SQL connection.
use std::sync::Arc;
use tokio::sync::Mutex;
mod backend;
use backend::{Connection, Database, Transaction, TransactionBehavior};
use uuid::Uuid;
pub mod http;
mod migration;
mod operations;
mod protection;
mod recovery;
mod streaming;
pub use migration::{MigrationExport, MigrationReport, SourceFile, TableVerification};
pub use operations::OperationReceipt;
pub use protection::{Authenticated, Credential, EncryptionKey, Limits};
use protection::{authorize_agent, count, ensure_owner, limits, memory_quota, proposal_quota};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Storage(#[from] backend::Error),
    #[error("invalid, expired or revoked credential")]
    Authentication,
    #[error("configured quota exceeded")]
    Quota,
    #[error("invalid or conflicting persistent configuration")]
    Configuration,
    #[error("backup authentication or format validation failed")]
    InvalidBackup,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("agent does not exist")]
    UnknownAgent,
    #[error("agent access has been revoked")]
    Revoked,
    #[error("proposal does not exist")]
    UnknownProposal,
    #[error("proposal has already been reviewed")]
    AlreadyReviewed,
    #[error("shared data changed since this proposal was created")]
    Conflict,
    #[error("operation ID was already used with different input")]
    OperationConflict,
    #[error("key and value must be nonempty and no larger than 256 bytes / 64 KiB")]
    InvalidInput,
}
pub type Result<T> = std::result::Result<T, Error>;

struct Store {
    // Keep the engine alive for the lifetime of all session handles.
    _database: Database,
    // Serialize library operations. MVCC/parallel throughput is a later benchmark.
    connection: Mutex<Connection>,
}

#[derive(Clone)]
pub struct Owner {
    store: Arc<Store>,
    credential: Option<String>,
}

#[derive(Clone)]
/// An agent capability cannot approve changes, inspect proposals, read the owner
/// audit log, or change its identity. These restrictions are compile-tested.
///
/// ```compile_fail
/// async fn attack(agent: &dolphi::AgentSession) {
///     agent.approve("guessed-proposal-id").await.unwrap();
/// }
/// ```
/// ```compile_fail
/// async fn attack(agent: &dolphi::AgentSession) {
///     agent.audit().await.unwrap();
/// }
/// ```
/// ```compile_fail
/// fn attack(agent: &mut dolphi::AgentSession) {
///     agent.agent_id = "victim".to_owned();
/// }
/// ```
/// ```compile_fail
/// async fn attack(agent: &dolphi::AgentSession) {
///     agent.inspect("victim-proposal").await.unwrap();
/// }
pub struct AgentSession {
    store: Arc<Store>,
    agent_id: String,
    credential: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SharedValue {
    pub value: String,
    pub version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Proposal {
    pub id: String,
    pub agent_id: String,
    pub key: String,
    pub value: String,
    pub base_version: i64,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AuditEvent {
    pub sequence: i64,
    pub actor: String,
    pub action: String,
    pub subject: String,
    pub created_at: String,
}

fn validate(key: &str, value: &str) -> Result<()> {
    validate_key(key)?;
    if value.is_empty() || value.len() > 65536 {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 256 {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

async fn check_agent(c: &Connection, id: &str) -> Result<()> {
    let mut rows = c.query("SELECT id FROM agents WHERE id = ?", [id]).await?;
    if rows.next().await?.is_none() {
        return Err(Error::UnknownAgent);
    }
    drop(rows);
    let mut rows = c
        .query(
            "SELECT agent_id FROM revoked_agents WHERE agent_id = ?",
            [id],
        )
        .await?;
    if rows.next().await?.is_some() {
        return Err(Error::Revoked);
    }
    Ok(())
}

async fn record(c: &Connection, actor: &str, action: &str, subject: &str) -> Result<()> {
    let config = limits(c).await?;
    // Ordinary traffic cannot exhaust the capacity needed to revoke access.
    let ceiling = if matches!(action, "agent.revoked" | "credential.revoked") {
        config.audit_events + config.agents + config.credentials
    } else {
        config.audit_events
    };
    if count(c, "SELECT COUNT(*) FROM audit").await? >= ceiling {
        return Err(Error::Quota);
    }
    c.execute(
        "INSERT INTO audit(actor, action, subject) VALUES (?, ?, ?)",
        (actor, action, subject),
    )
    .await?;
    Ok(())
}

// The engine transaction guard rolls back on error or future cancellation.
async fn finish<T>(tx: Transaction<'_>, result: Result<T>) -> Result<T> {
    match result {
        Ok(value) => {
            tx.commit().await?;
            Ok(value)
        }
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}

async fn shared(c: &Connection, key: &str) -> Result<Option<SharedValue>> {
    let mut rows = c
        .query("SELECT value, version FROM shared WHERE key = ?", [key])
        .await?;
    Ok(match rows.next().await? {
        Some(row) => Some(SharedValue {
            value: row.get(0)?,
            version: row.get(1)?,
        }),
        None => None,
    })
}

async fn proposal(c: &Connection, id: &str) -> Result<Proposal> {
    let mut rows = c
        .query(
            "SELECT id, agent_id, key, value, base_version, status FROM proposals WHERE id = ?",
            [id],
        )
        .await?;
    let row = rows.next().await?.ok_or(Error::UnknownProposal)?;
    Ok(Proposal {
        id: row.get(0)?,
        agent_id: row.get(1)?,
        key: row.get(2)?,
        value: row.get(3)?,
        base_version: row.get(4)?,
        status: row.get(5)?,
    })
}

impl Owner {
    /// Open a local database. Possession of this handle grants owner authority.
    /// Call only from trusted host code; this is not a network login function.
    pub async fn open(path: &str) -> Result<Self> {
        Self::open_configured(path, None, None).await
    }

    async fn open_configured(
        path: &str,
        key: Option<&EncryptionKey>,
        requested: Option<Limits>,
    ) -> Result<Self> {
        if let Some(limits) = &requested {
            limits.validate()?;
        }
        #[cfg(feature = "turso-backend")]
        let mut builder = turso::Builder::new_local(path);
        if let Some(key) = key {
            protection::prepare_encrypted_path(path)?;
            #[cfg(feature = "turso-backend")]
            {
                builder =
                    builder
                        .experimental_encryption(true)
                        .with_encryption(turso::EncryptionOpts {
                            cipher: "aes256gcm".to_owned(),
                            hexkey: key.hex().to_string(),
                        });
            }
            #[cfg(feature = "sqlcipher-backend")]
            let _ = key;
        }
        #[cfg(feature = "turso-backend")]
        let database = builder.build().await?;
        #[cfg(feature = "sqlcipher-backend")]
        let database = Database::open(path, key).await?;
        let mut connection = database.connect()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let result = async {
            for statement in include_str!("schema.sql").split(';') {
                if !statement.trim().is_empty() {
                    tx.execute(statement, ()).await?;
                }
            }
            let initial = requested.clone().unwrap_or_default();
            tx.execute(
                "INSERT INTO settings(id, value) VALUES (1, ?) ON CONFLICT(id) DO NOTHING",
                [serde_json::to_string(&initial).map_err(|_| Error::Configuration)?],
            )
            .await?;
            let saved = limits(&tx).await?;
            if requested.as_ref().is_some_and(|r| r != &saved) {
                return Err(Error::Configuration);
            }
            Ok(())
        }
        .await;
        finish(tx, result).await?;
        Ok(Self {
            store: Arc::new(Store {
                _database: database,
                connection: Mutex::new(connection),
            }),
            credential: None,
        })
    }

    pub async fn create_agent(&self) -> Result<AgentSession> {
        let id = Uuid::new_v4().to_string();
        let mut connection = self.store.connection.lock().await;
        let c = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let result = async {
            ensure_owner(&c, self).await?;
            if count(&c, "SELECT COUNT(*) FROM agents").await? >= limits(&c).await?.agents {
                return Err(Error::Quota);
            }
            c.execute("INSERT INTO agents(id) VALUES (?)", [id.as_str()])
                .await?;
            record(&c, "owner", "agent.created", &id).await?;
            Ok(())
        }
        .await;
        finish(c, result).await?;
        Ok(AgentSession {
            store: self.store.clone(),
            agent_id: id,
            credential: None,
        })
    }

    /// Reissue a capability after restart. The caller must be trusted owner code.
    pub async fn agent(&self, id: &str) -> Result<AgentSession> {
        validate_key(id)?;
        let c = self.store.connection.lock().await;
        ensure_owner(&c, self).await?;
        check_agent(&c, id).await?;
        Ok(AgentSession {
            store: self.store.clone(),
            agent_id: id.to_owned(),
            credential: None,
        })
    }

    pub async fn inspect(&self, id: &str) -> Result<Proposal> {
        validate_key(id)?;
        let c = self.store.connection.lock().await;
        ensure_owner(&c, self).await?;
        proposal(&c, id).await
    }

    pub async fn read_shared(&self, key: &str) -> Result<Option<SharedValue>> {
        validate_key(key)?;
        let c = self.store.connection.lock().await;
        ensure_owner(&c, self).await?;
        shared(&c, key).await
    }

    pub async fn approve(&self, id: &str) -> Result<()> {
        self.review(id, true, None).await
    }

    pub async fn reject(&self, id: &str) -> Result<()> {
        self.review(id, false, None).await
    }

    pub async fn approve_once(&self, operation_id: &str, id: &str) -> Result<()> {
        self.review(id, true, Some(operation_id)).await
    }
    pub async fn reject_once(&self, operation_id: &str, id: &str) -> Result<()> {
        self.review(id, false, Some(operation_id)).await
    }
    async fn review(&self, id: &str, approve: bool, operation_id: Option<&str>) -> Result<()> {
        validate_key(id)?;
        let operation = operations::Request::new(
            operation_id,
            "owner",
            "",
            if approve {
                "proposal.approved"
            } else {
                "proposal.rejected"
            },
            &[id],
        )?;
        let mut connection = self.store.connection.lock().await;
        let c = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let result = async {
            ensure_owner(&c, self).await?;
            if operation.previous(&c).await?.is_some() { return Ok(()); }
            let p = proposal(&c, id).await?;
            if p.status != "pending" { return Err(Error::AlreadyReviewed); }
            if approve {
                check_agent(&c, &p.agent_id).await?;
                let version = shared(&c, &p.key).await?.map_or(0, |v| v.version);
                if version != p.base_version { return Err(Error::Conflict); }
                c.execute(
                    "INSERT INTO shared(key, value, version) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, version = excluded.version",
                    (p.key.as_str(), p.value.as_str(), version + 1),
                ).await?;
            }
            let status = if approve { "approved" } else { "rejected" };
            c.execute("UPDATE proposals SET status = ? WHERE id = ?", (status, id)).await?;
            record(&c, "owner", if approve { "proposal.approved" } else { "proposal.rejected" }, id).await?;
            operation.complete(&c, serde_json::json!({"ok":true})).await?;
            Ok(())
        }.await;
        finish(c, result).await
    }

    /// Permanently revoke all existing and future sessions for an agent.
    /// Pending proposals from that agent can be rejected but cannot be approved.
    pub async fn revoke_agent(&self, id: &str) -> Result<()> {
        self.revoke_agent_operation(id, None).await
    }
    pub async fn revoke_agent_once(&self, operation_id: &str, id: &str) -> Result<()> {
        self.revoke_agent_operation(id, Some(operation_id)).await
    }
    async fn revoke_agent_operation(&self, id: &str, operation_id: Option<&str>) -> Result<()> {
        validate_key(id)?;
        let operation =
            operations::Request::new(operation_id, "owner", "", "agent.revoked", &[id])?;
        let mut connection = self.store.connection.lock().await;
        let c = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let result = async {
            ensure_owner(&c, self).await?;
            if operation.previous(&c).await?.is_some() {
                return Ok(());
            }
            check_agent(&c, id).await?;
            c.execute("INSERT INTO revoked_agents(agent_id) VALUES (?)", [id])
                .await?;
            record(&c, "owner", "agent.revoked", id).await?;
            operation
                .complete(&c, serde_json::json!({"ok":true}))
                .await?;
            Ok(())
        }
        .await;
        finish(c, result).await
    }

    pub async fn audit(&self) -> Result<Vec<AuditEvent>> {
        let c = self.store.connection.lock().await;
        ensure_owner(&c, self).await?;
        let mut rows = c
            .query(
                "SELECT sequence, actor, action, subject, created_at FROM audit ORDER BY sequence",
                (),
            )
            .await?;
        let mut events = Vec::new();
        while let Some(row) = rows.next().await? {
            events.push(AuditEvent {
                sequence: row.get(0)?,
                actor: row.get(1)?,
                action: row.get(2)?,
                subject: row.get(3)?,
                created_at: row.get(4)?,
            });
        }
        Ok(events)
    }
}

impl AgentSession {
    pub fn id(&self) -> &str {
        &self.agent_id
    }

    pub async fn remember(&self, key: &str, value: &str) -> Result<()> {
        self.remember_operation(key, value, None).await
    }
    pub async fn remember_once(&self, operation_id: &str, key: &str, value: &str) -> Result<()> {
        self.remember_operation(key, value, Some(operation_id))
            .await
    }
    async fn remember_operation(
        &self,
        key: &str,
        value: &str,
        operation_id: Option<&str>,
    ) -> Result<()> {
        validate(key, value)?;
        let operation = operations::Request::new(
            operation_id,
            "agent",
            self.id(),
            "memory.saved",
            &[key, value],
        )?;
        let mut connection = self.store.connection.lock().await;
        let c = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let result = async {
            authorize_agent(&c, self).await?;
            if operation.previous(&c).await?.is_some() { return Ok(()); }
            c.execute(
                "INSERT INTO memories(agent_id, key, value) VALUES (?, ?, ?) ON CONFLICT(agent_id, key) DO UPDATE SET value = excluded.value",
                (self.id(), key, value),
            ).await?;
            memory_quota(&c, self.id()).await?;
            record(&c, self.id(), "memory.saved", key).await?;
            operation.complete(&c, serde_json::json!({"ok":true})).await?;
            Ok(())
        }.await;
        finish(c, result).await
    }

    pub async fn recall(&self, key: &str) -> Result<Option<String>> {
        validate_key(key)?;
        let mut connection = self.store.connection.lock().await;
        let c = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let result = async {
            authorize_agent(&c, self).await?;
            let value = {
                let mut rows = c
                    .query(
                        "SELECT value FROM memories WHERE agent_id = ? AND key = ?",
                        (self.id(), key),
                    )
                    .await?;
                match rows.next().await? {
                    Some(row) => Some(row.get::<String>(0)?),
                    None => None,
                }
            };
            record(&c, self.id(), "memory.recalled", key).await?;
            Ok(value)
        }
        .await;
        finish(c, result).await
    }

    /// All sessions belong to the same shared workspace in milestone one.
    pub async fn read_shared(&self, key: &str) -> Result<Option<SharedValue>> {
        validate_key(key)?;
        let mut connection = self.store.connection.lock().await;
        let c = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let result = async {
            authorize_agent(&c, self).await?;
            shared(&c, key).await
        }
        .await;
        finish(c, result).await
    }

    /// Stage a replacement value against the current shared version.
    pub async fn propose(&self, key: &str, value: &str) -> Result<String> {
        self.propose_operation(key, value, None).await
    }
    pub async fn propose_once(&self, operation_id: &str, key: &str, value: &str) -> Result<String> {
        self.propose_operation(key, value, Some(operation_id)).await
    }
    async fn propose_operation(
        &self,
        key: &str,
        value: &str,
        operation_id: Option<&str>,
    ) -> Result<String> {
        validate(key, value)?;
        let operation = operations::Request::new(
            operation_id,
            "agent",
            self.id(),
            "proposal.created",
            &[key, value],
        )?;
        let id = Uuid::new_v4().to_string();
        let mut connection = self.store.connection.lock().await;
        let c = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let result = async {
            authorize_agent(&c, self).await?;
            if let Some(saved) = operation.previous(&c).await? {
                return saved.get("id").and_then(serde_json::Value::as_str).map(str::to_owned).ok_or(Error::Configuration);
            }
            proposal_quota(&c, self.id()).await?;
            let version = shared(&c, key).await?.map_or(0, |v| v.version);
            c.execute(
                "INSERT INTO proposals(id, agent_id, key, value, base_version, status) VALUES (?, ?, ?, ?, ?, 'pending')",
                (id.as_str(), self.id(), key, value, version),
            ).await?;
            record(&c, self.id(), "proposal.created", &id).await?;
            operation.complete(&c, serde_json::json!({"id":id})).await?;
            Ok(id)
        }.await;
        finish(c, result).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fail_audit(owner: &Owner, enabled: bool) {
        let c = owner.store.connection.lock().await;
        if enabled {
            c.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END", ()).await.unwrap();
        } else {
            c.execute("DROP TRIGGER fail_audit", ()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn review_failure_rolls_back_shared_value_status_and_version() {
        let owner = Owner::open(":memory:").await.unwrap();
        let agent = owner.create_agent().await.unwrap();
        let initial = agent.propose("stock", "10").await.unwrap();
        owner.approve(&initial).await.unwrap();
        let update = agent.propose("stock", "999").await.unwrap();
        let history = owner.audit().await.unwrap();
        fail_audit(&owner, true).await;
        assert!(owner.approve(&update).await.is_err());
        assert!(owner.reject(&update).await.is_err());
        fail_audit(&owner, false).await;
        assert_eq!(owner.inspect(&update).await.unwrap().status, "pending");
        let value = owner.read_shared("stock").await.unwrap().unwrap();
        assert_eq!(value.value, "10");
        assert_eq!(value.version, 1);
        assert_eq!(owner.audit().await.unwrap(), history);
        owner.approve(&update).await.unwrap();
        assert_eq!(
            owner.read_shared("stock").await.unwrap().unwrap().version,
            2
        );
    }

    #[tokio::test]
    async fn proposal_and_revocation_failures_leave_no_unaudited_changes() {
        let owner = Owner::open(":memory:").await.unwrap();
        let agent = owner.create_agent().await.unwrap();
        fail_audit(&owner, true).await;
        assert!(agent.propose("stock", "999").await.is_err());
        assert!(owner.revoke_agent(agent.id()).await.is_err());
        assert!(owner.create_agent().await.is_err());
        fail_audit(&owner, false).await;
        assert!(owner.agent(agent.id()).await.is_ok());
        let c = owner.store.connection.lock().await;
        for (table, expected) in [("proposals", 0_i64), ("agents", 1), ("revoked_agents", 0)] {
            let mut rows = c
                .query(&format!("SELECT COUNT(*) FROM {table}"), ())
                .await
                .unwrap();
            assert_eq!(
                rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn recall_does_not_release_data_if_audit_write_fails() {
        let owner = Owner::open(":memory:").await.unwrap();
        let agent = owner.create_agent().await.unwrap();
        agent.remember("secret", "private").await.unwrap();
        fail_audit(&owner, true).await;
        assert!(agent.recall("secret").await.is_err());
        fail_audit(&owner, false).await;
        assert_eq!(
            agent.recall("secret").await.unwrap().as_deref(),
            Some("private")
        );
    }

    #[tokio::test]
    async fn aborted_task_rolls_back_in_flight_transaction() {
        let owner = Owner::open(":memory:").await.unwrap();
        let agent = owner.create_agent().await.unwrap();
        let store = owner.store.clone();
        let id = agent.id().to_owned();
        let (started, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut c = store.connection.lock().await;
            let tx = c
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .await
                .unwrap();
            tx.execute(
                "INSERT INTO memories(agent_id, key, value) VALUES (?, 'cancelled', 'uncommitted')",
                [id.as_str()],
            )
            .await
            .unwrap();
            record(&tx, &id, "memory.saved", "cancelled").await.unwrap();
            started.send(()).unwrap();
            std::future::pending::<()>().await;
            tx.commit().await.unwrap();
        });
        ready.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(agent.recall("cancelled").await.unwrap(), None);
        assert!(
            !owner
                .audit()
                .await
                .unwrap()
                .iter()
                .any(|e| e.action == "memory.saved" && e.subject == "cancelled")
        );
    }

    #[tokio::test]
    async fn audit_failure_rolls_back_memory_write() {
        let owner = Owner::open(":memory:").await.unwrap();
        let agent = owner.create_agent().await.unwrap();
        {
            let c = owner.store.connection.lock().await;
            c.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END", ()).await.unwrap();
        }
        assert!(agent.remember("secret", "must roll back").await.is_err());
        {
            let c = owner.store.connection.lock().await;
            c.execute("DROP TRIGGER fail_audit", ()).await.unwrap();
        }
        assert_eq!(agent.recall("secret").await.unwrap(), None);
        assert!(
            !owner
                .audit()
                .await
                .unwrap()
                .iter()
                .any(|e| e.action == "memory.saved")
        );
    }

    #[tokio::test]
    async fn dropped_transaction_is_rolled_back_before_next_operation() {
        let owner = Owner::open(":memory:").await.unwrap();
        let agent = owner.create_agent().await.unwrap();
        {
            let mut c = owner.store.connection.lock().await;
            let tx = c
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .await
                .unwrap();
            tx.execute(
                "INSERT INTO memories(agent_id, key, value) VALUES (?, 'abandoned', 'uncommitted')",
                [agent.id()],
            )
            .await
            .unwrap();
            // Dropping a future while inside an operation drops this same guard.
        }
        assert_eq!(agent.recall("abandoned").await.unwrap(), None);
        agent
            .remember("next", "connection remains usable")
            .await
            .unwrap();
    }
}
