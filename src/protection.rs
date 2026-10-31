use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Persisted logical quotas. Limits are not filesystem byte or CPU guarantees.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub agents: i64,
    pub memories_per_agent: i64,
    pub memory_bytes_per_agent: i64,
    pub proposals_per_agent: i64,
    pub audit_events: i64,
    pub credentials: i64,
    pub requests_per_minute: i64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            agents: 1000,
            memories_per_agent: 1000,
            memory_bytes_per_agent: 4 * 1024 * 1024,
            proposals_per_agent: 1000,
            audit_events: 1_000_000,
            credentials: 10_000,
            requests_per_minute: 6000,
        }
    }
}

impl Limits {
    pub(crate) fn validate(&self) -> Result<()> {
        if [
            self.agents,
            self.memories_per_agent,
            self.memory_bytes_per_agent,
            self.proposals_per_agent,
            self.audit_events,
            self.credentials,
            self.requests_per_minute,
        ]
        .iter()
        .any(|n| *n <= 0 || *n > 1_000_000_000)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

/// A random 256-bit key, supplied by trusted application key management.
/// Deliberately has no Debug/Display implementation and is zeroized on drop.
pub struct EncryptionKey(Zeroizing<[u8; 32]>);

impl EncryptionKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn generate() -> Result<Self> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Configuration)?;
        Ok(Self::from_bytes(bytes))
    }
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub(crate) fn hex(&self) -> Zeroizing<String> {
        Zeroizing::new(self.0.iter().map(|b| format!("{b:02x}")).collect())
    }
}

/// Secret is returned only at issuance. Persist the secret separately from DB.
pub struct Credential {
    secret: Zeroizing<String>,
    id: String,
}

impl Credential {
    pub fn expose_secret(&self) -> &str {
        &self.secret
    }
    pub fn id(&self) -> &str {
        &self.id
    }
}

pub enum Authenticated {
    Owner(Owner),
    Agent(AgentSession),
}

pub(crate) fn now() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Configuration)?
        .as_secs()
        .try_into()
        .map_err(|_| Error::Configuration)
}

fn digest(secret: &str) -> Result<String> {
    if secret.len() != 64 || !secret.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Authentication);
    }
    Ok(format!("{:x}", Sha256::digest(secret.as_bytes())))
}

pub(crate) async fn limits(c: &Connection) -> Result<Limits> {
    let mut rows = c
        .query("SELECT value FROM settings WHERE id = 1", ())
        .await?;
    let row = rows.next().await?.ok_or(Error::Configuration)?;
    let result: Limits =
        serde_json::from_str(&row.get::<String>(0)?).map_err(|_| Error::Configuration)?;
    result.validate()?;
    Ok(result)
}

pub(crate) async fn count(c: &Connection, sql: &str) -> Result<i64> {
    let mut rows = c.query(sql, ()).await?;
    Ok(rows.next().await?.ok_or(Error::Configuration)?.get(0)?)
}

pub(crate) fn prepare_encrypted_path(path: &str) -> Result<()> {
    if path == ":memory:" {
        return Ok(());
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(Error::Configuration)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(path)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) async fn ensure_credential(
    c: &Connection,
    credential: &Option<String>,
    role: &str,
    agent: &str,
) -> Result<()> {
    let Some(id) = credential else {
        return Ok(());
    }; // Trusted embedded capability.
    let mut rows = c.query("SELECT digest FROM credentials WHERE digest = ? AND role = ? AND agent_id = ? AND expires_at > ? AND revoked = 0", (id.as_str(), role, agent, now()?)).await?;
    if rows.next().await?.is_none() {
        return Err(Error::Authentication);
    }
    Ok(())
}

pub(crate) async fn ensure_owner(c: &Connection, owner: &Owner) -> Result<()> {
    ensure_credential(c, &owner.credential, "owner", "").await
}

pub(crate) async fn authorize_agent(c: &Connection, session: &AgentSession) -> Result<()> {
    ensure_credential(c, &session.credential, "agent", session.id()).await?;
    check_agent(c, session.id()).await?;
    let window = now()? / 60;
    let limit = limits(c).await?.requests_per_minute;
    c.execute("INSERT INTO request_windows(agent_id, window, requests) VALUES (?, ?, 1) ON CONFLICT(agent_id) DO UPDATE SET requests = CASE WHEN window = excluded.window THEN requests + 1 ELSE 1 END, window = excluded.window", (session.id(), window)).await?;
    let mut rows = c
        .query(
            "SELECT requests FROM request_windows WHERE agent_id = ?",
            [session.id()],
        )
        .await?;
    if rows
        .next()
        .await?
        .ok_or(Error::Configuration)?
        .get::<i64>(0)?
        > limit
    {
        return Err(Error::Quota);
    }
    Ok(())
}

pub(crate) async fn memory_quota(c: &Connection, agent: &str) -> Result<()> {
    let limit = limits(c).await?;
    let mut rows = c.query("SELECT COUNT(*), COALESCE(SUM(length(CAST(key AS BLOB)) + length(CAST(value AS BLOB))), 0) FROM memories WHERE agent_id = ?", [agent]).await?;
    let row = rows.next().await?.ok_or(Error::Configuration)?;
    if row.get::<i64>(0)? > limit.memories_per_agent
        || row.get::<i64>(1)? > limit.memory_bytes_per_agent
    {
        return Err(Error::Quota);
    }
    Ok(())
}

pub(crate) async fn proposal_quota(c: &Connection, agent: &str) -> Result<()> {
    let mut rows = c
        .query("SELECT COUNT(*) FROM proposals WHERE agent_id = ?", [agent])
        .await?;
    if rows
        .next()
        .await?
        .ok_or(Error::Configuration)?
        .get::<i64>(0)?
        >= limits(c).await?.proposals_per_agent
    {
        return Err(Error::Quota);
    }
    Ok(())
}

impl Owner {
    /// Create an identity and its initial credential in one transaction.
    pub async fn create_agent_credential(&self, ttl: Duration) -> Result<(String, Credential)> {
        if ttl.as_secs() == 0 || ttl.as_secs() > 30 * 86400 {
            return Err(Error::Configuration);
        }
        let expires = now()?
            .checked_add(ttl.as_secs() as i64)
            .ok_or(Error::Configuration)?;
        let agent = Uuid::new_v4().to_string();
        let secret = EncryptionKey::generate()?.hex();
        let id = digest(&secret)?;
        let mut connection = self.store.connection.lock().await;
        let c = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let result = async {
            ensure_owner(&c, self).await?;
            let config = limits(&c).await?;
            if count(&c, "SELECT COUNT(*) FROM agents").await? >= config.agents || count(&c, "SELECT COUNT(*) FROM credentials").await? >= config.credentials { return Err(Error::Quota); }
            c.execute("INSERT INTO agents(id) VALUES (?)", [agent.as_str()]).await?;
            c.execute("INSERT INTO credentials(digest, role, agent_id, expires_at) VALUES (?, 'agent', ?, ?)", (id.as_str(), agent.as_str(), expires)).await?;
            record(&c, "owner", "agent.created", &agent).await?;
            record(&c, "owner", "credential.issued", &id).await?;
            Ok(())
        }.await;
        finish(c, result).await?;
        Ok((agent, Credential { secret, id }))
    }

    /// Bounded administrative audit access for network adapters.
    pub async fn audit_page(&self, after: i64, limit: u32) -> Result<Vec<AuditEvent>> {
        if after < 0 || !(1..=1000).contains(&limit) {
            return Err(Error::InvalidInput);
        }
        let c = self.store.connection.lock().await;
        ensure_owner(&c, self).await?;
        let mut rows = c.query("SELECT sequence, actor, action, subject, created_at FROM audit WHERE sequence > ? ORDER BY sequence LIMIT ?", (after, i64::from(limit))).await?;
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

    /// Open with persisted quotas. Passing different quotas on reopen fails.
    pub async fn open_with_limits(path: &str, limits: Limits) -> Result<Self> {
        Self::open_configured(path, None, Some(limits)).await
    }

    /// Page encryption uses the selected backend: experimental AES-256-GCM on
    /// Turso, or SQLCipher 4.20 Community on the opt-in sqlcipher-backend profile.
    /// There is no fallback to plaintext or in-place plaintext conversion.
    pub async fn open_encrypted(
        path: &str,
        key: &EncryptionKey,
        limits: Option<Limits>,
    ) -> Result<Self> {
        Self::open_configured(path, Some(key), limits).await
    }

    pub async fn limits(&self) -> Result<Limits> {
        let c = self.store.connection.lock().await;
        ensure_owner(&c, self).await?;
        limits(&c).await
    }

    /// Explicit audited quota changes. Reopening with a different configuration
    /// is rejected; use this owner operation to change persisted policy.
    pub async fn update_limits(&self, requested: Limits) -> Result<()> {
        self.update_limits_operation(requested, None).await
    }
    pub async fn update_limits_once(&self, operation_id: &str, requested: Limits) -> Result<()> {
        self.update_limits_operation(requested, Some(operation_id))
            .await
    }
    async fn update_limits_operation(
        &self,
        requested: Limits,
        operation_id: Option<&str>,
    ) -> Result<()> {
        requested.validate()?;
        let encoded = serde_json::to_string(&requested).map_err(|_| Error::Configuration)?;
        let operation =
            operations::Request::new(operation_id, "owner", "", "limits.updated", &[&encoded])?;
        let mut connection = self.store.connection.lock().await;
        let c = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let result = async {
            ensure_owner(&c, self).await?;
            if operation.previous(&c).await?.is_some() {
                return Ok(());
            }
            c.execute(
                "UPDATE settings SET value = ? WHERE id = 1",
                [serde_json::to_string(&requested).map_err(|_| Error::Configuration)?],
            )
            .await?;
            super::recovery::validate_snapshot(&c)
                .await
                .map_err(|_| Error::Configuration)?;
            record(&c, "owner", "limits.updated", "limits").await?;
            operation
                .complete(&c, serde_json::json!({"ok":true}))
                .await?;
            Ok(())
        }
        .await;
        finish(c, result).await
    }

    pub async fn issue_agent_credential(&self, agent: &str, ttl: Duration) -> Result<Credential> {
        validate_key(agent)?;
        self.issue_credential("agent", agent, ttl).await
    }

    pub async fn issue_owner_credential(&self, ttl: Duration) -> Result<Credential> {
        self.issue_credential("owner", "", ttl).await
    }

    async fn issue_credential(&self, role: &str, agent: &str, ttl: Duration) -> Result<Credential> {
        if ttl.as_secs() == 0 || ttl.as_secs() > 30 * 86400 {
            return Err(Error::Configuration);
        }
        let expires = now()?
            .checked_add(ttl.as_secs() as i64)
            .ok_or(Error::Configuration)?;
        let random = EncryptionKey::generate()?;
        let secret = random.hex();
        let id = digest(&secret)?;
        let mut connection = self.store.connection.lock().await;
        let c = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let result = async {
            ensure_owner(&c, self).await?;
            if role == "agent" {
                check_agent(&c, agent).await?;
            }
            if count(&c, "SELECT COUNT(*) FROM credentials").await? >= limits(&c).await?.credentials
            {
                return Err(Error::Quota);
            }
            c.execute(
                "INSERT INTO credentials(digest, role, agent_id, expires_at) VALUES (?, ?, ?, ?)",
                (id.as_str(), role, agent, expires),
            )
            .await?;
            record(&c, "owner", "credential.issued", &id).await?;
            Ok(())
        }
        .await;
        finish(c, result).await?;
        Ok(Credential { secret, id })
    }

    /// Only a trusted adapter should retain the bootstrap Owner and call this.
    /// No raw credentials are stored or logged; errors do not reveal identities.
    pub async fn authenticate(&self, secret: &str) -> Result<Authenticated> {
        let id = digest(secret)?;
        let c = self.store.connection.lock().await;
        ensure_owner(&c, self).await?;
        let (role, agent) = {
            let mut rows = c.query("SELECT role, agent_id FROM credentials WHERE digest = ? AND expires_at > ? AND revoked = 0", (id.as_str(), now()?)).await?;
            let row = rows.next().await?.ok_or(Error::Authentication)?;
            (row.get::<String>(0)?, row.get::<String>(1)?)
        };
        match role.as_str() {
            "owner" => Ok(Authenticated::Owner(Owner {
                store: self.store.clone(),
                credential: Some(id),
            })),
            "agent" => {
                check_agent(&c, &agent)
                    .await
                    .map_err(|_| Error::Authentication)?;
                Ok(Authenticated::Agent(AgentSession {
                    store: self.store.clone(),
                    agent_id: agent,
                    credential: Some(id),
                }))
            }
            _ => Err(Error::Authentication),
        }
    }

    pub async fn revoke_credential(&self, id: &str) -> Result<()> {
        self.revoke_credential_operation(id, None).await
    }
    pub async fn revoke_credential_once(&self, operation_id: &str, id: &str) -> Result<()> {
        self.revoke_credential_operation(id, Some(operation_id))
            .await
    }
    async fn revoke_credential_operation(
        &self,
        id: &str,
        operation_id: Option<&str>,
    ) -> Result<()> {
        validate_key(id)?;
        let operation =
            operations::Request::new(operation_id, "owner", "", "credential.revoked", &[id])?;
        let mut connection = self.store.connection.lock().await;
        let c = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let result = async {
            ensure_owner(&c, self).await?;
            if operation.previous(&c).await?.is_some() {
                return Ok(());
            }
            if c.execute(
                "UPDATE credentials SET revoked = 1 WHERE digest = ? AND revoked = 0",
                [id],
            )
            .await?
                != 0
            {
                record(&c, "owner", "credential.revoked", id).await?;
            }
            operation
                .complete(&c, serde_json::json!({"ok":true}))
                .await?;
            Ok(())
        }
        .await;
        finish(c, result).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expired_credentials_fail_on_previously_authenticated_handles() {
        let owner = Owner::open(":memory:").await.unwrap();
        let agent = owner.create_agent().await.unwrap();
        let token = owner
            .issue_agent_credential(agent.id(), Duration::from_secs(60))
            .await
            .unwrap();
        let authenticated = match owner.authenticate(token.expose_secret()).await.unwrap() {
            Authenticated::Agent(value) => value,
            _ => panic!("wrong role"),
        };
        let owner_token = owner
            .issue_owner_credential(Duration::from_secs(60))
            .await
            .unwrap();
        let authenticated_owner = match owner
            .authenticate(owner_token.expose_secret())
            .await
            .unwrap()
        {
            Authenticated::Owner(value) => value,
            _ => panic!("wrong role"),
        };
        {
            let c = owner.store.connection.lock().await;
            c.execute("UPDATE credentials SET expires_at = 0", ())
                .await
                .unwrap();
        }
        assert!(matches!(
            owner.authenticate(token.expose_secret()).await,
            Err(Error::Authentication)
        ));
        assert!(matches!(
            authenticated.remember("x", "y").await,
            Err(Error::Authentication)
        ));
        assert!(matches!(
            authenticated.recall("x").await,
            Err(Error::Authentication)
        ));
        assert!(matches!(
            authenticated.propose("x", "y").await,
            Err(Error::Authentication)
        ));
        assert!(matches!(
            authenticated.read_shared("x").await,
            Err(Error::Authentication)
        ));
        assert!(matches!(
            authenticated_owner.create_agent().await,
            Err(Error::Authentication)
        ));
    }

    #[tokio::test]
    async fn rate_window_rollover_and_reopen_preserve_enforcement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rate.db");
        let path = path.to_str().unwrap();
        let owner = Owner::open_with_limits(
            path,
            Limits {
                requests_per_minute: 1,
                ..Limits::default()
            },
        )
        .await
        .unwrap();
        let agent = owner.create_agent().await.unwrap();
        agent.remember("key", "value").await.unwrap();
        {
            let c = owner.store.connection.lock().await;
            c.execute(
                "UPDATE request_windows SET window = ?",
                [now().unwrap() / 60 - 1],
            )
            .await
            .unwrap();
        }
        assert_eq!(agent.recall("key").await.unwrap().as_deref(), Some("value"));
        let id = agent.id().to_owned();
        drop(agent);
        drop(owner);
        let reopened = Owner::open(path).await.unwrap();
        let agent = reopened.agent(&id).await.unwrap();
        assert!(matches!(agent.read_shared("x").await, Err(Error::Quota)));
    }

    #[tokio::test]
    async fn only_token_hash_is_stored_and_logging_never_receives_the_secret() {
        let owner = Owner::open(":memory:").await.unwrap();
        let token = owner
            .issue_owner_credential(Duration::from_secs(60))
            .await
            .unwrap();
        let c = owner.store.connection.lock().await;
        let mut rows = c.query("SELECT digest FROM credentials", ()).await.unwrap();
        let stored = rows
            .next()
            .await
            .unwrap()
            .unwrap()
            .get::<String>(0)
            .unwrap();
        assert_ne!(stored, token.expose_secret());
        assert_eq!(stored, token.id());
        drop(rows);
        drop(c);
        for event in owner.audit().await.unwrap() {
            assert!(!format!("{event:?}").contains(token.expose_secret()));
        }
    }
}
