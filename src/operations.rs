//! Durable successful-write receipts. No request payloads or bearer secrets.
use super::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(crate) const PER_PRINCIPAL: i64 = 10_000;
pub(crate) const TOTAL: i64 = 100_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OperationReceipt {
    pub status: String,
    pub operation_id: String,
    pub action: String,
    pub result: Value,
    pub created_at: String,
}

pub(crate) fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

pub(crate) async fn lookup(
    c: &Connection,
    role: &str,
    principal: &str,
    id: &str,
) -> Result<Option<OperationReceipt>> {
    let mut rows = c.query("SELECT action, result, created_at FROM operations WHERE role=? AND principal=? AND operation_id=?", (role, principal, id)).await?;
    match rows.next().await? {
        None => Ok(None),
        Some(row) => Ok(Some(OperationReceipt {
            status: "committed".to_owned(),
            operation_id: id.to_owned(),
            action: row.get(0)?,
            result: serde_json::from_str(&row.get::<String>(1)?)
                .map_err(|_| Error::Configuration)?,
            created_at: row.get(2)?,
        })),
    }
}

pub(crate) struct Request<'a> {
    role: &'static str,
    principal: &'a str,
    id: Option<&'a str>,
    action: &'static str,
    fingerprint: String,
}
impl<'a> Request<'a> {
    pub(crate) fn new(
        id: Option<&'a str>,
        role: &'static str,
        principal: &'a str,
        action: &'static str,
        payload: &[&str],
    ) -> Result<Self> {
        if let Some(id) = id {
            validate_id(id)?;
        }
        // A JSON array gives unambiguous boundaries and preserves exact Unicode.
        let encoded = zeroize::Zeroizing::new(
            serde_json::to_vec(&(1u32, action, payload)).map_err(|_| Error::Configuration)?,
        );
        let fingerprint = format!("{:x}", Sha256::digest(&*encoded));
        Ok(Self {
            role,
            principal,
            id,
            action,
            fingerprint,
        })
    }

    // Call only AFTER current authorization succeeds, even on a replay.
    pub(crate) async fn previous(&self, c: &Connection) -> Result<Option<Value>> {
        let Some(id) = self.id else {
            return Ok(None);
        };
        let mut rows = c.query("SELECT action, fingerprint, result FROM operations WHERE role=? AND principal=? AND operation_id=?", (self.role, self.principal, id)).await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        if row.get::<String>(0)? != self.action || row.get::<String>(1)? != self.fingerprint {
            return Err(Error::OperationConflict);
        }
        Ok(Some(
            serde_json::from_str(&row.get::<String>(2)?).map_err(|_| Error::Configuration)?,
        ))
    }

    pub(crate) async fn complete(&self, c: &Connection, result: Value) -> Result<()> {
        let Some(id) = self.id else {
            return Ok(());
        };
        let reserve = if self.role == "owner"
            && matches!(self.action, "agent.revoked" | "credential.revoked")
        {
            let config = limits(c).await?;
            config.agents + config.credentials
        } else {
            0
        };
        let mut rows = c
            .query(
                "SELECT COUNT(*) FROM operations WHERE role=? AND principal=?",
                (self.role, self.principal),
            )
            .await?;
        if rows
            .next()
            .await?
            .ok_or(Error::Configuration)?
            .get::<i64>(0)?
            >= PER_PRINCIPAL + reserve
        {
            return Err(Error::Quota);
        }
        drop(rows);
        if count(c, "SELECT COUNT(*) FROM operations").await? >= TOTAL + reserve {
            return Err(Error::Quota);
        }
        c.execute("INSERT INTO operations(role,principal,operation_id,action,fingerprint,result) VALUES (?,?,?,?,?,?)", (self.role, self.principal, id, self.action, self.fingerprint.as_str(), serde_json::to_string(&result).map_err(|_| Error::Configuration)?.as_str())).await?;
        Ok(())
    }
}

impl Owner {
    /// Only this owner namespace is visible; agent receipts are private.
    pub async fn operation_status(&self, id: &str) -> Result<Option<OperationReceipt>> {
        validate_id(id)?;
        let c = self.store.connection.lock().await;
        ensure_owner(&c, self).await?;
        lookup(&c, "owner", "", id).await
    }
}

impl AgentSession {
    pub async fn operation_status(&self, id: &str) -> Result<Option<OperationReceipt>> {
        validate_id(id)?;
        let mut connection = self.store.connection.lock().await;
        let c = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let result = async {
            authorize_agent(&c, self).await?;
            lookup(&c, "agent", self.id(), id).await
        }
        .await;
        finish(c, result).await
    }
}

// Backup validation must reject receipts that could claim an unsupported result.
pub(crate) async fn validate(c: &Connection) -> Result<()> {
    let config = limits(c).await?;
    let reserve = config.agents + config.credentials;
    if count(c, "SELECT COUNT(*) FROM operations").await? > TOTAL + reserve {
        return Err(Error::InvalidBackup);
    }
    let mut groups = c.query("SELECT COUNT(*) FROM (SELECT role,principal FROM operations GROUP BY role,principal HAVING COUNT(*) > ? + CASE WHEN role='owner' THEN ? ELSE 0 END)", (PER_PRINCIPAL,reserve)).await?;
    if groups
        .next()
        .await?
        .ok_or(Error::InvalidBackup)?
        .get::<i64>(0)?
        != 0
    {
        return Err(Error::InvalidBackup);
    }
    drop(groups);
    // Bounded membership cache; large snapshots never require materializing
    // the complete agents, proposals or operations tables.
    let mut agents = std::collections::HashSet::new();
    let mut rows = crate::streaming::TableRows::new(
        "operations",
        "role,principal,operation_id,action,fingerprint,result,created_at",
    );
    while let Some(row) = rows.next(c).await? {
        let text = |index: usize| {
            row.get(index)
                .and_then(Value::as_str)
                .ok_or(Error::InvalidBackup)
        };
        let role = text(0)?;
        let principal = text(1)?;
        let id = text(2)?;
        let action = text(3)?;
        let hash = text(4)?;
        let encoded = text(5)?;
        validate_id(id).map_err(|_| Error::InvalidBackup)?;
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
            || text(6)?.is_empty()
            || text(6)?.len() > 64
        {
            return Err(Error::InvalidBackup);
        }
        let result: Value = serde_json::from_str(encoded).map_err(|_| Error::InvalidBackup)?;
        let allowed = match (role, action) {
            ("agent", "proposal.created") => {
                if let Some(id) = result.get("id").and_then(Value::as_str).filter(|id| {
                    result.as_object().is_some_and(|o| o.len() == 1)
                        && uuid::Uuid::parse_str(id).is_ok()
                }) {
                    let mut found = c
                        .query(
                            "SELECT COUNT(*) FROM proposals WHERE id=? AND agent_id=?",
                            (id, principal),
                        )
                        .await?;
                    found
                        .next()
                        .await?
                        .ok_or(Error::InvalidBackup)?
                        .get::<i64>(0)?
                        == 1
                } else {
                    false
                }
            }
            ("agent", "memory.saved")
            | (
                "owner",
                "proposal.approved" | "proposal.rejected" | "agent.revoked" | "credential.revoked"
                | "limits.updated",
            ) => result == json!({"ok":true}),
            _ => false,
        };
        if !allowed || (role == "owner" && !principal.is_empty()) {
            return Err(Error::InvalidBackup);
        }
        if role == "agent" && !agents.contains(principal) {
            let mut found = c
                .query("SELECT COUNT(*) FROM agents WHERE id=?", [principal])
                .await?;
            if found
                .next()
                .await?
                .ok_or(Error::InvalidBackup)?
                .get::<i64>(0)?
                != 1
            {
                return Err(Error::InvalidBackup);
            }
            if agents.len() == 4096 {
                agents.clear();
            }
            agents.insert(principal.to_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn receipt_insert_failure_rolls_back_data_audit_and_receipt() {
        let owner = Owner::open(":memory:").await.unwrap();
        let a = owner.create_agent().await.unwrap();
        let before = owner.audit().await.unwrap();
        {
            let c = owner.store.connection.lock().await;
            c.execute("CREATE TRIGGER deny_receipt BEFORE INSERT ON operations BEGIN SELECT RAISE(ABORT,'injected'); END",()).await.unwrap();
        }
        assert!(
            a.remember_once("receipt-fail", "key", "value")
                .await
                .is_err()
        );
        assert_eq!(owner.audit().await.unwrap(), before);
        assert!(a.operation_status("receipt-fail").await.unwrap().is_none());
        {
            let c = owner.store.connection.lock().await;
            c.execute("DROP TRIGGER deny_receipt", ()).await.unwrap();
        }
        assert!(a.recall("key").await.unwrap().is_none());
        a.remember_once("receipt-fail", "key", "value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn expired_owner_and_agent_cannot_read_or_replay_existing_receipts() {
        let owner = Owner::open(":memory:").await.unwrap();
        let (id, token) = owner
            .create_agent_credential(Duration::from_secs(300))
            .await
            .unwrap();
        let agent = match owner.authenticate(token.expose_secret()).await.unwrap() {
            Authenticated::Agent(a) => a,
            _ => panic!(),
        };
        agent
            .remember_once("expired", "key", "value")
            .await
            .unwrap();
        let token = owner
            .issue_owner_credential(Duration::from_secs(300))
            .await
            .unwrap();
        let authenticated = match owner.authenticate(token.expose_secret()).await.unwrap() {
            Authenticated::Owner(a) => a,
            _ => panic!(),
        };
        authenticated
            .update_limits_once("owner-expired", Limits::default())
            .await
            .unwrap();
        owner
            .store
            .connection
            .lock()
            .await
            .execute("UPDATE credentials SET expires_at=0", ())
            .await
            .unwrap();
        assert!(matches!(
            agent.operation_status("expired").await,
            Err(Error::Authentication)
        ));
        assert!(matches!(
            agent.remember_once("expired", "key", "value").await,
            Err(Error::Authentication)
        ));
        assert!(matches!(
            authenticated.operation_status("owner-expired").await,
            Err(Error::Authentication)
        ));
        assert!(matches!(
            authenticated
                .update_limits_once("owner-expired", Limits::default())
                .await,
            Err(Error::Authentication)
        ));
        assert!(owner.agent(&id).await.is_ok());
    }

    async fn fill(owner: &Owner, role: &str, principal: &str) {
        let mut connection = owner.store.connection.lock().await;
        let c = connection.transaction().await.unwrap();
        for round in 0..14 {
            let mut rows = c
                .query(
                    "SELECT COUNT(*) FROM operations WHERE role=? AND principal=?",
                    (role, principal),
                )
                .await
                .unwrap();
            let count = rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap();
            drop(rows);
            if count == PER_PRINCIPAL {
                break;
            }
            c.execute("INSERT INTO operations SELECT role,principal,? || operation_id,action,fingerprint,result,created_at FROM operations WHERE role=? AND principal=? LIMIT ?",(format!("r{round}_").as_str(),role,principal,PER_PRINCIPAL-count)).await.unwrap();
        }
        c.commit().await.unwrap();
    }

    #[tokio::test]
    async fn receipt_capacity_rolls_back_new_writes_but_allows_replays_and_emergency_revocation() {
        let owner = Owner::open(":memory:").await.unwrap();
        let a = owner.create_agent().await.unwrap();
        a.remember_once("seed", "key", "original").await.unwrap();
        fill(&owner, "agent", a.id()).await;
        assert!(matches!(
            a.remember_once("overflow", "key", "bad").await,
            Err(Error::Quota)
        ));
        assert!(a.operation_status("overflow").await.unwrap().is_none());
        a.remember_once("seed", "key", "original").await.unwrap();
        assert_eq!(a.recall("key").await.unwrap().as_deref(), Some("original"));
        owner
            .update_limits_once("seed", Limits::default())
            .await
            .unwrap();
        fill(&owner, "owner", "").await;
        assert!(matches!(
            owner
                .update_limits_once("overflow", Limits::default())
                .await,
            Err(Error::Quota)
        ));
        owner.revoke_agent_once("emergency", a.id()).await.unwrap();
        owner.revoke_agent_once("emergency", a.id()).await.unwrap();
        assert!(owner.operation_status("emergency").await.unwrap().is_some());
        assert!(matches!(
            a.operation_status("seed").await,
            Err(Error::Revoked)
        ));
    }
}
