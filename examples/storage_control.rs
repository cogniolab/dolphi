//! Qualification-only controls for synthetic temporary databases.
#[cfg(feature = "sqlcipher-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use dolphi::{EncryptionKey, Owner};
    use std::{path::Path, time::Instant};
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: storage_control check|checkpoint|recovery-benchmark|recovery-benchmark-large DB KEY".into());
    }
    let path = Path::new(&args[2]);
    let canonical = path.parent().ok_or("missing parent")?.canonicalize()?;
    if !canonical
        .to_string_lossy()
        .starts_with("/tmp/dolphi-storage-")
    {
        return Err("qualification requires its synthetic /tmp root".into());
    }
    let bytes = zeroize::Zeroizing::new(std::fs::read(&args[3])?);
    let key: [u8; 32] = bytes.as_slice().try_into()?;
    match args[1].as_str() {
        "check" | "checkpoint" => {
            let db = sqlcipher_engine::open(path, &key)?;
            if args[1] == "checkpoint" {
                let row: (i64, i64, i64) =
                    db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                    })?;
                if row.0 != 0 {
                    return Err("checkpoint busy".into());
                }
            }
            let result: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
            if result != "ok" {
                return Err("structural integrity failed".into());
            }
            let errors: Vec<String> = db
                .prepare("PRAGMA cipher_integrity_check")?
                .query_map([], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            if !errors.is_empty() {
                return Err("page authentication failed".into());
            }
            let mut counts = serde_json::Map::new();
            for table in [
                "agents",
                "revoked_agents",
                "credentials",
                "settings",
                "request_windows",
                "memories",
                "shared",
                "proposals",
                "audit",
                "operations",
            ] {
                let count: i64 =
                    db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
                counts.insert(table.to_owned(), count.into());
            }
            let candidate_memories: i64 = db.query_row(
                "SELECT count(*) FROM memories WHERE key='candidate'",
                [],
                |r| r.get(0),
            )?;
            let candidate_proposals: i64 = db.query_row(
                "SELECT count(*) FROM proposals WHERE key='candidate'",
                [],
                |r| r.get(0),
            )?;
            println!(
                "{}",
                serde_json::json!({"structural_integrity":"ok","page_authentication":"ok","counts":counts,"candidate_memories":candidate_memories,"candidate_proposals":candidate_proposals})
            );
        }
        "recovery-benchmark" | "recovery-benchmark-large" => {
            let large = args[1] == "recovery-benchmark-large";
            let agents = if large { 16 } else { 8 };
            let owner =
                Owner::open_encrypted(&args[2], &EncryptionKey::from_bytes(key), None).await?;
            let seed = Instant::now();
            let mut ids = Vec::new();
            let value = "synthetic qualification data ".repeat(if large { 211 } else { 147 });
            for _ in 0..agents {
                let agent = owner.create_agent().await?;
                ids.push(agent.id().to_owned());
                for row in 0..512 {
                    agent
                        .remember_once(&format!("op-{row}"), &format!("row-{row}"), &value)
                        .await?;
                }
            }
            let seed_ms = seed.elapsed().as_millis();
            let backup_key = EncryptionKey::generate()?;
            let new_key = EncryptionKey::generate()?;
            let backup = canonical.join("benchmark.mimi");
            let target = canonical.join("recovered.db");
            let now = Instant::now();
            owner.backup(&backup, &backup_key).await?;
            let backup_ms = now.elapsed().as_millis();
            let now = Instant::now();
            let (restored, report) =
                Owner::restore_verified(&backup, &backup_key, &target, &new_key).await?;
            for id in &ids {
                let agent = restored.agent(id).await?;
                for row in [0, 127, 511] {
                    if agent.recall(&format!("row-{row}")).await?.as_deref() != Some(&value) {
                        return Err("recovery sample differs".into());
                    }
                    agent
                        .remember_once(&format!("op-{row}"), &format!("row-{row}"), &value)
                        .await?;
                }
            }
            let restore_ms = now.elapsed().as_millis();
            if large {
                // Cross the logical snapshot limit while keeping each agent
                // below its normal memory quota. Refusal must leave no file.
                let extra = "X".repeat(4000);
                for id in &ids {
                    let agent = owner.agent(id).await?;
                    // Leave this query below the adapter's 64 MiB bound;
                    // receipts/audit push the total snapshot over its limit.
                    for row in 0..224 {
                        agent.remember(&format!("extra-{row}"), &extra).await?;
                    }
                }
                let oversized = canonical.join("over-limit.mimi");
                if !matches!(
                    owner.backup(&oversized, &backup_key).await,
                    Err(dolphi::Error::Quota)
                ) || oversized.exists()
                {
                    return Err("oversized backup was not safely refused".into());
                }
                for id in &ids {
                    if owner.agent(id).await?.recall("extra-223").await?.as_deref() != Some(&extra)
                    {
                        return Err("oversized backup changed source data".into());
                    }
                }
            }
            println!(
                "{}",
                serde_json::json!({"rows":agents*512,"logical_value_bytes":value.len()*agents*512,"seed_ms":seed_ms,"backup_ms":backup_ms,"restore_verify_sample_ms":restore_ms,"encrypted_backup_bytes":std::fs::metadata(backup)?.len(),"tables_verified":report.tables.len(),"recovery_samples_match":true,"durable_receipts_replayed":true,"oversize_case_exercised":large,"oversize_rejected_without_publication":large})
            );
        }
        _ => return Err("unknown qualification control".into()),
    }
    Ok(())
}

#[cfg(not(feature = "sqlcipher-backend"))]
fn main() {
    eprintln!("storage_control requires the encrypted backend");
}
