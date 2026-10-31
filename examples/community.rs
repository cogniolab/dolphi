//! An ephemeral end-to-end demo. Generated keys are not printed or retained.
use dolphi::{Authenticated, EncryptionKey, Error, Limits, Owner};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let database_key = EncryptionKey::generate()?;
    let backup_key = EncryptionKey::generate()?;
    let recovery_key = EncryptionKey::generate()?;
    let source = directory.path().join("community.db");
    let owner = Owner::open_encrypted(
        source.to_str().unwrap(),
        &database_key,
        Some(Limits::default()),
    )
    .await?;
    let embedded_agent = owner.create_agent().await?;
    let credential = owner
        .issue_agent_credential(embedded_agent.id(), Duration::from_secs(300))
        .await?;
    let agent = match owner.authenticate(credential.expose_secret()).await? {
        Authenticated::Agent(value) => value,
        _ => return Err("unexpected credential role".into()),
    };
    agent.remember("task", "Count inventory").await?;
    let proposal = agent.propose("stock", "12 units").await?;
    owner.approve(&proposal).await?;
    println!("PASS: authenticated agent memory and owner-approved changes");
    let backup = directory.path().join("snapshot.mimi");
    owner.backup(&backup, &backup_key).await?;
    owner.revoke_credential(credential.id()).await?;
    assert!(matches!(
        agent.recall("task").await,
        Err(Error::Authentication)
    ));
    let target = directory.path().join("restored.db");
    let restored = Owner::restore(&backup, &backup_key, &target, &recovery_key).await?;
    assert!(matches!(
        restored.authenticate(credential.expose_secret()).await,
        Err(Error::Authentication)
    ));
    let fresh = restored
        .issue_agent_credential(embedded_agent.id(), Duration::from_secs(300))
        .await?;
    let recovered = match restored.authenticate(fresh.expose_secret()).await? {
        Authenticated::Agent(value) => value,
        _ => return Err("unexpected credential role".into()),
    };
    assert_eq!(
        recovered.recall("task").await?.as_deref(),
        Some("Count inventory")
    );
    println!("PASS: encrypted backup/restore with fresh credentials and a new database key");
    println!("Dolphi Community protections ready for local evaluation");
    Ok(())
}
