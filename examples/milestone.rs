use dolphi::{Error, Owner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "data/milestone.db".into());
    if let Some(parent) = std::path::Path::new(&path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let owner = Owner::open(&path).await?;
    let inventory = owner.create_agent().await?;
    let assistant = owner.create_agent().await?;
    inventory.remember("task", "Count inventory").await?;
    assistant.remember("task", "Prepare owner summary").await?;
    inventory
        .remember("private-note", "Supplier conversation")
        .await?;
    assert_eq!(assistant.recall("private-note").await?, None);
    println!("PASS: agents have isolated persistent memory");
    let change = inventory.propose("stock", "12 units").await?;
    let competing = assistant.propose("stock", "18 units").await?;
    println!("Owner review: {:?}", owner.inspect(&change).await?);
    owner.approve(&change).await?;
    assert!(matches!(
        owner.approve(&competing).await,
        Err(Error::Conflict)
    ));
    owner.reject(&competing).await?;
    println!("PASS: approved change applied; stale change blocked and rejected");
    let agent_id = inventory.id().to_owned();
    drop(inventory);
    drop(assistant);
    drop(owner);
    let reopened = Owner::open(&path).await?;
    assert_eq!(
        reopened
            .agent(&agent_id)
            .await?
            .recall("task")
            .await?
            .as_deref(),
        Some("Count inventory")
    );
    println!("PASS: memory survives database reopen");
    for event in reopened.audit().await? {
        println!("{event:?}");
    }
    println!("Dolphi milestone 1 ready");
    Ok(())
}
