//! Synthetic >64 MiB recovery drill. No actual installation is opened.
use dolphi::{EncryptionKey, Owner};
use std::{path::Path, time::Instant};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: streaming_qualification seed|check DB KEY".into());
    }
    let path = Path::new(&args[2]);
    if !path
        .parent()
        .ok_or("parent missing")?
        .canonicalize()?
        .to_string_lossy()
        .starts_with("/tmp/dolphi-operations-")
    {
        return Err("synthetic qualification directory required".into());
    }
    let key = zeroize::Zeroizing::new(std::fs::read(&args[3])?);
    let key: [u8; 32] = key.as_slice().try_into()?;
    let owner = Owner::open_encrypted(&args[2], &EncryptionKey::from_bytes(key), None).await?;
    let value = "synthetic streaming backup value ".repeat(245);
    let begin = Instant::now();
    if args[1] == "seed" {
        let mut ids = Vec::new();
        for _ in 0..32 {
            let agent = owner.create_agent().await?;
            ids.push(agent.id().to_owned());
            for row in 0..512 {
                agent
                    .remember_once(&format!("op-{row}"), &format!("row-{row}"), &value)
                    .await?;
            }
        }
        let manifest =
            serde_json::json!({"agents":ids,"rows":16384,"logical_value_bytes":value.len()*16384});
        let bytes = serde_json::to_vec(&manifest)?;
        std::fs::write(path.parent().unwrap().join("oracle.json"), bytes)?;
        println!(
            "{}",
            serde_json::json!({"rows":16384,"logical_value_bytes":value.len()*16384,"seed_ms":begin.elapsed().as_millis()})
        );
    } else if args[1] == "check" {
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path.parent().unwrap().join("oracle.json"))?)?;
        for id in manifest["agents"].as_array().ok_or("oracle missing")? {
            let agent = owner.agent(id.as_str().ok_or("agent invalid")?).await?;
            for row in [0, 127, 511] {
                if agent.recall(&format!("row-{row}")).await?.as_deref() != Some(&value) {
                    return Err("sample mismatch".into());
                }
                agent
                    .remember_once(&format!("op-{row}"), &format!("row-{row}"), &value)
                    .await?;
            }
        }
        println!(
            "{}",
            serde_json::json!({"sampled_memories_and_replayed_receipts":96,"passed":true})
        );
    } else {
        return Err("unknown qualification mode".into());
    }
    Ok(())
}
