use dolphi::{EncryptionKey, Owner};

#[tokio::test]
async fn encrypted_header_page_corruption_and_truncation_fail_closed() {
    let temporary = tempfile::tempdir().unwrap();
    let backup = temporary.path().join("snapshot");
    let source = Owner::open(":memory:").await.unwrap();
    let agent = source.create_agent().await.unwrap();
    agent
        .remember("secret", "qualification-sentinel")
        .await
        .unwrap();
    let key = EncryptionKey::generate().unwrap();
    source.backup(&backup, &key).await.unwrap();
    let baseline = temporary.path().join("checkpointed.db");
    let restored = Owner::restore(&backup, &key, &baseline, &key)
        .await
        .unwrap();
    drop(restored);
    let bytes = std::fs::read(&baseline).unwrap();
    assert!(bytes.len() >= 4096);
    for (name, damaged) in [
        ("header", {
            let mut data = bytes.clone();
            data[0] ^= 0x80;
            data
        }),
        ("page", {
            let mut data = bytes.clone();
            data[256] ^= 0x80;
            data
        }),
        ("truncated", bytes[..128].to_vec()),
    ] {
        let path = temporary.path().join(format!("{name}.db"));
        std::fs::write(&path, damaged).unwrap();
        assert!(
            Owner::open_encrypted(path.to_str().unwrap(), &key, None)
                .await
                .is_err(),
            "corrupted {name} opened successfully"
        );
    }
    assert_eq!(std::fs::read(&baseline).unwrap(), bytes);
    let restored = Owner::open_encrypted(baseline.to_str().unwrap(), &key, None)
        .await
        .unwrap();
    assert_eq!(
        restored
            .agent(agent.id())
            .await
            .unwrap()
            .recall("secret")
            .await
            .unwrap()
            .as_deref(),
        Some("qualification-sentinel")
    );
}

#[tokio::test]
async fn backup_filesystem_errors_preserve_live_data_and_existing_destinations() {
    let temporary = tempfile::tempdir().unwrap();
    let owner = Owner::open(":memory:").await.unwrap();
    let agent = owner.create_agent().await.unwrap();
    agent.remember("secret", "original").await.unwrap();
    let key = EncryptionKey::generate().unwrap();
    let before = owner.audit().await.unwrap();
    let missing = temporary.path().join("missing-parent/backup");
    assert!(owner.backup(&missing, &key).await.is_err());
    assert!(!missing.exists());
    assert!(owner.backup(temporary.path(), &key).await.is_err());
    let existing = temporary.path().join("existing");
    std::fs::write(&existing, "preserve-me").unwrap();
    assert!(owner.backup(&existing, &key).await.is_err());
    assert_eq!(std::fs::read_to_string(existing).unwrap(), "preserve-me");
    assert_eq!(owner.audit().await.unwrap(), before);
    assert_eq!(
        agent.recall("secret").await.unwrap().as_deref(),
        Some("original")
    );
}

#[tokio::test]
async fn restore_under_new_database_key_rejects_old_key_after_reopen() {
    let temporary = tempfile::tempdir().unwrap();
    let old_key = EncryptionKey::generate().unwrap();
    let backup_key = EncryptionKey::generate().unwrap();
    let new_key = EncryptionKey::generate().unwrap();
    let source_path = temporary.path().join("source.db");
    let source = Owner::open_encrypted(source_path.to_str().unwrap(), &old_key, None)
        .await
        .unwrap();
    let agent = source.create_agent().await.unwrap();
    agent.remember("key", "rotated").await.unwrap();
    let backup = temporary.path().join("backup");
    source.backup(&backup, &backup_key).await.unwrap();
    let target = temporary.path().join("new.db");
    drop(
        Owner::restore(&backup, &backup_key, &target, &new_key)
            .await
            .unwrap(),
    );
    assert!(
        Owner::open_encrypted(target.to_str().unwrap(), &old_key, None)
            .await
            .is_err()
    );
    let rotated = Owner::open_encrypted(target.to_str().unwrap(), &new_key, None)
        .await
        .unwrap();
    assert_eq!(
        rotated
            .agent(agent.id())
            .await
            .unwrap()
            .recall("key")
            .await
            .unwrap()
            .as_deref(),
        Some("rotated")
    );
}
