use dolphi::{Authenticated, EncryptionKey, Owner};
use std::{path::Path, time::Duration};

const HEADER: usize = b"MIMIDB-BACKUP-3\0".len() + 12 + 7 + 48;

fn frames(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut at = HEADER;
    let mut result = Vec::new();
    while at < bytes.len() {
        let size = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        result.push(bytes[at..at + 5 + size].to_vec());
        at += 5 + size;
    }
    result
}

#[tokio::test]
async fn streaming_restores_all_tables_permissions_receipts_and_snapshot_point() {
    let temp = tempfile::tempdir().unwrap();
    let owner = Owner::open(":memory:").await.unwrap();
    let a = owner.create_agent().await.unwrap();
    let b = owner.create_agent().await.unwrap();
    let revoked = owner.create_agent().await.unwrap();
    let credential = owner
        .issue_agent_credential(a.id(), Duration::from_secs(300))
        .await
        .unwrap();
    // Multiple revoked/live credentials exercise normalization without relying
    // on either backend's physical update order.
    let extra = owner
        .issue_agent_credential(a.id(), Duration::from_secs(300))
        .await
        .unwrap();
    owner.revoke_credential(extra.id()).await.unwrap();
    let other_credential = owner
        .issue_agent_credential(b.id(), Duration::from_secs(300))
        .await
        .unwrap();
    for row in 0..19 {
        a.remember_once(
            &format!("op-{row}"),
            &format!("key-{row}"),
            &format!("A{row} É🐬\0"),
        )
        .await
        .unwrap();
        b.remember(&format!("key-{row}"), "private B")
            .await
            .unwrap();
    }
    // Exercise maximum accepted escaped values across multiple source pages.
    let maximum = "\0".repeat(65_536);
    for row in 0..9 {
        b.remember(&format!("max-{row}"), &maximum).await.unwrap();
    }
    let applied = a.propose_once("proposal", "stock", "12").await.unwrap();
    owner.approve_once("approval", &applied).await.unwrap();
    let pending = b.propose("next", "review me").await.unwrap();
    owner.revoke_agent(revoked.id()).await.unwrap();
    let receipt = a.operation_status("op-0").await.unwrap();
    let key = EncryptionKey::generate().unwrap();
    let snapshot = temp.path().join("snapshot.mimi");
    owner.backup_streaming(&snapshot, &key).await.unwrap();
    a.remember("after-snapshot", "not in snapshot")
        .await
        .unwrap();
    let new_key = EncryptionKey::generate().unwrap();
    let (restored, report) =
        Owner::restore_verified(&snapshot, &key, &temp.path().join("restored.db"), &new_key)
            .await
            .unwrap();
    assert_eq!(report.snapshot_version, 3);
    assert_eq!(report.tables.len(), 10);
    assert!(report.verified_before_publication);
    assert!(
        restored
            .authenticate(credential.expose_secret())
            .await
            .is_err()
    );
    assert!(restored.agent(revoked.id()).await.is_err());
    assert!(restored.authenticate(extra.expose_secret()).await.is_err());
    assert!(
        restored
            .authenticate(other_credential.expose_secret())
            .await
            .is_err()
    );
    let fresh = restored
        .issue_agent_credential(a.id(), Duration::from_secs(300))
        .await
        .unwrap();
    let a = match restored.authenticate(fresh.expose_secret()).await.unwrap() {
        Authenticated::Agent(a) => a,
        _ => panic!(),
    };
    let b = restored.agent(b.id()).await.unwrap();
    assert_eq!(
        a.recall("key-0").await.unwrap().as_deref(),
        Some("A0 É🐬\0")
    );
    assert_eq!(
        b.recall("key-0").await.unwrap().as_deref(),
        Some("private B")
    );
    assert_eq!(
        b.recall("max-8").await.unwrap().as_deref(),
        Some(maximum.as_str())
    );
    assert!(a.recall("after-snapshot").await.unwrap().is_none());
    assert_eq!(a.operation_status("op-0").await.unwrap(), receipt);
    let history = restored.audit().await.unwrap();
    a.remember_once("op-0", "key-0", "A0 É🐬\0").await.unwrap();
    restored.approve_once("approval", &applied).await.unwrap();
    assert_eq!(restored.audit().await.unwrap(), history);
    restored.approve(&pending).await.unwrap();
    assert_eq!(
        b.read_shared("next").await.unwrap().unwrap().value,
        "review me"
    );
}

async fn refused(snapshot: &Path, key: &EncryptionKey, target: &Path) {
    assert!(
        Owner::restore(snapshot, key, target, &EncryptionKey::generate().unwrap())
            .await
            .is_err()
    );
    assert!(!target.exists());
    assert!(
        !std::fs::read_dir(target.parent().unwrap())
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".dolphi-restore-"))
    );
}

#[tokio::test]
async fn streaming_authentication_rejects_truncation_reordering_splicing_and_forged_lengths() {
    let temp = tempfile::tempdir().unwrap();
    let owner = Owner::open(":memory:").await.unwrap();
    let a = owner.create_agent().await.unwrap();
    a.remember("sentinel", "private-stream-secret-É🐬")
        .await
        .unwrap();
    let key = EncryptionKey::generate().unwrap();
    let original = temp.path().join("original");
    owner.backup_streaming(&original, &key).await.unwrap();
    let bytes = std::fs::read(&original).unwrap();
    assert!(
        !bytes
            .windows(b"private-stream-secret".len())
            .any(|w| w == b"private-stream-secret")
    );
    let second = temp.path().join("second");
    owner.backup_streaming(&second, &key).await.unwrap();
    let other = std::fs::read(second).unwrap();
    assert_ne!(bytes, other);
    let pieces = frames(&bytes);
    let mut damaged = Vec::new();
    for end in [0, HEADER - 1, HEADER + 5, bytes.len() / 2, bytes.len() - 1] {
        damaged.push(bytes[..end].to_vec());
    }
    for position in [0, 18, HEADER - 1, HEADER + 7, bytes.len() - 2] {
        let mut changed = bytes.clone();
        changed[position] ^= 0x80;
        damaged.push(changed);
    }
    let assemble = |parts: &[Vec<u8>]| [bytes[..HEADER].to_vec(), parts.concat()].concat();
    let mut reordered = pieces.clone();
    reordered.swap(2, 3);
    damaged.push(assemble(&reordered));
    let mut repeated = pieces.clone();
    repeated.insert(3, pieces[2].clone());
    damaged.push(assemble(&repeated));
    let mut missing = pieces.clone();
    missing.remove(3);
    damaged.push(assemble(&missing));
    let mut splice = pieces.clone();
    splice[2] = frames(&other)[2].clone();
    damaged.push(assemble(&splice));
    let mut appended = bytes.clone();
    appended.push(0);
    damaged.push(appended);
    let mut length = bytes.clone();
    length[HEADER..HEADER + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    damaged.push(length);
    let mut final_flag = bytes.clone();
    final_flag[HEADER + 4] = 1;
    damaged.push(final_flag);
    for (case, data) in damaged.into_iter().enumerate() {
        let source = temp.path().join(format!("damaged-{case}"));
        std::fs::write(&source, data).unwrap();
        refused(
            &source,
            &key,
            &temp.path().join(format!("target-{case}.db")),
        )
        .await;
    }
    refused(
        &original,
        &EncryptionKey::generate().unwrap(),
        &temp.path().join("wrong.db"),
    )
    .await;
    let target = temp.path().join("existing");
    std::fs::write(&target, b"keep").unwrap();
    assert!(
        Owner::restore(&original, &key, &target, &key)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    assert!(owner.backup_streaming(&original, &key).await.is_err());
    assert_eq!(std::fs::read(&original).unwrap(), bytes);
}
