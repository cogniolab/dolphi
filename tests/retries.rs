use dolphi::{Authenticated, EncryptionKey, Error, Limits, Owner};
use std::{collections::HashSet, time::Duration};

#[tokio::test]
async fn concurrent_duplicate_proposals_have_one_result_and_one_audit_event() {
    let owner = Owner::open(":memory:").await.unwrap();
    let agent = owner.create_agent().await.unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let agent = agent.clone();
        tasks.spawn(async move { agent.propose_once("job-1", "stock", "12").await.unwrap() });
    }
    let mut ids = HashSet::new();
    while let Some(result) = tasks.join_next().await {
        ids.insert(result.unwrap());
    }
    assert_eq!(ids.len(), 1);
    assert_eq!(
        owner
            .audit()
            .await
            .unwrap()
            .iter()
            .filter(|e| e.action == "proposal.created")
            .count(),
        1
    );
    let status = agent.operation_status("job-1").await.unwrap().unwrap();
    assert_eq!(status.status, "committed");
    assert_eq!(status.result["id"], ids.into_iter().next().unwrap());
}

#[tokio::test]
async fn concurrent_changed_input_has_one_winner_and_no_extra_effect() {
    let owner = Owner::open(":memory:").await.unwrap();
    let a = owner.create_agent().await.unwrap();
    let b = a.clone();
    let (one, two) = tokio::join!(
        a.remember_once("race", "key", "one"),
        b.remember_once("race", "key", "two")
    );
    assert!(matches!(
        (&one, &two),
        (Ok(()), Err(Error::OperationConflict)) | (Err(Error::OperationConflict), Ok(()))
    ));
    assert_eq!(
        a.recall("key").await.unwrap().unwrap(),
        if one.is_ok() { "one" } else { "two" }
    );
    assert!(matches!(
        a.propose_once("race", "key", "one").await,
        Err(Error::OperationConflict)
    ));
    assert_eq!(
        owner
            .audit()
            .await
            .unwrap()
            .iter()
            .filter(|e| e.action == "memory.saved")
            .count(),
        1
    );
}

#[tokio::test]
async fn replay_never_reapplies_an_old_memory_write_or_recharges_audit() {
    let owner = Owner::open(":memory:").await.unwrap();
    let agent = owner.create_agent().await.unwrap();
    agent.remember_once("old", "key", "old").await.unwrap();
    let receipt = agent.operation_status("old").await.unwrap().unwrap();
    agent.remember_once("new", "key", "new").await.unwrap();
    let before = owner.audit().await.unwrap();
    agent.remember_once("old", "key", "old").await.unwrap();
    assert_eq!(owner.audit().await.unwrap(), before);
    assert_eq!(
        agent.operation_status("old").await.unwrap().unwrap(),
        receipt
    );
    assert_eq!(agent.recall("key").await.unwrap().as_deref(), Some("new"));
}

#[tokio::test]
async fn same_id_is_isolated_between_agents_and_owner_namespace() {
    let owner = Owner::open(":memory:").await.unwrap();
    let a = owner.create_agent().await.unwrap();
    let b = owner.create_agent().await.unwrap();
    let first = a.propose_once("same", "key", "a").await.unwrap();
    assert!(b.operation_status("same").await.unwrap().is_none());
    assert!(owner.operation_status("same").await.unwrap().is_none());
    let second = b.propose_once("same", "key", "b").await.unwrap();
    assert_ne!(first, second);
    owner.approve_once("same", &first).await.unwrap();
    assert_eq!(
        owner
            .operation_status("same")
            .await
            .unwrap()
            .unwrap()
            .action,
        "proposal.approved"
    );
    assert_eq!(
        a.operation_status("same").await.unwrap().unwrap().result["id"],
        first
    );
    assert_eq!(
        b.operation_status("same").await.unwrap().unwrap().result["id"],
        second
    );
}

#[tokio::test]
async fn rotation_preserves_scope_but_revocation_blocks_cached_results() {
    let owner = Owner::open(":memory:").await.unwrap();
    let (id, token) = owner
        .create_agent_credential(Duration::from_secs(300))
        .await
        .unwrap();
    let a = match owner.authenticate(token.expose_secret()).await.unwrap() {
        Authenticated::Agent(a) => a,
        _ => panic!(),
    };
    let proposal = a.propose_once("rotation", "key", "value").await.unwrap();
    let fresh = owner
        .issue_agent_credential(&id, Duration::from_secs(300))
        .await
        .unwrap();
    owner
        .revoke_credential_once("revoke-token", token.id())
        .await
        .unwrap();
    assert!(matches!(
        a.operation_status("rotation").await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        a.propose_once("rotation", "key", "value").await,
        Err(Error::Authentication)
    ));
    let b = match owner.authenticate(fresh.expose_secret()).await.unwrap() {
        Authenticated::Agent(a) => a,
        _ => panic!(),
    };
    assert_eq!(
        b.propose_once("rotation", "key", "value").await.unwrap(),
        proposal
    );
    owner.revoke_agent_once("revoke-agent", &id).await.unwrap();
    owner.revoke_agent_once("revoke-agent", &id).await.unwrap();
    assert!(matches!(
        b.operation_status("rotation").await,
        Err(Error::Revoked)
    ));
    assert!(matches!(
        b.propose_once("rotation", "key", "value").await,
        Err(Error::Revoked)
    ));
}

#[tokio::test]
async fn receipts_and_saved_proposal_results_survive_encrypted_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("retry.db");
    let key = EncryptionKey::generate().unwrap();
    let owner = Owner::open_encrypted(path.to_str().unwrap(), &key, None)
        .await
        .unwrap();
    let a = owner.create_agent().await.unwrap();
    let agent_id = a.id().to_owned();
    let proposal = a.propose_once("restart", "key", "value").await.unwrap();
    let history = owner.audit().await.unwrap();
    drop(a);
    drop(owner);
    let owner = Owner::open_encrypted(path.to_str().unwrap(), &key, None)
        .await
        .unwrap();
    let a = owner.agent(&agent_id).await.unwrap();
    assert_eq!(
        a.propose_once("restart", "key", "value").await.unwrap(),
        proposal
    );
    assert_eq!(owner.audit().await.unwrap(), history);
}

#[tokio::test]
async fn encrypted_snapshot_preserves_receipts_and_invalidates_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let backup = temp.path().join("backup.mimi");
    let destination = temp.path().join("restored.db");
    let owner = Owner::open(":memory:").await.unwrap();
    let (id, token) = owner
        .create_agent_credential(Duration::from_secs(300))
        .await
        .unwrap();
    let a = owner.agent(&id).await.unwrap();
    let p = a.propose_once("backup", "key", "value").await.unwrap();
    owner.approve_once("approved", &p).await.unwrap();
    let key = EncryptionKey::generate().unwrap();
    owner.backup(&backup, &key).await.unwrap();
    let restored = Owner::restore(
        &backup,
        &key,
        &destination,
        &EncryptionKey::generate().unwrap(),
    )
    .await
    .unwrap();
    assert!(matches!(
        restored.authenticate(token.expose_secret()).await,
        Err(Error::Authentication)
    ));
    let a = restored.agent(&id).await.unwrap();
    assert_eq!(a.propose_once("backup", "key", "value").await.unwrap(), p);
    restored.approve_once("approved", &p).await.unwrap();
    assert_eq!(
        restored.read_shared("key").await.unwrap().unwrap().version,
        1
    );
}

#[tokio::test]
async fn failed_write_has_no_receipt_and_can_be_retried_after_quota_change() {
    let owner = Owner::open_with_limits(
        ":memory:",
        Limits {
            audit_events: 1,
            ..Limits::default()
        },
    )
    .await
    .unwrap();
    let a = owner.create_agent().await.unwrap();
    assert!(matches!(
        a.remember_once("retry", "key", "value").await,
        Err(Error::Quota)
    ));
    assert!(a.operation_status("retry").await.unwrap().is_none());
    owner
        .update_limits_once("raise", Limits::default())
        .await
        .unwrap();
    a.remember_once("retry", "key", "value").await.unwrap();
    assert_eq!(a.recall("key").await.unwrap().as_deref(), Some("value"));
    assert_eq!(
        owner
            .audit()
            .await
            .unwrap()
            .iter()
            .filter(|e| e.action == "memory.saved")
            .count(),
        1
    );
}

#[tokio::test]
async fn owner_review_replay_cannot_increment_versions_or_change_decision() {
    let owner = Owner::open(":memory:").await.unwrap();
    let a = owner.create_agent().await.unwrap();
    let one = a.propose_once("one", "key", "one").await.unwrap();
    owner.approve_once("review", &one).await.unwrap();
    let two = a.propose_once("two", "key", "two").await.unwrap();
    owner.approve(&two).await.unwrap();
    let history = owner.audit().await.unwrap();
    owner.approve_once("review", &one).await.unwrap();
    assert_eq!(owner.audit().await.unwrap(), history);
    assert_eq!(owner.read_shared("key").await.unwrap().unwrap().version, 2);
    assert!(matches!(
        owner.reject_once("review", &one).await,
        Err(Error::OperationConflict)
    ));
    assert!(matches!(
        owner.approve_once("different", &one).await,
        Err(Error::AlreadyReviewed)
    ));
    assert!(owner.operation_status("different").await.unwrap().is_none());
}

#[tokio::test]
async fn invalid_ids_never_create_receipts_or_writes() {
    let owner = Owner::open(":memory:").await.unwrap();
    let a = owner.create_agent().await.unwrap();
    for id in ["", "with spaces", "../path", "é", "bad\n", &"x".repeat(129)] {
        assert!(matches!(
            a.remember_once(id, "key", "value").await,
            Err(Error::InvalidInput)
        ));
        assert!(matches!(
            a.operation_status(id).await,
            Err(Error::InvalidInput)
        ));
    }
    assert_eq!(a.recall("key").await.unwrap(), None);
}
