use dolphi::{Authenticated, EncryptionKey, Error, Limits, Owner};
use std::time::Duration;

async fn auth_agent(owner: &Owner, token: &str) -> dolphi::AgentSession {
    match owner.authenticate(token).await.unwrap() {
        Authenticated::Agent(session) => session,
        _ => panic!("agent credential must not grant owner authority"),
    }
}

#[tokio::test]
async fn credentials_are_scoped_unforgeable_and_revocable_on_existing_handles() {
    let owner = Owner::open(":memory:").await.unwrap();
    let alice = owner.create_agent().await.unwrap();
    let bob = owner.create_agent().await.unwrap();
    bob.remember("secret", "bob-only").await.unwrap();
    let token = owner
        .issue_agent_credential(alice.id(), Duration::from_secs(300))
        .await
        .unwrap();
    assert_eq!(token.expose_secret().len(), 64);
    let other_database = Owner::open(":memory:").await.unwrap();
    assert!(matches!(
        other_database.authenticate(token.expose_secret()).await,
        Err(Error::Authentication)
    ));
    let session = auth_agent(&owner, token.expose_secret()).await;
    session.remember("secret", "alice-only").await.unwrap();
    assert_eq!(
        session.recall("secret").await.unwrap().as_deref(),
        Some("alice-only")
    );
    for forged in [
        "",
        "owner",
        alice.id(),
        token.id(),
        &"0".repeat(64),
        "' OR 1=1 --",
    ] {
        assert!(matches!(
            owner.authenticate(forged).await,
            Err(Error::Authentication)
        ));
    }
    let clone = session.clone();
    owner.revoke_credential(token.id()).await.unwrap();
    assert!(matches!(
        owner.authenticate(token.expose_secret()).await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        session.recall("secret").await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        clone.remember("secret", "overwrite").await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        clone.propose("stock", "999").await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        clone.read_shared("stock").await,
        Err(Error::Authentication)
    ));
    // Revoking one credential does not revoke the trusted embedded agent.
    assert_eq!(
        alice.recall("secret").await.unwrap().as_deref(),
        Some("alice-only")
    );
}

#[tokio::test]
async fn owner_credentials_are_checked_on_every_administrative_operation() {
    let owner = Owner::open(":memory:").await.unwrap();
    let agent = owner.create_agent().await.unwrap();
    let proposal = agent.propose("stock", "12").await.unwrap();
    let token = owner
        .issue_owner_credential(Duration::from_secs(300))
        .await
        .unwrap();
    let delegated = match owner.authenticate(token.expose_secret()).await.unwrap() {
        Authenticated::Owner(value) => value,
        _ => panic!("wrong role"),
    };
    assert!(delegated.inspect(&proposal).await.is_ok());
    owner.revoke_credential(token.id()).await.unwrap();
    assert!(matches!(
        delegated.create_agent().await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        delegated.agent(agent.id()).await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        delegated.inspect(&proposal).await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        delegated.approve(&proposal).await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        delegated.reject(&proposal).await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        delegated.audit().await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        delegated.read_shared("stock").await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        delegated.revoke_agent(agent.id()).await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        delegated.limits().await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        delegated.update_limits(Limits::default()).await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        delegated
            .issue_owner_credential(Duration::from_secs(10))
            .await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        delegated.revoke_credential(token.id()).await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        delegated.authenticate(token.expose_secret()).await,
        Err(Error::Authentication)
    ));
    let temp = tempfile::tempdir().unwrap();
    let backup = temp.path().join("denied-backup");
    assert!(matches!(
        delegated
            .backup(&backup, &EncryptionKey::generate().unwrap())
            .await,
        Err(Error::Authentication)
    ));
    assert!(!backup.exists());
    assert_eq!(owner.inspect(&proposal).await.unwrap().status, "pending");
}

#[tokio::test]
async fn credential_revocation_and_limits_persist_across_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("identity.db");
    let path = path.to_str().unwrap();
    let config = Limits {
        credentials: 2,
        ..Limits::default()
    };
    let owner = Owner::open_with_limits(path, config.clone()).await.unwrap();
    let agent = owner.create_agent().await.unwrap();
    let active = owner
        .issue_agent_credential(agent.id(), Duration::from_secs(300))
        .await
        .unwrap();
    let revoked = owner
        .issue_owner_credential(Duration::from_secs(300))
        .await
        .unwrap();
    owner.revoke_credential(revoked.id()).await.unwrap();
    assert!(matches!(
        owner.issue_owner_credential(Duration::from_secs(300)).await,
        Err(Error::Quota)
    ));
    drop(agent);
    drop(owner);
    let owner = Owner::open(path).await.unwrap();
    assert_eq!(owner.limits().await.unwrap(), config);
    assert!(owner.authenticate(active.expose_secret()).await.is_ok());
    assert!(matches!(
        owner.authenticate(revoked.expose_secret()).await,
        Err(Error::Authentication)
    ));
    assert!(matches!(
        Owner::open_with_limits(path, Limits::default()).await,
        Err(Error::Configuration)
    ));
}

#[tokio::test]
async fn invalid_ttl_and_unknown_agent_never_issue_credentials() {
    let owner = Owner::open(":memory:").await.unwrap();
    let before = owner.audit().await.unwrap();
    for ttl in [Duration::ZERO, Duration::from_secs(31 * 86400)] {
        assert!(matches!(
            owner.issue_owner_credential(ttl).await,
            Err(Error::Configuration)
        ));
    }
    assert!(matches!(
        owner
            .issue_agent_credential("missing", Duration::from_secs(10))
            .await,
        Err(Error::UnknownAgent)
    ));
    assert_eq!(owner.audit().await.unwrap(), before);
}

#[tokio::test]
async fn quotas_bound_agent_creation_memory_bytes_and_proposals_atomically() {
    let config = Limits {
        agents: 2,
        memories_per_agent: 1,
        memory_bytes_per_agent: 8,
        proposals_per_agent: 1,
        ..Limits::default()
    };
    let owner = Owner::open_with_limits(":memory:", config).await.unwrap();
    let a = owner.create_agent().await.unwrap();
    let b = owner.create_agent().await.unwrap();
    let before = owner.audit().await.unwrap();
    assert!(matches!(owner.create_agent().await, Err(Error::Quota)));
    assert_eq!(owner.audit().await.unwrap(), before);
    a.remember("k", "1234567").await.unwrap(); // Exactly eight bytes.
    let before = owner.audit().await.unwrap();
    assert!(matches!(
        a.remember("k", "12345678").await,
        Err(Error::Quota)
    ));
    assert!(matches!(a.remember("x", "v").await, Err(Error::Quota)));
    assert_eq!(owner.audit().await.unwrap(), before);
    assert_eq!(a.recall("k").await.unwrap().as_deref(), Some("1234567"));
    a.remember("k", "v").await.unwrap(); // Overwriting does not consume a new slot.
    b.remember("k", "other").await.unwrap(); // Another agent has a separate budget.
    let p = a.propose("stock", "12").await.unwrap();
    assert!(matches!(
        a.propose("another", "13").await,
        Err(Error::Quota)
    ));
    owner.approve(&p).await.unwrap();
    // Reviewed proposals retain their history and continue to count.
    assert!(matches!(a.propose("stock", "14").await, Err(Error::Quota)));
}

#[tokio::test]
async fn audit_capacity_fails_closed_without_silent_data_changes() {
    let owner = Owner::open_with_limits(
        ":memory:",
        Limits {
            audit_events: 2,
            ..Limits::default()
        },
    )
    .await
    .unwrap();
    let agent = owner.create_agent().await.unwrap();
    agent.remember("key", "original").await.unwrap();
    assert!(matches!(
        agent.remember("key", "modified").await,
        Err(Error::Quota)
    ));
    assert!(matches!(agent.recall("key").await, Err(Error::Quota)));
    assert_eq!(owner.audit().await.unwrap().len(), 2);
    // Filling ordinary history must not prevent emergency access revocation.
    owner.revoke_agent(agent.id()).await.unwrap();
    assert!(matches!(agent.recall("key").await, Err(Error::Revoked)));
    assert_eq!(owner.audit().await.unwrap().len(), 3);
}

#[tokio::test]
async fn emergency_credential_revocation_remains_available_at_audit_capacity() {
    let owner = Owner::open_with_limits(
        ":memory:",
        Limits {
            audit_events: 2,
            ..Limits::default()
        },
    )
    .await
    .unwrap();
    let agent = owner.create_agent().await.unwrap();
    let token = owner
        .issue_agent_credential(agent.id(), Duration::from_secs(60))
        .await
        .unwrap();
    let session = auth_agent(&owner, token.expose_secret()).await;
    owner.revoke_credential(token.id()).await.unwrap();
    let after = owner.audit().await.unwrap();
    owner.revoke_credential(token.id()).await.unwrap();
    assert_eq!(owner.audit().await.unwrap(), after);
    assert!(matches!(
        session.read_shared("key").await,
        Err(Error::Authentication)
    ));
    assert_eq!(after.len(), 3);
}

#[tokio::test]
async fn invalid_limits_are_rejected_before_creating_a_database() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("invalid.db");
    let limits = Limits {
        agents: 0,
        ..Limits::default()
    };
    assert!(matches!(
        Owner::open_with_limits(target.to_str().unwrap(), limits).await,
        Err(Error::Configuration)
    ));
    assert!(!target.exists());
}

#[tokio::test]
async fn owner_can_raise_quotas_but_not_lower_them_below_stored_usage() {
    let owner = Owner::open_with_limits(
        ":memory:",
        Limits {
            agents: 1,
            ..Limits::default()
        },
    )
    .await
    .unwrap();
    owner.create_agent().await.unwrap();
    assert!(matches!(owner.create_agent().await, Err(Error::Quota)));
    let updated = Limits {
        agents: 2,
        ..Limits::default()
    };
    owner.update_limits(updated.clone()).await.unwrap();
    owner.create_agent().await.unwrap();
    assert!(matches!(
        owner
            .update_limits(Limits {
                agents: 1,
                ..Limits::default()
            })
            .await,
        Err(Error::Configuration)
    ));
    assert_eq!(owner.limits().await.unwrap(), updated);
    assert_eq!(
        owner
            .audit()
            .await
            .unwrap()
            .iter()
            .filter(|e| e.action == "limits.updated")
            .count(),
        1
    );
}

#[tokio::test]
async fn agent_request_budget_is_shared_across_clones_and_credentials() {
    let owner = Owner::open_with_limits(
        ":memory:",
        Limits {
            requests_per_minute: 1,
            ..Limits::default()
        },
    )
    .await
    .unwrap();
    let agent = owner.create_agent().await.unwrap();
    let first = owner
        .issue_agent_credential(agent.id(), Duration::from_secs(300))
        .await
        .unwrap();
    let second = owner
        .issue_agent_credential(agent.id(), Duration::from_secs(300))
        .await
        .unwrap();
    let a = auth_agent(&owner, first.expose_secret()).await;
    let b = auth_agent(&owner, second.expose_secret()).await;
    let (one, two) = tokio::join!(a.remember("key", "one"), b.remember("key", "two"));
    assert_eq!(usize::from(one.is_ok()) + usize::from(two.is_ok()), 1);
    assert!(matches!(
        a.clone().read_shared("key").await,
        Err(Error::Quota)
    ));
}

#[tokio::test]
async fn encrypted_database_rejects_wrong_missing_keys_and_hides_db_wal_secrets() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("encrypted.db");
    let key = EncryptionKey::generate().unwrap();
    let wrong = EncryptionKey::generate().unwrap();
    let owner = Owner::open_encrypted(path.to_str().unwrap(), &key, None)
        .await
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let agent = owner.create_agent().await.unwrap();
    let marker = "DOLPHI-SECRET-MARKER-7b181f8cc3b94742";
    agent.remember(marker, marker).await.unwrap();
    let id = agent.id().to_owned();
    let token = owner
        .issue_agent_credential(&id, Duration::from_secs(300))
        .await
        .unwrap();
    for entry in std::fs::read_dir(temp.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        for secret in [marker, token.expose_secret()] {
            assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));
        }
    }
    drop(agent);
    drop(owner);
    assert!(Owner::open(path.to_str().unwrap()).await.is_err());
    assert!(
        Owner::open_encrypted(path.to_str().unwrap(), &wrong, None)
            .await
            .is_err()
    );
    let reopened = Owner::open_encrypted(path.to_str().unwrap(), &key, None)
        .await
        .unwrap();
    assert_eq!(
        reopened
            .agent(&id)
            .await
            .unwrap()
            .recall(marker)
            .await
            .unwrap()
            .as_deref(),
        Some(marker)
    );
    assert!(reopened.authenticate(token.expose_secret()).await.is_ok());
}

#[tokio::test]
async fn encrypted_open_never_silently_upgrades_existing_plaintext() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("plain.db");
    let plain = Owner::open(path.to_str().unwrap()).await.unwrap();
    let agent = plain.create_agent().await.unwrap();
    let id = agent.id().to_owned();
    agent.remember("key", "plaintext").await.unwrap();
    drop(agent);
    drop(plain);
    assert!(
        Owner::open_encrypted(
            path.to_str().unwrap(),
            &EncryptionKey::generate().unwrap(),
            None
        )
        .await
        .is_err()
    );
    let plain = Owner::open(path.to_str().unwrap()).await.unwrap();
    assert_eq!(
        plain
            .agent(&id)
            .await
            .unwrap()
            .recall("key")
            .await
            .unwrap()
            .as_deref(),
        Some("plaintext")
    );
}

#[tokio::test]
async fn encrypted_backup_restores_memory_reviews_revocation_limits_and_invalidates_tokens() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source.db");
    let destination = temp.path().join("restored.db");
    let backup = temp.path().join("backup.mimi");
    let key = EncryptionKey::generate().unwrap();
    let backup_key = EncryptionKey::generate().unwrap();
    let new_key = EncryptionKey::generate().unwrap();
    let owner = Owner::open_encrypted(source.to_str().unwrap(), &key, None)
        .await
        .unwrap();
    let agent = owner.create_agent().await.unwrap();
    let revoked = owner.create_agent().await.unwrap();
    owner.revoke_agent(revoked.id()).await.unwrap();
    agent
        .remember("secret", "recover-my-memory-7df68c")
        .await
        .unwrap();
    let approved = agent.propose("stock", "12").await.unwrap();
    owner.approve(&approved).await.unwrap();
    let pending = agent.propose("stock", "15").await.unwrap();
    let token = owner
        .issue_agent_credential(agent.id(), Duration::from_secs(300))
        .await
        .unwrap();
    let history = owner.audit().await.unwrap();
    owner.backup(&backup, &backup_key).await.unwrap();
    let bytes = std::fs::read(&backup).unwrap();
    let marker = b"recover-my-memory-7df68c";
    assert!(!bytes.windows(marker.len()).any(|w| w == marker));
    let restored = Owner::restore(&backup, &backup_key, &destination, &new_key)
        .await
        .unwrap();
    assert_eq!(restored.audit().await.unwrap(), history);
    assert_eq!(
        restored
            .read_shared("stock")
            .await
            .unwrap()
            .unwrap()
            .version,
        1
    );
    assert_eq!(
        restored
            .agent(agent.id())
            .await
            .unwrap()
            .recall("secret")
            .await
            .unwrap()
            .as_deref(),
        Some("recover-my-memory-7df68c")
    );
    assert!(matches!(
        restored.agent(revoked.id()).await,
        Err(Error::Revoked)
    ));
    assert!(matches!(
        restored.authenticate(token.expose_secret()).await,
        Err(Error::Authentication)
    ));
    assert_eq!(
        restored.limits().await.unwrap(),
        owner.limits().await.unwrap()
    );
    restored.approve(&pending).await.unwrap();
    assert_eq!(
        restored
            .read_shared("stock")
            .await
            .unwrap()
            .unwrap()
            .version,
        2
    );
    assert!(matches!(
        restored.approve(&approved).await,
        Err(Error::AlreadyReviewed)
    ));
    let fresh = restored
        .issue_agent_credential(agent.id(), Duration::from_secs(300))
        .await
        .unwrap();
    assert!(restored.authenticate(fresh.expose_secret()).await.is_ok());
    assert!(
        Owner::restore(&backup, &backup_key, &destination, &new_key)
            .await
            .is_err()
    );
    assert!(owner.backup(&backup, &backup_key).await.is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&destination)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[tokio::test]
async fn corrupt_truncated_and_wrong_key_backups_cannot_create_or_replace_destination() {
    let temp = tempfile::tempdir().unwrap();
    let owner = Owner::open(":memory:").await.unwrap();
    owner.create_agent().await.unwrap();
    let key = EncryptionKey::generate().unwrap();
    let wrong = EncryptionKey::generate().unwrap();
    let backup = temp.path().join("backup");
    let target = temp.path().join("target");
    owner.backup(&backup, &key).await.unwrap();
    assert!(matches!(
        Owner::restore(&backup, &wrong, &target, &key).await,
        Err(Error::InvalidBackup)
    ));
    assert!(!target.exists());
    let original = std::fs::read(&backup).unwrap();
    for index in [0, 16, original.len() - 1] {
        let mut damaged = original.clone();
        damaged[index] ^= 1;
        std::fs::write(&backup, damaged).unwrap();
        assert!(matches!(
            Owner::restore(&backup, &key, &target, &key).await,
            Err(Error::InvalidBackup)
        ));
        assert!(!target.exists());
    }
    std::fs::write(&backup, &original[..original.len() / 2]).unwrap();
    assert!(matches!(
        Owner::restore(&backup, &key, &target, &key).await,
        Err(Error::InvalidBackup)
    ));
    std::fs::write(&target, "do not overwrite").unwrap();
    std::fs::write(&backup, original).unwrap();
    assert!(Owner::restore(&backup, &key, &target, &key).await.is_err());
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "do not overwrite"
    );
}
