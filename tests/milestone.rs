use dolphi::{Error, Owner};

#[tokio::test]
async fn private_memory_persists_without_cross_agent_access() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("memory.db");
    let path = path.to_str().unwrap();
    let (alice_id, bob_id);
    {
        let owner = Owner::open(path).await.unwrap();
        let alice = owner.create_agent().await.unwrap();
        let bob = owner.create_agent().await.unwrap();
        alice_id = alice.id().to_owned();
        bob_id = bob.id().to_owned();
        alice
            .remember("secret", "Alice private data")
            .await
            .unwrap();
        assert_eq!(bob.recall("secret").await.unwrap(), None);
        bob.remember("secret", "Bob private data").await.unwrap();
        assert_eq!(
            alice.recall("secret").await.unwrap().as_deref(),
            Some("Alice private data")
        );
        // Keys are parameters, including SQL-looking input.
        alice.remember("x' OR 1=1 --", "literal").await.unwrap();
        assert_eq!(bob.recall("x' OR 1=1 --").await.unwrap(), None);
    }
    let owner = Owner::open(path).await.unwrap();
    assert_eq!(
        owner
            .agent(&alice_id)
            .await
            .unwrap()
            .recall("secret")
            .await
            .unwrap()
            .as_deref(),
        Some("Alice private data")
    );
    assert_eq!(
        owner
            .agent(&bob_id)
            .await
            .unwrap()
            .recall("secret")
            .await
            .unwrap()
            .as_deref(),
        Some("Bob private data")
    );
    assert!(matches!(
        owner.agent("unknown").await,
        Err(Error::UnknownAgent)
    ));
}

#[tokio::test]
async fn approval_is_explicit_atomic_and_attributable() {
    let owner = Owner::open(":memory:").await.unwrap();
    let agent = owner.create_agent().await.unwrap();
    let id = agent.propose("inventory", "12").await.unwrap();
    assert_eq!(agent.read_shared("inventory").await.unwrap(), None);
    let review = owner.inspect(&id).await.unwrap();
    assert_eq!(review.agent_id, agent.id());
    assert_eq!(review.value, "12");
    assert_eq!(review.status, "pending");
    owner.approve(&id).await.unwrap();
    let value = agent.read_shared("inventory").await.unwrap().unwrap();
    assert_eq!(value.value, "12");
    assert_eq!(value.version, 1);
    assert!(matches!(
        owner.approve(&id).await,
        Err(Error::AlreadyReviewed)
    ));
    let events = owner.audit().await.unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[1].actor, agent.id());
    assert_eq!(events[1].subject, id);
    assert_eq!(events[2].actor, "owner");
    assert_eq!(events[2].action, "proposal.approved");
    assert!(
        events
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence)
    );
}

#[tokio::test]
async fn stale_proposals_cannot_overwrite_newer_data() {
    let owner = Owner::open(":memory:").await.unwrap();
    let alice = owner.create_agent().await.unwrap();
    let bob = owner.create_agent().await.unwrap();
    let first = alice.propose("stock", "10").await.unwrap();
    let stale = bob.propose("stock", "20").await.unwrap();
    owner.approve(&first).await.unwrap();
    let before = owner.audit().await.unwrap();
    assert!(matches!(owner.approve(&stale).await, Err(Error::Conflict)));
    assert_eq!(
        owner.read_shared("stock").await.unwrap().unwrap().value,
        "10"
    );
    assert_eq!(owner.inspect(&stale).await.unwrap().status, "pending");
    assert_eq!(owner.audit().await.unwrap(), before);
    owner.reject(&stale).await.unwrap();
    assert!(matches!(
        owner.approve(&stale).await,
        Err(Error::AlreadyReviewed)
    ));
    let fresh = bob.propose("stock", "30").await.unwrap();
    owner.approve(&fresh).await.unwrap();
    assert_eq!(
        owner.read_shared("stock").await.unwrap().unwrap().version,
        2
    );
}

#[tokio::test]
async fn parallel_proposals_have_only_one_winner() {
    let owner = Owner::open(":memory:").await.unwrap();
    let a = owner.create_agent().await.unwrap();
    let b = owner.create_agent().await.unwrap();
    let (first, second) = tokio::join!(a.propose("key", "a"), b.propose("key", "b"));
    let (first, second) = (first.unwrap(), second.unwrap());
    let (a_result, b_result) = tokio::join!(owner.approve(&first), owner.approve(&second));
    assert!(a_result.is_ok());
    assert!(matches!(b_result, Err(Error::Conflict)));
    assert_eq!(owner.read_shared("key").await.unwrap().unwrap().version, 1);
}

#[tokio::test]
async fn invalid_requests_and_unknown_reviews_leave_no_changes() {
    let owner = Owner::open(":memory:").await.unwrap();
    let agent = owner.create_agent().await.unwrap();
    assert!(matches!(
        agent.remember("", "value").await,
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        agent.propose("key", &"x".repeat(65537)).await,
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        owner.approve("missing").await,
        Err(Error::UnknownProposal)
    ));
    assert_eq!(owner.audit().await.unwrap().len(), 1);
    agent
        .remember("valid", "still usable after rollback")
        .await
        .unwrap();
}
