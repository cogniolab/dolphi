use dolphi::{EncryptionKey, Owner};
use std::{
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

// Invoked explicitly by the parent test in a separate process, never as normal
// application code. SIGKILL avoids destructors, checkpoint-on-close and core dumps.
#[tokio::test]
#[ignore = "subprocess fixture exercised by committed_encrypted_wal_survives_process_kill"]
async fn crash_writer_fixture() {
    let directory = PathBuf::from(std::env::var_os("DOLPHI_TEST_CRASH_DIRECTORY").unwrap());
    let path = directory.join("crash.db");
    let owner = Owner::open_encrypted(
        path.to_str().unwrap(),
        &EncryptionKey::from_bytes([73; 32]),
        None,
    )
    .await
    .unwrap();
    let agent = owner.create_agent().await.unwrap();
    agent
        .remember_once("crash-memory", "committed", "survive-unclean-exit")
        .await
        .unwrap();
    let proposal = agent
        .propose_once("crash-proposal", "stock", "12")
        .await
        .unwrap();
    owner
        .approve_once("crash-approval", &proposal)
        .await
        .unwrap();
    let marker = directory.join("ready");
    let pending_marker = directory.join("ready.tmp");
    std::fs::write(&pending_marker, agent.id()).unwrap();
    std::fs::rename(pending_marker, &marker).unwrap();
    loop {
        std::thread::park();
    }
}

#[tokio::test]
async fn committed_encrypted_wal_survives_process_kill() {
    let temp = tempfile::tempdir().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_writer_fixture", "--ignored"])
        .env("DOLPHI_TEST_CRASH_DIRECTORY", temp.path())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let marker = temp.path().join("ready");
    while !marker.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("writer exited before commit: {status}");
        }
        if start.elapsed() > Duration::from_secs(15) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("writer did not commit in time");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // Ready file is written after both transactions report successful commits.
    let id = std::fs::read_to_string(marker).unwrap();
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    let path = temp.path().join("crash.db");
    let owner = Owner::open_encrypted(
        path.to_str().unwrap(),
        &EncryptionKey::from_bytes([73; 32]),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        owner
            .agent(&id)
            .await
            .unwrap()
            .recall("committed")
            .await
            .unwrap()
            .as_deref(),
        Some("survive-unclean-exit")
    );
    assert_eq!(
        owner.read_shared("stock").await.unwrap().unwrap().value,
        "12"
    );
    assert!(
        owner
            .audit()
            .await
            .unwrap()
            .iter()
            .any(|event| event.action == "proposal.approved")
    );
    let agent = owner.agent(&id).await.unwrap();
    let receipt = agent
        .operation_status("crash-proposal")
        .await
        .unwrap()
        .unwrap();
    let proposal = receipt.result["id"].as_str().unwrap();
    let history = owner.audit().await.unwrap();
    assert_eq!(
        agent
            .propose_once("crash-proposal", "stock", "12")
            .await
            .unwrap(),
        proposal
    );
    agent
        .remember_once("crash-memory", "committed", "survive-unclean-exit")
        .await
        .unwrap();
    owner
        .approve_once("crash-approval", proposal)
        .await
        .unwrap();
    assert_eq!(owner.audit().await.unwrap(), history);
    assert_eq!(
        owner.read_shared("stock").await.unwrap().unwrap().version,
        1
    );
}
