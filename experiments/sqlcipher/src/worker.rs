//! Trusted storage worker, not an agent-accessible raw SQL API.
//!
//! One dedicated thread owns the connection. Admission never waits for queue
//! capacity. An accepted job completes even if its async caller disappears:
//! callers must reconcile by operation ID rather than blindly retrying writes.
use rusqlite::Connection;
use std::{path::PathBuf, thread::JoinHandle};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

type Job = Box<dyn FnOnce(&mut Connection) + Send>;

#[derive(Debug)]
pub enum Error {
    Busy,
    Closed,
    InvalidCapacity,
    Storage(rusqlite::Error),
    Thread(std::io::Error),
}

pub struct Worker {
    sender: mpsc::Sender<Job>,
    thread: JoinHandle<()>,
}

impl Worker {
    /// Capacity counts queued jobs, in addition to at most one active job.
    pub async fn open(path: PathBuf, key: [u8; 32], capacity: usize) -> Result<Self, Error> {
        Self::open_configured(path, Some(key), capacity).await
    }

    /// Explicit plaintext embedded profile; never a fallback after key failure.
    pub async fn open_plain(path: PathBuf, capacity: usize) -> Result<Self, Error> {
        Self::open_configured(path, None, capacity).await
    }

    async fn open_configured(
        path: PathBuf,
        key: Option<[u8; 32]>,
        capacity: usize,
    ) -> Result<Self, Error> {
        // Bound both accidental misconfiguration and channel allocation.
        let key = key.map(Zeroizing::new);
        if !(1..=1024).contains(&capacity) {
            return Err(Error::InvalidCapacity);
        }
        let (sender, mut receiver) = mpsc::channel::<Job>(capacity);
        let (ready_tx, ready_rx) = oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("dolphi-cipher".into())
            .spawn(move || {
                let opened = super::configured(&path, key.as_deref()).and_then(|connection| {
                    connection.execute_batch(super::SCHEMA)?;
                    Ok(connection)
                });
                drop(key);
                match opened {
                    Ok(mut connection) => {
                        if ready_tx.send(Ok(())).is_err() {
                            return;
                        }
                        while let Some(job) = receiver.blocking_recv() {
                            job(&mut connection);
                        }
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(Error::Storage(error)));
                    }
                }
            })
            .map_err(Error::Thread)?;
        ready_rx.await.map_err(|_| Error::Closed)??;
        Ok(Self { sender, thread })
    }

    /// Closures are internal trusted operations and must bound their own work.
    /// A panic terminates this worker; queued callers fail closed.
    pub async fn run<T, F>(&self, operation: F) -> Result<T, Error>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        self.try_run(operation)?
            .await
            .map_err(|_| Error::Closed)?
            .map_err(Error::Storage)
    }

    /// Synchronous admission also lets a dropped transaction queue cleanup.
    pub fn try_run<T, F>(
        &self,
        operation: F,
    ) -> Result<oneshot::Receiver<rusqlite::Result<T>>, Error>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .try_send(Box::new(move |connection| {
                let _ = response_tx.send(operation(connection));
            }))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => Error::Busy,
                mpsc::error::TrySendError::Closed(_) => Error::Closed,
            })?;
        Ok(response_rx)
    }

    /// Drain accepted work and close the connection without joining on Tokio.
    pub async fn shutdown(self) -> Result<(), Error> {
        drop(self.sender);
        tokio::task::spawn_blocking(move || self.thread.join())
            .await
            .map_err(|_| Error::Closed)?
            .map_err(|_| Error::Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, mpsc as blocking};

    #[tokio::test(flavor = "current_thread")]
    async fn admission_is_bounded_and_worker_does_not_block_async_runtime() {
        let temp = tempfile::tempdir().unwrap();
        let worker = Arc::new(
            Worker::open(temp.path().join("db"), [3; 32], 1)
                .await
                .unwrap(),
        );
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = blocking::channel();
        let first_worker = worker.clone();
        let first = tokio::spawn(async move {
            first_worker
                .run(move |_| {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                })
                .await
        });
        started_rx.await.unwrap();
        // Polling run once admits it, then waits on its response.
        let second = worker.run(|_| Ok(2));
        tokio::pin!(second);
        tokio::select! {
            biased;
            result = &mut second => panic!("queued operation completed early: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }
        let rejected = worker.run(|_| Ok(3)).await;
        // Release before assertions so a failure cannot strand a worker thread.
        release_tx.send(()).unwrap();
        assert!(matches!(rejected, Err(Error::Busy)));
        first.await.unwrap().unwrap();
        assert_eq!(second.await.unwrap(), 2);
    }

    #[tokio::test]
    async fn canceled_response_does_not_cancel_an_admitted_transaction() {
        let temp = tempfile::tempdir().unwrap();
        let worker = Arc::new(
            Worker::open(temp.path().join("db"), [4; 32], 2)
                .await
                .unwrap(),
        );
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = blocking::channel();
        let caller_worker = worker.clone();
        let caller = tokio::spawn(async move {
            caller_worker
                .run(move |connection| {
                    let tx = connection.transaction()?;
                    tx.execute("INSERT INTO agents VALUES ('committed')", [])?;
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    tx.commit()
                })
                .await
        });
        started_rx.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        release_tx.send(()).unwrap();
        assert_eq!(
            worker
                .run(|connection| connection.query_row(
                    "SELECT count(*) FROM agents WHERE id='committed'",
                    [],
                    |row| row.get::<_, i64>(0)
                ))
                .await
                .unwrap(),
            1
        );
        Arc::try_unwrap(worker)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn transaction_failure_rolls_back_and_worker_remains_usable() {
        let temp = tempfile::tempdir().unwrap();
        let worker = Worker::open(temp.path().join("db"), [5; 32], 2)
            .await
            .unwrap();
        let failed = worker
            .run(|connection| {
                let tx = connection.transaction()?;
                tx.execute("INSERT INTO agents VALUES ('rollback')", [])?;
                tx.execute("INSERT INTO nonexistent VALUES (1)", [])?;
                tx.commit()
            })
            .await;
        assert!(matches!(failed, Err(Error::Storage(_))));
        assert_eq!(
            worker
                .run(|connection| connection
                    .query_row("SELECT count(*) FROM agents", [], |row| row
                        .get::<_, i64>(0)))
                .await
                .unwrap(),
            0
        );
        worker.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn panic_rolls_back_and_closes_worker() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("db");
        let worker = Worker::open(path.clone(), [6; 32], 2).await.unwrap();
        assert!(matches!(
            worker
                .run::<(), _>(|connection| {
                    let tx = connection.transaction()?;
                    tx.execute("INSERT INTO agents VALUES ('rollback')", [])?;
                    panic!("injected trusted-operation panic");
                })
                .await,
            Err(Error::Closed)
        ));
        assert!(matches!(worker.run(|_| Ok(())).await, Err(Error::Closed)));
        assert!(matches!(worker.shutdown().await, Err(Error::Closed)));
        let reopened = super::super::open(&path, &[6; 32]).unwrap();
        assert_eq!(
            reopened
                .query_row("SELECT count(*) FROM agents", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn startup_rejects_wrong_key_and_invalid_capacity() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("db");
        Worker::open(path.clone(), [7; 32], 1)
            .await
            .unwrap()
            .shutdown()
            .await
            .unwrap();
        assert!(matches!(
            Worker::open(path.clone(), [8; 32], 1).await,
            Err(Error::Storage(_))
        ));
        for capacity in [0, 1025] {
            assert!(matches!(
                Worker::open(path.clone(), [7; 32], capacity).await,
                Err(Error::InvalidCapacity)
            ));
        }
    }
}
