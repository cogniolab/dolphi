pub(crate) use rusqlite::types::Value;
use rusqlite::types::{FromSql, ValueRef};
use sqlcipher_engine::{rusqlite, worker::Worker};
use std::{
    collections::VecDeque,
    ops::Deref,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Debug, thiserror::Error)]
#[error("SQLCipher storage operation failed")]
pub struct Error;
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self
    }
}
impl From<sqlcipher_engine::worker::Error> for Error {
    fn from(_: sqlcipher_engine::worker::Error) -> Self {
        Self
    }
}

type State = Arc<Mutex<Option<Arc<AtomicBool>>>>;

pub(crate) struct Database {
    worker: Arc<Worker>,
    state: State,
}
pub(crate) struct Connection {
    worker: Arc<Worker>,
    state: State,
    context: Option<Arc<AtomicBool>>,
}

// Called only on the dedicated storage thread, before every operation.
fn cleanup(db: &mut rusqlite::Connection, state: &State) -> rusqlite::Result<()> {
    let mut active = state.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
    if active
        .as_ref()
        .is_some_and(|flag| flag.load(Ordering::SeqCst))
    {
        if !db.is_autocommit() {
            db.execute_batch("ROLLBACK")?;
        }
        *active = None;
    }
    Ok(())
}

impl Database {
    pub(crate) async fn open(
        path: &str,
        key: Option<&crate::EncryptionKey>,
    ) -> Result<Self, Error> {
        let worker = match key {
            Some(key) => Worker::open(path.into(), *key.bytes(), 128).await?,
            None => Worker::open_plain(path.into(), 128).await?,
        };
        Ok(Self {
            worker: Arc::new(worker),
            state: Arc::new(Mutex::new(None)),
        })
    }
    pub(crate) fn connect(&self) -> Result<Connection, Error> {
        Ok(Connection {
            worker: self.worker.clone(),
            state: self.state.clone(),
            context: None,
        })
    }
}

pub(crate) trait Params {
    fn values(self) -> Vec<Value>;
}
pub(crate) trait IntoValue {
    fn value(self) -> Value;
}
impl IntoValue for &str {
    fn value(self) -> Value {
        Value::Text(self.to_owned())
    }
}
impl IntoValue for String {
    fn value(self) -> Value {
        Value::Text(self)
    }
}
impl IntoValue for i64 {
    fn value(self) -> Value {
        Value::Integer(self)
    }
}
impl IntoValue for i32 {
    fn value(self) -> Value {
        Value::Integer(self.into())
    }
}
impl Params for () {
    fn values(self) -> Vec<Value> {
        Vec::new()
    }
}
impl<T: IntoValue, const N: usize> Params for [T; N] {
    fn values(self) -> Vec<Value> {
        self.into_iter().map(IntoValue::value).collect()
    }
}
impl Params for Vec<Value> {
    fn values(self) -> Vec<Value> {
        self
    }
}
pub(crate) fn params_from_iter(values: Vec<Value>) -> Vec<Value> {
    values
}
macro_rules! tuple_params {
    ($($name:ident),+) => {
        impl<$($name: IntoValue),+> Params for ($($name,)+) {
            #[allow(non_snake_case)]
            fn values(self) -> Vec<Value> { let ($($name,)+) = self; vec![$($name.value()),+] }
        }
    }
}
tuple_params!(A, B);
tuple_params!(A, B, C);
tuple_params!(A, B, C, D);
tuple_params!(A, B, C, D, E);
tuple_params!(A, B, C, D, E, F);

pub(crate) struct Row(Vec<Value>);
impl Row {
    pub(crate) fn get<T: FromSql>(&self, column: usize) -> Result<T, Error> {
        let value = self.0.get(column).ok_or(Error)?;
        T::column_result(ValueRef::from(value)).map_err(|_| Error)
    }
}
pub(crate) struct Rows(VecDeque<Row>);
impl Rows {
    pub(crate) async fn next(&mut self) -> Result<Option<Row>, Error> {
        Ok(self.0.pop_front())
    }
}

impl Connection {
    // Restore must finish closing the staged file before publishing its name.
    pub(crate) async fn close(&self) -> Result<(), Error> {
        self.run(|db| {
            let closed = std::mem::replace(db, rusqlite::Connection::open_in_memory()?);
            closed.close().map_err(|(_, error)| error)
        })
        .await
    }
    async fn run<T, F>(&self, operation: F) -> Result<T, Error>
    where
        T: Send + 'static,
        F: FnOnce(&mut rusqlite::Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        let state = self.state.clone();
        let context = self.context.clone();
        Ok(self
            .worker
            .run(move |db| {
                cleanup(db, &state)?;
                // An abandoned transaction's queued statement must never run
                // as an autocommit write after its transaction is rolled back.
                if context
                    .as_ref()
                    .is_some_and(|flag| flag.load(Ordering::SeqCst))
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                operation(db)
            })
            .await?)
    }
    pub(crate) async fn execute(&self, sql: &str, params: impl Params) -> Result<u64, Error> {
        let sql = sql.to_owned();
        let params = params.values();
        self.run(move |db| Ok(db.execute(&sql, rusqlite::params_from_iter(params))? as u64))
            .await
    }
    pub(crate) async fn query(&self, sql: &str, params: impl Params) -> Result<Rows, Error> {
        let sql = sql.to_owned();
        let params = params.values();
        self.run(move |db| {
            let mut statement = db.prepare(&sql)?;
            let width = statement.column_count();
            let mut cursor = statement.query(rusqlite::params_from_iter(params))?;
            let mut result = VecDeque::new();
            let mut budget = 0usize;
            while let Some(row) = cursor.next()? {
                let mut values = Vec::with_capacity(width);
                for column in 0..width {
                    let value: Value = row.get(column)?;
                    budget += match &value {
                        Value::Text(s) => s.len(),
                        Value::Blob(b) => b.len(),
                        _ => 8,
                    } + 64;
                    if budget > 64 * 1024 * 1024 {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    values.push(value);
                }
                result.push_back(Row(values));
            }
            Ok(Rows(result))
        })
        .await
    }
    pub(crate) async fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        self.begin("BEGIN DEFERRED").await
    }
    pub(crate) async fn transaction_with_behavior(
        &mut self,
        _: TransactionBehavior,
    ) -> Result<Transaction<'_>, Error> {
        self.begin("BEGIN IMMEDIATE").await
    }
    async fn begin(&mut self, sql: &'static str) -> Result<Transaction<'_>, Error> {
        // Construct the cancellation guard BEFORE submitting BEGIN. This also
        // covers cancellation while BEGIN is queued or its response is pending.
        let abandoned = Arc::new(AtomicBool::new(false));
        self.context = Some(abandoned.clone());
        let tx = Transaction {
            connection: self,
            abandoned,
        };
        let state = tx.connection.state.clone();
        let flag = tx.abandoned.clone();
        tx.connection
            .run(move |db| {
                if flag.load(Ordering::SeqCst) {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                db.execute_batch(sql)?;
                *state.lock().map_err(|_| rusqlite::Error::InvalidQuery)? = Some(flag);
                Ok(())
            })
            .await?;
        Ok(tx)
    }
}

pub(crate) enum TransactionBehavior {
    Immediate,
}
pub(crate) struct Transaction<'a> {
    connection: &'a mut Connection,
    abandoned: Arc<AtomicBool>,
}
impl Deref for Transaction<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.connection
    }
}
impl Transaction<'_> {
    async fn end(self, sql: &'static str) -> Result<(), Error> {
        let state = self.connection.state.clone();
        self.connection
            .run(move |db| {
                db.execute_batch(sql)?;
                *state.lock().map_err(|_| rusqlite::Error::InvalidQuery)? = None;
                Ok(())
            })
            .await
    }
    pub(crate) async fn commit(self) -> Result<(), Error> {
        self.end("COMMIT").await
    }
    pub(crate) async fn rollback(self) -> Result<(), Error> {
        self.end("ROLLBACK").await
    }
}
impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        self.abandoned.store(true, Ordering::SeqCst);
        self.connection.context = None;
        let state = self.connection.state.clone();
        // If admission is full, an already queued job will perform this same
        // cleanup first. If idle, this wakes the worker to release write locks.
        let _ = self
            .connection
            .worker
            .try_run(move |db| cleanup(db, &state));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Stall the actual dedicated worker, not the Tokio executor.
    async fn stall(
        worker: Arc<Worker>,
    ) -> (std::sync::mpsc::Sender<()>, tokio::task::JoinHandle<()>) {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let task = tokio::spawn(async move {
            worker
                .run(move |_| {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                })
                .await
                .unwrap();
        });
        started_rx.await.unwrap();
        (release_tx, task)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_while_begin_is_queued_does_not_leak_transaction() {
        let database = Database::open(":memory:", None).await.unwrap();
        let mut connection = database.connect().unwrap();
        let (release, task) = stall(database.worker.clone()).await;
        {
            let begin = connection.transaction();
            tokio::pin!(begin);
            tokio::select! {
                biased;
                _ = &mut begin => panic!("BEGIN unexpectedly finished while worker stalled"),
                _ = tokio::task::yield_now() => {}
            }
            // Drop the future and its pre-admission guard while BEGIN is queued.
        }
        release.send(()).unwrap();
        task.await.unwrap();
        assert!(connection.run(|db| Ok(db.is_autocommit())).await.unwrap());
        connection
            .transaction()
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_before_queued_commit_executes_rolls_back() {
        let database = Database::open(":memory:", None).await.unwrap();
        let mut connection = database.connect().unwrap();
        let tx = connection.transaction().await.unwrap();
        tx.execute("INSERT INTO agents VALUES ('cancelled')", ())
            .await
            .unwrap();
        let (release, task) = stall(database.worker.clone()).await;
        {
            let commit = tx.commit();
            tokio::pin!(commit);
            tokio::select! {
                biased;
                _ = &mut commit => panic!("COMMIT unexpectedly finished while worker stalled"),
                _ = tokio::task::yield_now() => {}
            }
        }
        release.send(()).unwrap();
        task.await.unwrap();
        let mut rows = connection
            .query("SELECT count(*) FROM agents", ())
            .await
            .unwrap();
        assert_eq!(
            rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
            0
        );
        assert!(connection.run(|db| Ok(db.is_autocommit())).await.unwrap());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn abandoned_queued_write_cannot_execute_outside_its_transaction() {
        let database = Database::open(":memory:", None).await.unwrap();
        let mut connection = database.connect().unwrap();
        let tx = connection.transaction().await.unwrap();
        let (release, task) = stall(database.worker.clone()).await;
        {
            let write = tx.execute("INSERT INTO agents VALUES ('must-not-autocommit')", ());
            tokio::pin!(write);
            tokio::select! {
                biased;
                _ = &mut write => panic!("write finished while worker stalled"),
                _ = tokio::task::yield_now() => {}
            }
        }
        drop(tx);
        release.send(()).unwrap();
        task.await.unwrap();
        let mut rows = connection
            .query("SELECT count(*) FROM agents", ())
            .await
            .unwrap();
        assert_eq!(
            rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
            0
        );
        // The same connection must still support a subsequent valid transaction.
        let next = connection.transaction().await.unwrap();
        next.execute("INSERT INTO agents VALUES ('valid')", ())
            .await
            .unwrap();
        next.commit().await.unwrap();
    }
}
