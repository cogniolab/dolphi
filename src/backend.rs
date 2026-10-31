//! Private storage boundary. Raw SQL is never an agent capability.
#[cfg(all(feature = "turso-backend", feature = "sqlcipher-backend"))]
compile_error!(
    "select exactly one backend: use --no-default-features --features sqlcipher-backend"
);
#[cfg(not(any(feature = "turso-backend", feature = "sqlcipher-backend")))]
compile_error!("select one storage backend");

#[cfg(feature = "turso-backend")]
pub(crate) use turso::transaction::{Transaction, TransactionBehavior};
#[cfg(feature = "turso-backend")]
pub(crate) use turso::{Connection, Database, Error, Value, params_from_iter};

#[cfg(feature = "sqlcipher-backend")]
mod sqlcipher;
#[cfg(feature = "sqlcipher-backend")]
pub(crate) use sqlcipher::*;
