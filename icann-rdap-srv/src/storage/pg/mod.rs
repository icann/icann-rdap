#![allow(dead_code)] // TODO remove

use async_trait::async_trait;
use sqlx::{query, PgPool, Postgres};
use tracing::{debug, info};

use crate::error::RdapServerError;

use super::{StorageOperations, TransactionHandle};

#[derive(Clone)]
pub struct Pg {
    pg_pool: PgPool,
}

impl Pg {
    pub fn new(pg_pool: PgPool) -> Self {
        Self { pg_pool }
    }
}

#[async_trait]
impl StorageOperations for Pg {
    async fn init(&self) -> Result<(), RdapServerError> {
        debug!("Testing database connection.");
        let mut conn = self.pg_pool.acquire().await?;
        query("select 1").fetch_one(&mut conn).await?;
        info!("Database connection test is successful.");
        Ok(())
    }
    async fn new_transaction(&self) -> Result<Box<dyn super::TransactionHandle>, RdapServerError> {
        Ok(Box::new(Transaction::new(&self.pg_pool).await?))
    }
}

pub struct Transaction<'a> {
    db_tx: sqlx::Transaction<'a, Postgres>,
}

impl<'a> Transaction<'a> {
    async fn new(pg_pool: &PgPool) -> Result<Transaction<'a>, RdapServerError> {
        let db_tx = pg_pool.begin().await?;
        Ok(Transaction { db_tx })
    }
}

#[async_trait]
impl<'a> TransactionHandle for Transaction<'a> {
    async fn commit(self) -> Result<(), RdapServerError> {
        self.db_tx.commit().await?;
        Ok(())
    }
    async fn rollback(self) -> Result<(), RdapServerError> {
        self.db_tx.rollback().await?;
        Ok(())
    }
}
