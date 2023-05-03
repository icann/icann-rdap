use async_trait::async_trait;
use icann_rdap_common::response::domain::Domain;
use sqlx::{PgPool, Postgres};

use crate::error::RdapServerError;

use super::TransactionHandle;

pub struct Transaction<'a> {
    db_tx: sqlx::Transaction<'a, Postgres>,
}

impl<'a> Transaction<'a> {
    pub async fn new(pg_pool: &PgPool) -> Result<Transaction<'a>, RdapServerError> {
        let db_tx = pg_pool.begin().await?;
        Ok(Transaction { db_tx })
    }
}

#[async_trait]
impl<'a> TransactionHandle for Transaction<'a> {
    async fn add_domain(&mut self, _domain: &Domain) -> Result<(), RdapServerError> {
        // TODO actually complete this
        // this is just here to make sure something will compile
        sqlx::query("insert domain")
            .execute(&mut self.db_tx)
            .await?;
        Ok(())
    }
    async fn commit(self: Box<Self>) -> Result<(), RdapServerError> {
        self.db_tx.commit().await?;
        Ok(())
    }
    async fn rollback(self: Box<Self>) -> Result<(), RdapServerError> {
        self.db_tx.rollback().await?;
        Ok(())
    }
}
