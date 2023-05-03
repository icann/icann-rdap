use async_trait::async_trait;
use icann_rdap_common::response::RdapResponse;
use sqlx::{query, PgPool};
use tracing::{debug, info};

use crate::error::RdapServerError;

use super::{tx::Transaction, StorageOperations};

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
    async fn get_domain_by_ldh(&self, _ldh: &str) -> Result<RdapResponse, RdapServerError> {
        todo!()
    }
}
