#![allow(dead_code)] // TODO remove
use sqlx::PgPool;

use super::StorageOperations;

#[derive(Clone)]
pub struct Pg {
    pg_pool: PgPool,
}

impl Pg {
    pub fn new(pg_pool: PgPool) -> Self {
        Self { pg_pool }
    }
}

impl StorageOperations for Pg {}
