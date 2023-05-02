use async_trait::async_trait;

use crate::error::RdapServerError;

pub mod mem;
pub mod pg;

#[async_trait]
pub trait StorageOperations {
    /// Initializes the backend storage
    async fn init(&self) -> Result<(), RdapServerError>;

    /// Gets a new transaction.
    async fn new_transaction(&self) -> Result<Box<dyn TransactionHandle>, RdapServerError>;
}

/// Represents a handle to a transaction.
/// The implementation of the transaction
/// are dependent on the storage type.
#[async_trait]
pub trait TransactionHandle {
    async fn commit(self) -> Result<(), RdapServerError>;
    async fn rollback(self) -> Result<(), RdapServerError>;
}
