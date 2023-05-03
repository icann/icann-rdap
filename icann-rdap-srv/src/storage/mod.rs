use async_trait::async_trait;
use icann_rdap_common::response::{domain::Domain, RdapResponse};

use crate::error::RdapServerError;

pub mod mem;
pub mod pg;

#[async_trait]
pub trait StorageOperations {
    /// Initializes the backend storage
    async fn init(&self) -> Result<(), RdapServerError>;

    /// Gets a new transaction.
    async fn new_transaction(&self) -> Result<Box<dyn TransactionHandle>, RdapServerError>;

    async fn get_domain_by_ldh(&self, ldh: &str) -> Result<RdapResponse, RdapServerError>;
}

/// Represents a handle to a transaction.
/// The implementation of the transaction
/// are dependent on the storage type.
#[async_trait]
pub trait TransactionHandle {
    async fn add_domain(&mut self, domain: &Domain) -> Result<(), RdapServerError>;
    async fn commit(self: Box<Self>) -> Result<(), RdapServerError>;
    async fn rollback(self: Box<Self>) -> Result<(), RdapServerError>;
}
