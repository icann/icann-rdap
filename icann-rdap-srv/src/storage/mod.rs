use async_trait::async_trait;
use icann_rdap_common::response::{domain::Domain, entity::Entity};

use crate::{error::RdapServerError, rdap::response::RdapServerResponse};

pub mod mem;
pub mod pg;

#[async_trait]
pub trait StoreOps {
    /// Initializes the backend storage
    async fn init(&self) -> Result<(), RdapServerError>;

    /// Gets a new transaction.
    async fn new_tx(&self) -> Result<Box<dyn TxHandle>, RdapServerError>;

    async fn get_domain_by_ldh(&self, ldh: &str) -> Result<RdapServerResponse, RdapServerError>;

    async fn get_entity_by_handle(
        &self,
        handle: &str,
    ) -> Result<RdapServerResponse, RdapServerError>;
}

/// Represents a handle to a transaction.
/// The implementation of the transaction
/// are dependent on the storage type.
#[async_trait]
pub trait TxHandle: Send {
    async fn add_domain(&mut self, domain: &Domain) -> Result<(), RdapServerError>;
    async fn add_entity(&mut self, entity: &Entity) -> Result<(), RdapServerError>;
    async fn commit(self: Box<Self>) -> Result<(), RdapServerError>;
    async fn rollback(self: Box<Self>) -> Result<(), RdapServerError>;
}
