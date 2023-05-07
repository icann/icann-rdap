use async_trait::async_trait;
use icann_rdap_common::response::{domain::Domain, entity::Entity};

use crate::{error::RdapServerError, rdap::response::RdapServerResponse};

pub mod mem;
pub mod pg;

pub type DynStoreOps = dyn StoreOps + Send + Sync;

/// This trait defines the operations for a storage engine.
#[async_trait]
pub trait StoreOps: Send + Sync {
    /// Initializes the backend storage
    async fn init(&self) -> Result<(), RdapServerError>;

    /// Gets a new transaction.
    async fn new_tx(&self) -> Result<Box<dyn TxHandle>, RdapServerError>;

    /// Get a domain from storage using the 'ldhName' as the key.
    async fn get_domain_by_ldh(&self, ldh: &str) -> Result<RdapServerResponse, RdapServerError>;

    /// Get an entity from storage using the 'handle' of the entity as the key.
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
    /// Add a domain name to storage.
    async fn add_domain(&mut self, domain: &Domain) -> Result<(), RdapServerError>;

    /// Add an entitty to storage.
    async fn add_entity(&mut self, entity: &Entity) -> Result<(), RdapServerError>;

    /// Commit the transaction.
    async fn commit(self: Box<Self>) -> Result<(), RdapServerError>;

    /// Rollback the transaction.
    async fn rollback(self: Box<Self>) -> Result<(), RdapServerError>;
}
