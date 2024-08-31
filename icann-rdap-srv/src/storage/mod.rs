use async_trait::async_trait;
use buildstructor::Builder;
use icann_rdap_common::response::{
    autnum::Autnum, domain::Domain, entity::Entity, help::Help, nameserver::Nameserver,
    network::Network, RdapResponse,
};

use crate::error::RdapServerError;

use self::data::{AutnumId, DomainId, EntityId, NameserverId, NetworkId};

pub mod data;
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

    /// Gets a new transaction in which all the previous data has been truncated (cleared).
    async fn new_truncate_tx(&self) -> Result<Box<dyn TxHandle>, RdapServerError>;

    /// Get a domain from storage using the 'ldhName' as the key.
    async fn get_domain_by_ldh(&self, ldh: &str) -> Result<RdapResponse, RdapServerError>;

    /// Get a domain from storage using the 'unicodeName' as the key.
    async fn get_domain_by_unicode(&self, unicode: &str) -> Result<RdapResponse, RdapServerError>;

    /// Get an entity from storage using the 'handle' of the entity as the key.
    async fn get_entity_by_handle(&self, handle: &str) -> Result<RdapResponse, RdapServerError>;

    /// Get a nameserver from storage using the 'ldhName' as the key.
    async fn get_nameserver_by_ldh(&self, ldh: &str) -> Result<RdapResponse, RdapServerError>;

    /// Get an autnum from storage using an autonomous system numbers as the key.
    async fn get_autnum_by_num(&self, num: u32) -> Result<RdapResponse, RdapServerError>;

    /// Get a network from storage using an IP address. The network returned should be the
    /// most specific (longest prefix) network containing the IP address.
    async fn get_network_by_ipaddr(&self, ipaddr: &str) -> Result<RdapResponse, RdapServerError>;

    /// Get a network from storage using a CIDR notation network (e.g. "10.0.0.0/8"). The IP address
    /// portion of the CIDR should be assumed to be complete, that is not "10.0/8". The network
    /// returned should be the most specific (longest prefix) network containing the IP address.
    async fn get_network_by_cidr(&self, cidr: &str) -> Result<RdapResponse, RdapServerError>;

    /// Get server help.
    async fn get_srv_help(&self, host: Option<&str>) -> Result<RdapResponse, RdapServerError>;

    /// Search for domains by name.
    async fn search_domains_by_name(&self, name: &str) -> Result<RdapResponse, RdapServerError>;
}

/// Represents a handle to a transaction.
/// The implementation of the transaction
/// are dependent on the storage type.
#[async_trait]
pub trait TxHandle: Send {
    /// Add a domain name to storage.
    async fn add_domain(&mut self, domain: &Domain) -> Result<(), RdapServerError>;

    /// Add an error as a domain to storage. This is useful for specifying redirects.
    async fn add_domain_err(
        &mut self,
        domain_id: &DomainId,
        error: &icann_rdap_common::response::error::Error,
    ) -> Result<(), RdapServerError>;

    /// Add an entitty to storage.
    async fn add_entity(&mut self, entity: &Entity) -> Result<(), RdapServerError>;

    /// Add an error as an entity to storage. This is useful for specifying redirects.
    async fn add_entity_err(
        &mut self,
        entity_id: &EntityId,
        error: &icann_rdap_common::response::error::Error,
    ) -> Result<(), RdapServerError>;

    /// Add a nameserver to storage.
    async fn add_nameserver(&mut self, nameserver: &Nameserver) -> Result<(), RdapServerError>;

    /// Add an error as a nameserver to storage. This is useful for specifying redirects.
    async fn add_nameserver_err(
        &mut self,
        nameserver_id: &NameserverId,
        error: &icann_rdap_common::response::error::Error,
    ) -> Result<(), RdapServerError>;

    /// Add a nameserver to storage.
    async fn add_autnum(&mut self, autnum: &Autnum) -> Result<(), RdapServerError>;

    /// Add an error as an autnum to storage. This is useful for specifying redirects.
    async fn add_autnum_err(
        &mut self,
        autnum_id: &AutnumId,
        error: &icann_rdap_common::response::error::Error,
    ) -> Result<(), RdapServerError>;

    /// Add a network to storage.
    async fn add_network(&mut self, network: &Network) -> Result<(), RdapServerError>;

    /// Add a network as an autnum to storage. This is useful for specifying redirects.
    async fn add_network_err(
        &mut self,
        network_id: &NetworkId,
        error: &icann_rdap_common::response::error::Error,
    ) -> Result<(), RdapServerError>;

    async fn add_srv_help(
        &mut self,
        help: &Help,
        host: Option<&str>,
    ) -> Result<(), RdapServerError>;

    /// Commit the transaction.
    async fn commit(self: Box<Self>) -> Result<(), RdapServerError>;

    /// Rollback the transaction.
    async fn rollback(self: Box<Self>) -> Result<(), RdapServerError>;
}

/// Common configuration for storage back ends.
#[derive(Debug, Clone, Copy, Builder)]
pub struct CommonConfig {
    pub domain_search_by_name_enable: bool,
}

impl Default for CommonConfig {
    fn default() -> Self {
        CommonConfig {
            domain_search_by_name_enable: true,
        }
    }
}
