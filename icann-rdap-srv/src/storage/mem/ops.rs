use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use btree_range_map::RangeMap;
use icann_rdap_common::response::{
    autnum::Autnum, domain::Domain, entity::Entity, nameserver::Nameserver, network::Network,
};
use ipnet::{Ipv4Net, Ipv6Net};
use pinboard::NonEmptyPinboard;
use prefix_trie::PrefixMap;

use crate::{
    error::RdapServerError,
    rdap::response::{ArcRdapResponse, RdapServerResponse, NOT_FOUND},
    storage::{StoreOps, TxHandle},
};

use super::{config::MemConfig, state::load_state, tx::MemTx};

#[derive(Clone)]
pub struct Mem {
    pub(crate) autnums: Arc<NonEmptyPinboard<RangeMap<u32, Arc<Autnum>>>>,
    pub(crate) ip4: Arc<NonEmptyPinboard<PrefixMap<Ipv4Net, Arc<Network>>>>,
    pub(crate) ip6: Arc<NonEmptyPinboard<PrefixMap<Ipv6Net, Arc<Network>>>>,
    pub(crate) domains: Arc<NonEmptyPinboard<HashMap<String, Arc<Domain>>>>,
    pub(crate) nameservers: Arc<NonEmptyPinboard<HashMap<String, Arc<Nameserver>>>>,
    pub(crate) entities: Arc<NonEmptyPinboard<HashMap<String, Arc<Entity>>>>,
    pub(crate) config: MemConfig,
}

impl Mem {
    pub fn new(config: MemConfig) -> Self {
        Self {
            autnums: Arc::new(NonEmptyPinboard::new(RangeMap::new())),
            ip4: Arc::new(NonEmptyPinboard::new(PrefixMap::new())),
            ip6: Arc::new(NonEmptyPinboard::new(PrefixMap::new())),
            domains: Arc::new(NonEmptyPinboard::new(HashMap::new())),
            nameservers: Arc::new(NonEmptyPinboard::new(HashMap::new())),
            entities: Arc::new(NonEmptyPinboard::new(HashMap::new())),
            config,
        }
    }
}

impl Default for Mem {
    fn default() -> Self {
        Mem::new(
            MemConfig::builder()
                .state_dir("/tmp/rdap-srv/state")
                .build(),
        )
    }
}

#[async_trait]
impl StoreOps for Mem {
    async fn init(&self) -> Result<(), RdapServerError> {
        load_state(self).await?;
        Ok(())
    }

    async fn new_tx(&self) -> Result<Box<dyn TxHandle>, RdapServerError> {
        Ok(Box::new(MemTx::new(self)))
    }

    async fn get_domain_by_ldh(&self, ldh: &str) -> Result<RdapServerResponse, RdapServerError> {
        let domains = self.domains.get_ref();
        let result = domains.get(ldh);
        match result {
            Some(domain) => Ok(RdapServerResponse::Arc(ArcRdapResponse::Domain(
                domain.clone(),
            ))),
            None => Ok(NOT_FOUND.clone()),
        }
    }

    async fn get_entity_by_handle(
        &self,
        handle: &str,
    ) -> Result<RdapServerResponse, RdapServerError> {
        let entities = self.entities.get_ref();
        let result = entities.get(handle);
        match result {
            Some(entity) => Ok(RdapServerResponse::Arc(ArcRdapResponse::Entity(
                entity.clone(),
            ))),
            None => Ok(NOT_FOUND.clone()),
        }
    }
}
