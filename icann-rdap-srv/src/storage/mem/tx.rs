use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use btree_range_map::RangeMap;
use icann_rdap_common::response::{
    autnum::Autnum, domain::Domain, entity::Entity, nameserver::Nameserver, network::Network,
};
use ipnet::{Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;

use crate::{error::RdapServerError, storage::TransactionHandle};

use super::ops::Mem;

pub struct Transaction {
    mem: Mem,
    autnums: RangeMap<u32, Autnum>,
    ip4: PrefixMap<Ipv4Net, Network>,
    ip6: PrefixMap<Ipv6Net, Network>,
    domains: HashMap<String, Domain>,
    nameservers: HashMap<String, Nameserver>,
    entities: HashMap<String, Entity>,
}

impl Transaction {
    pub fn new(mem: &Mem) -> Self {
        Self {
            mem: mem.clone(),
            autnums: Arc::clone(&mem.autnums).get_ref().clone(),
            ip4: Arc::clone(&mem.ip4).get_ref().clone(),
            ip6: Arc::clone(&mem.ip6).get_ref().clone(),
            domains: Arc::clone(&mem.domains).get_ref().clone(),
            nameservers: Arc::clone(&mem.nameservers).get_ref().clone(),
            entities: Arc::clone(&mem.entities).get_ref().clone(),
        }
    }
}

#[async_trait]
impl TransactionHandle for Transaction {
    async fn add_entity(&mut self, entity: &Entity) -> Result<(), RdapServerError> {
        let handle = entity
            .object_common
            .handle
            .as_ref()
            .ok_or_else(|| RdapServerError::EmptyIndexData("handle".to_string()))?;
        self.entities.insert(handle.to_owned(), entity.clone());
        Ok(())
    }
    async fn add_domain(&mut self, domain: &Domain) -> Result<(), RdapServerError> {
        let ldh_name = domain
            .ldh_name
            .as_ref()
            .ok_or_else(|| RdapServerError::EmptyIndexData("ldhName".to_string()))?;
        self.domains.insert(ldh_name.to_owned(), domain.clone());
        Ok(())
    }
    async fn commit(self: Box<Self>) -> Result<(), RdapServerError> {
        self.mem.autnums.set(self.autnums);
        self.mem.ip4.set(self.ip4);
        self.mem.ip6.set(self.ip6);
        self.mem.domains.set(self.domains);
        self.mem.nameservers.set(self.nameservers);
        self.mem.entities.set(self.entities);
        Ok(())
    }
    async fn rollback(self: Box<Self>) -> Result<(), RdapServerError> {
        // Nothing to do.
        Ok(())
    }
}
