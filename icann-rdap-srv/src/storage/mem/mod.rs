#![allow(dead_code)] // TODO remove
use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use btree_range_map::RangeMap;
use icann_rdap_common::response::{
    autnum::Autnum, domain::Domain, entity::Entity, nameserver::Nameserver, network::Network,
};
use ipnet::{Ipv4Net, Ipv6Net};
use pinboard::NonEmptyPinboard;
use prefix_trie::PrefixMap;

use crate::error::RdapServerError;

use super::{StorageOperations, TransactionHandle};

#[derive(Clone)]
pub struct Mem {
    autnums: Arc<NonEmptyPinboard<RangeMap<u32, Autnum>>>,
    ip4: Arc<NonEmptyPinboard<PrefixMap<Ipv4Net, Network>>>,
    ip6: Arc<NonEmptyPinboard<PrefixMap<Ipv6Net, Network>>>,
    domains: Arc<NonEmptyPinboard<HashMap<String, Domain>>>,
    nameservers: Arc<NonEmptyPinboard<HashMap<String, Nameserver>>>,
    entities: Arc<NonEmptyPinboard<HashMap<String, Entity>>>,
}

impl Mem {
    pub fn new() -> Self {
        Self {
            autnums: Arc::new(NonEmptyPinboard::new(RangeMap::new())),
            ip4: Arc::new(NonEmptyPinboard::new(PrefixMap::new())),
            ip6: Arc::new(NonEmptyPinboard::new(PrefixMap::new())),
            domains: Arc::new(NonEmptyPinboard::new(HashMap::new())),
            nameservers: Arc::new(NonEmptyPinboard::new(HashMap::new())),
            entities: Arc::new(NonEmptyPinboard::new(HashMap::new())),
        }
    }
}

impl Default for Mem {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StorageOperations for Mem {
    async fn init(&self) -> Result<(), RdapServerError> {
        todo!()
    }

    async fn new_transaction(&self) -> Result<Box<dyn super::TransactionHandle>, RdapServerError> {
        Ok(Box::new(Transaction::new(self)))
    }
}

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
    fn new(mem: &Mem) -> Self {
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
    async fn commit(self) -> Result<(), RdapServerError> {
        self.mem.autnums.set(self.autnums);
        self.mem.ip4.set(self.ip4);
        self.mem.ip6.set(self.ip6);
        self.mem.domains.set(self.domains);
        self.mem.nameservers.set(self.nameservers);
        self.mem.entities.set(self.entities);
        Ok(())
    }
    async fn rollback(self) -> Result<(), RdapServerError> {
        // Nothing to do.
        Ok(())
    }
}
