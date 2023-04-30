#![allow(dead_code)] // TODO remove
use std::{
    collections::HashMap,
    sync::{atomic::AtomicPtr, Arc},
};

use btree_range_map::RangeMap;
use icann_rdap_common::response::{
    autnum::Autnum, domain::Domain, entity::Entity, nameserver::Nameserver, network::Network,
};
use ipnet::{Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;

use super::StorageOperations;

#[derive(Clone)]
pub struct Mem {
    autnums: Arc<AtomicPtr<RangeMap<u32, Autnum>>>,
    ip4: Arc<AtomicPtr<PrefixMap<Ipv4Net, Network>>>,
    ip6: Arc<AtomicPtr<PrefixMap<Ipv6Net, Network>>>,
    domains: Arc<AtomicPtr<HashMap<String, Domain>>>,
    nameservers: Arc<AtomicPtr<HashMap<String, Nameserver>>>,
    entities: Arc<AtomicPtr<HashMap<String, Entity>>>,
}

impl Mem {
    pub fn new() -> Self {
        Self {
            autnums: Arc::new(AtomicPtr::new(&mut RangeMap::new())),
            ip4: Arc::new(AtomicPtr::new(&mut PrefixMap::new())),
            ip6: Arc::new(AtomicPtr::new(&mut PrefixMap::new())),
            domains: Arc::new(AtomicPtr::new(&mut HashMap::new())),
            nameservers: Arc::new(AtomicPtr::new(&mut HashMap::new())),
            entities: Arc::new(AtomicPtr::new(&mut HashMap::new())),
        }
    }
}

impl Default for Mem {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageOperations for Mem {}
