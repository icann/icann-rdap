use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use btree_range_map::RangeMap;
use icann_rdap_common::response::{
    autnum::Autnum, domain::Domain, entity::Entity, nameserver::Nameserver, network::Network,
};
use ipnet::{Ipv4Net, Ipv4Subnets, Ipv6Net, Ipv6Subnets};
use prefix_trie::PrefixMap;

use crate::{error::RdapServerError, storage::TxHandle};

use super::ops::Mem;

pub struct MemTx {
    mem: Mem,
    autnums: RangeMap<u32, Arc<Autnum>>,
    ip4: PrefixMap<Ipv4Net, Arc<Network>>,
    ip6: PrefixMap<Ipv6Net, Arc<Network>>,
    domains: HashMap<String, Arc<Domain>>,
    nameservers: HashMap<String, Arc<Nameserver>>,
    entities: HashMap<String, Arc<Entity>>,
}

impl MemTx {
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

    pub fn new_truncate(mem: &Mem) -> Self {
        Self {
            mem: mem.clone(),
            autnums: RangeMap::new(),
            ip4: PrefixMap::new(),
            ip6: PrefixMap::new(),
            domains: HashMap::new(),
            nameservers: HashMap::new(),
            entities: HashMap::new(),
        }
    }
}

#[async_trait]
impl TxHandle for MemTx {
    async fn add_entity(&mut self, entity: &Entity) -> Result<(), RdapServerError> {
        let handle = entity
            .object_common
            .handle
            .as_ref()
            .ok_or_else(|| RdapServerError::EmptyIndexData("handle".to_string()))?;
        self.entities
            .insert(handle.to_owned(), Arc::new(entity.clone()));
        Ok(())
    }

    async fn add_domain(&mut self, domain: &Domain) -> Result<(), RdapServerError> {
        let ldh_name = domain
            .ldh_name
            .as_ref()
            .ok_or_else(|| RdapServerError::EmptyIndexData("ldhName".to_string()))?;
        self.domains
            .insert(ldh_name.to_owned(), Arc::new(domain.clone()));
        Ok(())
    }

    async fn add_nameserver(&mut self, nameserver: &Nameserver) -> Result<(), RdapServerError> {
        let ldh_name = nameserver
            .ldh_name
            .as_ref()
            .ok_or_else(|| RdapServerError::EmptyIndexData("ldhName".to_string()))?;
        self.nameservers
            .insert(ldh_name.to_owned(), Arc::new(nameserver.clone()));
        Ok(())
    }

    async fn add_autnum(&mut self, autnum: &Autnum) -> Result<(), RdapServerError> {
        let start_num = autnum
            .start_autnum
            .as_ref()
            .ok_or_else(|| RdapServerError::EmptyIndexData("startNum".to_string()))?;
        let end_num = autnum
            .end_autnum
            .as_ref()
            .ok_or_else(|| RdapServerError::EmptyIndexData("endNum".to_string()))?;
        self.autnums
            .insert((*start_num)..=(*end_num), Arc::new(autnum.clone()));
        Ok(())
    }

    async fn add_network(&mut self, network: &Network) -> Result<(), RdapServerError> {
        let start_addr = network
            .start_address
            .as_ref()
            .ok_or_else(|| RdapServerError::EmptyIndexData("startAddress".to_string()))?;
        let end_addr = network
            .end_address
            .as_ref()
            .ok_or_else(|| RdapServerError::EmptyIndexData("endAddress".to_string()))?;
        let ip_type = network
            .ip_version
            .as_ref()
            .ok_or_else(|| RdapServerError::EmptyIndexData("ipVersion".to_string()))?;
        let is_v4 = ip_type.eq_ignore_ascii_case("v4");
        if is_v4 {
            let subnets = Ipv4Subnets::new(start_addr.parse()?, end_addr.parse()?, 0);
            for net in subnets {
                self.ip4.insert(net, Arc::new(network.clone()));
            }
        } else {
            let subnets = Ipv6Subnets::new(start_addr.parse()?, end_addr.parse()?, 0);
            for net in subnets {
                self.ip6.insert(net, Arc::new(network.clone()));
            }
        };
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
