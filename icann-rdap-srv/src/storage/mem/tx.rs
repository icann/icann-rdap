use std::{collections::HashMap, net::IpAddr, str::FromStr, sync::Arc};

use {
    async_trait::async_trait,
    btree_range_map::RangeMap,
    icann_rdap_common::{
        prelude::ToResponse,
        response::{Autnum, Domain, Entity, Help, Nameserver, Network, RdapResponse, Rfc9083Error},
    },
    ipnet::{IpSubnets, Ipv4Net, Ipv4Subnets, Ipv6Net, Ipv6Subnets},
    prefix_trie::PrefixMap,
};

use crate::{
    error::RdapServerError,
    storage::{
        data::{AutnumId, DomainId, EntityId, NameserverId, NetworkId},
        TxHandle,
    },
};

use super::{label_search::SearchLabels, ops::Mem};

pub struct MemTx {
    mem: Mem,
    autnums: RangeMap<u32, Arc<RdapResponse>>,
    ip4: PrefixMap<Ipv4Net, Arc<RdapResponse>>,
    ip6: PrefixMap<Ipv6Net, Arc<RdapResponse>>,
    domains: HashMap<String, Arc<RdapResponse>>,
    domains_by_name: SearchLabels<Arc<RdapResponse>>,
    idns: HashMap<String, Arc<RdapResponse>>,
    nameservers: HashMap<String, Arc<RdapResponse>>,
    nameservers_by_name: SearchLabels<Arc<RdapResponse>>,
    entities: HashMap<String, Arc<RdapResponse>>,
    srvhelps: HashMap<String, Arc<RdapResponse>>,
}

impl MemTx {
    pub async fn new(mem: &Mem) -> Self {
        let domains = Arc::clone(&mem.domains).read_owned().await.clone();
        let mut domains_by_name = SearchLabels::builder().build();
        let nameservers = Arc::clone(&mem.nameservers).read_owned().await.clone();
        let mut nameservers_by_name = SearchLabels::builder().build();

        // only do load up domain search labels if search by domain names is supported
        if mem.config.common_config.domain_search_by_name_enable {
            for (name, value) in domains.iter() {
                domains_by_name.insert(name, value.clone());
            }
        }

        // only do load up nameserver search labels if search by nameserver names is supported
        if mem.config.common_config.nameserver_search_by_name_enable {
            for (name, value) in nameservers.iter() {
                nameservers_by_name.insert(name, value.clone());
            }
        }

        Self {
            mem: mem.clone(),
            autnums: Arc::clone(&mem.autnums).read_owned().await.clone(),
            ip4: Arc::clone(&mem.ip4).read_owned().await.clone(),
            ip6: Arc::clone(&mem.ip6).read_owned().await.clone(),
            domains,
            domains_by_name,
            idns: Arc::clone(&mem.idns).read_owned().await.clone(),
            nameservers,
            nameservers_by_name,
            entities: Arc::clone(&mem.entities).read_owned().await.clone(),
            srvhelps: Arc::clone(&mem.srvhelps).read_owned().await.clone(),
        }
    }

    pub fn new_truncate(mem: &Mem) -> Self {
        Self {
            mem: mem.clone(),
            autnums: RangeMap::new(),
            ip4: PrefixMap::new(),
            ip6: PrefixMap::new(),
            domains: HashMap::new(),
            domains_by_name: SearchLabels::builder().build(),
            idns: HashMap::new(),
            nameservers: HashMap::new(),
            nameservers_by_name: SearchLabels::builder().build(),
            entities: HashMap::new(),
            srvhelps: HashMap::new(),
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
        self.entities.insert(
            handle.to_owned().to_string(),
            Arc::new(entity.clone().to_response()),
        );
        Ok(())
    }

    async fn add_entity_err(
        &mut self,
        entity_id: &EntityId,
        error: &Rfc9083Error,
    ) -> Result<(), RdapServerError> {
        self.entities.insert(
            entity_id.handle.to_owned(),
            Arc::new(error.clone().to_response()),
        );
        Ok(())
    }

    async fn add_domain(&mut self, domain: &Domain) -> Result<(), RdapServerError> {
        let domain_response = Arc::new(domain.clone().to_response());

        // add the domain as LDH, which is required.
        let ldh_name = domain
            .ldh_name
            .as_ref()
            .ok_or_else(|| RdapServerError::EmptyIndexData("ldhName".to_string()))?;
        self.domains
            .insert(ldh_name.to_owned(), domain_response.clone());

        // add the domain by unicodeName
        if let Some(unicode_name) = domain.unicode_name.as_ref() {
            self.idns
                .insert(unicode_name.to_owned(), domain_response.clone());
        };

        if self.mem.config.common_config.domain_search_by_name_enable {
            self.domains_by_name.insert(ldh_name, domain_response);
        }

        Ok(())
    }

    async fn add_domain_err(
        &mut self,
        domain_id: &DomainId,
        error: &Rfc9083Error,
    ) -> Result<(), RdapServerError> {
        self.domains.insert(
            domain_id.ldh_name.to_owned(),
            Arc::new(error.clone().to_response()),
        );
        Ok(())
    }

    async fn add_nameserver(&mut self, nameserver: &Nameserver) -> Result<(), RdapServerError> {
        let ldh_name = nameserver
            .ldh_name
            .as_ref()
            .ok_or_else(|| RdapServerError::EmptyIndexData("ldhName".to_string()))?;
        let nameserver_response = Arc::new(nameserver.clone().to_response());
        self.nameservers
            .insert(ldh_name.to_owned(), nameserver_response.clone());

        if self
            .mem
            .config
            .common_config
            .nameserver_search_by_name_enable
        {
            self.nameservers_by_name
                .insert(ldh_name, nameserver_response);
        }

        Ok(())
    }

    async fn add_nameserver_err(
        &mut self,
        nameserver_id: &NameserverId,
        error: &Rfc9083Error,
    ) -> Result<(), RdapServerError> {
        self.nameservers.insert(
            nameserver_id.ldh_name.to_owned(),
            Arc::new(error.clone().to_response()),
        );
        Ok(())
    }

    async fn add_autnum(&mut self, autnum: &Autnum) -> Result<(), RdapServerError> {
        let start_num = autnum
            .start_autnum
            .as_ref()
            .and_then(|n| n.as_u32())
            .ok_or_else(|| RdapServerError::EmptyIndexData("startNum".to_string()))?;
        let end_num = autnum
            .end_autnum
            .as_ref()
            .and_then(|n| n.as_u32())
            .ok_or_else(|| RdapServerError::EmptyIndexData("endNum".to_string()))?;
        self.autnums.insert(
            (start_num)..=(end_num),
            Arc::new(autnum.clone().to_response()),
        );
        Ok(())
    }

    async fn add_autnum_err(
        &mut self,
        autnum_id: &AutnumId,
        error: &Rfc9083Error,
    ) -> Result<(), RdapServerError> {
        self.autnums.insert(
            (autnum_id.start_autnum)..=(autnum_id.end_autnum),
            Arc::new(error.clone().to_response()),
        );
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
                self.ip4
                    .insert(net, Arc::new(network.clone().to_response()));
            }
        } else {
            let subnets = Ipv6Subnets::new(start_addr.parse()?, end_addr.parse()?, 0);
            for net in subnets {
                self.ip6
                    .insert(net, Arc::new(network.clone().to_response()));
            }
        };
        Ok(())
    }

    async fn add_network_err(
        &mut self,
        network_id: &NetworkId,
        error: &Rfc9083Error,
    ) -> Result<(), RdapServerError> {
        let subnets = match &network_id.network_id {
            crate::storage::data::NetworkIdType::Cidr(cidr) => cidr.subnets(cidr.prefix_len())?,
            crate::storage::data::NetworkIdType::Range {
                start_address,
                end_address,
            } => {
                let start_addr = IpAddr::from_str(start_address)?;
                let end_addr = IpAddr::from_str(end_address)?;
                if start_addr.is_ipv4() && end_addr.is_ipv4() {
                    let IpAddr::V4(start_addr) = start_addr else {
                        panic!("check failed")
                    };
                    let IpAddr::V4(end_addr) = end_addr else {
                        panic!("check failed")
                    };
                    IpSubnets::from(Ipv4Subnets::new(start_addr, end_addr, 0))
                } else if start_addr.is_ipv6() && end_addr.is_ipv6() {
                    let IpAddr::V6(start_addr) = start_addr else {
                        panic!("check failed")
                    };
                    let IpAddr::V6(end_addr) = end_addr else {
                        panic!("check failed")
                    };
                    IpSubnets::from(Ipv6Subnets::new(start_addr, end_addr, 0))
                } else {
                    return Err(RdapServerError::EmptyIndexData(
                        "mismatch ip version".to_string(),
                    ));
                }
            }
        };
        match subnets {
            IpSubnets::V4(subnets) => {
                for net in subnets {
                    self.ip4.insert(net, Arc::new(error.clone().to_response()));
                }
            }
            IpSubnets::V6(subnets) => {
                for net in subnets {
                    self.ip6.insert(net, Arc::new(error.clone().to_response()));
                }
            }
        }
        Ok(())
    }

    async fn add_srv_help(
        &mut self,
        help: &Help,
        host: Option<&str>,
    ) -> Result<(), RdapServerError> {
        let host = host.unwrap_or("..default");
        self.srvhelps
            .insert(host.to_string(), Arc::new(help.clone().to_response()));
        Ok(())
    }

    async fn commit(mut self: Box<Self>) -> Result<(), RdapServerError> {
        // autnums
        let mut autnum_g = self.mem.autnums.write().await;
        std::mem::swap(&mut self.autnums, &mut autnum_g);

        // ip4
        let mut ip4_g = self.mem.ip4.write().await;
        std::mem::swap(&mut self.ip4, &mut ip4_g);

        // ip6
        let mut ip6_g = self.mem.ip6.write().await;
        std::mem::swap(&mut self.ip6, &mut ip6_g);

        // domains
        let mut domains_g = self.mem.domains.write().await;
        std::mem::swap(&mut self.domains, &mut domains_g);

        //domains by name
        let mut domains_by_name_g = self.mem.domains_by_name.write().await;
        std::mem::swap(&mut self.domains_by_name, &mut domains_by_name_g);

        //idns
        let mut idns_g = self.mem.idns.write().await;
        std::mem::swap(&mut self.idns, &mut idns_g);

        // nameservers
        let mut nameservers_g = self.mem.nameservers.write().await;
        std::mem::swap(&mut self.nameservers, &mut nameservers_g);

        // nameservers by name
        let mut nameservers_by_name_g = self.mem.nameservers_by_name.write().await;
        std::mem::swap(&mut self.nameservers_by_name, &mut nameservers_by_name_g);

        // entities
        let mut entities_g = self.mem.entities.write().await;
        std::mem::swap(&mut self.entities, &mut entities_g);

        //srvhelps
        let mut srvhelps_g = self.mem.srvhelps.write().await;
        std::mem::swap(&mut self.srvhelps, &mut srvhelps_g);

        Ok(())
    }

    async fn rollback(self: Box<Self>) -> Result<(), RdapServerError> {
        // Nothing to do.
        Ok(())
    }
}
