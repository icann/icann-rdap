use std::{collections::HashMap, net::IpAddr, str::FromStr, sync::Arc};

use async_trait::async_trait;
use btree_range_map::RangeMap;
use icann_rdap_common::response::{
    autnum::Autnum, domain::Domain, entity::Entity, help::Help, nameserver::Nameserver,
    network::Network, RdapResponse,
};
use ipnet::{IpSubnets, Ipv4Net, Ipv4Subnets, Ipv6Net, Ipv6Subnets};
use prefix_trie::PrefixMap;

use crate::{
    error::RdapServerError,
    storage::{
        data::{AutnumId, DomainId, EntityId, NameserverId, NetworkId},
        TxHandle,
    },
};

use super::ops::Mem;

pub struct MemTx {
    mem: Mem,
    autnums: RangeMap<u32, Arc<RdapResponse>>,
    ip4: PrefixMap<Ipv4Net, Arc<RdapResponse>>,
    ip6: PrefixMap<Ipv6Net, Arc<RdapResponse>>,
    domains: HashMap<String, Arc<RdapResponse>>,
    nameservers: HashMap<String, Arc<RdapResponse>>,
    entities: HashMap<String, Arc<RdapResponse>>,
    srvhelps: HashMap<String, Arc<RdapResponse>>,
}

impl MemTx {
    pub async fn new(mem: &Mem) -> Self {
        Self {
            mem: mem.clone(),
            autnums: Arc::clone(&mem.autnums).read_owned().await.clone(),
            ip4: Arc::clone(&mem.ip4).read_owned().await.clone(),
            ip6: Arc::clone(&mem.ip6).read_owned().await.clone(),
            domains: Arc::clone(&mem.domains).read_owned().await.clone(),
            nameservers: Arc::clone(&mem.nameservers).read_owned().await.clone(),
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
            nameservers: HashMap::new(),
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
            handle.to_owned(),
            Arc::new(RdapResponse::Entity(entity.clone())),
        );
        Ok(())
    }

    async fn add_entity_err(
        &mut self,
        entity_id: &EntityId,
        error: &icann_rdap_common::response::error::Error,
    ) -> Result<(), RdapServerError> {
        self.entities.insert(
            entity_id.handle.to_owned(),
            Arc::new(RdapResponse::ErrorResponse(error.clone())),
        );
        Ok(())
    }

    async fn add_domain(&mut self, domain: &Domain) -> Result<(), RdapServerError> {
        let ldh_name = domain
            .ldh_name
            .as_ref()
            .ok_or_else(|| RdapServerError::EmptyIndexData("ldhName".to_string()))?;
        self.domains.insert(
            ldh_name.to_owned(),
            Arc::new(RdapResponse::Domain(domain.clone())),
        );
        Ok(())
    }

    async fn add_domain_err(
        &mut self,
        domain_id: &DomainId,
        error: &icann_rdap_common::response::error::Error,
    ) -> Result<(), RdapServerError> {
        self.domains.insert(
            domain_id.ldh_name.to_owned(),
            Arc::new(RdapResponse::ErrorResponse(error.clone())),
        );
        Ok(())
    }

    async fn add_nameserver(&mut self, nameserver: &Nameserver) -> Result<(), RdapServerError> {
        let ldh_name = nameserver
            .ldh_name
            .as_ref()
            .ok_or_else(|| RdapServerError::EmptyIndexData("ldhName".to_string()))?;
        self.nameservers.insert(
            ldh_name.to_owned(),
            Arc::new(RdapResponse::Nameserver(nameserver.clone())),
        );
        Ok(())
    }

    async fn add_nameserver_err(
        &mut self,
        nameserver_id: &NameserverId,
        error: &icann_rdap_common::response::error::Error,
    ) -> Result<(), RdapServerError> {
        self.nameservers.insert(
            nameserver_id.ldh_name.to_owned(),
            Arc::new(RdapResponse::ErrorResponse(error.clone())),
        );
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
        self.autnums.insert(
            (*start_num)..=(*end_num),
            Arc::new(RdapResponse::Autnum(autnum.clone())),
        );
        Ok(())
    }

    async fn add_autnum_err(
        &mut self,
        autnum_id: &AutnumId,
        error: &icann_rdap_common::response::error::Error,
    ) -> Result<(), RdapServerError> {
        self.autnums.insert(
            (autnum_id.start_autnum)..=(autnum_id.end_autnum),
            Arc::new(RdapResponse::ErrorResponse(error.clone())),
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
                    .insert(net, Arc::new(RdapResponse::Network(network.clone())));
            }
        } else {
            let subnets = Ipv6Subnets::new(start_addr.parse()?, end_addr.parse()?, 0);
            for net in subnets {
                self.ip6
                    .insert(net, Arc::new(RdapResponse::Network(network.clone())));
            }
        };
        Ok(())
    }

    async fn add_network_err(
        &mut self,
        network_id: &NetworkId,
        error: &icann_rdap_common::response::error::Error,
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
                    self.ip4
                        .insert(net, Arc::new(RdapResponse::ErrorResponse(error.clone())));
                }
            }
            IpSubnets::V6(subnets) => {
                for net in subnets {
                    self.ip6
                        .insert(net, Arc::new(RdapResponse::ErrorResponse(error.clone())));
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
            .insert(host.to_string(), Arc::new(RdapResponse::Help(help.clone())));
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

        // nameservers
        let mut nameservers_g = self.mem.nameservers.write().await;
        std::mem::swap(&mut self.nameservers, &mut nameservers_g);

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
