use std::{collections::HashMap, net::IpAddr, str::FromStr, sync::Arc};

use icann_rdap_common::prelude::ObjectCommonFields;
use rangemap::RangeInclusiveMap;

use {
    async_trait::async_trait,
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
        TxHandle,
        data::{AutnumId, DomainId, EntityId, NameserverId, NetworkId},
    },
};

use super::{label_search::SearchLabels, ops::Mem};

pub struct MemTx {
    mem: Mem,
    autnums: RangeInclusiveMap<u32, Arc<RdapResponse>>,
    ip4: PrefixMap<Ipv4Net, Arc<RdapResponse>>,
    ip6: PrefixMap<Ipv6Net, Arc<RdapResponse>>,
    domains: HashMap<String, Arc<RdapResponse>>,
    domains_by_name: SearchLabels<Arc<RdapResponse>>,
    domains_by_ns_ip: HashMap<IpAddr, Vec<Arc<RdapResponse>>>,
    domains_by_ns_ldh_name: SearchLabels<Arc<RdapResponse>>,
    domains_by_ipv4: PrefixMap<Ipv4Net, Arc<RdapResponse>>,
    domains_by_ipv6: PrefixMap<Ipv6Net, Arc<RdapResponse>>,
    idns: HashMap<String, Arc<RdapResponse>>,
    nameservers: HashMap<String, Arc<RdapResponse>>,
    nameservers_by_name: SearchLabels<Arc<RdapResponse>>,
    nameservers_by_ip: HashMap<IpAddr, Vec<Arc<RdapResponse>>>,
    entities: HashMap<String, Arc<RdapResponse>>,
    entities_by_handle: SearchLabels<Arc<RdapResponse>>,
    entities_by_full_name: SearchLabels<Arc<RdapResponse>>,
    networks_by_handle: SearchLabels<Arc<RdapResponse>>,
    networks_by_name: SearchLabels<Arc<RdapResponse>>,
    autnums_by_handle: SearchLabels<Arc<RdapResponse>>,
    autnums_by_name: SearchLabels<Arc<RdapResponse>>,
    srvhelps: HashMap<String, Arc<RdapResponse>>,
}

impl MemTx {
    pub async fn new(mem: &Mem) -> Self {
        let domains = Arc::clone(&mem.domains).read_owned().await.clone();
        let mut domains_by_name = SearchLabels::dns_labels().build();
        let domains_by_ns_ip = Arc::clone(&mem.domains_by_ns_ip).read_owned().await.clone();
        let mut domains_by_ns_ldh_name = SearchLabels::dns_labels().build();
        let nameservers = Arc::clone(&mem.nameservers).read_owned().await.clone();
        let mut nameservers_by_name = SearchLabels::dns_labels().build();
        let nameservers_by_ip = Arc::clone(&mem.nameservers_by_ip)
            .read_owned()
            .await
            .clone();
        let entities = Arc::clone(&mem.entities).read_owned().await.clone();
        let mut entities_by_handle = SearchLabels::handle_labels().build();
        let mut entities_by_full_name = SearchLabels::name_labels().build();
        let ip4 = Arc::clone(&mem.ip4).read_owned().await.clone();
        let ip6 = Arc::clone(&mem.ip6).read_owned().await.clone();
        let mut networks_by_handle = SearchLabels::handle_labels().build();
        let mut networks_by_name = SearchLabels::name_labels().build();
        let mut autnums_by_handle = SearchLabels::handle_labels().build();
        let mut autnums_by_name = SearchLabels::name_labels().build();

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

        // only load up domain search by ns ldh name if supported
        if mem.config.common_config.domain_search_by_ns_ldh_name_enable {
            for (_name, value) in domains.iter() {
                if let RdapResponse::Domain(domain) = value.as_ref()
                    && let Some(nameservers) = domain.nameservers.as_ref()
                {
                    for ns in nameservers {
                        if let Some(ns_ldh_name) = ns.ldh_name.as_ref() {
                            domains_by_ns_ldh_name.insert(ns_ldh_name, value.clone());
                        }
                    }
                }
            }
        }

        // only load up entity search by handle if supported
        if mem.config.common_config.entity_search_by_handle_enable {
            for (handle, value) in entities.iter() {
                entities_by_handle.insert(handle, value.clone());
            }
        }

        if mem.config.common_config.entity_search_by_full_name_enable {
            for (_handle, value) in entities.iter() {
                if let RdapResponse::Entity(entity) = value.as_ref()
                    && let Some(contact) = entity.contact()
                    && let Some(full_name) = contact.full_name()
                {
                    entities_by_full_name.insert(full_name, value.clone());
                }
            }
        }

        if mem.config.common_config.network_search_by_handle_enable {
            for (_net, value) in ip4.iter() {
                if let RdapResponse::Network(network) = value.as_ref()
                    && let Some(handle) = network.handle()
                {
                    networks_by_handle.insert(handle, value.clone());
                }
            }
            for (_net, value) in ip6.iter() {
                if let RdapResponse::Network(network) = value.as_ref()
                    && let Some(handle) = network.handle()
                {
                    networks_by_handle.insert(handle, value.clone());
                }
            }
        }

        if mem.config.common_config.network_search_by_name_enable {
            for (_net, value) in ip4.iter() {
                if let RdapResponse::Network(network) = value.as_ref()
                    && let Some(name) = network.name()
                {
                    networks_by_name.insert(name, value.clone());
                }
            }
            for (_net, value) in ip6.iter() {
                if let RdapResponse::Network(network) = value.as_ref()
                    && let Some(name) = network.name()
                {
                    networks_by_name.insert(name, value.clone());
                }
            }
        }

        if mem.config.common_config.autnum_search_by_handle_enable {
            let autnums = mem.autnums.read().await;
            for (_range, value) in autnums.iter() {
                if let RdapResponse::Autnum(autnum) = value.as_ref()
                    && let Some(handle) = autnum.handle()
                {
                    autnums_by_handle.insert(handle, value.clone());
                }
            }
        }

        if mem.config.common_config.autnum_search_by_name_enable {
            let autnums = mem.autnums.read().await;
            for (_range, value) in autnums.iter() {
                if let RdapResponse::Autnum(autnum) = value.as_ref()
                    && let Some(name) = autnum.name()
                {
                    autnums_by_name.insert(name, value.clone());
                }
            }
        }

        Self {
            mem: mem.clone(),
            autnums: Arc::clone(&mem.autnums).read_owned().await.clone(),
            ip4: Arc::clone(&mem.ip4).read_owned().await.clone(),
            ip6: Arc::clone(&mem.ip6).read_owned().await.clone(),
            domains,
            domains_by_name,
            domains_by_ns_ip,
            domains_by_ns_ldh_name,
            domains_by_ipv4: Arc::clone(&mem.domains_by_ipv4).read_owned().await.clone(),
            domains_by_ipv6: Arc::clone(&mem.domains_by_ipv6).read_owned().await.clone(),
            idns: Arc::clone(&mem.idns).read_owned().await.clone(),
            nameservers,
            nameservers_by_name,
            nameservers_by_ip,
            entities,
            entities_by_handle,
            entities_by_full_name,
            networks_by_handle,
            networks_by_name,
            autnums_by_handle,
            autnums_by_name,
            srvhelps: Arc::clone(&mem.srvhelps).read_owned().await.clone(),
        }
    }

    pub fn new_truncate(mem: &Mem) -> Self {
        Self {
            mem: mem.clone(),
            autnums: RangeInclusiveMap::new(),
            ip4: PrefixMap::new(),
            ip6: PrefixMap::new(),
            domains: HashMap::new(),
            domains_by_name: SearchLabels::dns_labels().build(),
            domains_by_ns_ip: HashMap::new(),
            domains_by_ns_ldh_name: SearchLabels::dns_labels().build(),
            domains_by_ipv4: PrefixMap::new(),
            domains_by_ipv6: PrefixMap::new(),
            idns: HashMap::new(),
            nameservers: HashMap::new(),
            nameservers_by_name: SearchLabels::dns_labels().build(),
            nameservers_by_ip: HashMap::new(),
            entities: HashMap::new(),
            entities_by_handle: SearchLabels::handle_labels().build(),
            entities_by_full_name: SearchLabels::name_labels().build(),
            networks_by_handle: SearchLabels::handle_labels().build(),
            networks_by_name: SearchLabels::name_labels().build(),
            autnums_by_handle: SearchLabels::handle_labels().build(),
            autnums_by_name: SearchLabels::name_labels().build(),
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
        let entity_response = Arc::new(entity.clone().to_response());
        self.entities
            .insert(handle.to_owned().to_string(), entity_response.clone());
        if self.mem.config.common_config.entity_search_by_handle_enable {
            self.entities_by_handle
                .insert(handle, entity_response.clone());
        }
        if self
            .mem
            .config
            .common_config
            .entity_search_by_full_name_enable
            && let Some(contact) = entity.contact()
            && let Some(full_name) = contact.full_name()
        {
            self.entities_by_full_name
                .insert(full_name, entity_response.clone());
        }
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
            self.domains_by_name
                .insert(ldh_name, domain_response.clone());
        }

        if self.mem.config.common_config.domain_search_by_ns_ip_enable
            && let Some(nameservers) = domain.nameservers.as_ref()
        {
            for nameserver in nameservers {
                if let Some(ip_addresses) = nameserver.ip_addresses() {
                    for ip_str in ip_addresses.v4s() {
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            self.domains_by_ns_ip
                                .entry(ip)
                                .or_default()
                                .push(domain_response.clone());
                        }
                    }
                    for ip_str in ip_addresses.v6s() {
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            self.domains_by_ns_ip
                                .entry(ip)
                                .or_default()
                                .push(domain_response.clone());
                        }
                    }
                }
            }
        }

        if self
            .mem
            .config
            .common_config
            .domain_search_by_ns_ldh_name_enable
            && let Some(nameservers) = domain.nameservers.as_ref()
        {
            for nameserver in nameservers {
                if let Some(ldh_name) = nameserver.ldh_name.as_ref() {
                    self.domains_by_ns_ldh_name
                        .insert(ldh_name, domain_response.clone());
                }
            }
        }

        // Index reverse DNS domains by their embedded network IP prefix
        if let Some(network) = domain.network()
            && let Some(cidrs) = network.cidr0_cidrs().first()
            && let Some(prefix) = cidrs.prefix()
            && let Some(length) = cidrs.length()
            && let Some(ip_version) = network.ip_version()
        {
            if ip_version.eq_ignore_ascii_case("v4") {
                if let Ok(ipnet) = format!("{}/{}", prefix, length).parse::<Ipv4Net>() {
                    self.domains_by_ipv4.insert(ipnet, domain_response.clone());
                }
            } else if ip_version.eq_ignore_ascii_case("v6")
                && let Ok(ipnet) = format!("{}/{}", prefix, length).parse::<Ipv6Net>()
            {
                self.domains_by_ipv6.insert(ipnet, domain_response.clone());
            }
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
                .insert(ldh_name, nameserver_response.clone());
        }

        if self.mem.config.common_config.nameserver_search_by_ip_enable
            && let Some(ip_addresses) = nameserver.ip_addresses()
        {
            for ip_str in ip_addresses.v4s() {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    self.nameservers_by_ip
                        .entry(ip)
                        .or_default()
                        .push(nameserver_response.clone());
                }
            }
            for ip_str in ip_addresses.v6s() {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    self.nameservers_by_ip
                        .entry(ip)
                        .or_default()
                        .push(nameserver_response.clone());
                }
            }
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
        let autnum_response = Arc::new(autnum.clone().to_response());
        self.autnums
            .insert((start_num)..=(end_num), autnum_response.clone());
        if self.mem.config.common_config.autnum_search_by_handle_enable
            && let Some(handle) = autnum.handle()
        {
            self.autnums_by_handle
                .insert(handle, autnum_response.clone());
        }
        if self.mem.config.common_config.autnum_search_by_name_enable
            && let Some(name) = autnum.name()
        {
            self.autnums_by_name.insert(name, autnum_response);
        }
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
        let handle = network.object_common.handle.as_ref().map(|h| h.to_string());
        let network_response = Arc::new(network.clone().to_response());

        if self
            .mem
            .config
            .common_config
            .network_search_by_handle_enable
            && let Some(ref handle_str) = handle
        {
            self.networks_by_handle
                .insert(handle_str, network_response.clone());
        }

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
            if let Some(cidr0_cidrs) = &network.cidr0_cidrs {
                for cidr in cidr0_cidrs {
                    let prefix = cidr
                        .prefix()
                        .ok_or_else(|| RdapServerError::EmptyIndexData("cidr0prefix".to_string()))?;
                    let length = cidr
                        .length()
                        .ok_or_else(|| RdapServerError::EmptyIndexData("cidr0length".to_string()))?;
                    let cidr_str = format!("{}/{}", prefix, length);
                    let ipnet: Ipv4Net = cidr_str.parse()?;
                    self.ip4.insert(ipnet, network_response.clone());
                }
            } else {
                let subnets = Ipv4Subnets::new(start_addr.parse()?, end_addr.parse()?, 0);
                for net in subnets {
                    self.ip4.insert(net, network_response.clone());
                }
            }
        } else {
            if let Some(cidr0_cidrs) = &network.cidr0_cidrs {
                for cidr in cidr0_cidrs {
                    let prefix = cidr
                        .prefix()
                        .ok_or_else(|| RdapServerError::EmptyIndexData("cidr0prefix".to_string()))?;
                    let length = cidr
                        .length()
                        .ok_or_else(|| RdapServerError::EmptyIndexData("cidr0length".to_string()))?;
                    let cidr_str = format!("{}/{}", prefix, length);
                    let ipnet: Ipv6Net = cidr_str.parse()?;
                    self.ip6.insert(ipnet, network_response.clone());
                }
            } else {
                let subnets = Ipv6Subnets::new(start_addr.parse()?, end_addr.parse()?, 0);
                for net in subnets {
                    self.ip6.insert(net, network_response.clone());
                }
            }
        };

        if self.mem.config.common_config.network_search_by_name_enable
            && let Some(ref name) = network.name
        {
            self.networks_by_name.insert(name, network_response.clone());
        }

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

        //domains by nameserver ip
        let mut domains_by_ns_ip_g = self.mem.domains_by_ns_ip.write().await;
        std::mem::swap(&mut self.domains_by_ns_ip, &mut domains_by_ns_ip_g);

        //domains by nameserver ldhName
        let mut domains_by_ns_ldh_name_g = self.mem.domains_by_ns_ldh_name.write().await;
        std::mem::swap(
            &mut self.domains_by_ns_ldh_name,
            &mut domains_by_ns_ldh_name_g,
        );

        //domains by ipv4
        let mut domains_by_ipv4_g = self.mem.domains_by_ipv4.write().await;
        std::mem::swap(&mut self.domains_by_ipv4, &mut domains_by_ipv4_g);

        //domains by ipv6
        let mut domains_by_ipv6_g = self.mem.domains_by_ipv6.write().await;
        std::mem::swap(&mut self.domains_by_ipv6, &mut domains_by_ipv6_g);

        //idns
        let mut idns_g = self.mem.idns.write().await;
        std::mem::swap(&mut self.idns, &mut idns_g);

        // nameservers
        let mut nameservers_g = self.mem.nameservers.write().await;
        std::mem::swap(&mut self.nameservers, &mut nameservers_g);

        // nameservers by name
        let mut nameservers_by_name_g = self.mem.nameservers_by_name.write().await;
        std::mem::swap(&mut self.nameservers_by_name, &mut nameservers_by_name_g);

        // nameservers by ip
        let mut nameservers_by_ip_g = self.mem.nameservers_by_ip.write().await;
        std::mem::swap(&mut self.nameservers_by_ip, &mut nameservers_by_ip_g);

        // entities
        let mut entities_g = self.mem.entities.write().await;
        std::mem::swap(&mut self.entities, &mut entities_g);

        // entities by handle
        let mut entities_by_handle_g = self.mem.entities_by_handle.write().await;
        std::mem::swap(&mut self.entities_by_handle, &mut entities_by_handle_g);

        // entities by full name
        let mut entities_by_full_name_g = self.mem.entities_by_full_name.write().await;
        std::mem::swap(
            &mut self.entities_by_full_name,
            &mut entities_by_full_name_g,
        );

        // networks by handle
        let mut networks_by_handle_g = self.mem.networks_by_handle.write().await;
        std::mem::swap(&mut self.networks_by_handle, &mut networks_by_handle_g);

        // networks by name
        let mut networks_by_name_g = self.mem.networks_by_name.write().await;
        std::mem::swap(&mut self.networks_by_name, &mut networks_by_name_g);

        // autnums by handle
        let mut autnums_by_handle_g = self.mem.autnums_by_handle.write().await;
        std::mem::swap(&mut self.autnums_by_handle, &mut autnums_by_handle_g);

        // autnums by name
        let mut autnums_by_name_g = self.mem.autnums_by_name.write().await;
        std::mem::swap(&mut self.autnums_by_name, &mut autnums_by_name_g);

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use crate::storage::StoreOps;

    #[test]
    fn ipv4_subnets_min_prefix_len_0_produces_larger_networks() {
        // GIVEN
        // Range: 10.0.0.0 to 10.0.255.0 (256 addresses)
        // With min_prefix_len=0, Ipv4Subnets::new creates the largest possible networks
        // If all subnets were /32 (smallest), we'd get 256 subnets
        let start: Ipv4Addr = "10.0.0.0".parse().unwrap();
        let end: Ipv4Addr = "10.0.255.0".parse().unwrap();

        // WHEN
        let subnets: Vec<_> = Ipv4Subnets::new(start, end, 0).collect();

        // THEN
        // Should be far fewer than 256 because some are larger than /32
        dbg!(&subnets);
        assert!(
            subnets.len() < 256,
            "Expected fewer than 256 subnets (all /32), got {} - proving largest networks are used",
            subnets.len()
        );

        // Verify at least one subnet is larger than /32
        assert!(
            subnets.iter().any(|net| net.prefix_len() < 32),
            "At least one subnet should be larger than /32"
        );
    }

    #[test]
    fn ipv6_subnets_min_prefix_len_0_produces_larger_networks() {
        // GIVEN
        // Range: ::1 to ::100 (256 addresses)
        // With min_prefix_len=0, Ipv6Subnets::new creates the largest possible networks
        let start: Ipv6Addr = "::1".parse().unwrap();
        let end: Ipv6Addr = "::100".parse().unwrap();

        // WHEN
        let subnets: Vec<_> = Ipv6Subnets::new(start, end, 0).collect();

        // THEN
        // If all subnets were /128 (smallest), we'd get 256 subnets
        // Should be fewer because some are larger
        dbg!(&subnets);
        assert!(
            subnets.len() < 256,
            "Expected fewer than 256 subnets, got {} - proving largest networks are used",
            subnets.len()
        );

        // Verify at least one subnet is larger than /128
        assert!(
            subnets.iter().any(|net| net.prefix_len() < 128),
            "At least one subnet should be larger than /128"
        );
    }

    #[tokio::test]
    async fn add_network_uses_cidr0_for_ipv4() {
        // GIVEN a network with CIDR0 extension
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let network = Network::builder()
            .cidr("10.0.0.0/24")
            .handle("TEST-NET-4")
            .build()
            .expect("network build");

        // WHEN
        tx.add_network(&network).await.expect("add network");
        tx.commit().await.expect("commit");

        // THEN the CIDR0 prefix/length is used - only 10.0.0.0/24 is indexed
        let ip4 = mem.ip4.read().await;
        let count = ip4.iter().count();
        assert_eq!(count, 1, "expected exactly 1 subnet from CIDR0");
        let (entry, _) = ip4.iter().next().expect("should have entry");
        assert_eq!(entry.to_string(), "10.0.0.0/24");
    }

    #[tokio::test]
    async fn add_network_uses_cidr0_for_ipv6() {
        // GIVEN a network with CIDR0 extension
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let network = Network::builder()
            .cidr("2620:1ec::/36")
            .handle("TEST-NET-V6")
            .build()
            .expect("network build");

        // WHEN
        tx.add_network(&network).await.expect("add network");
        tx.commit().await.expect("commit");

        // THEN the CIDR0 prefix/length is used - only 2620:1ec::/36 is indexed
        let ip6 = mem.ip6.read().await;
        let count = ip6.iter().count();
        assert_eq!(count, 1, "expected exactly 1 subnet from CIDR0");
        let (entry, _) = ip6.iter().next().expect("should have entry");
        assert_eq!(entry.to_string(), "2620:1ec::/36");
    }

    #[tokio::test]
    async fn add_network_cidr0_absent_ipv4_fallback() {
        // GIVEN a network with cidr0_cidrs = None (no CIDR0 extension)
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let network = Network {
            common: icann_rdap_common::response::Common {
                rdap_conformance: None,
                notices: None,
            },
            object_common: icann_rdap_common::response::ObjectCommon {
                object_class_name: "ip network".to_string(),
                handle: Some("TEST-FALLBACK".into()),
                remarks: None,
                links: None,
                events: None,
                status: None,
                port_43: None,
                entities: None,
                redacted: None,
            },
            start_address: Some("10.0.0.0".to_string()),
            end_address: Some("10.0.0.255".to_string()),
            ip_version: Some("v4".to_string().into()),
            name: None,
            network_type: None,
            parent_handle: None,
            country: None,
            cidr0_cidrs: None,
        };

        // WHEN
        tx.add_network(&network).await.expect("add network");
        tx.commit().await.expect("commit");

        // THEN falls back to Ipv4Subnets::new - generates subnets from range
        let ip4 = mem.ip4.read().await;
        let count = ip4.iter().count();
        assert!(
            count > 0,
            "expected at least 1 subnet from Ipv4Subnets fallback, got {}",
            count
        );
    }

    #[tokio::test]
    async fn add_network_cidr0_absent_ipv6_fallback() {
        // GIVEN a network with cidr0_cidrs = None (no CIDR0 extension)
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let network = Network {
            common: icann_rdap_common::response::Common {
                rdap_conformance: None,
                notices: None,
            },
            object_common: icann_rdap_common::response::ObjectCommon {
                object_class_name: "ip network".to_string(),
                handle: Some("TEST-FALLBACK-V6".into()),
                remarks: None,
                links: None,
                events: None,
                status: None,
                port_43: None,
                entities: None,
                redacted: None,
            },
            start_address: Some("2001:db8::".to_string()),
            end_address: Some("2001:db8::ffff".to_string()),
            ip_version: Some("v6".to_string().into()),
            name: None,
            network_type: None,
            parent_handle: None,
            country: None,
            cidr0_cidrs: None,
        };

        // WHEN
        tx.add_network(&network).await.expect("add network");
        tx.commit().await.expect("commit");

        // THEN falls back to Ipv6Subnets::new - generates subnets from range
        let ip6 = mem.ip6.read().await;
        let count = ip6.iter().count();
        assert!(
            count > 0,
            "expected at least 1 subnet from Ipv6Subnets fallback, got {}",
            count
        );
    }

    #[tokio::test]
    async fn add_network_cidr0_missing_prefix_returns_error() {
        // GIVEN a network with CIDR0 entry that has no prefix
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let network = Network {
            common: icann_rdap_common::response::Common {
                rdap_conformance: None,
                notices: None,
            },
            object_common: icann_rdap_common::response::ObjectCommon {
                object_class_name: "ip network".to_string(),
                handle: Some("TEST-BAD-CIDR".into()),
                remarks: None,
                links: None,
                events: None,
                status: None,
                port_43: None,
                entities: None,
                redacted: None,
            },
            start_address: Some("10.0.0.0".to_string()),
            end_address: Some("10.0.0.255".to_string()),
            ip_version: Some("v4".to_string().into()),
            name: None,
            network_type: None,
            parent_handle: None,
            country: None,
            cidr0_cidrs: Some(vec![
                icann_rdap_common::prelude::Cidr0Cidr {
                    prefix: None,
                    length: Some(icann_rdap_common::response::Numberish::from(24u8)),
                },
            ]),
        };

        // WHEN
        let result = tx.add_network(&network).await;

        // THEN returns EmptyIndexData error for missing prefix
        assert!(result.is_err());
        match result.unwrap_err() {
            RdapServerError::EmptyIndexData(field) => assert_eq!(field, "cidr0prefix"),
            other => panic!("expected EmptyIndexData, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn add_network_cidr0_missing_length_returns_error() {
        // GIVEN a network with CIDR0 entry that has no length
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let network = Network {
            common: icann_rdap_common::response::Common {
                rdap_conformance: None,
                notices: None,
            },
            object_common: icann_rdap_common::response::ObjectCommon {
                object_class_name: "ip network".to_string(),
                handle: Some("TEST-BAD-CIDR2".into()),
                remarks: None,
                links: None,
                events: None,
                status: None,
                port_43: None,
                entities: None,
                redacted: None,
            },
            start_address: Some("10.0.0.0".to_string()),
            end_address: Some("10.0.0.255".to_string()),
            ip_version: Some("v4".to_string().into()),
            name: None,
            network_type: None,
            parent_handle: None,
            country: None,
            cidr0_cidrs: Some(vec![
                icann_rdap_common::prelude::Cidr0Cidr {
                    prefix: Some(
                        icann_rdap_common::prelude::Cidr0CidrPrefix::V4Prefix(
                            "10.0.0.0".to_string(),
                        ),
                    ),
                    length: None,
                },
            ]),
        };

        // WHEN
        let result = tx.add_network(&network).await;

        // THEN returns EmptyIndexData error for missing length
        assert!(result.is_err());
        match result.unwrap_err() {
            RdapServerError::EmptyIndexData(field) => assert_eq!(field, "cidr0length"),
            other => panic!("expected EmptyIndexData, got {:?}", other),
        }
    }
}
