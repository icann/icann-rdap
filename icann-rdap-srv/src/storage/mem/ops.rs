use std::{collections::HashMap, net::IpAddr, str::FromStr, sync::Arc};

use {
    async_trait::async_trait,
    btree_range_map::RangeMap,
    icann_rdap_common::{
        prelude::ToResponse,
        response::{
            Domain, DomainSearchResults, Nameserver, NameserverSearchResults, RdapResponse,
        },
    },
    ipnet::{IpNet, Ipv4Net, Ipv6Net},
    prefix_trie::PrefixMap,
    tokio::sync::RwLock,
};

use crate::{
    error::RdapServerError,
    rdap::response::{NOT_FOUND, NOT_IMPLEMENTED},
    storage::{CommonConfig, StoreOps, TxHandle},
};

use super::{config::MemConfig, label_search::SearchLabels, tx::MemTx};

#[derive(Clone)]
pub struct Mem {
    pub(crate) autnums: Arc<RwLock<RangeMap<u32, Arc<RdapResponse>>>>,
    pub(crate) ip4: Arc<RwLock<PrefixMap<Ipv4Net, Arc<RdapResponse>>>>,
    pub(crate) ip6: Arc<RwLock<PrefixMap<Ipv6Net, Arc<RdapResponse>>>>,
    pub(crate) domains: Arc<RwLock<HashMap<String, Arc<RdapResponse>>>>,
    pub(crate) domains_by_name: Arc<RwLock<SearchLabels<Arc<RdapResponse>>>>,
    pub(crate) domains_by_ns_ip: Arc<RwLock<HashMap<IpAddr, Vec<Arc<RdapResponse>>>>>,
    pub(crate) domains_by_ns_ldh_name: Arc<RwLock<SearchLabels<Arc<RdapResponse>>>>,
    pub(crate) idns: Arc<RwLock<HashMap<String, Arc<RdapResponse>>>>,
    pub(crate) nameservers: Arc<RwLock<HashMap<String, Arc<RdapResponse>>>>,
    pub(crate) nameservers_by_name: Arc<RwLock<SearchLabels<Arc<RdapResponse>>>>,
    pub(crate) nameservers_by_ip: Arc<RwLock<HashMap<IpAddr, Vec<Arc<RdapResponse>>>>>,
    pub(crate) entities: Arc<RwLock<HashMap<String, Arc<RdapResponse>>>>,
    pub(crate) srvhelps: Arc<RwLock<HashMap<String, Arc<RdapResponse>>>>,
    pub(crate) config: MemConfig,
}

impl Mem {
    pub fn new(config: MemConfig) -> Self {
        Self {
            autnums: <_>::default(),
            ip4: <_>::default(),
            ip6: <_>::default(),
            domains: <_>::default(),
            domains_by_name: Arc::new(RwLock::new(SearchLabels::builder().build())),
            domains_by_ns_ip: <_>::default(),
            domains_by_ns_ldh_name: Arc::new(RwLock::new(SearchLabels::builder().build())),
            idns: <_>::default(),
            nameservers: <_>::default(),
            nameservers_by_name: Arc::new(RwLock::new(SearchLabels::builder().build())),
            nameservers_by_ip: <_>::default(),
            entities: <_>::default(),
            srvhelps: <_>::default(),
            config,
        }
    }
}

impl Default for Mem {
    fn default() -> Self {
        Self::new(
            MemConfig::builder()
                .common_config(CommonConfig::default())
                .build(),
        )
    }
}

#[async_trait]
impl StoreOps for Mem {
    async fn init(&self) -> Result<(), RdapServerError> {
        Ok(())
    }

    async fn new_tx(&self) -> Result<Box<dyn TxHandle>, RdapServerError> {
        Ok(Box::new(MemTx::new(self).await))
    }

    async fn new_truncate_tx(&self) -> Result<Box<dyn TxHandle>, RdapServerError> {
        Ok(Box::new(MemTx::new_truncate(self)))
    }

    async fn get_domain_by_ldh(&self, ldh: &str) -> Result<RdapResponse, RdapServerError> {
        let domains = self.domains.read().await;
        let result = domains.get(ldh);
        match result {
            Some(domain) => Ok(RdapResponse::clone(domain)),
            None => Ok(NOT_FOUND.clone()),
        }
    }

    async fn get_domain_by_unicode(&self, unicode: &str) -> Result<RdapResponse, RdapServerError> {
        let idns = self.idns.read().await;
        let result = idns.get(unicode);
        match result {
            Some(domain) => Ok(RdapResponse::clone(domain)),
            None => Ok(NOT_FOUND.clone()),
        }
    }

    async fn get_entity_by_handle(&self, handle: &str) -> Result<RdapResponse, RdapServerError> {
        let entities = self.entities.read().await;
        let result = entities.get(handle);
        match result {
            Some(entity) => Ok(RdapResponse::clone(entity)),
            None => Ok(NOT_FOUND.clone()),
        }
    }

    async fn get_nameserver_by_ldh(&self, ldh: &str) -> Result<RdapResponse, RdapServerError> {
        let nameservers = self.nameservers.read().await;
        let result = nameservers.get(ldh);
        match result {
            Some(nameserver) => Ok(RdapResponse::clone(nameserver)),
            None => Ok(NOT_FOUND.clone()),
        }
    }

    async fn get_autnum_by_num(&self, num: u32) -> Result<RdapResponse, RdapServerError> {
        let autnums = self.autnums.read().await;
        let result = autnums.get(num);
        match result {
            Some(autnum) => Ok(RdapResponse::clone(autnum)),
            None => Ok(NOT_FOUND.clone()),
        }
    }

    async fn get_network_by_ipaddr(&self, ipaddr: &str) -> Result<RdapResponse, RdapServerError> {
        let addr = ipaddr.parse::<IpAddr>()?;
        match addr {
            IpAddr::V4(v4) => {
                let slash32 = Ipv4Net::new(v4, 32)?;
                let ip4s = self.ip4.read().await;
                let result = ip4s.get_lpm(&slash32);
                match result {
                    Some(network) => Ok(RdapResponse::clone(network.1)),
                    None => Ok(NOT_FOUND.clone()),
                }
            }
            IpAddr::V6(v6) => {
                let slash128 = Ipv6Net::new(v6, 128)?;
                let ip6s = self.ip6.read().await;
                let result = ip6s.get_lpm(&slash128);
                match result {
                    Some(network) => Ok(RdapResponse::clone(network.1)),
                    None => Ok(NOT_FOUND.clone()),
                }
            }
        }
    }

    async fn get_network_by_cidr(&self, cidr: &str) -> Result<RdapResponse, RdapServerError> {
        let net = IpNet::from_str(cidr)?;
        match net {
            IpNet::V4(ipv4net) => {
                let ip4s = self.ip4.read().await;
                let result = ip4s.get_lpm(&ipv4net);
                match result {
                    Some(network) => Ok(RdapResponse::clone(network.1)),
                    None => Ok(NOT_FOUND.clone()),
                }
            }
            IpNet::V6(ipv6net) => {
                let ip6s = self.ip6.read().await;
                let result = ip6s.get_lpm(&ipv6net);
                match result {
                    Some(network) => Ok(RdapResponse::clone(network.1)),
                    None => Ok(NOT_FOUND.clone()),
                }
            }
        }
    }

    async fn get_srv_help(&self, host: Option<&str>) -> Result<RdapResponse, RdapServerError> {
        let host = host.unwrap_or("..default");
        let srvhelps = self.srvhelps.read().await;
        let result = srvhelps.get(host);
        match result {
            Some(srvhelp) => Ok(RdapResponse::clone(srvhelp)),
            None => Ok(NOT_FOUND.clone()),
        }
    }

    async fn search_domains_by_name(&self, name: &str) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.domain_search_by_name_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        //else
        let domains_by_name = self.domains_by_name.read().await;
        let results = domains_by_name
            .search(name)
            .unwrap_or_default()
            .into_iter()
            .map(Arc::<RdapResponse>::unwrap_or_clone)
            .filter_map(|d| match d {
                RdapResponse::Domain(d) => Some(*d),
                _ => None,
            })
            .collect::<Vec<Domain>>();
        let response = DomainSearchResults::response_obj()
            .results(results)
            .build()
            .to_response();
        Ok(response)
    }

    async fn search_nameservers_by_name(
        &self,
        name: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.nameserver_search_by_name_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        //else
        let nameservers_by_name = self.nameservers_by_name.read().await;
        let results = nameservers_by_name
            .search(name)
            .unwrap_or_default()
            .into_iter()
            .map(Arc::<RdapResponse>::unwrap_or_clone)
            .filter_map(|n| match n {
                RdapResponse::Nameserver(ns) => Some(*ns),
                _ => None,
            })
            .collect::<Vec<Nameserver>>();
        let response = NameserverSearchResults::response_obj()
            .results(results)
            .build()
            .to_response();
        Ok(response)
    }

    async fn search_nameservers_by_ip(&self, ip: IpAddr) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.nameserver_search_by_ip_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        //else
        let nameservers_by_ip = self.nameservers_by_ip.read().await;
        let results: Vec<Nameserver> = nameservers_by_ip
            .get(&ip)
            .map(|vec| {
                vec.iter()
                    .map(|r| Arc::<RdapResponse>::unwrap_or_clone(r.clone()))
                    .filter_map(|n| match n {
                        RdapResponse::Nameserver(ns) => Some(*ns),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let response = NameserverSearchResults::response_obj()
            .results(results)
            .build()
            .to_response();
        Ok(response)
    }

    async fn search_domains_by_ns_ip(&self, ip: IpAddr) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.domain_search_by_ns_ip_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let domains_by_ns_ip = self.domains_by_ns_ip.read().await;
        let results: Vec<Domain> = domains_by_ns_ip
            .get(&ip)
            .map(|vec| {
                vec.iter()
                    .map(|r| Arc::<RdapResponse>::unwrap_or_clone(r.clone()))
                    .filter_map(|d| match d {
                        RdapResponse::Domain(dom) => Some(*dom),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let response = DomainSearchResults::response_obj()
            .results(results)
            .build()
            .to_response();
        Ok(response)
    }

    async fn search_domains_by_ns_ldh_name(
        &self,
        name: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self
            .config
            .common_config
            .domain_search_by_ns_ldh_name_enable
        {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let domains_by_ns_ldh_name = self.domains_by_ns_ldh_name.read().await;
        let results = domains_by_ns_ldh_name
            .search(name)
            .unwrap_or_default()
            .into_iter()
            .map(Arc::<RdapResponse>::unwrap_or_clone)
            .filter_map(|d| match d {
                RdapResponse::Domain(dom) => Some(*dom),
                _ => None,
            })
            .collect::<Vec<Domain>>();
        let response = DomainSearchResults::response_obj()
            .results(results)
            .build()
            .to_response();
        Ok(response)
    }
}
