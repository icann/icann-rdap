use std::net::IpAddr;
use std::ops::Range;
use std::sync::Arc;

use icann_rdap_common::{prelude::RdapResponse, rdns::reverse_dns_to_ipnet};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::{Prefix, PrefixMap};

use crate::storage::mem::ops::Mem;

pub trait RdapPrefix: Prefix + Copy {}

impl RdapPrefix for Ipv4Net {}

impl RdapPrefix for Ipv6Net {}

// Define an enum that holds either a single u32 or a Range<u32>
#[derive(Debug, Clone, PartialEq)]
pub enum U32OrRange {
    Single(u32),
    Range(Range<u32>),
}

fn get_ip_rdap_down<P: RdapPrefix + Copy + PartialEq, T: Clone>(
    map: &PrefixMap<P, T>,
    query: &P,
) -> Vec<T> {
    let mut immediate_children = Vec::new();
    let mut current_cover: Option<P> = None;

    for (prefix, value) in map.children(query) {
        if prefix == *query {
            continue; // Skip the exact match of the query itself
        }

        if let Some(cover) = current_cover
            && cover.contains(&prefix)
        {
            continue;
        }

        immediate_children.push(value.clone());
        current_cover = Some(prefix);
    }

    immediate_children
}

fn get_ip_rdap_bottom<P: RdapPrefix + Copy + PartialEq, T: Clone>(
    map: &PrefixMap<P, T>,
    query: &P,
) -> Vec<T> {
    let children: Vec<(P, T)> = map
        .children(query)
        .filter(|(p, _)| *p != *query)
        .map(|(p, v)| (p, v.clone()))
        .collect();

    if children.is_empty() {
        return Vec::new();
    }

    let mut leaves = Vec::new();
    for (i, (prefix, _)) in children.iter().enumerate() {
        let mut is_leaf = true;
        for (j, (other, _)) in children.iter().enumerate() {
            if i != j && prefix.contains(other) {
                is_leaf = false;
                break;
            }
        }
        if is_leaf {
            leaves.push(children[i].1.clone());
        }
    }

    leaves
}

fn get_domain_rdap_down<P: RdapPrefix + Copy + PartialEq, T: Clone>(
    map: &PrefixMap<P, T>,
    query: &P,
) -> Vec<T> {
    let mut immediate_children = Vec::new();
    let mut current_cover: Option<P> = None;

    for (prefix, value) in map.children(query) {
        if prefix == *query {
            continue;
        }

        if let Some(cover) = current_cover
            && cover.contains(&prefix)
        {
            continue;
        }

        immediate_children.push(value.clone());
        current_cover = Some(prefix);
    }

    immediate_children
}

fn get_domain_rdap_bottom<P: RdapPrefix + Copy + PartialEq, T: Clone>(
    map: &PrefixMap<P, T>,
    query: &P,
) -> Vec<T> {
    let children: Vec<(P, T)> = map
        .children(query)
        .filter(|(p, _)| *p != *query)
        .map(|(p, v)| (p, v.clone()))
        .collect();

    if children.is_empty() {
        return Vec::new();
    }

    let mut leaves = Vec::new();
    for (i, (prefix, _)) in children.iter().enumerate() {
        let mut is_leaf = true;
        for (j, (other, _)) in children.iter().enumerate() {
            if i != j && prefix.contains(other) {
                is_leaf = false;
                break;
            }
        }
        if is_leaf {
            leaves.push(children[i].1.clone());
        }
    }

    leaves
}

impl Mem {
    pub(crate) async fn ip_rdap_top(&self, query: &IpNet) -> Option<Arc<RdapResponse>> {
        match query {
            IpNet::V4(v4_query) => {
                let ip4s = self.ip4.read().await;
                ip4s.get_spm(v4_query).map(|r| r.1.clone())
            }
            IpNet::V6(v6_query) => {
                let ip6s = self.ip6.read().await;
                ip6s.get_spm(v6_query).map(|r| r.1.clone())
            }
        }
    }

    pub(crate) async fn ip_rdap_up(&self, query: &IpNet) -> Option<Arc<RdapResponse>> {
        match query {
            IpNet::V4(v4_query) => {
                let ip4s = self.ip4.read().await;
                if let Some((network_net, _)) = ip4s.get_lpm(v4_query) {
                    if let Some(supernet) = network_net.supernet() {
                        ip4s.get_lpm(&supernet).map(|r| r.1.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            IpNet::V6(v6_query) => {
                let ip6s = self.ip6.read().await;
                if let Some((network_net, _)) = ip6s.get_lpm(v6_query) {
                    if let Some(supernet) = network_net.supernet() {
                        ip6s.get_lpm(&supernet).map(|r| r.1.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        }
    }

    pub(crate) async fn ip_rdap_down(&self, query: &IpNet) -> Vec<Arc<RdapResponse>> {
        match query {
            IpNet::V4(v4_query) => {
                let ip4s = self.ip4.read().await;
                get_ip_rdap_down(&ip4s, v4_query)
            }
            IpNet::V6(v6_query) => {
                let ip6s = self.ip6.read().await;
                get_ip_rdap_down(&(*ip6s), v6_query)
            }
        }
    }

    pub(crate) async fn ip_rdap_bottom(&self, query: &IpNet) -> Vec<Arc<RdapResponse>> {
        match query {
            IpNet::V4(v4_query) => {
                let ip4s = self.ip4.read().await;
                get_ip_rdap_bottom(&(*ip4s), v4_query)
            }
            IpNet::V6(v6_query) => {
                let ip6s = self.ip6.read().await;
                get_ip_rdap_bottom(&(*ip6s), v6_query)
            }
        }
    }

    pub(crate) async fn autnum_rdap_up(&self, query: &U32OrRange) -> Option<Arc<RdapResponse>> {
        let autnums = self.autnums.read().await;
        match query {
            U32OrRange::Single(autnum) => autnums.get(autnum).cloned(),
            U32OrRange::Range(range) => {
                if let (Some(start), Some(end)) =
                    (autnums.get(&range.start), autnums.get(&range.end))
                {
                    if start == end {
                        Some(start.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        }
    }

    pub(crate) async fn autnum_rdap_top(&self, query: &U32OrRange) -> Option<Arc<RdapResponse>> {
        self.autnum_rdap_up(query).await
    }

    pub(crate) async fn autnum_rdap_down(&self, query: &U32OrRange) -> Vec<Arc<RdapResponse>> {
        let (start, end) = match query {
            U32OrRange::Single(autnum) => (*autnum, *autnum),
            U32OrRange::Range(range) => (range.start, range.end),
        };

        let autnums = self.autnums.read().await;

        autnums
            .overlapping(start..=end)
            .map(|(_r, a)| a.clone())
            .collect()
    }

    pub(crate) async fn autnum_rdap_bottom(&self, query: &U32OrRange) -> Vec<Arc<RdapResponse>> {
        self.autnum_rdap_down(query).await
    }

    pub(crate) async fn domain_rdap_top(&self, ldh: &str) -> Option<Arc<RdapResponse>> {
        if let Some(ip) = icann_rdap_common::rdns::reverse_dns_to_ip(ldh) {
            match ip {
                IpAddr::V4(v4) => {
                    let v4net = Ipv4Net::new(v4, 32).ok()?;
                    let domains = self.domains_by_ipv4.read().await;
                    domains.get_lpm(&v4net).map(|r| r.1.clone())
                }
                IpAddr::V6(v6) => {
                    let v6net = Ipv6Net::new(v6, 128).ok()?;
                    let domains = self.domains_by_ipv6.read().await;
                    domains.get_lpm(&v6net).map(|r| r.1.clone())
                }
            }
        } else {
            None
        }
    }

    pub(crate) async fn domain_rdap_up(&self, ldh: &str) -> Option<Arc<RdapResponse>> {
        if let Some(ip) = icann_rdap_common::rdns::reverse_dns_to_ip(ldh) {
            match ip {
                IpAddr::V4(v4) => {
                    let v4net = Ipv4Net::new(v4, 32).ok()?;
                    let domains = self.domains_by_ipv4.read().await;
                    if let Some((network_net, _)) = domains.get_lpm(&v4net) {
                        network_net
                            .supernet()
                            .and_then(|supernet| domains.get_lpm(&supernet).map(|r| r.1.clone()))
                    } else {
                        None
                    }
                }
                IpAddr::V6(v6) => {
                    let v6net = Ipv6Net::new(v6, 128).ok()?;
                    let domains = self.domains_by_ipv6.read().await;
                    if let Some((network_net, _)) = domains.get_lpm(&v6net) {
                        network_net
                            .supernet()
                            .and_then(|supernet| domains.get_lpm(&supernet).map(|r| r.1.clone()))
                    } else {
                        None
                    }
                }
            }
        } else {
            None
        }
    }

    pub(crate) async fn domain_rdap_down(&self, ldh: &str) -> Vec<Arc<RdapResponse>> {
        if let Some(ipnet) = reverse_dns_to_ipnet(ldh) {
            match ipnet {
                IpNet::V4(v4net) => {
                    let guard = self.domains_by_ipv4.read().await;
                    if let Some((container_prefix, _)) = guard.get_lpm(&v4net) {
                        get_domain_rdap_down(&*guard, &container_prefix)
                    } else {
                        Vec::new()
                    }
                }
                IpNet::V6(v6net) => {
                    let guard = self.domains_by_ipv6.read().await;
                    if let Some((container_prefix, _)) = guard.get_lpm(&v6net) {
                        get_domain_rdap_down(&*guard, &container_prefix)
                    } else {
                        Vec::new()
                    }
                }
            }
        } else {
            Vec::new()
        }
    }

    pub(crate) async fn domain_rdap_bottom(&self, ldh: &str) -> Vec<Arc<RdapResponse>> {
        if let Some(ipnet) = reverse_dns_to_ipnet(ldh) {
            match ipnet {
                IpNet::V4(v4net) => {
                    let guard = self.domains_by_ipv4.read().await;
                    get_domain_rdap_bottom(&*guard, &v4net)
                }
                IpNet::V6(v6net) => {
                    let guard = self.domains_by_ipv6.read().await;
                    get_domain_rdap_bottom(&*guard, &v6net)
                }
            }
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {

    use super::U32OrRange;
    use icann_rdap_common::prelude::{Autnum, Domain, Network, RdapResponse};
    use std::str::FromStr;

    use crate::storage::{StoreOps, mem::ops::Mem};

    #[tokio::test]
    async fn test_ip_rdap_top_with_ordered_insertion() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let cidrs = ["10.1.0.0/8", "10.1.0.0/16", "10.1.0.0/24"];
        for cidr in cidrs {
            tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
                .await
                .expect("add network in tx");
        }
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.ip_rdap_top(&("10.1.0.1/32".parse().unwrap())).await;

        // THEN
        let actual = result.unwrap();
        let RdapResponse::Network(ref actual) = *actual else {
            panic!("not a network")
        };
        let actual = actual.cidr0_cidrs().first().expect("empty cidrs");
        assert_eq!(actual.prefix().expect("prefix"), "10.0.0.0");
        assert_eq!(actual.length().expect("length"), 8);
    }

    #[tokio::test]
    async fn test_ip_rdap_up() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let cidrs = ["10.1.0.0/8", "10.1.0.0/16", "10.1.0.0/24"];
        for cidr in cidrs {
            tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
                .await
                .expect("add network in tx");
        }
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.ip_rdap_up(&("10.1.0.1/24".parse().unwrap())).await;

        // THEN
        let actual = result.unwrap();
        let RdapResponse::Network(ref actual) = *actual else {
            panic!("not a network")
        };
        let actual = actual.cidr0_cidrs().first().expect("empty cidrs");
        assert_eq!(actual.prefix().expect("prefix"), "10.1.0.0");
        assert_eq!(actual.length().expect("length"), 16);
    }

    #[tokio::test]
    async fn test_ip_rdap_top_empty() {
        // GIVEN
        let mem = Mem::default();

        // WHEN
        let result = mem.ip_rdap_top(&("10.1.0.1/32".parse().unwrap())).await;

        // THEN
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_ip_rdap_top_ipv6() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let cidrs = ["2001:db8::/32", "2001:db8:1::/48", "2001:db8:1::/64"];
        for cidr in cidrs {
            tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
                .await
                .expect("add network in tx");
        }
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem
            .ip_rdap_top(&("2001:db8:1::1/128".parse().unwrap()))
            .await;

        // THEN
        let actual = result.unwrap();
        let RdapResponse::Network(ref actual) = *actual else {
            panic!("not a network")
        };
        let actual = actual.cidr0_cidrs().first().expect("empty cidrs");
        assert_eq!(actual.prefix().expect("prefix"), "2001:db8::");
        assert_eq!(actual.length().expect("length"), 32);
    }

    #[tokio::test]
    async fn test_ip_rdap_top_unordered() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let cidrs = ["10.1.0.0/24", "10.1.0.0/16", "10.0.0.0/8"];
        for cidr in cidrs {
            tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
                .await
                .expect("add network in tx");
        }
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.ip_rdap_top(&("10.1.0.1/32".parse().unwrap())).await;

        // THEN
        let actual = result.unwrap();
        let RdapResponse::Network(ref actual) = *actual else {
            panic!("not a network")
        };
        let actual = actual.cidr0_cidrs().first().expect("empty cidrs");
        assert_eq!(actual.prefix().expect("prefix"), "10.0.0.0");
        assert_eq!(actual.length().expect("length"), 8);
    }

    #[tokio::test]
    async fn test_ip_rdap_top_multiple_hierarchies() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let cidrs = ["10.0.0.0/8", "10.1.0.0/16", "192.0.0.0/8", "192.168.0.0/16"];
        for cidr in cidrs {
            tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
                .await
                .expect("add network in tx");
        }
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.ip_rdap_top(&("10.1.0.1/32".parse().unwrap())).await;

        // THEN
        let actual = result.unwrap();
        let RdapResponse::Network(ref actual) = *actual else {
            panic!("not a network")
        };
        let actual = actual.cidr0_cidrs().first().expect("empty cidrs");
        assert_eq!(actual.prefix().expect("prefix"), "10.0.0.0");
    }

    #[tokio::test]
    async fn test_ip_rdap_top_outside_range() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let cidrs = ["10.0.0.0/8"];
        for cidr in cidrs {
            tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
                .await
                .expect("add network in tx");
        }
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.ip_rdap_top(&("192.168.1.1/32".parse().unwrap())).await;

        // THEN
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_ip_rdap_up_root_network() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let cidrs = ["10.0.0.0/8"];
        for cidr in cidrs {
            tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
                .await
                .expect("add network in tx");
        }
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.ip_rdap_up(&("10.0.0.0/8".parse().unwrap())).await;

        // THEN
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_ip_rdap_up_ipv6() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let cidrs = ["2001:db8::/32", "2001:db8:1::/48", "2001:db8:1::/64"];
        for cidr in cidrs {
            tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
                .await
                .expect("add network in tx");
        }
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.ip_rdap_up(&("2001:db8:1::/64".parse().unwrap())).await;

        // THEN
        let actual = result.unwrap();
        let RdapResponse::Network(ref actual) = *actual else {
            panic!("not a network")
        };
        let actual = actual.cidr0_cidrs().first().expect("empty cidrs");
        assert_eq!(actual.prefix().expect("prefix"), "2001:db8:1::");
        assert_eq!(actual.length().expect("length"), 48);
    }

    #[tokio::test]
    async fn test_ip_rdap_up_multiple_levels() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let cidrs = ["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.1.2.128/25"];
        for cidr in cidrs {
            tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
                .await
                .expect("add network in tx");
        }
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.ip_rdap_up(&("10.1.2.128/25".parse().unwrap())).await;

        // THEN
        let actual = result.unwrap();
        let RdapResponse::Network(ref actual) = *actual else {
            panic!("not a network")
        };
        let actual = actual.cidr0_cidrs().first().expect("empty cidrs");
        assert_eq!(actual.prefix().expect("prefix"), "10.1.2.0");
        assert_eq!(actual.length().expect("length"), 24);
    }

    #[tokio::test]
    async fn test_ip_rdap_up_outside_range() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let cidrs = ["10.0.0.0/8"];
        for cidr in cidrs {
            tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
                .await
                .expect("add network in tx");
        }
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.ip_rdap_up(&("192.168.1.1/32".parse().unwrap())).await;

        // THEN
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_ip_rdap_down_empty() {
        // GIVEN
        let mem = Mem::default();

        // WHEN
        let result = mem.ip_rdap_down(&("10.0.0.0/8".parse().unwrap())).await;

        // THEN
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_ip_rdap_down_no_children() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        tx.add_network(
            &Network::builder()
                .cidr("10.0.0.0/24")
                .build()
                .expect("cidr parsing"),
        )
        .await
        .expect("add network in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.ip_rdap_down(&("10.0.0.0/24".parse().unwrap())).await;

        // THEN
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_ip_rdap_down_single_level() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let cidrs = ["10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24", "10.1.1.128/25"];
        for cidr in cidrs {
            tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
                .await
                .expect("add network in tx");
        }
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.ip_rdap_down(&("10.0.0.0/8".parse().unwrap())).await;

        // THEN
        assert_eq!(result.len(), 1);
        let RdapResponse::Network(ref net) = *result[0] else {
            panic!("not a network")
        };
        let cidr = net.cidr0_cidrs().first().expect("empty cidrs");
        assert_eq!(cidr.prefix().expect("prefix"), "10.1.0.0");
        assert_eq!(cidr.length().expect("length"), 16);
    }

    #[tokio::test]
    async fn test_ip_rdap_down_ipv6() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let cidrs = ["2001:db8::/32", "2001:db8:1::/48", "2001:db8:2::/48"];
        for cidr in cidrs {
            tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
                .await
                .expect("add network in tx");
        }
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.ip_rdap_down(&("2001:db8::/32".parse().unwrap())).await;

        // THEN
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_ip_rdap_down_query_exact_match() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let cidrs = ["10.0.0.0/16", "10.0.1.0/24", "10.0.2.0/24"];
        for cidr in cidrs {
            tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
                .await
                .expect("add network in tx");
        }
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.ip_rdap_down(&("10.0.0.0/16".parse().unwrap())).await;

        // THEN
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_ip_rdap_down_multiple_hierarchies() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let cidrs = ["10.0.0.0/8", "10.1.0.0/16", "192.0.0.0/8", "192.168.0.0/16"];
        for cidr in cidrs {
            tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
                .await
                .expect("add network in tx");
        }
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.ip_rdap_down(&("10.0.0.0/8".parse().unwrap())).await;

        // THEN
        assert_eq!(result.len(), 1);
        let RdapResponse::Network(ref net) = *result[0] else {
            panic!("not a network")
        };
        let cidr = net.cidr0_cidrs().first().expect("empty cidrs");
        assert_eq!(cidr.prefix().expect("prefix"), "10.1.0.0");
    }

    #[tokio::test]
    async fn test_ip_rdap_bottom_nested_leaves() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let cidrs = ["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.1.2.128/25"];
        for cidr in cidrs {
            tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
                .await
                .expect("add network in tx");
        }
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.ip_rdap_bottom(&("10.0.0.0/8".parse().unwrap())).await;

        // THEN
        assert_eq!(result.len(), 1);
        let RdapResponse::Network(ref net) = *result[0] else {
            panic!("not a network")
        };
        let cidr = net.cidr0_cidrs().first().expect("empty cidrs");
        assert_eq!(cidr.prefix().expect("prefix"), "10.1.2.128");
    }

    #[tokio::test]
    async fn test_ip_rdap_bottom_outside_range() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        tx.add_network(
            &Network::builder()
                .cidr("10.0.0.0/8")
                .build()
                .expect("cidr parsing"),
        )
        .await
        .expect("add network in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem
            .ip_rdap_bottom(&("192.168.1.0/24".parse().unwrap()))
            .await;

        // THEN
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_ip_rdap_bottom_single_network_no_descendants() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        tx.add_network(
            &Network::builder()
                .cidr("10.0.0.0/8")
                .build()
                .expect("cidr parsing"),
        )
        .await
        .expect("add network in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.ip_rdap_bottom(&("10.0.0.0/8".parse().unwrap())).await;

        // THEN
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_autnum_rdap_up_empty() {
        // GIVEN
        let mem = Mem::default();

        // WHEN
        let result = mem.autnum_rdap_up(&U32OrRange::Single(700)).await;

        // THEN
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_autnum_rdap_up_single_exact_match() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
            .await
            .expect("add autnum in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.autnum_rdap_up(&U32OrRange::Single(705)).await;

        // THEN
        let actual = result.unwrap();
        let RdapResponse::Autnum(ref autnum) = *actual else {
            panic!("not an autnum")
        };
        assert_eq!(autnum.start_autnum(), Some(700));
        assert_eq!(autnum.end_autnum(), Some(710));
    }

    #[tokio::test]
    async fn test_autnum_rdap_up_range_exact_match() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
            .await
            .expect("add autnum in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.autnum_rdap_up(&U32OrRange::Range(700..710)).await;

        // THEN
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_autnum_rdap_up_range_too_large() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
            .await
            .expect("add autnum in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.autnum_rdap_up(&U32OrRange::Range(700..719)).await;

        // THEN
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_autnum_rdap_up_range_same_start_end() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
            .await
            .expect("add autnum in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.autnum_rdap_up(&U32OrRange::Range(700..700)).await;

        // THEN
        let actual = result.unwrap();
        let RdapResponse::Autnum(ref autnum) = *actual else {
            panic!("not an autnum")
        };
        assert_eq!(autnum.start_autnum(), Some(700));
    }

    #[tokio::test]
    async fn test_autnum_rdap_up_non_existent() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
            .await
            .expect("add autnum in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.autnum_rdap_up(&U32OrRange::Single(800)).await;

        // THEN
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_autnum_rdap_top_empty() {
        // GIVEN
        let mem = Mem::default();

        // WHEN
        let result = mem.autnum_rdap_top(&U32OrRange::Single(700)).await;

        // THEN
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_autnum_rdap_top_single() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
            .await
            .expect("add autnum in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.autnum_rdap_top(&U32OrRange::Single(705)).await;

        // THEN
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_autnum_rdap_down_empty() {
        // GIVEN
        let mem = Mem::default();

        // WHEN
        let result = mem.autnum_rdap_down(&U32OrRange::Single(700)).await;

        // THEN
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_autnum_rdap_down_no_children() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
            .await
            .expect("add autnum in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.autnum_rdap_down(&U32OrRange::Single(705)).await;

        // THEN
        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn test_autnum_rdap_down_two_children() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        tx.add_autnum(&Autnum::builder().autnum_range(700..709).build())
            .await
            .expect("add autnum in tx");
        tx.add_autnum(&Autnum::builder().autnum_range(710..719).build())
            .await
            .expect("add autnum in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.autnum_rdap_down(&U32OrRange::Single(700)).await;

        // THEN
        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn test_autnum_rdap_down_multiple_children() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        tx.add_autnum(&Autnum::builder().autnum_range(700..709).build())
            .await
            .expect("add autnum in tx");
        tx.add_autnum(&Autnum::builder().autnum_range(710..719).build())
            .await
            .expect("add autnum in tx");
        tx.add_autnum(&Autnum::builder().autnum_range(720..729).build())
            .await
            .expect("add autnum in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.autnum_rdap_down(&U32OrRange::Single(700)).await;

        // THEN
        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn test_autnum_rdap_down_range_end_greater() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        tx.add_autnum(&Autnum::builder().autnum_range(700..709).build())
            .await
            .expect("add autnum in tx");
        tx.add_autnum(&Autnum::builder().autnum_range(710..719).build())
            .await
            .expect("add autnum in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.autnum_rdap_down(&U32OrRange::Range(700..720)).await;

        // THEN
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_autnum_rdap_down_range_start_lesser() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        tx.add_autnum(&Autnum::builder().autnum_range(700..709).build())
            .await
            .expect("add autnum in tx");
        tx.add_autnum(&Autnum::builder().autnum_range(710..719).build())
            .await
            .expect("add autnum in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.autnum_rdap_down(&U32OrRange::Range(699..719)).await;

        // THEN
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_autnum_rdap_down_exact_range() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        tx.add_autnum(&Autnum::builder().autnum_range(700..709).build())
            .await
            .expect("add autnum in tx");
        tx.add_autnum(&Autnum::builder().autnum_range(710..719).build())
            .await
            .expect("add autnum in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.autnum_rdap_down(&U32OrRange::Range(700..719)).await;

        // THEN
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_autnum_rdap_bottom_empty() {
        // GIVEN
        let mem = Mem::default();

        // WHEN
        let result = mem.autnum_rdap_bottom(&U32OrRange::Single(700)).await;

        // THEN
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_autnum_rdap_bottom_with_children() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        tx.add_autnum(&Autnum::builder().autnum_range(700..709).build())
            .await
            .expect("add autnum in tx");
        tx.add_autnum(&Autnum::builder().autnum_range(710..719).build())
            .await
            .expect("add autnum in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.autnum_rdap_bottom(&U32OrRange::Single(700)).await;

        // THEN
        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn test_domain_rdap_top_empty() {
        // GIVEN
        let mem = Mem::default();

        // WHEN
        let result = mem.domain_rdap_top("1.0.0.10.in-addr.arpa").await;

        // THEN
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_domain_rdap_top_ipv4() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let domain = Domain::builder()
            .ldh_name("10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.0.0.0/8")
                    .build()
                    .expect("cidr parsing"),
            )
            .build();
        tx.add_domain(&domain).await.expect("add domain in tx");
        tx.commit().await.expect("tx commit");

        // IP 10.1.2.3 in reverse DNS is "3.2.1.10.in-addr.arpa"
        // WHEN
        let result = mem.domain_rdap_top("3.2.1.10.in-addr.arpa").await;

        // THEN
        let actual = result.expect("expected result");
        let RdapResponse::Domain(ref domain) = *actual else {
            panic!("not a domain")
        };
        assert_eq!(domain.ldh_name(), Some("10.in-addr.arpa"));
    }

    #[tokio::test]
    async fn test_domain_rdap_top_ipv6() {
        use icann_rdap_common::rdns::ip_to_reverse_dns;
        use std::net::{IpAddr, Ipv6Addr};

        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let domain = Domain::builder()
            .ldh_name("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa")
            .network(
                Network::builder()
                    .cidr("2001:db8::/32")
                    .build()
                    .expect("cidr parsing"),
            )
            .build();
        tx.add_domain(&domain).await.expect("add domain in tx");
        tx.commit().await.expect("tx commit");

        // Generate the correct reverse DNS string for 2001:db8::1
        let ip = Ipv6Addr::from_str("2001:db8::1").unwrap();
        let rdns_query = ip_to_reverse_dns(&IpAddr::V6(ip));

        let result = mem.domain_rdap_top(&rdns_query).await;

        // THEN
        let actual = result.expect("expected result");
        let RdapResponse::Domain(ref domain) = *actual else {
            panic!("not a domain")
        };
        assert_eq!(
            domain.ldh_name(),
            Some("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa")
        );
    }

    #[tokio::test]
    async fn test_domain_rdap_up_empty() {
        // GIVEN
        let mem = Mem::default();

        // WHEN
        let result = mem.domain_rdap_up("1.0.0.10.in-addr.arpa").await;

        // THEN
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_domain_rdap_up_ipv4() {
        // Given: we have two hierarchical domains
        // "1.10.in-addr.arpa" (10.1.0.0/16) is inside "10.in-addr.arpa" (10.0.0.0/8)
        // When querying for IP 10.1.0.128, rdap-up should return "10.in-addr.arpa"

        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let domain1 = Domain::builder()
            .ldh_name("10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.0.0.0/8")
                    .build()
                    .expect("cidr parsing"),
            )
            .build();
        let domain2 = Domain::builder()
            .ldh_name("1.10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.1.0.0/16")
                    .build()
                    .expect("cidr parsing"),
            )
            .build();
        tx.add_domain(&domain1).await.expect("add domain1 in tx");
        tx.add_domain(&domain2).await.expect("add domain2 in tx");
        tx.commit().await.expect("tx commit");

        // Use a specific IP within 10.1.0.0/16, e.g., 10.1.2.3
        // In reverse DNS: 3.2.1.10.in-addr.arpa
        // WHEN
        let result = mem.domain_rdap_up("3.2.1.10.in-addr.arpa").await;

        // THEN - we should get the supernet "10.in-addr.arpa"
        let actual = result.expect("expected result");
        let RdapResponse::Domain(ref domain) = *actual else {
            panic!("not a domain")
        };
        assert_eq!(domain.ldh_name(), Some("10.in-addr.arpa"));
    }

    #[tokio::test]
    async fn test_domain_rdap_up_root_no_supernet() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let domain = Domain::builder()
            .ldh_name("10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.0.0.0/8")
                    .build()
                    .expect("cidr parsing"),
            )
            .build();
        tx.add_domain(&domain).await.expect("add domain in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.domain_rdap_up("10.in-addr.arpa").await;

        // THEN
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_domain_rdap_down_empty() {
        // GIVEN
        let mem = Mem::default();

        // WHEN
        let result = mem.domain_rdap_down("10.in-addr.arpa").await;

        // THEN
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_domain_rdap_down_no_children() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let domain = Domain::builder()
            .ldh_name("10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.0.0.0/8")
                    .build()
                    .expect("cidr parsing"),
            )
            .build();
        tx.add_domain(&domain).await.expect("add domain in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.domain_rdap_down("10.in-addr.arpa").await;

        // THEN
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_domain_rdap_bottom_empty() {
        // GIVEN
        let mem = Mem::default();

        // WHEN
        let result = mem.domain_rdap_bottom("10.in-addr.arpa").await;

        // THEN
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_domain_rdap_bottom_single_network_no_children() {
        // GIVEN
        let mem = Mem::default();
        let mut tx = mem.new_tx().await.expect("new transaction");
        let domain = Domain::builder()
            .ldh_name("10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.0.0.0/8")
                    .build()
                    .expect("cidr parsing"),
            )
            .build();
        tx.add_domain(&domain).await.expect("add domain in tx");
        tx.commit().await.expect("tx commit");

        // WHEN
        let result = mem.domain_rdap_bottom("10.in-addr.arpa").await;

        // THEN
        assert!(result.is_empty());
    }
}
