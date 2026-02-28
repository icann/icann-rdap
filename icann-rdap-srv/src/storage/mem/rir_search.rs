use std::sync::Arc;

use icann_rdap_common::prelude::RdapResponse;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::{AsView, Prefix, PrefixMap};

use crate::storage::mem::ops::Mem;

pub trait RdapPrefix: Prefix + Copy {
    fn contains_prefix(&self, other: &Self) -> bool;
}

impl RdapPrefix for Ipv4Net {
    fn contains_prefix(&self, other: &Self) -> bool {
        self.contains(other)
    }
}

impl RdapPrefix for Ipv6Net {
    fn contains_prefix(&self, other: &Self) -> bool {
        self.contains(other)
    }
}

fn get_rdap_down<P: RdapPrefix + PartialEq, T: Clone>(map: &PrefixMap<P, T>, query: &P) -> Vec<T> {
    let mut immediate_children = Vec::new();
    let mut current_cover: Option<P> = None;

    // view_at limits our iteration only to prefixes covered by the query
    let view = map.view_at(*query);

    for trie in view.iter() {
        if trie.prefix() == query {
            continue; // Skip the exact match of the query itself
        }

        if let Some(cover) = current_cover {
            if cover.contains(trie.prefix()) {
                // This node is a descendant of our current immediate child, skip it
                continue;
            }
        }

        // It is not covered by the previous immediate child, so it's a new one
        if let Some(value) = trie.value() {
            immediate_children.push(value.clone());
        }
        current_cover = Some(*trie.prefix());
    }

    immediate_children
}

fn get_rdap_bottom<P: RdapPrefix + PartialEq, T: Clone>(
    map: &PrefixMap<P, T>,
    query: &P,
) -> Vec<T> {
    let mut bottom_objects = Vec::new();
    let mut prev: Option<P> = None;
    let mut prev_value: Option<&T> = None;

    let view = map.view_at(*query);

    for trie in view.iter() {
        if trie.prefix() == query {
            continue; // Skip the exact match
        }

        if let Some(p) = prev {
            // If the previous prefix does not cover the current one,
            // it has no children in the registry. It is a leaf!
            if !p.contains(trie.prefix()) {
                if let Some(value) = trie.value() {
                    bottom_objects.push(value.clone());
                }
            }
        }
        prev = Some(*trie.prefix());
        prev_value = trie.value();
    }

    // The very last node in the traversal has no subsequent nodes to check,
    // meaning it is always a bottom object.
    if let Some(value) = prev_value {
        bottom_objects.push(value.clone());
    }

    bottom_objects
}

impl Mem {
    async fn rdap_top(&self, query: &IpNet) -> Option<Arc<RdapResponse>> {
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

    async fn rdap_up(&self, query: &IpNet) -> Option<Arc<RdapResponse>> {
        if let Some(supernet) = query.supernet() {
            match supernet {
                IpNet::V4(v4_supernet) => {
                    let ip4s = self.ip4.read().await;
                    ip4s.get_lpm(&v4_supernet).map(|r| r.1.clone())
                }
                IpNet::V6(v6_supernet) => {
                    let ip6s = self.ip6.read().await;
                    ip6s.get_lpm(&v6_supernet).map(|r| r.1.clone())
                }
            }
        } else {
            None
        }
    }

    async fn rdap_down(&self, query: &IpNet) -> Vec<Arc<RdapResponse>> {
        match query {
            IpNet::V4(v4_query) => {
                let ip4s = self.ip4.read().await;
                get_rdap_down(&ip4s, v4_query)
            }
            IpNet::V6(v6_query) => {
                let ip6s = self.ip6.read().await;
                get_rdap_down(&(*ip6s), v6_query)
            }
        }
    }

    async fn rdap_bottom(&self, query: &IpNet) -> Vec<Arc<RdapResponse>> {
        match query {
            IpNet::V4(v4_query) => {
                let ip4s = self.ip4.read().await;
                get_rdap_bottom(&(*ip4s), v4_query)
            }
            IpNet::V6(v6_query) => {
                let ip6s = self.ip6.read().await;
                get_rdap_bottom(&(*ip6s), v6_query)
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use icann_rdap_common::prelude::{Network, RdapResponse};

    use crate::storage::{mem::ops::Mem, StoreOps};

    #[tokio::test]
    async fn test_rdap_top_with_ordered_insertion() {
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
        let result = mem.rdap_top(&("10.1.0.1/32".parse().unwrap())).await;

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
    async fn test_rdap_up() {
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
        let result = mem.rdap_up(&("10.1.0.1/24".parse().unwrap())).await;

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
    async fn test_rdap_top_empty() {
        // GIVEN
        let mem = Mem::default();

        // WHEN
        let result = mem.rdap_top(&("10.1.0.1/32".parse().unwrap())).await;

        // THEN
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_rdap_top_ipv6() {
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
        let result = mem.rdap_top(&("2001:db8:1::1/128".parse().unwrap())).await;

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
    async fn test_rdap_top_unordered() {
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
        let result = mem.rdap_top(&("10.1.0.1/32".parse().unwrap())).await;

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
    async fn test_rdap_top_multiple_hierarchies() {
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
        let result = mem.rdap_top(&("10.1.0.1/32".parse().unwrap())).await;

        // THEN
        let actual = result.unwrap();
        let RdapResponse::Network(ref actual) = *actual else {
            panic!("not a network")
        };
        let actual = actual.cidr0_cidrs().first().expect("empty cidrs");
        assert_eq!(actual.prefix().expect("prefix"), "10.0.0.0");
    }

    #[tokio::test]
    async fn test_rdap_top_outside_range() {
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
        let result = mem.rdap_top(&("192.168.1.1/32".parse().unwrap())).await;

        // THEN
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_rdap_up_root_network() {
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
        let result = mem.rdap_up(&("10.0.0.0/8".parse().unwrap())).await;

        // THEN
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_rdap_up_ipv6() {
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
        let result = mem.rdap_up(&("2001:db8:1::/64".parse().unwrap())).await;

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
    async fn test_rdap_up_multiple_levels() {
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
        let result = mem.rdap_up(&("10.1.2.128/25".parse().unwrap())).await;

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
    async fn test_rdap_up_outside_range() {
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
        let result = mem.rdap_up(&("192.168.1.1/32".parse().unwrap())).await;

        // THEN
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_rdap_down_empty() {
        // GIVEN
        let mem = Mem::default();

        // WHEN
        let result = mem.rdap_down(&("10.0.0.0/8".parse().unwrap())).await;

        // THEN
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_rdap_down_outside_range() {
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
        let result = mem.rdap_down(&("192.168.1.0/24".parse().unwrap())).await;

        // THEN
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_rdap_bottom_empty() {
        // GIVEN
        let mem = Mem::default();

        // WHEN
        let result = mem.rdap_bottom(&("10.0.0.0/8".parse().unwrap())).await;

        // THEN
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_rdap_bottom_single_network_no_descendants() {
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
        let result = mem.rdap_bottom(&("10.0.0.0/8".parse().unwrap())).await;

        // THEN
        assert!(result.is_empty());
    }
}
