use std::net::{IpAddr, Ipv4Addr};

use icann_rdap_common::rdns::ip_to_reverse_dns;
use icann_rdap_common::response::{Domain, Network, RdapResponse};
use icann_rdap_srv::rdap::response::NOT_FOUND;
use icann_rdap_srv::storage::StoreOps;
use icann_rdap_srv::storage::pg::ops::Pg;
use sqlx::{Pool, Postgres};

/// A domain whose network range is `cidr`.
fn domain_with_network(name: &str, cidr: &str) -> Domain {
    Domain::builder()
        .ldh_name(name)
        .network(
            Network::builder()
                .cidr(cidr)
                .build()
                .expect("building network"),
        )
        .build()
}

/// Seeds a two-level v4 hierarchy plus an ipv6 pair:
///   root.example      10.0.0.0/8
///   mid-a.example     10.1.0.0/16
///   leaf-a1.example   10.1.1.0/24
///   leaf-a2.example   10.1.2.0/24
///   deep-a1x.example  10.1.1.128.0/25
///   mid-b.example     10.2.0.0/16
///   root6.example     2001:db8::/32
///   child6.example    2001:db8:1::/48
async fn seed_hierarchy(store: &Pg) {
    let mut tx = store.new_tx().await.expect("new tx");
    for (name, cidr) in [
        ("root.example", "10.0.0.0/8"),
        ("mid-a.example", "10.1.0.0/16"),
        ("leaf-a1.example", "10.1.1.0/24"),
        ("leaf-a2.example", "10.1.2.0/24"),
        ("deep-a1x.example", "10.1.1.128/25"),
        ("mid-b.example", "10.2.0.0/16"),
        ("root6.example", "2001:db8::/32"),
        ("child6.example", "2001:db8:1::/48"),
    ] {
        tx.add_domain(&domain_with_network(name, cidr))
            .await
            .expect("adding domain");
    }
    Box::new(tx).commit().await.expect("committing seed tx");
}

fn assert_single_domain(actual: &RdapResponse, ldh: &str) {
    let RdapResponse::DomainSearchResults(results) = actual else {
        panic!("expected DomainSearchResults, got {actual:?}");
    };
    assert_eq!(results.results().len(), 1);
    assert_eq!(results.results()[0].ldh_name.as_deref(), Some(ldh));
}

fn assert_domain_results(actual: &RdapResponse, expected: &[&str]) {
    let RdapResponse::DomainSearchResults(results) = actual else {
        panic!("expected DomainSearchResults, got {actual:?}");
    };
    let mut names: Vec<&str> = results
        .results()
        .iter()
        .map(|d| d.ldh_name.as_deref().expect("domain has ldhName"))
        .collect();
    names.sort_unstable();
    let mut want: Vec<&str> = expected.to_vec();
    want.sort_unstable();
    assert_eq!(names, want);
}

fn assert_not_found(actual: &RdapResponse) {
    assert_eq!(*actual, *NOT_FOUND);
}

// -- generated column regression --------------------------------------------

#[sqlx::test]
async fn domain_net_columns_populated_from_content(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db.clone());
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_domain(&domain_with_network("colcheck.example", "10.9.0.0/24"))
        .await
        .expect("adding domain");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let (start, end): (IpAddr, IpAddr) =
        sqlx::query_as("SELECT net_start_address, net_end_address FROM domain WHERE ldh_name = $1")
            .bind("colcheck.example")
            .fetch_one(&db)
            .await
            .expect("domain row");

    // THEN
    assert_eq!(start, IpAddr::V4(Ipv4Addr::new(10, 9, 0, 0)));
    assert_eq!(end, IpAddr::V4(Ipv4Addr::new(10, 9, 0, 255)));
}

// -- top ----------------------------------------------------------------------

#[sqlx::test]
async fn domain_rdap_top_returns_most_specific(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_hierarchy(&store).await;
    let ip: IpAddr = "10.1.1.200".parse().unwrap();

    // WHEN — 10.1.1.200 lies in deep-a1x (10.1.1.128.0/25), the most specific stored range.
    let actual = store
        .search_domain_rdap_top_by_ldh(&ip_to_reverse_dns(&ip))
        .await
        .expect("rdap top");

    // THEN
    assert_single_domain(&actual, "deep-a1x.example");
}

#[sqlx::test]
async fn domain_rdap_top_childless_range(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_hierarchy(&store).await;
    let ip: IpAddr = "10.2.7.7".parse().unwrap();

    // WHEN — mid-b (10.2.0.0/16) is the only stored range containing 10.2.7.7.
    let actual = store
        .search_domain_rdap_top_by_ldh(&ip_to_reverse_dns(&ip))
        .await
        .expect("rdap top");

    // THEN
    assert_single_domain(&actual, "mid-b.example");
}

#[sqlx::test]
async fn domain_rdap_top_no_match(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_hierarchy(&store).await;
    let ip: IpAddr = "192.168.5.5".parse().unwrap();

    // WHEN — no stored range contains 192.168.5.5.
    let actual = store
        .search_domain_rdap_top_by_ldh(&ip_to_reverse_dns(&ip))
        .await
        .expect("rdap top");

    // THEN
    assert_not_found(&actual);
}

#[sqlx::test]
async fn domain_rdap_top_non_rdns_input(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);

    // WHEN
    let actual = store
        .search_domain_rdap_top_by_ldh("example.com")
        .await
        .expect("rdap top");

    // THEN
    assert_not_found(&actual);
}

#[sqlx::test]
async fn domain_rdap_top_ipv6(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_hierarchy(&store).await;

    // WHEN — 2001:db8:1::5 lies in child6 (2001:db8:1::/48); 2001:db8:9::1 only in root6.
    let ip: IpAddr = "2001:db8:1::5".parse().unwrap();
    let actual = store
        .search_domain_rdap_top_by_ldh(&ip_to_reverse_dns(&ip))
        .await
        .expect("rdap top");
    assert_single_domain(&actual, "child6.example");

    let ip: IpAddr = "2001:db8:9::1".parse().unwrap();
    let actual = store
        .search_domain_rdap_top_by_ldh(&ip_to_reverse_dns(&ip))
        .await
        .expect("rdap top");
    assert_single_domain(&actual, "root6.example");
}

// -- up -----------------------------------------------------------------------

#[sqlx::test]
async fn domain_rdap_up_returns_parent_of_most_specific(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_hierarchy(&store).await;
    let ip: IpAddr = "10.1.1.200".parse().unwrap();

    // WHEN — container is deep-a1x (10.1.1.128.0/25); its supernet 10.1.1.0/24 is most
    // specifically stored by leaf-a1.
    let actual = store
        .search_domain_rdap_up_by_ldh(&ip_to_reverse_dns(&ip))
        .await
        .expect("rdap up");

    // THEN
    assert_single_domain(&actual, "leaf-a1.example");
}

#[sqlx::test]
async fn domain_rdap_up_mid_level(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_hierarchy(&store).await;
    let ip: IpAddr = "10.1.2.9".parse().unwrap();

    // WHEN — container is leaf-a2 (10.1.2.0/24); its supernet 10.1.2.0/23 is most
    // specifically stored by mid-a.
    let actual = store
        .search_domain_rdap_up_by_ldh(&ip_to_reverse_dns(&ip))
        .await
        .expect("rdap up");

    // THEN
    assert_single_domain(&actual, "mid-a.example");
}

#[sqlx::test]
async fn domain_rdap_up_top_level_not_found(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_hierarchy(&store).await;
    let ip: IpAddr = "10.3.0.1".parse().unwrap();

    // WHEN — container is root (10.0.0.0/8); nothing stored contains its supernet 10.0.0.0/7.
    let actual = store
        .search_domain_rdap_up_by_ldh(&ip_to_reverse_dns(&ip))
        .await
        .expect("rdap up");

    // THEN
    assert_not_found(&actual);
}

#[sqlx::test]
async fn domain_rdap_up_non_rdns_input(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);

    // WHEN
    let actual = store
        .search_domain_rdap_up_by_ldh("example.com")
        .await
        .expect("rdap up");

    // THEN
    assert_not_found(&actual);
}

// -- down ---------------------------------------------------------------------

#[sqlx::test]
async fn domain_rdap_down_immediate_children(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_hierarchy(&store).await;

    // WHEN — "1.10.in-addr.arpa" is 10.1.0.0/16; container mid-a; the maximal proper
    // sub-ranges are leaf-a1 and leaf-a2 (deep-a1x is covered by leaf-a1).
    let actual = store
        .search_domain_rdap_down_by_ldh("1.10.in-addr.arpa")
        .await
        .expect("rdap down");

    // THEN
    assert_domain_results(&actual, &["leaf-a1.example", "leaf-a2.example"]);
}

#[sqlx::test]
async fn domain_rdap_down_no_container_empty(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_hierarchy(&store).await;

    // WHEN — "5.192.168.in-addr.arpa" is 192.168.5.0/24; nothing stored contains it.
    let actual = store
        .search_domain_rdap_down_by_ldh("5.192.168.in-addr.arpa")
        .await
        .expect("rdap down");

    // THEN — an empty search result, not a 404.
    assert_domain_results(&actual, &[]);
}

#[sqlx::test]
async fn domain_rdap_down_non_rdns_input(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);

    // WHEN
    let actual = store
        .search_domain_rdap_down_by_ldh("example.com")
        .await
        .expect("rdap down");

    // THEN
    assert_domain_results(&actual, &[]);
}

#[sqlx::test]
async fn domain_rdap_down_queried_block_inside_container(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_hierarchy(&store).await;

    // WHEN — "0.3.10.in-addr.arpa" is 10.3.0.0/24, strictly inside root (10.0.0.0/8);
    // the maximal proper sub-ranges of root are mid-a and mid-b.
    let actual = store
        .search_domain_rdap_down_by_ldh("0.3.10.in-addr.arpa")
        .await
        .expect("rdap down");

    // THEN
    assert_domain_results(&actual, &["mid-a.example", "mid-b.example"]);
}

#[sqlx::test]
async fn domain_rdap_down_ipv6(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_hierarchy(&store).await;

    // WHEN — "8.b.d.0.1.0.0.2.ip6.arpa" is 2001:db8::/32; container root6 → child6.
    let actual = store
        .search_domain_rdap_down_by_ldh("8.b.d.0.1.0.0.2.ip6.arpa")
        .await
        .expect("rdap down");

    // THEN
    assert_domain_results(&actual, &["child6.example"]);
}

// -- bottom -------------------------------------------------------------------

#[sqlx::test]
async fn domain_rdap_bottom_returns_leaves(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_hierarchy(&store).await;

    // WHEN — "1.10.in-addr.arpa" is 10.1.0.0/16; the leaves are deep-a1x and leaf-a2
    // (leaf-a1 contains deep-a1x, so it is not a leaf).
    let actual = store
        .search_domain_rdap_bottom_by_ldh("1.10.in-addr.arpa")
        .await
        .expect("rdap bottom");

    // THEN
    assert_domain_results(&actual, &["deep-a1x.example", "leaf-a2.example"]);
}

#[sqlx::test]
async fn domain_rdap_bottom_queried_block_inside_container(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_hierarchy(&store).await;

    // WHEN — 10.3.0.0/24 lies strictly inside root (10.0.0.0/8); the leaves under root
    // are deep-a1x, leaf-a2 and mid-b (leaf-a1 contains deep-a1x, so it is not a leaf).
    let actual = store
        .search_domain_rdap_bottom_by_ldh("0.3.10.in-addr.arpa")
        .await
        .expect("rdap bottom");

    // THEN
    assert_domain_results(
        &actual,
        &["deep-a1x.example", "leaf-a2.example", "mid-b.example"],
    );
}

#[sqlx::test]
async fn domain_rdap_bottom_no_container_empty(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_hierarchy(&store).await;

    // WHEN — nothing stored contains 192.168.5.0/24.
    let actual = store
        .search_domain_rdap_bottom_by_ldh("5.192.168.in-addr.arpa")
        .await
        .expect("rdap bottom");

    // THEN
    assert_domain_results(&actual, &[]);
}

#[sqlx::test]
async fn domain_rdap_bottom_ipv6(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_hierarchy(&store).await;

    // WHEN — 2001:db8::/32 → container root6 → leaf child6.
    let actual = store
        .search_domain_rdap_bottom_by_ldh("8.b.d.0.1.0.0.2.ip6.arpa")
        .await
        .expect("rdap bottom");

    // THEN
    assert_domain_results(&actual, &["child6.example"]);
}
