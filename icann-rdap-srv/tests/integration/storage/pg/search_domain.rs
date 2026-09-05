use icann_rdap_common::response::{Domain, Nameserver, RdapResponse};
use icann_rdap_srv::storage::StoreOps;

use super::pg_store;

#[tokio::test]
async fn search_domains_by_name_finds_match() {
    // GIVEN
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_domain(&Domain::builder().ldh_name("example-a.com").build())
        .await
        .expect("adding domain A");
    tx.add_domain(&Domain::builder().ldh_name("example-b.com").build())
        .await
        .expect("adding domain B");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .search_domains_by_name("example-a*")
        .await
        .expect("searching domains by name");

    // THEN
    let RdapResponse::DomainSearchResults(results) = actual else {
        panic!("expected domain search results, got {actual:?}");
    };
    assert_eq!(results.results().len(), 1);
    assert_eq!(
        results.results()[0].ldh_name.as_deref(),
        Some("example-a.com")
    );
}

#[tokio::test]
async fn search_domains_by_name_no_match() {
    // GIVEN
    let store = pg_store().await;

    // WHEN
    let actual = store
        .search_domains_by_name("no-such-domain*")
        .await
        .expect("searching domains by name");

    // THEN
    let RdapResponse::DomainSearchResults(results) = actual else {
        panic!("expected domain search results, got {actual:?}");
    };
    assert!(results.results().is_empty());
}

#[tokio::test]
async fn search_domains_by_name_label_boundary() {
    // GIVEN
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_domain(&Domain::builder().ldh_name("boundary-foo.com").build())
        .await
        .expect("adding domain A");
    tx.add_domain(&Domain::builder().ldh_name("boundary-bar.com").build())
        .await
        .expect("adding domain B");
    tx.add_domain(&Domain::builder().ldh_name("otherdomain-foo.com").build())
        .await
        .expect("adding domain C");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .search_domains_by_name("boundary-*.com")
        .await
        .expect("searching domains by name");

    // THEN — matches boundary-foo.com and boundary-bar.com, not otherdomain-foo.com
    let RdapResponse::DomainSearchResults(results) = actual else {
        panic!("expected domain search results, got {actual:?}");
    };
    assert_eq!(results.results().len(), 2);
    let names: Vec<&str> = results
        .results()
        .iter()
        .filter_map(|d| d.ldh_name.as_deref())
        .collect();
    assert!(names.contains(&"boundary-foo.com"));
    assert!(names.contains(&"boundary-bar.com"));
}

#[tokio::test]
async fn search_domains_by_ns_ip_v4_finds_match() {
    // GIVEN — two domains, each with a nameserver holding a distinct IPv4 address
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("dbyip-v4-a.example.com")
            .nameservers(vec![
                Nameserver::builder()
                    .ldh_name("ns-v4-a.example.com")
                    .addresses(vec!["198.51.100.30".to_string()])
                    .build()
                    .expect("building nameserver A"),
            ])
            .build(),
    )
    .await
    .expect("adding domain A");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("dbyip-v4-b.example.com")
            .nameservers(vec![
                Nameserver::builder()
                    .ldh_name("ns-v4-b.example.com")
                    .addresses(vec!["198.51.100.40".to_string()])
                    .build()
                    .expect("building nameserver B"),
            ])
            .build(),
    )
    .await
    .expect("adding domain B");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — search for the IPv4 address held only by domain A's nameserver
    let actual = store
        .search_domains_by_ns_ip("198.51.100.30".parse().unwrap())
        .await
        .expect("searching domains by ns ip");

    // THEN — matches only dbyip-v4-a.example.com, not dbyip-v4-b.example.com
    let RdapResponse::DomainSearchResults(results) = actual else {
        panic!("expected domain search results, got {actual:?}");
    };
    assert_eq!(results.results().len(), 1);
    assert_eq!(
        results.results()[0].ldh_name.as_deref(),
        Some("dbyip-v4-a.example.com")
    );
}

#[tokio::test]
async fn search_domains_by_ns_ip_v6_finds_match() {
    // GIVEN — two domains, each with a nameserver holding a distinct IPv6 address
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("dbyip-v6-a.example.com")
            .nameservers(vec![
                Nameserver::builder()
                    .ldh_name("ns-v6-a.example.com")
                    .addresses(vec!["2001:db8::e1".to_string()])
                    .build()
                    .expect("building nameserver A"),
            ])
            .build(),
    )
    .await
    .expect("adding domain A");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("dbyip-v6-b.example.com")
            .nameservers(vec![
                Nameserver::builder()
                    .ldh_name("ns-v6-b.example.com")
                    .addresses(vec!["2001:db8::e2".to_string()])
                    .build()
                    .expect("building nameserver B"),
            ])
            .build(),
    )
    .await
    .expect("adding domain B");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — search for the IPv6 address held only by domain A's nameserver
    let actual = store
        .search_domains_by_ns_ip("2001:db8::e1".parse().unwrap())
        .await
        .expect("searching domains by ns ip");

    // THEN — matches only dbyip-v6-a.example.com, not dbyip-v6-b.example.com
    let RdapResponse::DomainSearchResults(results) = actual else {
        panic!("expected domain search results, got {actual:?}");
    };
    assert_eq!(results.results().len(), 1);
    assert_eq!(
        results.results()[0].ldh_name.as_deref(),
        Some("dbyip-v6-a.example.com")
    );
}

#[tokio::test]
async fn search_domains_by_ns_ip_no_match() {
    // GIVEN
    let store = pg_store().await;

    // WHEN — an IPv4 address no domain's nameserver holds
    let actual = store
        .search_domains_by_ns_ip("198.51.100.99".parse().unwrap())
        .await
        .expect("searching domains by ns ip");

    // THEN
    let RdapResponse::DomainSearchResults(results) = actual else {
        panic!("expected domain search results, got {actual:?}");
    };
    assert!(results.results().is_empty());
}
