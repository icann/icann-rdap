use icann_rdap_common::response::{Nameserver, RdapResponse};
use icann_rdap_srv::storage::StoreOps;

use super::pg_store;

#[tokio::test]
async fn search_nameservers_by_name_finds_match() {
    // GIVEN
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("ns-one.example.com")
            .addresses(vec!["192.0.2.1".to_string()])
            .build()
            .expect("building nameserver A"),
    )
    .await
    .expect("adding nameserver A");
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("ns-two.example.com")
            .addresses(vec!["192.0.2.2".to_string()])
            .build()
            .expect("building nameserver B"),
    )
    .await
    .expect("adding nameserver B");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .search_nameservers_by_name("ns-one*")
        .await
        .expect("searching nameservers by name");

    // THEN
    let RdapResponse::NameserverSearchResults(results) = actual else {
        panic!("expected nameserver search results, got {actual:?}");
    };
    assert_eq!(results.results().len(), 1);
    assert_eq!(
        results.results()[0].ldh_name.as_deref(),
        Some("ns-one.example.com")
    );
}

#[tokio::test]
async fn search_nameservers_by_name_label_boundary() {
    // GIVEN
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("prefix-foo.com")
            .addresses(vec!["192.0.2.10".to_string()])
            .build()
            .expect("building nameserver A"),
    )
    .await
    .expect("adding nameserver A");
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("prefix-bar.com")
            .addresses(vec!["192.0.2.11".to_string()])
            .build()
            .expect("building nameserver B"),
    )
    .await
    .expect("adding nameserver B");
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("other-foo.com")
            .addresses(vec!["192.0.2.12".to_string()])
            .build()
            .expect("building nameserver C"),
    )
    .await
    .expect("adding nameserver C");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .search_nameservers_by_name("prefix-*.com")
        .await
        .expect("searching nameservers by name");

    // THEN — matches prefix-foo.com and prefix-bar.com, not other-foo.com
    let RdapResponse::NameserverSearchResults(results) = actual else {
        panic!("expected nameserver search results, got {actual:?}");
    };
    assert_eq!(results.results().len(), 2);
    let names: Vec<&str> = results
        .results()
        .iter()
        .filter_map(|ns| ns.ldh_name.as_deref())
        .collect();
    assert!(names.contains(&"prefix-foo.com"));
    assert!(names.contains(&"prefix-bar.com"));
}

#[tokio::test]
async fn search_nameservers_by_name_no_match() {
    // GIVEN
    let store = pg_store().await;

    // WHEN
    let actual = store
        .search_nameservers_by_name("no-such-ns*")
        .await
        .expect("searching nameservers by name");

    // THEN
    let RdapResponse::NameserverSearchResults(results) = actual else {
        panic!("expected nameserver search results, got {actual:?}");
    };
    assert!(results.results().is_empty());
}
