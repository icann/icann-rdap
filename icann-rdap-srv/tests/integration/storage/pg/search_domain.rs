use icann_rdap_common::response::{Domain, RdapResponse};
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
