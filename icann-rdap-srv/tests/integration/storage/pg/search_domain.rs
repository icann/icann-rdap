use icann_rdap_common::response::{Domain, Nameserver, RdapResponse};
use icann_rdap_srv::storage::StoreOps;

use icann_rdap_srv::storage::pg::ops::Pg;
use sqlx::{Pool, postgres::Postgres};

#[sqlx::test]
async fn search_domains_by_name_finds_match(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
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

#[sqlx::test]
async fn search_domains_by_name_no_match(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);

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

#[sqlx::test]
async fn search_domains_by_name_label_boundary(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
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

#[sqlx::test]
async fn search_domains_by_ns_ip_v4_finds_match(db: Pool<Postgres>) {
    // GIVEN — two domains, each with a nameserver holding a distinct IPv4 address
    let store = Pg::from_pool(db);
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

#[sqlx::test]
async fn search_domains_by_ns_ip_v6_finds_match(db: Pool<Postgres>) {
    // GIVEN — two domains, each with a nameserver holding a distinct IPv6 address
    let store = Pg::from_pool(db);
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

#[sqlx::test]
async fn search_domains_by_ns_ip_no_match(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);

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

#[sqlx::test]
async fn search_domains_by_ns_ldh_name_wildcard_finds_match(db: Pool<Postgres>) {
    // GIVEN — domain A has two nameservers (only one matches); domain B's does not
    let store = Pg::from_pool(db);
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("dbyns-a.example.com")
            .nameservers(vec![
                Nameserver::builder()
                    .ldh_name("alpha.other.net")
                    .build()
                    .expect("building nameserver A1"),
                Nameserver::builder()
                    .ldh_name("ns1.dbyns-a.example.com")
                    .build()
                    .expect("building nameserver A2"),
            ])
            .build(),
    )
    .await
    .expect("adding domain A");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("dbyns-b.example.com")
            .nameservers(vec![
                Nameserver::builder()
                    .ldh_name("ns1.dbyns-b.example.com")
                    .build()
                    .expect("building nameserver B"),
            ])
            .build(),
    )
    .await
    .expect("adding domain B");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — wildcard pattern matching only domain A's second nameserver
    let actual = store
        .search_domains_by_ns_ldh_name("ns1.dbyns-a.*")
        .await
        .expect("searching domains by ns ldh name");

    // THEN — matches only dbyns-a.example.com, not dbyns-b.example.com
    let RdapResponse::DomainSearchResults(results) = actual else {
        panic!("expected domain search results, got {actual:?}");
    };
    assert_eq!(results.results().len(), 1);
    assert_eq!(
        results.results()[0].ldh_name.as_deref(),
        Some("dbyns-a.example.com")
    );
}

#[sqlx::test]
async fn search_domains_by_ns_ldh_name_no_match(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);

    // WHEN — wildcard pattern matching no domain's nameserver
    let actual = store
        .search_domains_by_ns_ldh_name("zzz-nonexistent.*")
        .await
        .expect("searching domains by ns ldh name");

    // THEN
    let RdapResponse::DomainSearchResults(results) = actual else {
        panic!("expected domain search results, got {actual:?}");
    };
    assert!(results.results().is_empty());
}
