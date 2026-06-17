use {
    icann_rdap_common::response::{Domain, RdapResponse},
    icann_rdap_srv::{
        config::CommonConfig,
        storage::{
            StoreOps,
            mem::{config::MemConfig, ops::Mem},
        },
    },
};

#[tokio::test]
async fn truncate_removes_domain() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let tx = mem.new_truncate_tx().await.expect("new truncate tx");
    tx.commit().await.expect("tx commit");

    // THEN
    let actual = mem
        .get_domain_by_ldh("foo.example")
        .await
        .expect("getting domain by ldh");
    let RdapResponse::ErrorResponse(error) = actual else {
        panic!()
    };
    assert_eq!(error.error_code(), 404)
}

#[tokio::test]
async fn lookup_by_ldh() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_domain_by_ldh("foo.example")
        .await
        .expect("getting domain by ldh");

    // THEN
    let RdapResponse::Domain(domain) = actual else {
        panic!()
    };
    assert_eq!(
        domain.ldh_name.as_ref().expect("ldhName is none"),
        "foo.example"
    )
}

#[tokio::test]
async fn lookup_by_unicode() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::idn()
            .unicode_name("foo.example")
            .ldh_name("foo.example")
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_domain_by_unicode("foo.example")
        .await
        .expect("getting domain by unicode");

    // THEN
    let RdapResponse::Domain(domain) = actual else {
        panic!()
    };
    assert_eq!(
        domain.unicode_name.as_ref().expect("unicodeName is none"),
        "foo.example"
    )
}

#[tokio::test]
async fn search_by_name() {
    // GIVEN
    let mem_config = MemConfig::builder()
        .common_config(
            CommonConfig::builder()
                .domain_search_by_name_enable(true)
                .build(),
        )
        .build();
    let mem = Mem::new(mem_config);
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::idn()
            .unicode_name("foo.example.com")
            .ldh_name("foo.example.com")
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .search_domains_by_name("foo.example.*")
        .await
        .expect("getting domain by unicode");

    // THEN
    let RdapResponse::DomainSearchResults(domains) = actual else {
        panic!()
    };
    assert_eq!(domains.clone().results.len(), 1);
    assert_eq!(
        domains
            .results
            .first()
            .expect("at least one")
            .unicode_name
            .as_ref()
            .expect("unicodeName is none"),
        "foo.example.com"
    )
}

#[tokio::test]
async fn search_by_name_disabled() {
    // GIVEN
    let mem_config = MemConfig::builder()
        .common_config(
            CommonConfig::builder()
                .domain_search_by_name_enable(false)
                .build(),
        )
        .build();
    let mem = Mem::new(mem_config);
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::idn()
            .unicode_name("foo.example.com")
            .ldh_name("foo.example.com")
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .search_domains_by_name("foo.example.*")
        .await
        .expect("getting domain by unicode");

    // THEN
    let RdapResponse::ErrorResponse(_e) = actual else {
        panic!()
    };
}

#[tokio::test]
async fn lookup_not_found() {
    // GIVEN
    let mem = Mem::default();

    // WHEN
    let actual = mem
        .get_domain_by_ldh("foo.example")
        .await
        .expect("getting domain by ldh");

    // THEN
    let RdapResponse::ErrorResponse(error) = actual else {
        panic!()
    };
    assert_eq!(error.error_code(), 404)
}
