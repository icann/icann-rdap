use crate::test_jig::SrvTestJig;
use {
    icann_rdap_client::{
        http::{ClientConfig, create_client},
        rdap::{QueryType, rdap_request},
    },
    icann_rdap_common::{prelude::RdapResponse, response::Autnum},
    icann_rdap_srv::{config::CommonConfig, storage::StoreOps},
};

#[tokio::test]
async fn test_server_autnum_search_by_handle_disabled() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_search_by_handle_enable(false)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(700..710)
            .handle("AS700-1")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::AutnumHandleSearch("AS700-*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("valid response");

    // THEN
    assert_eq!(response.http_data.status_code(), 501);
}

#[tokio::test]
async fn test_server_autnum_search_by_handle_enabled() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_search_by_handle_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(700..710)
            .handle("AS700-1")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::AutnumHandleSearch("AS700-*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::AutnumSearchResults(results) = response.rdap else {
        panic!("not autnum search results")
    };
    assert_eq!(results.results().len(), 1);
}

#[tokio::test]
async fn test_server_autnum_search_by_handle_not_found() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_search_by_handle_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(700..710)
            .handle("AS700-1")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN - search for autnum that doesn't exist
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::AutnumHandleSearch("Nonexistent-*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN - returns 200 with empty results (RFC 9082)
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::AutnumSearchResults(results) = response.rdap else {
        panic!("not autnum search results")
    };
    assert_eq!(results.results().len(), 0);
}

#[tokio::test]
async fn test_server_autnum_search_by_handle_multiple_results() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_search_by_handle_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(700..710)
            .handle("AS700-1")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(710..720)
            .handle("AS700-2")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(800..810)
            .handle("AS800-1")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN - search for autnums matching AS700-*
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::AutnumHandleSearch("AS700-*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN - returns both AS700-* autnums
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::AutnumSearchResults(results) = response.rdap else {
        panic!("not autnum search results")
    };
    assert_eq!(results.results().len(), 2);
}

#[tokio::test]
async fn test_server_autnum_search_by_name_disabled() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_search_by_name_enable(false)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(700..710)
            .handle("AS700-1")
            .name("Test AS Network")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::AutnumNameSearch("Test *".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("valid response");

    // THEN
    assert_eq!(response.http_data.status_code(), 501);
}

#[tokio::test]
async fn test_server_autnum_search_by_name_enabled() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_search_by_name_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(700..710)
            .handle("AS700-1")
            .name("Test AS Network")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::AutnumNameSearch("Test *".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::AutnumSearchResults(results) = response.rdap else {
        panic!("not autnum search results")
    };
    assert_eq!(results.results().len(), 1);
}

#[tokio::test]
async fn test_server_autnum_search_by_name_not_found() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_search_by_name_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(700..710)
            .handle("AS700-1")
            .name("Test AS Network")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN - search for autnum that doesn't exist
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::AutnumNameSearch("Nonexistent *".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN - returns 200 with empty results (RFC 9082)
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::AutnumSearchResults(results) = response.rdap else {
        panic!("not autnum search results")
    };
    assert_eq!(results.results().len(), 0);
}

#[tokio::test]
async fn test_server_autnum_search_by_name_multiple_results() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_search_by_name_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(700..710)
            .handle("AS700-1")
            .name("Network Allocation")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(710..720)
            .handle("AS700-2")
            .name("Network Assignment")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(800..810)
            .handle("AS800-1")
            .name("Autnum Allocation")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN - search for autnums matching Network*
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::AutnumNameSearch("Network*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN - returns both Network* autnums
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::AutnumSearchResults(results) = response.rdap else {
        panic!("not autnum search results")
    };
    assert_eq!(results.results().len(), 2);
}
