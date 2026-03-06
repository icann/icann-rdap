use {
    icann_rdap_client::{
        http::{create_client, ClientConfig},
        rdap::{rdap_request, QueryType},
    },
    icann_rdap_common::{contact::Contact, prelude::RdapResponse, response::Entity},
    icann_rdap_srv::storage::{CommonConfig, StoreOps},
};

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn test_server_entity_search_disabled() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .entity_search_by_handle_enable(false)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_entity(&Entity::builder().handle("Hostmaster-ARIN").build())
        .await
        .expect("add entity in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::EntityHandleSearch("Hostmaster-*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("valid response");

    // THEN
    assert_eq!(response.http_data.status_code(), 501);
}

#[tokio::test]
async fn test_server_entity_search_enabled() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .entity_search_by_handle_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_entity(&Entity::builder().handle("Hostmaster-ARIN").build())
        .await
        .expect("add entity in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::EntityHandleSearch("Hostmaster-*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::EntitySearchResults(results) = response.rdap else {
        panic!("not entity search results")
    };
    assert_eq!(results.results().len(), 1);
}

#[tokio::test]
async fn test_server_entity_search_not_found() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .entity_search_by_handle_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_entity(&Entity::builder().handle("Hostmaster-ARIN").build())
        .await
        .expect("add entity in tx");
    tx.commit().await.expect("tx commit");

    // WHEN - search for entity that doesn't exist
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::EntityHandleSearch("Nonexistent-*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN - returns 200 with empty results (RFC 9082)
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::EntitySearchResults(results) = response.rdap else {
        panic!("not entity search results")
    };
    assert_eq!(results.results().len(), 0);
}

#[tokio::test]
async fn test_server_entity_search_multiple_results() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .entity_search_by_handle_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_entity(&Entity::builder().handle("Hostmaster-ARIN").build())
        .await
        .expect("add entity in tx");
    tx.add_entity(&Entity::builder().handle("Hostmaster-RIPE").build())
        .await
        .expect("add entity in tx");
    tx.commit().await.expect("tx commit");

    // WHEN - search for entities matching Hostmaster-*
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::EntityHandleSearch("Hostmaster-*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN - returns both entities
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::EntitySearchResults(results) = response.rdap else {
        panic!("not entity search results")
    };
    assert_eq!(results.results().len(), 2);
}

#[tokio::test]
async fn test_server_entity_fn_search_disabled() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .entity_search_by_full_name_enable(false)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let contact = Contact::builder().full_name("John Doe").build();
    tx.add_entity(&Entity::builder().handle("JD-001").contact(contact).build())
        .await
        .expect("add entity in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::EntityNameSearch("John*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("valid response");

    // THEN
    assert_eq!(response.http_data.status_code(), 501);
}

#[tokio::test]
async fn test_server_entity_fn_search_enabled() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .entity_search_by_full_name_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let contact = Contact::builder().full_name("John Doe").build();
    tx.add_entity(&Entity::builder().handle("JD-001").contact(contact).build())
        .await
        .expect("add entity in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::EntityNameSearch("John*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::EntitySearchResults(results) = response.rdap else {
        panic!("not entity search results")
    };
    assert_eq!(results.results().len(), 1);
    let entity = results.results().first().expect("first result");
    assert_eq!(
        entity
            .object_common
            .handle
            .as_ref()
            .expect("handle is none")
            .to_string(),
        "JD-001"
    );
}

#[tokio::test]
async fn test_server_entity_fn_search_not_found() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .entity_search_by_full_name_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let contact = Contact::builder().full_name("John Doe").build();
    tx.add_entity(&Entity::builder().handle("JD-001").contact(contact).build())
        .await
        .expect("add entity in tx");
    tx.commit().await.expect("tx commit");

    // WHEN - search for entity that doesn't exist
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::EntityNameSearch("Jane*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN - returns 200 with empty results (RFC 9082)
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::EntitySearchResults(results) = response.rdap else {
        panic!("not entity search results")
    };
    assert_eq!(results.results().len(), 0);
}

#[tokio::test]
async fn test_server_entity_fn_search_multiple_results() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .entity_search_by_full_name_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");

    let contact1 = Contact::builder().full_name("John Doe").build();
    tx.add_entity(&Entity::builder().handle("JD-001").contact(contact1).build())
        .await
        .expect("add entity in tx");

    let contact2 = Contact::builder().full_name("John Smith").build();
    tx.add_entity(&Entity::builder().handle("JS-001").contact(contact2).build())
        .await
        .expect("add entity in tx");

    tx.commit().await.expect("tx commit");

    // WHEN - search for entities matching John*
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::EntityNameSearch("John*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN - returns both entities
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::EntitySearchResults(results) = response.rdap else {
        panic!("not entity search results")
    };
    assert_eq!(results.results().len(), 2);
}
