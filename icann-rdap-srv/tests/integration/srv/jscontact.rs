use icann_rdap_srv::config::JsContactConversion;
use {
    icann_rdap_client::{
        http::{create_client, ClientConfig},
        rdap::{rdap_request, QueryType},
    },
    icann_rdap_common::prelude::*,
    icann_rdap_srv::storage::StoreOps,
};

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn test_no_jscontact_conversion() {
    // GIVEN
    let test_srv = SrvTestJig::new_jscontact_conversion(JsContactConversion::None).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");

    // create an entity with vcard
    let contact = Contact::builder()
        .email(Email::builder().email("bob@example.com").build())
        .organization_name("Bob Fish & Tackle")
        .postal_address(
            PostalAddress::builder()
                .locality("Washington")
                .region_name("DC")
                .country_code("US")
                .build(),
        )
        .build();
    let entity = Entity::builder().handle("foo1234").contact(contact).build();

    tx.add_entity(&entity).await.expect("adding entity");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(true)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::Entity("foo1234".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::Entity(entity) = response.rdap else {
        panic!("not an entity")
    };
    assert!(entity.is_contact_as_vcard());
    assert!(!entity.is_contact_as_jscontact());
}

#[tokio::test]
async fn test_jscontact_also_conversion() {
    // GIVEN
    let test_srv = SrvTestJig::new_jscontact_conversion(JsContactConversion::Also).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");

    // create an entity with vcard
    let contact = Contact::builder()
        .email(Email::builder().email("bob@example.com").build())
        .organization_name("Bob Fish & Tackle")
        .postal_address(
            PostalAddress::builder()
                .locality("Washington")
                .region_name("DC")
                .country_code("US")
                .build(),
        )
        .build();
    let entity = Entity::builder().handle("foo1234").contact(contact).build();

    tx.add_entity(&entity).await.expect("adding entity");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(true)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::Entity("foo1234".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::Entity(entity) = response.rdap else {
        panic!("not an entity")
    };
    assert!(entity.is_contact_as_vcard());
    assert!(entity.is_contact_as_jscontact());
}

#[tokio::test]
async fn test_jscontact_only_conversion() {
    // GIVEN
    let test_srv = SrvTestJig::new_jscontact_conversion(JsContactConversion::Only).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");

    // create an entity with vcard
    let contact = Contact::builder()
        .email(Email::builder().email("bob@example.com").build())
        .organization_name("Bob Fish & Tackle")
        .postal_address(
            PostalAddress::builder()
                .locality("Washington")
                .region_name("DC")
                .country_code("US")
                .build(),
        )
        .build();
    let entity = Entity::builder().handle("foo1234").contact(contact).build();

    tx.add_entity(&entity).await.expect("adding entity");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(true)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::Entity("foo1234".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::Entity(entity) = response.rdap else {
        panic!("not an entity")
    };
    assert!(!entity.is_contact_as_vcard());
    assert!(entity.is_contact_as_jscontact());
}
