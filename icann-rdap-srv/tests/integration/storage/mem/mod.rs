#![allow(non_snake_case)]

mod state;

use icann_rdap_common::response::{domain::Domain, entity::Entity};
use icann_rdap_srv::{
    rdap::response::{ArcRdapResponse, RdapServerResponse},
    storage::{mem::ops::Mem, StoreOps},
};

#[tokio::test]
async fn GIVEN_domain_in_mem_WHEN_lookup_domain_by_ldh_THEN_domain_returned() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::basic().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_domain_by_ldh("foo.example")
        .await
        .expect("getting domain by ldh");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::Domain(_)));
    let ArcRdapResponse::Domain(domain) = response else { panic!() };
    assert_eq!(
        domain.ldh_name.as_ref().expect("ldhName is none"),
        "foo.example"
    )
}

#[tokio::test]
async fn GIVEN_no_domain_in_mem_WHEN_lookup_domain_by_ldh_THEN_404_returned() {
    // GIVEN
    let mem = Mem::default();

    // WHEN
    let actual = mem
        .get_domain_by_ldh("foo.example")
        .await
        .expect("getting domain by ldh");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::ErrorResponse(_)));
    let ArcRdapResponse::ErrorResponse(error) = response else { panic!() };
    assert_eq!(error.error_code, 404)
}

#[tokio::test]
async fn GIVEN_entity_in_mem_WHEN_lookup_entity_by_handle_THEN_entity_returned() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_entity(&Entity::basic().handle("foo").build())
        .await
        .expect("add entity in tx");
    tx.commit().await.expect("entity tx commit");

    // WHEN
    let actual = mem
        .get_entity_by_handle("foo")
        .await
        .expect("getting entity by handle");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::Entity(_)));
    let ArcRdapResponse::Entity(entity) = response else { panic!() };
    assert_eq!(
        entity
            .object_common
            .handle
            .as_ref()
            .expect("handle is none"),
        "foo"
    )
}

#[tokio::test]
async fn GIVEN_no_entity_in_mem_WHEN_lookup_entity_by_handle_THEN_404_returned() {
    // GIVEN
    let mem = Mem::default();

    // WHEN
    let actual = mem
        .get_entity_by_handle("foo")
        .await
        .expect("getting entity by handle");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::ErrorResponse(_)));
    let ArcRdapResponse::ErrorResponse(error) = response else { panic!() };
    assert_eq!(error.error_code, 404)
}
