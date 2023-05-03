#![allow(non_snake_case)]

use icann_rdap_common::response::{
    domain::Domain,
    types::{Common, ObjectCommon},
    RdapResponse, entity::Entity,
};
use icann_rdap_srv::storage::{mem::ops::Mem, StorageOperations};

#[tokio::test]
async fn GIVEN_domain_in_mem_WHEN_lookup_domain_by_ldh_THEN_domain_returned() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_transaction().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .common(Common::builder().build())
            .ldh_name("foo.example")
            .object_common(ObjectCommon::builder().object_class_name("domain").build())
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_domain_by_ldh("foo.example")
        .await
        .expect("getting domain by ldh");

    // THEN
    assert!(matches!(actual, RdapResponse::Domain(_)));
    let icann_rdap_common::response::RdapResponse::Domain(Domain {
        common: _,
        object_common: _,
        ldh_name,
        unicode_name: _,
        variants: _,
        secure_dns: _,
        nameservers: _,
        public_ids: _,
        network: _,
    }) = actual else { panic!()};
    assert_eq!(ldh_name.expect("ldhName is none"), "foo.example")
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
    assert!(matches!(actual, RdapResponse::ErrorResponse(_)));
    let RdapResponse::ErrorResponse(icann_rdap_common::response::error::Error 
        { common: _, error_code, title: _, description: _ 
    }) = actual else {panic!()};
    assert_eq!(error_code, 404)
}

#[tokio::test]
async fn GIVEN_entity_in_mem_WHEN_lookup_entity_by_handle_THEN_entity_returned() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_transaction().await.expect("new transaction");
    tx.add_entity(
        &Entity::builder()
            .common(Common::builder().build())
            .object_common(ObjectCommon::builder().handle("foo").object_class_name("entity").build())
            .build(),
    )
    .await
    .expect("add entity in tx");
    tx.commit().await.expect("entity tx commit");

    // WHEN
    let actual = mem
        .get_entity_by_handle("foo")
        .await
        .expect("getting entity by handle");

    // THEN
    assert!(matches!(actual, RdapResponse::Entity(_)));
    let icann_rdap_common::response::RdapResponse::Entity(Entity
        {common:_,object_common, vcard_array: _, roles: _, public_ids: _, 
        as_event_actor: _, status: _, autnums: _, networks: _ }) = actual else { panic!()};
    assert_eq!(object_common.handle.expect("handle is none"), "foo")
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
    assert!(matches!(actual, RdapResponse::ErrorResponse(_)));
    let RdapResponse::ErrorResponse(icann_rdap_common::response::error::Error 
        { common: _, error_code, title: _, description: _ 
    }) = actual else {panic!()};
    assert_eq!(error_code, 404)
}
