use {
    icann_rdap_common::response::{Entity, RdapResponse},
    icann_rdap_srv::storage::{mem::ops::Mem, StoreOps},
};

#[tokio::test]
async fn lookup_by_handle() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_entity(&Entity::builder().handle("foo").build())
        .await
        .expect("add entity in tx");
    tx.commit().await.expect("entity tx commit");

    // WHEN
    let actual = mem
        .get_entity_by_handle("foo")
        .await
        .expect("getting entity by handle");

    // THEN
    let RdapResponse::Entity(entity) = actual else {
        panic!()
    };
    assert_eq!(
        entity
            .object_common
            .handle
            .as_ref()
            .expect("handle is none")
            .to_string(),
        "foo"
    )
}

#[tokio::test]
async fn lookup_not_found() {
    // GIVEN
    let mem = Mem::default();

    // WHEN
    let actual = mem
        .get_entity_by_handle("foo")
        .await
        .expect("getting entity by handle");

    // THEN
    let RdapResponse::ErrorResponse(error) = actual else {
        panic!()
    };
    assert_eq!(error.error_code, 404)
}
