use {
    icann_rdap_common::{contact::Contact, response::Entity},
    icann_rdap_srv::storage::StoreOps,
};

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_entity_handle_search() {
    // GIVEN entity
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_entity(&Entity::builder().handle("Hostmaster-ARIN").build())
        .await
        .expect("add entity in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for the entity by handle
    test_jig
        .cmd
        .arg("-t")
        .arg("entity-handle")
        .arg("Hostmaster-*");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_entity_name_search() {
    // GIVEN entity with full name
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    let contact = Contact::builder().full_name("John Doe").build();
    tx.add_entity(&Entity::builder().handle("JD-001").contact(contact).build())
        .await
        .expect("add entity in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for the entity by full name
    test_jig.cmd.arg("-t").arg("entity-name").arg("John*");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}


