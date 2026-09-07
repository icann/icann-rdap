use icann_rdap_common::contact::Contact;
use icann_rdap_common::response::{Entity, RdapResponse};
use icann_rdap_srv::storage::StoreOps;

use icann_rdap_srv::storage::pg::ops::Pg;
use sqlx::{Pool, postgres::Postgres};

#[sqlx::test]
async fn search_entities_by_full_name_finds_match(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_entity(
        &Entity::builder()
            .handle("SEARCH-ENTITY-1")
            .contact(Contact::builder().full_name("John Doe").build())
            .build(),
    )
    .await
    .expect("adding entity 1");
    tx.add_entity(
        &Entity::builder()
            .handle("SEARCH-ENTITY-2")
            .contact(Contact::builder().full_name("Jane Smith").build())
            .build(),
    )
    .await
    .expect("adding entity 2");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .search_entities_by_full_name("John*")
        .await
        .expect("searching entities by full name");

    // THEN
    let RdapResponse::EntitySearchResults(results) = actual else {
        panic!("expected entity search results, got {actual:?}");
    };
    assert_eq!(results.results().len(), 1);
    assert_eq!(
        results.results()[0]
            .object_common
            .handle
            .as_ref()
            .map(|h| h.to_string()),
        Some("SEARCH-ENTITY-1".to_string())
    );
}

#[sqlx::test]
async fn search_entities_by_full_name_no_match(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);

    // WHEN
    let actual = store
        .search_entities_by_full_name("Zzz*")
        .await
        .expect("searching entities by full name");

    // THEN
    let RdapResponse::EntitySearchResults(results) = actual else {
        panic!("expected entity search results, got {actual:?}");
    };
    assert!(results.results().is_empty());
}

#[sqlx::test]
async fn search_entities_by_handle_finds_match(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_entity(&Entity::builder().handle("HANDLE-ENTITY-A").build())
        .await
        .expect("adding entity A");
    tx.add_entity(&Entity::builder().handle("HANDLE-ENTITY-B").build())
        .await
        .expect("adding entity B");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .search_entities_by_handle("HANDLE-ENTITY-A*")
        .await
        .expect("searching entities by handle");

    // THEN
    let RdapResponse::EntitySearchResults(results) = actual else {
        panic!("expected entity search results, got {actual:?}");
    };
    assert_eq!(results.results().len(), 1);
    assert_eq!(
        results.results()[0]
            .object_common
            .handle
            .as_ref()
            .map(|h| h.to_string()),
        Some("HANDLE-ENTITY-A".to_string())
    );
}

#[sqlx::test]
async fn search_entities_by_handle_no_match(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);

    // WHEN
    let actual = store
        .search_entities_by_handle("NO-SUCH-HANDLE*")
        .await
        .expect("searching entities by handle");

    // THEN
    let RdapResponse::EntitySearchResults(results) = actual else {
        panic!("expected entity search results, got {actual:?}");
    };
    assert!(results.results().is_empty());
}
