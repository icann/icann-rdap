use icann_rdap_common::response::{Autnum, RdapResponse};
use icann_rdap_srv::storage::StoreOps;

use super::pg_store;

#[tokio::test]
async fn search_autnums_by_handle_finds_match() {
    // GIVEN
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(1000..1010)
            .handle("AS-HANDLE-A")
            .build(),
    )
    .await
    .expect("adding autnum A");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(2000..2010)
            .handle("AS-HANDLE-B")
            .build(),
    )
    .await
    .expect("adding autnum B");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .search_autnums_by_handle("AS-HANDLE-A*")
        .await
        .expect("searching autnums by handle");

    // THEN
    let RdapResponse::AutnumSearchResults(results) = actual else {
        panic!("expected autnum search results, got {actual:?}");
    };
    assert_eq!(results.results().len(), 1);
    assert_eq!(
        results.results()[0]
            .object_common
            .handle
            .as_ref()
            .map(|h| h.to_string()),
        Some("AS-HANDLE-A".to_string())
    );
}

#[tokio::test]
async fn search_autnums_by_handle_no_match() {
    // GIVEN
    let store = pg_store().await;

    // WHEN
    let actual = store
        .search_autnums_by_handle("NO-SUCH-AS*")
        .await
        .expect("searching autnums by handle");

    // THEN
    let RdapResponse::AutnumSearchResults(results) = actual else {
        panic!("expected autnum search results, got {actual:?}");
    };
    assert!(results.results().is_empty());
}
