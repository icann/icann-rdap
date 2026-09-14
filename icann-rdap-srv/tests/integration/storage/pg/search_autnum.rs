use icann_rdap_common::response::{Autnum, RdapResponse};
use icann_rdap_srv::config::CommonConfig;
use icann_rdap_srv::rdap::response::NOT_IMPLEMENTED;
use icann_rdap_srv::storage::StoreOps;
use icann_rdap_srv::storage::pg::ops::Pg;
use sqlx::{Pool, postgres::Postgres};

use super::{assert_not_implemented, pg_store};

#[sqlx::test]
async fn search_autnums_by_handle_finds_match(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
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

#[sqlx::test]
async fn search_autnums_by_handle_no_match(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);

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

#[sqlx::test]
async fn search_autnums_by_name_finds_match(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(3000..3010)
            .name("Example Network A")
            .build(),
    )
    .await
    .expect("adding autnum A");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(4000..4010)
            .name("Example Network B")
            .build(),
    )
    .await
    .expect("adding autnum B");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .search_autnums_by_name("Example Network A*")
        .await
        .expect("searching autnums by name");

    // THEN
    let RdapResponse::AutnumSearchResults(results) = actual else {
        panic!("expected autnum search results, got {actual:?}");
    };
    assert_eq!(results.results().len(), 1);
    assert_eq!(
        results.results()[0].name.as_ref().map(|n| n.to_string()),
        Some("Example Network A".to_string())
    );
}

#[sqlx::test]
async fn search_autnums_by_name_no_match(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);

    // WHEN
    let actual = store
        .search_autnums_by_name("No Such Network*")
        .await
        .expect("searching autnums by name");

    // THEN
    let RdapResponse::AutnumSearchResults(results) = actual else {
        panic!("expected autnum search results, got {actual:?}");
    };
    assert!(results.results().is_empty());
}

/// Seed a non-overlapping autnum partition used by the RFC 9910 relationship tests:
///   A: 1000..1010 (AS-A), B: 2000..2010 (AS-B), C: 3000..3500 (AS-C)
async fn seed_blocks(store: &Pg) {
    let mut tx = store.new_tx().await.expect("new tx");
    for (range, handle) in [
        (1000u32..1010u32, "AS-A"),
        (2000u32..2010u32, "AS-B"),
        (3000u32..3500u32, "AS-C"),
    ] {
        tx.add_autnum(&Autnum::builder().autnum_range(range).handle(handle).build())
            .await
            .expect("adding autnum");
    }
    Box::new(tx).commit().await.expect("committing tx");
}

/// Assert the response is a single-element `AutnumSearchResults` whose record starts at `start`.
fn assert_single_autnum(actual: RdapResponse, start: u32) {
    let RdapResponse::AutnumSearchResults(results) = actual else {
        panic!("expected autnum search results, got {actual:?}");
    };
    assert_eq!(results.results().len(), 1);
    assert_eq!(results.results()[0].start_autnum(), Some(start));
}

/// Assert the response is a 404 error (the storage-level NOT_FOUND).
fn assert_not_found(actual: RdapResponse) {
    let RdapResponse::ErrorResponse(error) = actual else {
        panic!("expected 404 error, got {actual:?}");
    };
    assert_eq!(error.error_code(), 404);
}

#[sqlx::test]
async fn rdap_up_by_num_returns_containing_block(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_blocks(&store).await;

    // WHEN
    let actual = store
        .search_autnum_rdap_up_by_num(1005)
        .await
        .expect("up by num");

    // THEN
    assert_single_autnum(actual, 1000);
}

#[sqlx::test]
async fn rdap_up_by_num_not_found_in_gap(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_blocks(&store).await;

    // WHEN — 1500 lies in the gap between block A (..1010) and B (2000..)
    let actual = store
        .search_autnum_rdap_up_by_num(1500)
        .await
        .expect("up by num");

    // THEN
    assert_not_found(actual);
}

#[sqlx::test]
async fn rdap_top_by_num_matches_up(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_blocks(&store).await;

    // WHEN — "top" is the topmost covering block, identical to "up" here.
    let actual = store
        .search_autnum_rdap_top_by_num(3250)
        .await
        .expect("top by num");

    // THEN
    assert_single_autnum(actual, 3000);
}

#[sqlx::test]
async fn rdap_up_by_range_inside_single_block(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_blocks(&store).await;

    // WHEN — [1002, 1008] sits entirely inside block A.
    let actual = store
        .search_autnum_rdap_up_by_range(1002, 1008)
        .await
        .expect("up by range");

    // THEN
    assert_single_autnum(actual, 1000);
}

#[sqlx::test]
async fn rdap_up_by_range_spanning_blocks_not_found(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_blocks(&store).await;

    // WHEN — [1005, 2005] spans blocks A and B; no single block covers it.
    let actual = store
        .search_autnum_rdap_up_by_range(1005, 2005)
        .await
        .expect("up by range");

    // THEN
    assert_not_found(actual);
}

#[sqlx::test]
async fn rdap_up_by_range_exact_block(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_blocks(&store).await;

    // WHEN — [3000, 3500] is exactly block C.
    let actual = store
        .search_autnum_rdap_up_by_range(3000, 3500)
        .await
        .expect("up by range");

    // THEN
    assert_single_autnum(actual, 3000);
}

#[sqlx::test]
async fn rdap_top_by_range_matches_up(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_blocks(&store).await;

    // WHEN
    let actual = store
        .search_autnum_rdap_top_by_range(1002, 1008)
        .await
        .expect("top by range");

    // THEN
    assert_single_autnum(actual, 1000);
}

#[sqlx::test]
async fn rdap_down_by_num_returns_containing_block(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_blocks(&store).await;

    // WHEN — a point only overlaps the block that contains it.
    let actual = store
        .search_autnum_rdap_down_by_num(1005)
        .await
        .expect("down by num");

    // THEN
    assert_single_autnum(actual, 1000);
}

#[sqlx::test]
async fn rdap_down_by_range_returns_overlapping_blocks(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_blocks(&store).await;

    // WHEN — [1005, 2005] overlaps both A and B.
    let actual = store
        .search_autnum_rdap_down_by_range(1005, 2005)
        .await
        .expect("down by range");

    // THEN — two results, ordered by start_autnum (A then B).
    let RdapResponse::AutnumSearchResults(results) = actual else {
        panic!("expected autnum search results, got {actual:?}");
    };
    assert_eq!(results.results().len(), 2);
    assert_eq!(results.results()[0].start_autnum(), Some(1000));
    assert_eq!(results.results()[1].start_autnum(), Some(2000));
}

#[sqlx::test]
async fn rdap_down_by_range_partial_overlap(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_blocks(&store).await;

    // WHEN — [3400, 3600] partially overlaps block C (3000..3500) and nothing else.
    let actual = store
        .search_autnum_rdap_down_by_range(3400, 3600)
        .await
        .expect("down by range");

    // THEN
    assert_single_autnum(actual, 3000);
}

#[sqlx::test]
async fn rdap_bottom_by_num_matches_down(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_blocks(&store).await;

    // WHEN — "bottom" is the overlapping set, identical to "down" here.
    let actual = store
        .search_autnum_rdap_bottom_by_num(1005)
        .await
        .expect("bottom by num");

    // THEN
    assert_single_autnum(actual, 1000);
}

#[sqlx::test]
async fn rdap_bottom_by_range_matches_down(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_blocks(&store).await;

    // WHEN — [1005, 2005] overlaps A and B.
    let actual = store
        .search_autnum_rdap_bottom_by_range(1005, 2005)
        .await
        .expect("bottom by range");

    // THEN
    let RdapResponse::AutnumSearchResults(results) = actual else {
        panic!("expected autnum search results, got {actual:?}");
    };
    assert_eq!(results.results().len(), 2);
    assert_eq!(results.results()[0].start_autnum(), Some(1000));
    assert_eq!(results.results()[1].start_autnum(), Some(2000));
}

#[sqlx::test]
async fn rdap_down_by_num_in_gap_returns_empty(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    seed_blocks(&store).await;

    // WHEN — 1500 sits in the gap between A (..1010) and B (2000..); no block overlaps it.
    let actual = store
        .search_autnum_rdap_down_by_num(1500)
        .await
        .expect("down by num");

    // THEN — "down" yields an (empty) AutnumSearchResults, NOT a 404 like "up" would.
    let RdapResponse::AutnumSearchResults(results) = actual else {
        panic!("expected autnum search results, got {actual:?}");
    };
    assert!(results.results().is_empty());
}

#[sqlx::test]
async fn autnum_rdap_up_disabled(db: Pool<Postgres>) {
    let store = pg_store(db, CommonConfig::default());
    assert_not_implemented(&store.search_autnum_rdap_up_by_num(805).await.expect("call"));
}

#[sqlx::test]
async fn autnum_rdap_top_disabled(db: Pool<Postgres>) {
    let store = pg_store(db, CommonConfig::default());
    assert_not_implemented(
        &store
            .search_autnum_rdap_top_by_num(805)
            .await
            .expect("call"),
    );
}

#[sqlx::test]
async fn autnum_rdap_down_disabled(db: Pool<Postgres>) {
    let store = pg_store(db, CommonConfig::default());
    assert_not_implemented(
        &store
            .search_autnum_rdap_down_by_num(805)
            .await
            .expect("call"),
    );
}

#[sqlx::test]
async fn autnum_rdap_bottom_disabled(db: Pool<Postgres>) {
    let store = pg_store(db, CommonConfig::default());
    assert_not_implemented(
        &store
            .search_autnum_rdap_bottom_by_num(805)
            .await
            .expect("call"),
    );
}

#[sqlx::test]
async fn autnum_rdap_up_enabled(db: Pool<Postgres>) {
    // GIVEN
    let store = pg_store(
        db,
        CommonConfig::builder().autnum_rdap_up_enable(true).build(),
    );
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_autnum(&Autnum::builder().autnum_range(800..810).build())
        .await
        .expect("add autnum");
    Box::new(tx).commit().await.expect("commit");

    // WHEN — the flag is on, so the guard passes and a real query runs.
    let actual = store.search_autnum_rdap_up_by_num(805).await.expect("call");

    // THEN
    assert_ne!(actual, *NOT_IMPLEMENTED);
}

#[sqlx::test]
async fn autnum_rdap_down_enabled(db: Pool<Postgres>) {
    // GIVEN — two stored autnums that both overlap the queried range [805, 825].
    let store = pg_store(
        db,
        CommonConfig::builder()
            .autnum_rdap_down_enable(true)
            .build(),
    );
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_autnum(&Autnum::builder().autnum_range(800..810).build())
        .await
        .expect("add autnum 800-810");
    tx.add_autnum(&Autnum::builder().autnum_range(820..830).build())
        .await
        .expect("add autnum 820-830");
    Box::new(tx).commit().await.expect("commit");

    // WHEN — a range query spanning both blocks.
    let actual = store
        .search_autnum_rdap_down_by_range(805, 825)
        .await
        .expect("call");

    // THEN — BOTH overlapping autnums are returned (not vacuous).
    let RdapResponse::AutnumSearchResults(results) = actual else {
        panic!("expected AutnumSearchResults, got {actual:?}");
    };
    assert_eq!(results.results().len(), 2);
}
