use icann_rdap_srv::storage::{TxHandle, pg::tx::PgTx};
use sqlx::Pool;
use sqlx::postgres::Postgres;

use super::seed_all_tables;

async fn count_rows(db: &Pool<Postgres>) -> Vec<(&'static str, i64)> {
    vec![
        (
            "entity",
            count_table(db, "SELECT COUNT(*) FROM entity").await,
        ),
        (
            "domain",
            count_table(db, "SELECT COUNT(*) FROM domain").await,
        ),
        (
            "nameserver",
            count_table(db, "SELECT COUNT(*) FROM nameserver").await,
        ),
        (
            "autnum",
            count_table(db, "SELECT COUNT(*) FROM autnum").await,
        ),
        (
            "network",
            count_table(db, "SELECT COUNT(*) FROM network").await,
        ),
        (
            "srv_help",
            count_table(db, "SELECT COUNT(*) FROM srv_help").await,
        ),
    ]
}

async fn count_table(db: &Pool<Postgres>, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(db)
        .await
        .expect("count query")
}

#[sqlx::test]
async fn truncate_tx_removes_data_from_all_tables(db: Pool<Postgres>) {
    // GIVEN
    seed_all_tables(&db).await;

    // WHEN
    let tx = PgTx::new_truncate(&db)
        .await
        .expect("creating new truncate tx");
    Box::new(tx).commit().await.expect("committing truncate tx");

    // THEN
    for (table, count) in count_rows(&db).await {
        assert_eq!(
            count, 0,
            "expected table {table} to be empty after truncate"
        );
    }
}

#[sqlx::test]
async fn truncate_tx_rollback_keeps_existing_data(db: Pool<Postgres>) {
    // GIVEN
    seed_all_tables(&db).await;

    // WHEN
    let tx = PgTx::new_truncate(&db)
        .await
        .expect("creating new truncate tx");
    Box::new(tx)
        .rollback()
        .await
        .expect("rolling back truncate tx");

    // THEN
    for (table, count) in count_rows(&db).await {
        assert_eq!(
            count, 1,
            "expected table {table} to keep its row after rollback"
        );
    }
}
