//! Tests for `RDAP_SRV_PG_IGNORE_DATA_DIR`: when set, a Postgres-backed server must skip the
//! data-directory load (and therefore never react to `rdap-srv-store --update`/`--reload`
//! markers), treating the database as the sole source of truth.

use std::path::PathBuf;

use icann_rdap_common::prelude::ToResponse;
use icann_rdap_common::response::{Domain, RdapResponse};
use icann_rdap_srv::config::{CommonConfig, JsContactConversion, ServiceConfig, StorageType};
use icann_rdap_srv::server::AppState;
use icann_rdap_srv::storage::pg::{config::PgConfig, ops::Pg};
use sqlx::{Pool, Postgres};
use test_dir::{DirBuilder, TestDir};

use super::url_for_database;

/// Build a `ServiceConfig` whose data dir points at `data_dir`. The storage type is not read by
/// `new_pg` (it only consumes the data dir and reload/bootstrap flags), but we pass the real
/// Postgres variant so the config is self-consistent.
fn service_config(data_dir: &str, storage_type: StorageType) -> ServiceConfig {
    ServiceConfig::builder()
        .storage_type(storage_type)
        .data_dir(data_dir.to_string())
        .auto_reload(false)
        .bootstrap(false)
        .update_on_bootstrap(false)
        .jscontact_conversion(JsContactConversion::None)
        .build()
}

/// Connection URL for the isolated per-test database that `#[sqlx::test]` created, so a fresh
/// pool (built by `new_pg`) lands on the same database as the test's own pool.
async fn test_db_url(db: &Pool<Postgres>) -> String {
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL set by the test ctor");
    let name: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(db)
        .await
        .expect("current_database query");
    url_for_database(&base, &name)
}

async fn domain_count(db: &Pool<Postgres>) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM domain")
        .fetch_one(db)
        .await
        .expect("counting domains")
}

/// Write one valid RDAP domain document into `dir`. It is round-tripped through the real types,
/// so `load_data` is guaranteed to accept it (no dependence on external fixture files).
fn seed_domain_fixture(dir: &std::path::Path) {
    let domain = Domain::builder().ldh_name("foo.example").build();
    let rdap: RdapResponse = domain.to_response();
    let json = serde_json::to_string(&rdap).expect("serializing domain");
    std::fs::write(dir.join("foo_example.json"), json).expect("writing domain fixture");
}

/// With `ignore_data_dir` set, building the server must NOT load anything from the data dir.
#[sqlx::test]
async fn ignore_data_dir_skips_startup_load(db: Pool<Postgres>) {
    // GIVEN a data dir containing one domain and a config that ignores the data dir
    let td = TestDir::temp();
    let root: PathBuf = td.root().to_path_buf();
    seed_domain_fixture(&root);
    let config = PgConfig::builder()
        .db_url(test_db_url(&db).await)
        .common_config(CommonConfig::default())
        .ignore_data_dir(true)
        .build();
    let svc = service_config(
        root.to_string_lossy().as_ref(),
        StorageType::Postgres(config.clone()),
    );

    // WHEN the postgres server state is built
    AppState::<Pg>::new_pg(config, &svc)
        .await
        .expect("building server");

    // THEN nothing was loaded from the data dir
    assert_eq!(
        domain_count(&db).await,
        0,
        "data dir must be ignored when flag set"
    );
}

/// Control: without the flag the same data dir IS loaded (current behavior preserved).
#[sqlx::test]
async fn data_dir_loaded_when_flag_unset(db: Pool<Postgres>) {
    // GIVEN a data dir containing one domain and a config that does not ignore it
    let td = TestDir::temp();
    let root: PathBuf = td.root().to_path_buf();
    seed_domain_fixture(&root);
    let config = PgConfig::builder()
        .db_url(test_db_url(&db).await)
        .common_config(CommonConfig::default())
        .ignore_data_dir(false)
        .build();
    let svc = service_config(
        root.to_string_lossy().as_ref(),
        StorageType::Postgres(config.clone()),
    );

    // WHEN the postgres server state is built
    AppState::<Pg>::new_pg(config, &svc)
        .await
        .expect("building server");

    // THEN the domain from the data dir was loaded
    assert_eq!(
        domain_count(&db).await,
        1,
        "data dir should load when flag unset"
    );
}
