use std::sync::OnceLock;

use ctor::ctor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres as PostgresContainer;

mod autnum;
mod domain;
mod entity;
mod lookups;
mod nameserver;
mod network;

pub(crate) async fn pg_store() -> icann_rdap_srv::storage::pg::ops::Pg {
    use icann_rdap_srv::{
        config::CommonConfig,
        storage::pg::{config::PgConfig, ops::Pg},
    };
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL not set");
    let pool: sqlx::PgPool = sqlx::Pool::connect(&db_url)
        .await
        .expect("connecting to postgres");
    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("running migrations");
    Pg::new(
        PgConfig::builder()
            .db_url(db_url)
            .common_config(CommonConfig::default())
            .build(),
    )
    .await
    .expect("creating pg store")
}

static _CONTAINER: OnceLock<ContainerAsync<PostgresContainer>> = OnceLock::new();

#[ctor(unsafe)]
fn init_pg_container() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build test runtime");
    let (container, port) = rt.block_on(async {
        let container = PostgresContainer::default()
            .with_tag("18-alpine")
            .start()
            .await
            .expect("failed to start postgres 18-alpine container (is docker running?)");
        let port = container
            .get_host_port_ipv4(5432)
            .await
            .expect("no mapped postgres port");
        (container, port)
    });
    unsafe {
        // Safe: #[ctor] runs single-threaded before any test in this binary starts.
        std::env::set_var(
            "DATABASE_URL",
            format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres"),
        );
    }
    let _ = _CONTAINER.set(container);
}
