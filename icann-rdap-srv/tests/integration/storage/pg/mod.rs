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
mod search_autnum;
mod search_domain;
mod search_entity;
mod search_nameserver;
mod search_network;
mod truncate;

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

pub(crate) async fn seed_all_tables(db: &sqlx::PgPool) {
    use icann_rdap_common::response::{Autnum, Domain, Entity, Help, Nameserver, Network};
    use icann_rdap_srv::storage::TxHandle;

    let mut tx = icann_rdap_srv::storage::pg::tx::PgTx::new(db)
        .await
        .expect("creating new pg tx");
    tx.add_domain(&Domain::builder().ldh_name("seed.example").build())
        .await
        .expect("adding domain to tx");
    tx.add_entity(&Entity::builder().handle("SEED-ENTITY").build())
        .await
        .expect("adding entity to tx");
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("ns-seed.example")
            .addresses(vec!["192.0.2.1".to_string()])
            .build()
            .expect("building nameserver"),
    )
    .await
    .expect("adding nameserver to tx");
    tx.add_autnum(&Autnum::builder().autnum_range(800..810).build())
        .await
        .expect("adding autnum to tx");
    tx.add_network(
        &Network::builder()
            .cidr("203.0.113.0/24")
            .handle("NET-SEED")
            .build()
            .expect("building network"),
    )
    .await
    .expect("adding network to tx");
    tx.add_srv_help(&Help::response().build(), None)
        .await
        .expect("adding srv help to tx");
    Box::new(tx).commit().await.expect("committing seed tx");
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
