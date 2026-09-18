use std::sync::Mutex;

use ctor::ctor;
use dtor::dtor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres as PostgresContainer;

use icann_rdap_common::response::RdapResponse;
use icann_rdap_srv::config::CommonConfig;
use icann_rdap_srv::rdap::response::NOT_IMPLEMENTED;
use icann_rdap_srv::storage::pg::{config::PgConfig, ops::Pg};
use sqlx::{Pool, Postgres};

mod autnum;
mod del;
mod domain;
mod entity;
mod ignore_data_dir;
mod last_update;
mod lookups;
mod nameserver;
mod network;
mod notify;
mod search_autnum;
mod search_domain;
mod search_domain_rdap;
mod search_entity;
mod search_nameserver;
mod search_network;
mod truncate;
mod upsert;

/// Rebuild `base_url` so it points at the named database. Only the URL path (the
/// database component) changes; scheme, credentials, host and port are preserved.
pub(crate) fn url_for_database(base_url: &str, db_name: &str) -> String {
    let scheme_end = base_url.find("://").expect("well-formed url has a scheme") + 3;
    let authority_end = base_url[scheme_end..]
        .find('/')
        .map(|i| scheme_end + i)
        .unwrap_or(base_url.len());
    format!("{}/{}", &base_url[..authority_end], db_name)
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

/// Build a PG store over an already-connected pool with the supplied common config.
pub(crate) fn pg_store(db: Pool<Postgres>, common: CommonConfig) -> Pg {
    let config = PgConfig::builder()
        .db_url("postgresql://unused") // ignored; the pool is already connected
        .common_config(common)
        .ignore_data_dir(false)
        .build();
    Pg::from_pool_with_config(db, config)
}

pub(crate) fn assert_not_implemented(actual: &RdapResponse) {
    assert_eq!(*actual, *NOT_IMPLEMENTED);
}

static _CONTAINER: Mutex<Option<ContainerAsync<PostgresContainer>>> = Mutex::new(None);

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
    *_CONTAINER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(container);
}

/// Tear down the shared Postgres container when the test binary exits.
///
/// The docker container outlives any Rust object, so a leaked handle is what keeps piling up:
/// `ContainerAsync` only removes its container inside its async `Drop`, and that drop calls
/// `tokio::runtime::Handle::current()` — which requires a live runtime. There is no such
/// runtime during an exit handler (and the drop fires when `block_on` tears down its future,
/// i.e. *outside* any runtime context), so letting the handle drop here panics with "panic in a
/// destructor during cleanup" and aborts the process. Instead we remove the container
/// synchronously via the docker CLI using its id, then leak the handle (`mem::forget`) so its
/// async `Drop` never runs. This reaps both green and red runs; only hard kills (SIGKILL / power
/// loss) still need the `just test pg-prune` recipe. Assumes the `docker` CLI is on PATH.
#[dtor(unsafe)]
fn cleanup_pg_container() {
    // Block-scoped guard so the mutex is released before we shell out (which can be slow).
    let container = {
        let mut guard = match _CONTAINER.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.take()
    };
    let Some(container) = container else {
        return;
    };

    // Synchronous removal — no tokio runtime is available during exit handlers.
    let id = container.id().to_string();
    match std::process::Command::new("docker")
        .args(["rm", "-f", &id])
        .output()
    {
        Ok(out) if out.status.success() => {}
        Ok(out) => eprintln!(
            "warning: failed to remove postgres test container {id}: {}",
            String::from_utf8_lossy(&out.stderr),
        ),
        Err(err) => eprintln!("warning: failed to run `docker rm` for container {id}: {err}"),
    }

    // Leak the handle so ContainerAsync's async Drop (which requires a tokio runtime) never runs.
    std::mem::forget(container);
}
