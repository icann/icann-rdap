//! RFC 9910 relationship-search feature-flag gating for the PostgreSQL backend.
//!
//! The PG backend honours the same `CommonConfig` enable flags as the in-memory
//! backend: when a flag is off the corresponding `search_*_rdap_*` method returns
//! `NOT_IMPLEMENTED`; when on it runs the query. These tests lock that behaviour in
//! and guard against a flag being wired to the wrong method or dropped entirely.

use std::net::IpAddr;

use icann_rdap_common::{
    rdns::ip_to_reverse_dns,
    response::{Autnum, Domain, Network, RdapResponse},
};
use icann_rdap_srv::{
    config::CommonConfig,
    rdap::response::NOT_IMPLEMENTED,
    storage::{
        StoreOps,
        mem::{config::MemConfig, ops::Mem},
        pg::{config::PgConfig, ops::Pg},
    },
};
use sqlx::{Pool, postgres::Postgres};

// ---- helpers -----------------------------------------------------------------

fn domain_with_network(name: &str, cidr: &str) -> Domain {
    Domain::builder()
        .ldh_name(name)
        .network(
            Network::builder()
                .cidr(cidr)
                .build()
                .expect("building network"),
        )
        .build()
}

/// Build a PG store over an already-connected pool with the supplied common config.
fn pg_store(db: Pool<Postgres>, common: CommonConfig) -> Pg {
    let config = PgConfig::builder()
        .db_url("postgresql://unused") // ignored; the pool is already connected
        .common_config(common)
        .build();
    Pg::from_pool_with_config(db, config)
}

/// Build an in-memory store with the supplied common config (for parity checks).
fn mem_store(common: CommonConfig) -> Mem {
    Mem::new(MemConfig::builder().common_config(common).build())
}

fn assert_not_implemented(actual: &RdapResponse) {
    assert_eq!(*actual, *NOT_IMPLEMENTED);
}

const V4_IP: &str = "203.0.113.5";

// ---- flag OFF => NOT_IMPLEMENTED (one per flag; no data needed) --------------

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
async fn ip_rdap_up_disabled(db: Pool<Postgres>) {
    let store = pg_store(db, CommonConfig::default());
    assert_not_implemented(
        &store
            .search_ip_rdap_up_by_ipaddr(V4_IP)
            .await
            .expect("call"),
    );
}

#[sqlx::test]
async fn ip_rdap_top_disabled(db: Pool<Postgres>) {
    let store = pg_store(db, CommonConfig::default());
    assert_not_implemented(
        &store
            .search_ip_rdap_top_by_ipaddr(V4_IP)
            .await
            .expect("call"),
    );
}

#[sqlx::test]
async fn ip_rdap_down_disabled(db: Pool<Postgres>) {
    let store = pg_store(db, CommonConfig::default());
    assert_not_implemented(
        &store
            .search_ip_rdap_down_by_ipaddr(V4_IP)
            .await
            .expect("call"),
    );
}

#[sqlx::test]
async fn ip_rdap_bottom_disabled(db: Pool<Postgres>) {
    let store = pg_store(db, CommonConfig::default());
    assert_not_implemented(
        &store
            .search_ip_rdap_bottom_by_ipaddr(V4_IP)
            .await
            .expect("call"),
    );
}

#[sqlx::test]
async fn domain_rdap_up_disabled(db: Pool<Postgres>) {
    let store = pg_store(db, CommonConfig::default());
    let name = ip_to_reverse_dns(&"10.1.1.5".parse::<IpAddr>().unwrap());
    assert_not_implemented(
        &store
            .search_domain_rdap_up_by_ldh(&name)
            .await
            .expect("call"),
    );
}

#[sqlx::test]
async fn domain_rdap_top_disabled(db: Pool<Postgres>) {
    let store = pg_store(db, CommonConfig::default());
    let name = ip_to_reverse_dns(&"10.1.1.5".parse::<IpAddr>().unwrap());
    assert_not_implemented(
        &store
            .search_domain_rdap_top_by_ldh(&name)
            .await
            .expect("call"),
    );
}

#[sqlx::test]
async fn domain_rdap_down_disabled(db: Pool<Postgres>) {
    let store = pg_store(db, CommonConfig::default());
    let name = ip_to_reverse_dns(&"10.1.1.5".parse::<IpAddr>().unwrap());
    assert_not_implemented(
        &store
            .search_domain_rdap_down_by_ldh(&name)
            .await
            .expect("call"),
    );
}

#[sqlx::test]
async fn domain_rdap_bottom_disabled(db: Pool<Postgres>) {
    let store = pg_store(db, CommonConfig::default());
    let name = ip_to_reverse_dns(&"10.1.1.5".parse::<IpAddr>().unwrap());
    assert_not_implemented(
        &store
            .search_domain_rdap_bottom_by_ldh(&name)
            .await
            .expect("call"),
    );
}

// ---- flag ON => query runs (not NOT_IMPLEMENTED) -----------------------------

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

    // WHEN
    let actual = store.search_autnum_rdap_up_by_num(805).await.expect("call");

    // THEN — the guard passed, so this is a real result, not NOT_IMPLEMENTED.
    assert_ne!(actual, *NOT_IMPLEMENTED);
}

#[sqlx::test]
async fn ip_rdap_up_enabled(db: Pool<Postgres>) {
    // GIVEN
    let store = pg_store(db, CommonConfig::builder().ip_rdap_up_enable(true).build());
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("203.0.113.0/24")
            .handle("NET-UP")
            .build()
            .expect("building network"),
    )
    .await
    .expect("add network");
    Box::new(tx).commit().await.expect("commit");

    // WHEN
    let actual = store
        .search_ip_rdap_up_by_ipaddr(V4_IP)
        .await
        .expect("call");

    // THEN
    assert_ne!(actual, *NOT_IMPLEMENTED);
}

#[sqlx::test]
async fn domain_rdap_top_enabled(db: Pool<Postgres>) {
    // GIVEN
    let store = pg_store(
        db,
        CommonConfig::builder().domain_rdap_top_enable(true).build(),
    );
    let mut tx = store.new_tx().await.expect("new tx");
    for (name, cidr) in [
        ("root.example", "10.0.0.0/8"),
        ("leaf.example", "10.1.1.0/24"),
    ] {
        tx.add_domain(&domain_with_network(name, cidr))
            .await
            .expect("add domain");
    }
    Box::new(tx).commit().await.expect("commit");

    // WHEN — 10.1.1.5 lies in leaf.example (10.1.1.0/24), the most specific stored range.
    let name = ip_to_reverse_dns(&"10.1.1.5".parse::<IpAddr>().unwrap());
    let actual = store
        .search_domain_rdap_top_by_ldh(&name)
        .await
        .expect("call");

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

    // THEN — the guard passed and BOTH overlapping autnums are returned (not vacuous).
    let RdapResponse::AutnumSearchResults(results) = actual else {
        panic!("expected AutnumSearchResults, got {actual:?}");
    };
    assert_eq!(results.results().len(), 2);
}

// ---- Mem <-> Pg parity -------------------------------------------------------

#[sqlx::test]
async fn autnum_rdap_up_mem_pg_parity(db: Pool<Postgres>) {
    // Flag OFF in both backends => both NOT_IMPLEMENTED.
    let mem_off = mem_store(CommonConfig::default());
    let pg_off = pg_store(db.clone(), CommonConfig::default());
    assert_not_implemented(
        &mem_off
            .search_autnum_rdap_up_by_num(805)
            .await
            .expect("mem"),
    );
    assert_not_implemented(&pg_off.search_autnum_rdap_up_by_num(805).await.expect("pg"));

    // Flag ON in both, identical data => identical outcome.
    let autnum = Autnum::builder().autnum_range(800..810).build();
    let mem_on = mem_store(CommonConfig::builder().autnum_rdap_up_enable(true).build());
    let pg_on = pg_store(
        db,
        CommonConfig::builder().autnum_rdap_up_enable(true).build(),
    );

    let mut tx = mem_on.new_tx().await.expect("mem tx");
    tx.add_autnum(&autnum).await.expect("add autnum (mem)");
    Box::new(tx).commit().await.expect("commit (mem)");

    let mut tx = pg_on.new_tx().await.expect("pg tx");
    tx.add_autnum(&autnum).await.expect("add autnum (pg)");
    Box::new(tx).commit().await.expect("commit (pg)");

    let mem_res = mem_on.search_autnum_rdap_up_by_num(805).await.expect("mem");
    let pg_res = pg_on.search_autnum_rdap_up_by_num(805).await.expect("pg");

    assert_eq!(
        mem_res, pg_res,
        "mem and pg must agree on the autnum rdap up result"
    );
}

#[sqlx::test]
async fn autnum_rdap_down_mem_pg_parity(db: Pool<Postgres>) {
    // Identical data in both backends => identical down result. This exercises the
    // PG `autnum_overlapping` query against Mem's range-map `overlapping`, so any
    // divergence in which blocks are returned (or their order) is caught here.
    let autnums = [
        Autnum::builder().autnum_range(800..810).build(),
        Autnum::builder().autnum_range(820..830).build(),
    ];
    let common = CommonConfig::builder()
        .autnum_rdap_down_enable(true)
        .build();

    let mem_on = mem_store(common);
    {
        let mut tx = mem_on.new_tx().await.expect("mem tx");
        for a in &autnums {
            tx.add_autnum(a).await.expect("add autnum (mem)");
        }
        Box::new(tx).commit().await.expect("commit (mem)");
    }

    let pg_on = pg_store(db, common);
    {
        let mut tx = pg_on.new_tx().await.expect("pg tx");
        for a in &autnums {
            tx.add_autnum(a).await.expect("add autnum (pg)");
        }
        Box::new(tx).commit().await.expect("commit (pg)");
    }

    let mem_res = mem_on
        .search_autnum_rdap_down_by_range(805, 825)
        .await
        .expect("mem");
    let pg_res = pg_on
        .search_autnum_rdap_down_by_range(805, 825)
        .await
        .expect("pg");

    assert_eq!(
        mem_res, pg_res,
        "mem and pg must agree on the autnum rdap down result"
    );
}
