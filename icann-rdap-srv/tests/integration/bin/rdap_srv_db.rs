use {
    assert_cmd::Command,
    icann_rdap_common::{prelude::RdapResponse, response::ObjectCommonFields},
    icann_rdap_srv::{
        rdap::response::NOT_FOUND,
        storage::{StoreOps, pg::ops::Pg},
    },
    sqlx::{Pool, postgres::Postgres},
    std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    },
};

/// Test jig for the `rdap-srv-db` binary pointed at a live PostgreSQL database.
struct RdapSrvDbTestJig {
    cmd: Command,
    db_url: String,
}

impl RdapSrvDbTestJig {
    fn new(db_url: &str) -> Self {
        Self {
            cmd: Self::command(db_url),
            db_url: db_url.to_string(),
        }
    }

    /// Replaces the command with a fresh one so another invocation can be made.
    fn new_cmd(&mut self) {
        self.cmd = Self::command(&self.db_url);
    }

    fn command(db_url: &str) -> Command {
        let mut cmd = Command::cargo_bin("rdap-srv-db").expect("cannot find rdap-srv-db cmd");
        cmd.env_clear()
            .timeout(Duration::from_secs(10))
            .env("RDAP_SRV_LOG", "debug")
            .env("RDAP_SRV_DB_URL", db_url);
        cmd
    }
}

/// Derives the connection URL of the per-test database created by `#[sqlx::test]`.
async fn test_db_url(db: &Pool<Postgres>) -> String {
    let mut conn = db.acquire().await.expect("acquiring a connection");
    let dbname: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&mut *conn)
        .await
        .expect("reading the database name");
    drop(conn);
    // The pg test ctor sets DATABASE_URL to the container's `postgres` database.
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL is set by the pg test ctor");
    format!("{}/{}", base.trim_end_matches("/postgres"), dbname)
}

#[sqlx::test]
async fn add_domain_stores_row(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db.clone());
    let mut jig = RdapSrvDbTestJig::new(&test_db_url(&db).await);

    // WHEN
    jig.cmd
        .arg("add-domain")
        .arg("--ldh")
        .arg("db-add.example")
        .assert()
        .success();

    // THEN
    let actual = store
        .get_domain_by_ldh("db-add.example")
        .await
        .expect("getting domain");
    let RdapResponse::Domain(domain) = actual else {
        panic!("expected a domain response, got {actual:?}")
    };
    assert_eq!(domain.ldh_name.as_deref(), Some("db-add.example"));
}

#[sqlx::test]
async fn add_domain_last_write_wins(db: Pool<Postgres>) {
    // GIVEN — a domain with an initial handle.
    let store = Pg::from_pool(db.clone());
    let mut jig = RdapSrvDbTestJig::new(&test_db_url(&db).await);
    jig.cmd
        .arg("add-domain")
        .arg("--ldh")
        .arg("db-upsert.example")
        .arg("--handle")
        .arg("OLD-HANDLE")
        .assert()
        .success();

    // WHEN — the same LDH name is added again with a different handle.
    jig.new_cmd();
    jig.cmd
        .arg("add-domain")
        .arg("--ldh")
        .arg("db-upsert.example")
        .arg("--handle")
        .arg("NEW-HANDLE")
        .assert()
        .success();

    // THEN — the stored content reflects the last write.
    let actual = store
        .get_domain_by_ldh("db-upsert.example")
        .await
        .expect("getting domain");
    let RdapResponse::Domain(domain) = actual else {
        panic!("expected a domain response, got {actual:?}")
    };
    assert_eq!(domain.handle(), Some("NEW-HANDLE"));
}

#[sqlx::test]
async fn add_nameserver_updates_generated_columns(db: Pool<Postgres>) {
    // GIVEN — a nameserver with an initial v4 address.
    let mut jig = RdapSrvDbTestJig::new(&test_db_url(&db).await);
    jig.cmd
        .arg("add-nameserver")
        .arg("--ldh")
        .arg("ns-db.example")
        .arg("--v4")
        .arg("192.0.2.1")
        .assert()
        .success();

    // WHEN — the same LDH name is added again with a different v4 address.
    jig.new_cmd();
    jig.cmd
        .arg("add-nameserver")
        .arg("--ldh")
        .arg("ns-db.example")
        .arg("--v4")
        .arg("198.51.100.7")
        .assert()
        .success();

    // THEN — the generated v4 column was recomputed from the new content.
    let v4: Vec<IpAddr> = sqlx::query_scalar("SELECT v4 FROM nameserver WHERE ldh_name = $1")
        .bind("ns-db.example")
        .fetch_one(&db)
        .await
        .expect("reading the generated v4 column");
    assert_eq!(v4, vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))]);
}

#[sqlx::test]
async fn add_network_stores_row(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db.clone());
    let mut jig = RdapSrvDbTestJig::new(&test_db_url(&db).await);

    // WHEN
    jig.cmd
        .arg("add-network")
        .arg("--cidr")
        .arg("198.51.100.0/24")
        .arg("--handle")
        .arg("NET-DB")
        .assert()
        .success();

    // THEN
    let actual = store
        .get_network_by_cidr("198.51.100.0/24")
        .await
        .expect("getting network");
    let RdapResponse::Network(network) = actual else {
        panic!("expected a network response, got {actual:?}")
    };
    assert_eq!(network.handle(), Some("NET-DB"));
}

#[sqlx::test]
async fn delete_network_removes_row(db: Pool<Postgres>) {
    // GIVEN — a stored network.
    let store = Pg::from_pool(db.clone());
    let mut jig = RdapSrvDbTestJig::new(&test_db_url(&db).await);
    jig.cmd
        .arg("add-network")
        .arg("--cidr")
        .arg("203.0.113.64/26")
        .assert()
        .success();

    // WHEN
    jig.new_cmd();
    let assert = jig
        .cmd
        .arg("delete-network")
        .arg("--cidr")
        .arg("203.0.113.64/26")
        .assert()
        .success();
    // The tracing fmt layer writes to stdout in this workspace.
    let out = assert.get_output();
    assert!(String::from_utf8_lossy(&out.stdout).contains("network deleted from database."));

    // THEN
    let actual = store
        .get_network_by_cidr("203.0.113.64/26")
        .await
        .expect("getting network");
    assert_eq!(actual, *NOT_FOUND);
}

#[sqlx::test]
async fn add_autnum_stores_row(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db.clone());
    let mut jig = RdapSrvDbTestJig::new(&test_db_url(&db).await);

    // WHEN
    jig.cmd
        .arg("add-autnum")
        .arg("--start-autnum")
        .arg("65000")
        .arg("--end-autnum")
        .arg("65010")
        .arg("--name")
        .arg("DB Autnum")
        .assert()
        .success();

    // THEN
    let actual = store
        .get_autnum_by_num(65005)
        .await
        .expect("getting autnum");
    let RdapResponse::Autnum(autnum) = actual else {
        panic!("expected an autnum response, got {actual:?}")
    };
    assert_eq!(autnum.name(), Some("DB Autnum"));
}

#[sqlx::test]
async fn delete_autnum_removes_row(db: Pool<Postgres>) {
    // GIVEN — a stored autnum.
    let store = Pg::from_pool(db.clone());
    let mut jig = RdapSrvDbTestJig::new(&test_db_url(&db).await);
    jig.cmd
        .arg("add-autnum")
        .arg("--start-autnum")
        .arg("65020")
        .assert()
        .success();

    // WHEN — deleted without `--end`, so the single-block (start, start) key is used.
    jig.new_cmd();
    jig.cmd
        .arg("delete-autnum")
        .arg("--start")
        .arg("65020")
        .assert()
        .success();

    // THEN
    let actual = store
        .get_autnum_by_num(65020)
        .await
        .expect("getting autnum");
    assert_eq!(actual, *NOT_FOUND);
}

#[sqlx::test]
async fn delete_srv_help_removes_row(db: Pool<Postgres>) {
    // GIVEN — a stored server help response for a specific host.
    let store = Pg::from_pool(db.clone());
    let mut jig = RdapSrvDbTestJig::new(&test_db_url(&db).await);
    jig.cmd
        .arg("add-srv-help")
        .arg("--host")
        .arg("db-host.example")
        .arg("--notice")
        .arg("Help for db-host.example.")
        .assert()
        .success();
    let actual = store
        .get_srv_help(Some("db-host.example"))
        .await
        .expect("getting srv help");
    assert!(matches!(actual, RdapResponse::Help(_)));

    // WHEN
    jig.new_cmd();
    jig.cmd
        .arg("delete-srv-help")
        .arg("--host")
        .arg("db-host.example")
        .assert()
        .success();

    // THEN
    let actual = store
        .get_srv_help(Some("db-host.example"))
        .await
        .expect("getting srv help");
    assert_eq!(actual, *NOT_FOUND);
}

#[sqlx::test]
async fn delete_missing_warns(db: Pool<Postgres>) {
    // GIVEN
    let mut jig = RdapSrvDbTestJig::new(&test_db_url(&db).await);

    // WHEN — deleting a domain that was never added.
    let assert = jig
        .cmd
        .arg("delete-domain")
        .arg("--ldh")
        .arg("no-such-db.example")
        .assert()
        .success();

    // THEN — the command succeeds and warns that nothing was deleted.
    // The tracing fmt layer writes to stdout in this workspace.
    let out = assert.get_output();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No matching domain found; nothing deleted."),
        "stdout was: {stdout}"
    );
}

#[sqlx::test]
async fn add_json_stores_row(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db.clone());
    let mut jig = RdapSrvDbTestJig::new(&test_db_url(&db).await);

    // WHEN — a raw domain document is passed as a positional argument.
    jig.cmd
        .arg("add-json")
                .arg(
            r#"{
                "objectClassName": "domain",
                "ldhName": "db-json.example",
                "handle": "DB-JSON-1",
                "rdapConformance": ["rdap_conformance_0", "rdap_domain_object_0", "rdap_event_based_0"],
                "status": ["active"],
                "events": [{"eventAction": "registration", "eventDate": "2024-01-15T00:00:00Z"}]
            }"#,
        )
        .assert()
        .success();

    // THEN
    let actual = store
        .get_domain_by_ldh("db-json.example")
        .await
        .expect("getting domain");
    assert!(matches!(actual, RdapResponse::Domain(_)));
}

#[sqlx::test]
async fn add_json_invalid_fails(db: Pool<Postgres>) {
    // GIVEN
    let mut jig = RdapSrvDbTestJig::new(&test_db_url(&db).await);

    // WHEN — invalid JSON is piped via stdin.
    jig.cmd
        .arg("add-json")
        .write_stdin("not a json document")
        .assert()
        .failure();
}
