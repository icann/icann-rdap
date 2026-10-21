use {
    icann_rdap_client::{
        http::{Client, ClientConfig, create_client},
        rdap::{QueryType, rdap_request},
    },
    icann_rdap_common::response::{Help, Notice, NoticeOrRemark, RdapResponse},
    icann_rdap_srv::storage::{StoreOps, mem::ops::Mem},
};

use crate::test_jig::SrvTestJig;

/// Seed the store with a minimal `/help` response and commit it.
///
/// A `None` host stores the server-wide default help; `Some(host)` stores help
/// scoped to that virtual host.
async fn seed_help(mem: &Mem, host: Option<&str>) {
    let mut tx = mem.new_tx().await.expect("new transaction");
    let srvhelp = Help::response()
        .notice(Notice(
            NoticeOrRemark::builder()
                .description_entry("foo".to_string())
                .build(),
        ))
        .build();
    tx.add_srv_help(&srvhelp, host)
        .await
        .expect("adding srv help");
    tx.commit().await.expect("tx commit");
}

/// A client for the plain-HTTP test server that never follows redirects.
fn test_client() -> Client {
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    create_client(&client_config).expect("creating client")
}

#[tokio::test]
async fn test_default_help_returns_200() {
    // GIVEN a server whose store holds default, non host-specific help text
    let test_srv = SrvTestJig::new().await;
    seed_help(&test_srv.mem, None).await;

    // WHEN a client issues a /help service discovery query against the server
    let client = test_client();
    let response = rdap_request(&test_srv.rdap_base, &QueryType::Help, &client)
        .await
        .expect("querying server");

    // THEN the server answers with HTTP 200 rather than an error
    assert_eq!(response.http_data.status_code, 200);
}

#[tokio::test]
async fn test_default_help_advertises_exts_extension() {
    // GIVEN a server whose store holds default, non host-specific help text
    let test_srv = SrvTestJig::new().await;
    seed_help(&test_srv.mem, None).await;

    // WHEN a client issues a /help service discovery query against the server
    let client = test_client();
    let response = rdap_request(&test_srv.rdap_base, &QueryType::Help, &client)
        .await
        .expect("querying server");

    // THEN the rdapConformance array advertises the "exts" extension, which is
    // how a server signals that it understands the exts_list media type
    // parameter (draft-ietf-regext-rdap-x-media-type)
    let RdapResponse::Help(help) = &response.rdap else {
        panic!("expected a help response");
    };
    let conformance: Vec<&str> = help
        .common
        .rdap_conformance
        .iter()
        .flatten()
        .map(|e| e.as_str())
        .collect();
    assert!(
        conformance.contains(&"exts"),
        "expected 'exts' in rdapConformance: {conformance:?}"
    );
}

#[tokio::test]
async fn test_host_specific_help_returns_200() {
    // GIVEN a server whose store holds help text scoped to the virtual host
    // "foo.example.com"
    let test_srv = SrvTestJig::new().await;
    seed_help(&test_srv.mem, Some("foo.example.com")).await;

    // WHEN a client queries /help with a Host header naming that virtual host
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .host(reqwest::header::HeaderValue::from_static("foo.example.com"))
        .build();
    let client = create_client(&client_config).expect("creating client");
    let response = rdap_request(&test_srv.rdap_base, &QueryType::Help, &client)
        .await
        .expect("querying server");

    // THEN the host-specific help is served with HTTP 200
    assert_eq!(response.http_data.status_code, 200);
}
