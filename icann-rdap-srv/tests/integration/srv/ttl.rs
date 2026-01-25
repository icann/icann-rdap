use {
    icann_rdap_client::{
        http::{create_client, ClientConfig},
        rdap::{rdap_request, QueryType},
    },
    icann_rdap_common::{
        prelude::{ttl::Ttl0Data, RdapResponse},
        response::Domain,
    },
    icann_rdap_srv::storage::StoreOps,
};

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn test_domain_with_ttl() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("foo.example")
            .ttl0_data(Ttl0Data::builder().a_value(1000).aaaa_value(3000).build())
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::domain("foo.example").expect("invalid domain name");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("quering server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::Domain(domain) = response.rdap else {
        panic!("not a domain")
    };
    let Some(ttl0) = domain.ttl0_data() else {
        panic!("no ttl data")
    };
    assert_eq!(ttl0.a_value(), Some(1000));
    assert_eq!(ttl0.aaaa_value(), Some(3000));
}
