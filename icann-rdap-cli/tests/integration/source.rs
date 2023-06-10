#![allow(non_snake_case)]

use cidr_utils::cidr::IpCidr;
use icann_rdap_client::request::{RequestResponseOwned, SourceType};
use icann_rdap_common::response::network::Network;
use icann_rdap_srv::storage::StoreOps;
use rstest::rstest;

use crate::test_jig::TestJig;

#[rstest]
#[case("10.0.0.0/24", "10.0.0.0/24")]
#[case("10.0.0.0/24", "10.0.0.1")]
#[tokio::test(flavor = "multi_thread")]
async fn GIVEN_inr_query_WHEN_query_THEN_source_is_rir(
    #[case] db_cidr: &str,
    #[case] q_cidr: &str,
) {
    // GIVEN
    let mut test_jig = TestJig::new();
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::basic()
            .cidr(IpCidr::from_str(db_cidr).expect("cidr parsing"))
            .build(),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    test_jig.cmd.arg(q_cidr);

    // THEN
    let output = test_jig.cmd.output().expect("executing inr query");
    let responses: Vec<RequestResponseOwned> =
        serde_json::from_slice(&output.stdout).expect("parsing stdout");
    let source_type = responses
        .first()
        .expect("respons is empty")
        .req_data
        .source_type;
    assert!(matches!(source_type, SourceType::RegionalInternetRegistry));
}
