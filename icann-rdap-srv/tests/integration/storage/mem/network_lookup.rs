use {
    icann_rdap_common::response::{Common, Network, ObjectCommon, RdapResponse},
    icann_rdap_srv::storage::{StoreOps, mem::ops::Mem},
    rstest::rstest,
};

#[rstest]
#[case("192.168.0.0/24", "192.168.0.1", "192.168.0.0", "192.168.0.255")]
#[case("192.168.0.0/24", "192.168.0.0", "192.168.0.0", "192.168.0.255")]
#[case("192.168.0.0/24", "192.168.0.254", "192.168.0.0", "192.168.0.255")]
#[case("192.168.0.0/24", "192.168.0.255", "192.168.0.0", "192.168.0.255")]
#[tokio::test]
async fn lookup_by_address(
    #[case] cidr: &str,
    #[case] addr: &str,
    #[case] start: &str,
    #[case] end: &str,
) {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
        .await
        .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_network_by_ipaddr(addr)
        .await
        .expect("getting network by num");

    // THEN
    let RdapResponse::Network(network) = actual else {
        panic!()
    };
    assert_eq!(
        *network
            .start_address
            .as_ref()
            .expect("startAddress is none"),
        start
    );
    assert_eq!(
        *network.end_address.as_ref().expect("endAddress is none"),
        end
    );
}

#[tokio::test]
async fn lookup_not_found() {
    // GIVEN
    let mem = Mem::default();

    // WHEN
    let actual = mem
        .get_network_by_ipaddr("192.168.0.1")
        .await
        .expect("getting network by address");

    // THEN
    let RdapResponse::ErrorResponse(error) = actual else {
        panic!()
    };
    assert_eq!(error.error_code, 404)
}

#[rstest]
#[case(&["192.168.0.0/16", "192.168.0.0/8", "192.168.0.0/24"], "192.168.0.1", "192.168.0.0", "192.168.0.255")]
#[case(&["2001::/64", "2001::/56", "2001::/20"], "2001::1", "2001::", "2001::ffff:ffff:ffff:ffff")]
#[tokio::test]
async fn lookup_most_specific(
    #[case] cidrs: &[&str],
    #[case] addr: &str,
    #[case] start: &str,
    #[case] end: &str,
) {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    for cidr in cidrs {
        tx.add_network(
            &Network::builder()
                .cidr(*cidr)
                .build()
                .expect("cidr parsing"),
        )
        .await
        .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_network_by_ipaddr(addr)
        .await
        .expect("getting network by num");

    // THEN
    let RdapResponse::Network(network) = actual else {
        panic!()
    };
    assert_eq!(
        *network
            .start_address
            .as_ref()
            .expect("startAddress is none"),
        start
    );
    assert_eq!(
        *network.end_address.as_ref().expect("endAddress is none"),
        end
    );
}

#[tokio::test]
async fn lookup_offbit_first() {
    // GIVEN
    let start = "10.0.0.0";
    let end = "10.0.1.255";
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_network(&Network {
        common: Common {
            rdap_conformance: None,
            notices: None,
        },
        object_common: ObjectCommon {
            object_class_name: "ip network".to_string(),
            handle: None,
            remarks: None,
            links: None,
            events: None,
            status: None,
            port_43: None,
            entities: None,
            redacted: None,
        },
        start_address: Some(start.to_string()),
        end_address: Some(end.to_string()),
        ip_version: Some("v4".to_string().into()),
        name: None,
        network_type: None,
        parent_handle: None,
        country: None,
        cidr0_cidrs: None,
    })
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_network_by_ipaddr(start)
        .await
        .expect("getting network by num");

    // THEN
    let RdapResponse::Network(network) = actual else {
        panic!()
    };
    assert_eq!(
        *network
            .start_address
            .as_ref()
            .expect("startAddress is none"),
        start
    );
    assert_eq!(
        *network.end_address.as_ref().expect("endAddress is none"),
        end
    );
}

#[tokio::test]
async fn lookup_offbit_last() {
    // GIVEN
    let start = "10.0.0.0";
    let end = "10.0.1.255";
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_network(&Network {
        common: Common {
            rdap_conformance: None,
            notices: None,
        },
        object_common: ObjectCommon {
            object_class_name: "ip network".to_string(),
            handle: None,
            remarks: None,
            links: None,
            events: None,
            status: None,
            port_43: None,
            entities: None,
            redacted: None,
        },
        start_address: Some(start.to_string()),
        end_address: Some(end.to_string()),
        ip_version: Some("v4".to_string().into()),
        name: None,
        network_type: None,
        parent_handle: None,
        country: None,
        cidr0_cidrs: None,
    })
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_network_by_ipaddr(end)
        .await
        .expect("getting network by num");

    // THEN
    let RdapResponse::Network(network) = actual else {
        panic!()
    };
    assert_eq!(
        *network
            .start_address
            .as_ref()
            .expect("startAddress is none"),
        start
    );
    assert_eq!(
        *network.end_address.as_ref().expect("endAddress is none"),
        end
    );
}

#[rstest]
#[case("192.168.0.0/16", "192.168.0.0/24", "192.168.0.0", "192.168.255.255")]
#[case("192.168.0.0/16", "192.168.0.0/16", "192.168.0.0", "192.168.255.255")]
#[tokio::test]
async fn lookup_by_cidr(
    #[case] cidr: &str,
    #[case] lookup: &str,
    #[case] start: &str,
    #[case] end: &str,
) {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
        .await
        .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_network_by_cidr(lookup)
        .await
        .expect("getting network by cidr");

    // THEN
    let RdapResponse::Network(network) = actual else {
        panic!()
    };
    assert_eq!(
        *network
            .start_address
            .as_ref()
            .expect("startAddress is none"),
        start
    );
    assert_eq!(
        *network.end_address.as_ref().expect("endAddress is none"),
        end
    );
}

#[tokio::test]
async fn lookup_not_found_by_cidr() {
    // GIVEN
    let mem = Mem::default();

    // WHEN
    let actual = mem
        .get_network_by_cidr("192.168.0.0/24")
        .await
        .expect("getting network by address");

    // THEN
    let RdapResponse::ErrorResponse(error) = actual else {
        panic!()
    };
    assert_eq!(error.error_code, 404)
}
