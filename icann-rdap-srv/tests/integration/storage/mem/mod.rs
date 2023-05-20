#![allow(non_snake_case)]

use cidr_utils::cidr::IpCidr;
use icann_rdap_common::response::{
    autnum::Autnum,
    domain::Domain,
    entity::Entity,
    nameserver::Nameserver,
    network::Network,
    types::{Common, ObjectCommon},
};
use icann_rdap_srv::{
    rdap::response::{ArcRdapResponse, RdapServerResponse},
    storage::{mem::ops::Mem, StoreOps},
};
use rstest::rstest;

#[tokio::test]
async fn GIVEN_domain_in_mem_WHEN_new_truncate_tx_THEN_no_domain_in_mem() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::basic().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let tx = mem.new_truncate_tx().await.expect("new truncate tx");
    tx.commit().await.expect("tx commit");

    // THEN
    let actual = mem
        .get_domain_by_ldh("foo.example")
        .await
        .expect("getting domain by ldh");
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::ErrorResponse(_)));
    let ArcRdapResponse::ErrorResponse(error) = response else { panic!() };
    assert_eq!(error.error_code, 404)
}

#[tokio::test]
async fn GIVEN_domain_in_mem_WHEN_lookup_domain_by_ldh_THEN_domain_returned() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::basic().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_domain_by_ldh("foo.example")
        .await
        .expect("getting domain by ldh");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::Domain(_)));
    let ArcRdapResponse::Domain(domain) = response else { panic!() };
    assert_eq!(
        domain.ldh_name.as_ref().expect("ldhName is none"),
        "foo.example"
    )
}

#[tokio::test]
async fn GIVEN_no_domain_in_mem_WHEN_lookup_domain_by_ldh_THEN_404_returned() {
    // GIVEN
    let mem = Mem::default();

    // WHEN
    let actual = mem
        .get_domain_by_ldh("foo.example")
        .await
        .expect("getting domain by ldh");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::ErrorResponse(_)));
    let ArcRdapResponse::ErrorResponse(error) = response else { panic!() };
    assert_eq!(error.error_code, 404)
}

#[tokio::test]
async fn GIVEN_entity_in_mem_WHEN_lookup_entity_by_handle_THEN_entity_returned() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_entity(&Entity::basic().handle("foo").build())
        .await
        .expect("add entity in tx");
    tx.commit().await.expect("entity tx commit");

    // WHEN
    let actual = mem
        .get_entity_by_handle("foo")
        .await
        .expect("getting entity by handle");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::Entity(_)));
    let ArcRdapResponse::Entity(entity) = response else { panic!() };
    assert_eq!(
        entity
            .object_common
            .handle
            .as_ref()
            .expect("handle is none"),
        "foo"
    )
}

#[tokio::test]
async fn GIVEN_no_entity_in_mem_WHEN_lookup_entity_by_handle_THEN_404_returned() {
    // GIVEN
    let mem = Mem::default();

    // WHEN
    let actual = mem
        .get_entity_by_handle("foo")
        .await
        .expect("getting entity by handle");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::ErrorResponse(_)));
    let ArcRdapResponse::ErrorResponse(error) = response else { panic!() };
    assert_eq!(error.error_code, 404)
}

#[tokio::test]
async fn GIVEN_nameserver_in_mem_WHEN_lookup_nameserver_by_ldh_THEN_nameserver_returned() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_nameserver(&Nameserver::basic().ldh_name("ns.foo.example").build())
        .await
        .expect("add nameserver in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_nameserver_by_ldh("ns.foo.example")
        .await
        .expect("getting nameserver by ldh");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::Nameserver(_)));
    let ArcRdapResponse::Nameserver(nameserver) = response else { panic!() };
    assert_eq!(
        nameserver.ldh_name.as_ref().expect("ldhName is none"),
        "ns.foo.example"
    )
}

#[tokio::test]
async fn GIVEN_no_nameserver_in_mem_WHEN_lookup_nameserver_by_ldh_THEN_404_returned() {
    // GIVEN
    let mem = Mem::default();

    // WHEN
    let actual = mem
        .get_nameserver_by_ldh("ns.foo.example")
        .await
        .expect("getting nameserver by ldh");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::ErrorResponse(_)));
    let ArcRdapResponse::ErrorResponse(error) = response else { panic!() };
    assert_eq!(error.error_code, 404)
}

#[tokio::test]
async fn GIVEN_autnum_in_mem_WHEN_lookup_autnum_by_start_autnum_THEN_autnum_returned() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::basic_nums()
            .start_autnum(700)
            .end_autnum(710)
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_autnum_by_num(700)
        .await
        .expect("getting autnum by num");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::Autnum(_)));
    let ArcRdapResponse::Autnum(autnum) = response else { panic!() };
    assert_eq!(
        *autnum.start_autnum.as_ref().expect("startNum is none"),
        700
    );
    assert_eq!(*autnum.end_autnum.as_ref().expect("startNum is none"), 710);
}

#[tokio::test]
async fn GIVEN_autnum_in_mem_WHEN_lookup_autnum_by_end_autnum_THEN_autnum_returned() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::basic_nums()
            .start_autnum(700)
            .end_autnum(710)
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_autnum_by_num(710)
        .await
        .expect("getting autnum by num");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::Autnum(_)));
    let ArcRdapResponse::Autnum(autnum) = response else { panic!() };
    assert_eq!(
        *autnum.start_autnum.as_ref().expect("startNum is none"),
        700
    );
    assert_eq!(*autnum.end_autnum.as_ref().expect("startNum is none"), 710);
}

#[tokio::test]
async fn GIVEN_no_autnum_in_mem_WHEN_lookup_autnum_by_num_THEN_404_returned() {
    // GIVEN
    let mem = Mem::default();

    // WHEN
    let actual = mem
        .get_autnum_by_num(700)
        .await
        .expect("getting autnum by num");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::ErrorResponse(_)));
    let ArcRdapResponse::ErrorResponse(error) = response else { panic!() };
    assert_eq!(error.error_code, 404)
}

#[rstest]
#[case("192.168.0.0/24", "192.168.0.1", "192.168.0.0", "192.168.0.255")]
#[case("192.168.0.0/24", "192.168.0.0", "192.168.0.0", "192.168.0.255")]
#[case("192.168.0.0/24", "192.168.0.254", "192.168.0.0", "192.168.0.255")]
#[case("192.168.0.0/24", "192.168.0.255", "192.168.0.0", "192.168.0.255")]
#[tokio::test]
async fn GIVEN_network_in_mem_WHEN_lookup_network_by_address_THEN_network_returned(
    #[case] cidr: &str,
    #[case] addr: &str,
    #[case] start: &str,
    #[case] end: &str,
) {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::basic()
            .cidr(IpCidr::from_str(cidr).expect("cidr parsing"))
            .build(),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_network_by_ipaddr(addr)
        .await
        .expect("getting network by num");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::Network(_)));
    let ArcRdapResponse::Network(network) = response else { panic!() };
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
async fn GIVEN_no_network_in_mem_WHEN_lookup_network_by_address_THEN_404_returned() {
    // GIVEN
    let mem = Mem::default();

    // WHEN
    let actual = mem
        .get_network_by_ipaddr("192.168.0.1")
        .await
        .expect("getting network by address");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::ErrorResponse(_)));
    let ArcRdapResponse::ErrorResponse(error) = response else { panic!() };
    assert_eq!(error.error_code, 404)
}

#[rstest]
#[case(&["192.168.0.0/16", "192.168.0.0/8", "192.168.0.0/24"], "192.168.0.1", "192.168.0.0", "192.168.0.255")]
#[case(&["2001::/64", "2001::/56", "2001::/20"], "2001::1", "2001::", "2001::ffff:ffff:ffff:ffff")]
#[tokio::test]
async fn GIVEN_contained_networks_in_mem_WHEN_lookup_network_by_address_THEN_most_specific_network_returned(
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
            &Network::basic()
                .cidr(IpCidr::from_str(cidr).expect("cidr parsing"))
                .build(),
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
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::Network(_)));
    let ArcRdapResponse::Network(network) = response else { panic!() };
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
async fn GIVEN_offbit_network_in_mem_WHEN_lookup_network_by_first_address_THEN_network_returned() {
    // GIVEN
    let start = "10.0.0.0";
    let end = "10.0.1.255";
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .start_address(start)
            .end_address(end)
            .ip_version("v4")
            .object_common(
                ObjectCommon::builder()
                    .object_class_name("ip network")
                    .build(),
            )
            .common(Common::builder().build())
            .build(),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_network_by_ipaddr(start)
        .await
        .expect("getting network by num");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::Network(_)));
    let ArcRdapResponse::Network(network) = response else { panic!() };
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
async fn GIVEN_offbit_network_in_mem_WHEN_lookup_network_by_last_address_THEN_network_returned() {
    // GIVEN
    let start = "10.0.0.0";
    let end = "10.0.1.255";
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .start_address(start)
            .end_address(end)
            .ip_version("v4")
            .object_common(
                ObjectCommon::builder()
                    .object_class_name("ip network")
                    .build(),
            )
            .common(Common::builder().build())
            .build(),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_network_by_ipaddr(end)
        .await
        .expect("getting network by num");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::Network(_)));
    let ArcRdapResponse::Network(network) = response else { panic!() };
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
async fn GIVEN_network_in_mem_WHEN_lookup_network_by_cidr_THEN_network_returned(
    #[case] cidr: &str,
    #[case] lookup: &str,
    #[case] start: &str,
    #[case] end: &str,
) {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::basic()
            .cidr(IpCidr::from_str(cidr).expect("cidr parsing"))
            .build(),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_network_by_cidr(lookup)
        .await
        .expect("getting network by cidr");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::Network(_)));
    let ArcRdapResponse::Network(network) = response else { panic!() };
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
async fn GIVEN_no_network_in_mem_WHEN_lookup_network_by_cidr_THEN_404_returned() {
    // GIVEN
    let mem = Mem::default();

    // WHEN
    let actual = mem
        .get_network_by_cidr("192.168.0.0/24")
        .await
        .expect("getting network by address");

    // THEN
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::ErrorResponse(_)));
    let ArcRdapResponse::ErrorResponse(error) = response else { panic!() };
    assert_eq!(error.error_code, 404)
}
