use {
    icann_rdap_common::response::{Nameserver, RdapResponse},
    icann_rdap_srv::storage::{mem::ops::Mem, StoreOps},
};

#[tokio::test]
async fn lookup_by_ldh() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("ns.foo.example")
            .build()
            .unwrap(),
    )
    .await
    .expect("add nameserver in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_nameserver_by_ldh("ns.foo.example")
        .await
        .expect("getting nameserver by ldh");

    // THEN
    let RdapResponse::Nameserver(nameserver) = actual else {
        panic!()
    };
    assert_eq!(
        nameserver.ldh_name.as_ref().expect("ldhName is none"),
        "ns.foo.example"
    )
}

#[tokio::test]
async fn lookup_not_found() {
    // GIVEN
    let mem = Mem::default();

    // WHEN
    let actual = mem
        .get_nameserver_by_ldh("ns.foo.example")
        .await
        .expect("getting nameserver by ldh");

    // THEN
    let RdapResponse::ErrorResponse(error) = actual else {
        panic!()
    };
    assert_eq!(error.error_code, 404)
}
