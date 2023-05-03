#![allow(non_snake_case)]

use icann_rdap_common::response::{
    domain::Domain,
    types::{Common, ObjectCommon},
    RdapResponse,
};
use icann_rdap_srv::storage::{mem::ops::Mem, StorageOperations};

#[tokio::test]
async fn GIVEN_domain_in_mem_WHEN_lookup_domain_by_ldh_THEN_domain_returned() {
    // GIVEN
    let mem = Mem::new();
    let mut tx = mem.new_transaction().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .common(Common::builder().build())
            .ldh_name("foo.example")
            .object_common(ObjectCommon::builder().object_class_name("domain").build())
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_domain_by_ldh("foo.example")
        .await
        .expect("getting domain by ldh");

    // THEN
    assert!(matches!(actual, RdapResponse::Domain(_)));
    let icann_rdap_common::response::RdapResponse::Domain(Domain {
        common: _,
        object_common: _,
        ldh_name,
        unicode_name: _,
        variants: _,
        secure_dns: _,
        nameservers: _,
        public_ids: _,
        network: _,
    }) = actual else { panic!()};
    assert_eq!(ldh_name.expect("ldhName is none"), "foo.example")
}
