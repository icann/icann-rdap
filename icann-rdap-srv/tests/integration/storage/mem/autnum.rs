use {
    icann_rdap_common::{
        prelude::Numberish,
        response::{Autnum, RdapResponse},
    },
    icann_rdap_srv::storage::{StoreOps, mem::ops::Mem},
};

#[tokio::test]
async fn lookup_by_start() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_autnum_by_num(700)
        .await
        .expect("getting autnum by num");

    // THEN
    let RdapResponse::Autnum(autnum) = actual else {
        panic!()
    };
    assert_eq!(
        *autnum.start_autnum.as_ref().expect("startNum is none"),
        Numberish::<u32>::from(700)
    );
    assert_eq!(
        *autnum.end_autnum.as_ref().expect("startNum is none"),
        Numberish::<u32>::from(710)
    );
}

#[tokio::test]
async fn lookup_by_end() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_autnum_by_num(710)
        .await
        .expect("getting autnum by num");

    // THEN
    let RdapResponse::Autnum(autnum) = actual else {
        panic!()
    };
    assert_eq!(
        *autnum.start_autnum.as_ref().expect("startNum is none"),
        Numberish::<u32>::from(700)
    );
    assert_eq!(
        *autnum.end_autnum.as_ref().expect("startNum is none"),
        Numberish::<u32>::from(710)
    );
}

#[tokio::test]
async fn lookup_not_found() {
    // GIVEN
    let mem = Mem::default();

    // WHEN
    let actual = mem
        .get_autnum_by_num(700)
        .await
        .expect("getting autnum by num");

    // THEN
    let RdapResponse::ErrorResponse(error) = actual else {
        panic!()
    };
    assert_eq!(error.error_code(), 404)
}
