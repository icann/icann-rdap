use {icann_rdap_common::response::Autnum, icann_rdap_srv::storage::StoreOps};

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_query() {
    // GIVEN autnum
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query
    test_jig.cmd.arg("700");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_query_with_rpsl() {
    // GIVEN autnum
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query
    test_jig.cmd.arg("-O").arg("rpsl").arg("700");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_up_query() {
    // GIVEN autnum ranges with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..800).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(720..730).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-up type - query 725 to get its supernet (700-799)
    test_jig.cmd.arg("-t").arg("autnum-up").arg("725");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_down_query() {
    // GIVEN autnum ranges with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..800).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(720..730).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(740..750).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-down type - query 700 to get immediate subnets
    test_jig.cmd.arg("-t").arg("autnum-down").arg("700");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_top_query() {
    // GIVEN autnum ranges with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..800).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(720..730).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-top type - query for most specific autnum containing 725
    test_jig.cmd.arg("-t").arg("autnum-top").arg("725");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_bottom_query() {
    // GIVEN autnum ranges with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..800).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(720..730).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-bottom type - query 725 to get all supernets
    test_jig.cmd.arg("-t").arg("autnum-bottom").arg("725");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_up_query_prefix() {
    // GIVEN autnum ranges with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..800).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(720..730).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with up: prefix
    test_jig.cmd.arg("up:725");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_down_query_prefix() {
    // GIVEN autnum ranges with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..800).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(720..730).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with down: prefix
    test_jig.cmd.arg("down:700");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_top_query_prefix() {
    // GIVEN autnum ranges with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..800).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(720..730).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with top: prefix
    test_jig.cmd.arg("top:725");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_bottom_query_prefix() {
    // GIVEN autnum ranges with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..800).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(720..730).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with bottom: prefix
    test_jig.cmd.arg("bottom:725");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}
