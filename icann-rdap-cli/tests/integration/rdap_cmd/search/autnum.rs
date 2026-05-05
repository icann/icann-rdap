use {
    icann_rdap_common::response::Autnum,
    icann_rdap_srv::{config::CommonConfig, storage::StoreOps},
    serde_json::Value,
};

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_handle_search() {
    // GIVEN autnum with handle
    let common_config = CommonConfig::builder()
        .autnum_search_by_handle_enable(true)
        .build();
    let mut test_jig =
        TestJig::new_common_config(common_config, crate::test_jig::CommandType::Rdap).await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(700..710)
            .handle("AS700-1")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for the autnum by handle
    test_jig.cmd.arg("-t").arg("autnum-handle").arg("AS700-*");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_handle_search_multiple_results() {
    // GIVEN two autnums with matching handles
    let common_config = CommonConfig::builder()
        .autnum_search_by_handle_enable(true)
        .build();
    let mut test_jig =
        TestJig::new_common_config(common_config, crate::test_jig::CommandType::Rdap).await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(700..710)
            .handle("AS700-1")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(710..720)
            .handle("AS700-2")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for autnums by handle with wildcard
    test_jig.cmd.arg("-t").arg("autnum-handle").arg("AS700-*");

    // THEN success with two results
    let assert = test_jig.cmd.assert();
    let assert = assert.success();
    let output = &assert.get_output().stdout;
    let json: Value = serde_json::from_slice(output).expect("valid json");
    let results = &json[0]["res_data"]["rdap"]["autnumSearchResults"];
    assert!(results.is_array());
    assert_eq!(results.as_array().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_handle_search_not_found() {
    // GIVEN autnum with handle
    let common_config = CommonConfig::builder()
        .autnum_search_by_handle_enable(true)
        .build();
    let mut test_jig =
        TestJig::new_common_config(common_config, crate::test_jig::CommandType::Rdap).await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(700..710)
            .handle("AS700-1")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for a non-existent handle
    test_jig
        .cmd
        .arg("-t")
        .arg("autnum-handle")
        .arg("NONEXISTENT-*");

    // THEN success with empty results
    let assert = test_jig.cmd.assert();
    let assert = assert.success();
    let output = &assert.get_output().stdout;
    let json: Value = serde_json::from_slice(output).expect("valid json");
    let results = &json[0]["res_data"]["rdap"]["autnumSearchResults"];
    assert!(results.is_array());
    assert_eq!(results.as_array().unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_handle_search_disabled() {
    // GIVEN autnum with handle, search disabled (default)
    let common_config = CommonConfig::builder()
        .autnum_search_by_handle_enable(false)
        .build();
    let mut test_jig =
        TestJig::new_common_config(common_config, crate::test_jig::CommandType::Rdap).await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(700..710)
            .handle("AS700-1")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for the autnum by handle
    test_jig.cmd.arg("-t").arg("autnum-handle").arg("AS700-*");

    // THEN server returns 501 Not Implemented
    let assert = test_jig.cmd.assert();
    assert.failure();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_name_search() {
    // GIVEN autnum with name
    let common_config = CommonConfig::builder()
        .autnum_search_by_name_enable(true)
        .build();
    let mut test_jig =
        TestJig::new_common_config(common_config, crate::test_jig::CommandType::Rdap).await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(700..710)
            .handle("AS700-1")
            .name("Test AS Network")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for the autnum by name
    test_jig.cmd.arg("-t").arg("autnum-name").arg("Test *");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_name_search_multiple_results() {
    // GIVEN two autnums with matching names
    let common_config = CommonConfig::builder()
        .autnum_search_by_name_enable(true)
        .build();
    let mut test_jig =
        TestJig::new_common_config(common_config, crate::test_jig::CommandType::Rdap).await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(700..710)
            .handle("AS700-1")
            .name("Network Allocation")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(710..720)
            .handle("AS700-2")
            .name("Network Assignment")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for autnums by name with wildcard
    test_jig.cmd.arg("-t").arg("autnum-name").arg("Network*");

    // THEN success with two results
    let assert = test_jig.cmd.assert();
    let assert = assert.success();
    let output = &assert.get_output().stdout;
    let json: Value = serde_json::from_slice(output).expect("valid json");
    let results = &json[0]["res_data"]["rdap"]["autnumSearchResults"];
    assert!(results.is_array());
    assert_eq!(results.as_array().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_name_search_not_found() {
    // GIVEN autnum with name
    let common_config = CommonConfig::builder()
        .autnum_search_by_name_enable(true)
        .build();
    let mut test_jig =
        TestJig::new_common_config(common_config, crate::test_jig::CommandType::Rdap).await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(700..710)
            .handle("AS700-1")
            .name("Test AS Network")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for a non-existent name
    test_jig
        .cmd
        .arg("-t")
        .arg("autnum-name")
        .arg("Nonexistent *");

    // THEN success with empty results
    let assert = test_jig.cmd.assert();
    let assert = assert.success();
    let output = &assert.get_output().stdout;
    let json: Value = serde_json::from_slice(output).expect("valid json");
    let results = &json[0]["res_data"]["rdap"]["autnumSearchResults"];
    assert!(results.is_array());
    assert_eq!(results.as_array().unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_name_search_disabled() {
    // GIVEN autnum with name, search disabled (default)
    let common_config = CommonConfig::builder()
        .autnum_search_by_name_enable(false)
        .build();
    let mut test_jig =
        TestJig::new_common_config(common_config, crate::test_jig::CommandType::Rdap).await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(700..710)
            .handle("AS700-1")
            .name("Test AS Network")
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for the autnum by name
    test_jig.cmd.arg("-t").arg("autnum-name").arg("Test *");

    // THEN server returns 501 Not Implemented
    let assert = test_jig.cmd.assert();
    assert.failure();
}
