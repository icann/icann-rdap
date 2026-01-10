#![allow(non_snake_case)]

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_stdin() {
    // GIVEN
    let mut test_jig = TestJig::new_rdap_test_no_http_env().await;
    let rdap_json = r#"
    {
        "objectClassName": "autnum",
        "handle": "AS65541",
        "startAutnum": 65541,
        "endAutnum": 65541,
        "name": "AS-EXAMPLE",
        "type": "DIRECT ALLOCATION",
        "rdapConformance": [
            "rdap_level_0"
        ],
        "notices": [
            {
                "title": "Test Data",
                "description": [
                    "This is test data."
                ]
            }
        ]
    }
    "#;

    // WHEN
    test_jig.cmd.arg("--stdin").write_stdin(rdap_json);

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_stdin_with_extra_params() {
    // GIVEN
    let mut test_jig = TestJig::new_rdap_test_no_http_env().await;
    let rdap_json = r#"
    {
        "objectClassName": "autnum",
        "handle": "AS65541",
        "startAutnum": 65541,
        "endAutnum": 65541,
        "name": "AS-EXAMPLE",
        "type": "DIRECT ALLOCATION",
        "rdapConformance": [
            "rdap_level_0"
        ],
        "notices": [
            {
                "title": "Test Data",
                "description": [
                    "This is test data."
                ]
            }
        ]
    }
    "#;

    // WHEN
    test_jig
        .cmd
        .arg("--stdin")
        .arg("--allow-unregistered-extensions")
        .arg("--check-type")
        .arg("info")
        .write_stdin(rdap_json);

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}
