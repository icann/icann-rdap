#![allow(non_snake_case)]

use crate::test_jig::TestJig;
use std::io::Write;
use tempfile::NamedTempFile;

#[tokio::test(flavor = "multi_thread")]
async fn test_file_input() {
    // GIVEN
    let mut test_jig = TestJig::new_rdap_test_no_http_env().await;
    let mut file = NamedTempFile::new().expect("new temp file");
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
    file.write_all(rdap_json.as_bytes())
        .expect("write to temp file");
    let path = file.path().to_str().unwrap();

    // WHEN
    test_jig.cmd.arg("--in-file").arg(path);

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_file_input_with_extra_params() {
    // GIVEN
    let mut test_jig = TestJig::new_rdap_test_no_http_env().await;
    let mut file = NamedTempFile::new().expect("new temp file");
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
    file.write_all(rdap_json.as_bytes())
        .expect("write to temp file");
    let path = file.path().to_str().unwrap();

    // WHEN
    test_jig
        .cmd
        .arg("--in-file")
        .arg(path)
        .arg("--allow-unregistered-extensions")
        .arg("--check-type")
        .arg("info");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}
