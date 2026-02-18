use std::path::PathBuf;

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_bad_bootstrap_json_in_config_returns_error() {
    // Given a test jig with invalid JSON in DNS bootstrap config
    let test_jig = TestJig::new_rdap().await;

    let invalid_json = r#"{ "version": "1.0", bad json }"#;
    let config_dir: PathBuf = test_jig.config_dir().into();
    let config_path = config_dir.join("dns.json");
    std::fs::write(&config_path, invalid_json).expect("write invalid bootstrap json");

    // When querying with --base hint (triggers bootstrap lookup)
    let mut test_jig = test_jig.new_cmd();
    test_jig.cmd.arg("--base").arg("org").arg("example.org");

    // Then the command should fail with an error
    let output = test_jig.cmd.output().expect("executing domain query");

    assert!(
        !output.status.success(),
        "Expected failure due to bad bootstrap JSON but got success. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("JSON") || stderr.contains("parse") || stderr.contains("error"),
        "Expected error in stderr but got: {}",
        stderr
    );
}
