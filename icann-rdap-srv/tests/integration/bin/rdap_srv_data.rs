#![allow(non_snake_case)]

use {icann_rdap_common::prelude::RdapResponse, test_dir::DirBuilder};

use crate::test_jig::RdapSrvDataTestJig;

#[test]
fn GIVEN_data_dir_WHEN_invoked_THEN_data_stored_in_data_dir() {
    // GIVEN
    let mut test_jig = RdapSrvDataTestJig::new();

    // WHEN
    test_jig
        .cmd
        .arg("--data-dir")
        .arg(test_jig.source_dir.root())
        .arg("entity")
        .arg("--handle")
        .arg("foo1234")
        .arg("--email")
        .arg("joe@example.com")
        .arg("--full-name")
        .arg("Joe User");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
    assert!(
        test_jig
            .source_dir
            .root()
            .read_dir()
            .expect("source directory does not exist")
            .next()
            .is_some()
    );
    assert!(
        test_jig
            .data_dir
            .root()
            .read_dir()
            .expect("data directory does not exist")
            .next()
            .is_none()
    );
}

#[test]
fn GIVEN_no_data_dir_WHEN_invoked_THEN_data_stored_in_data_dir() {
    // GIVEN
    let mut test_jig = RdapSrvDataTestJig::new();

    // WHEN
    test_jig
        .cmd
        .arg("entity")
        .arg("--handle")
        .arg("foo1234")
        .arg("--email")
        .arg("joe@example.com")
        .arg("--full-name")
        .arg("Joe User");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
    assert!(
        test_jig
            .source_dir
            .root()
            .read_dir()
            .expect("source directory does not exist")
            .next()
            .is_none()
    );
    assert!(
        test_jig
            .data_dir
            .root()
            .read_dir()
            .expect("data directory does not exist")
            .next()
            .is_some()
    );
}

#[test]
fn GIVEN_entity_options_WHEN_create_data_THEN_success() {
    // GIVEN
    let _test_jig = make_foo1234();

    // WHEN
    // everything done in the helper function above

    // THEN
    // everything done in the helper function above
}

#[test]
fn GIVEN_nameserver_options_WHEN_create_data_THEN_success() {
    // GIVEN
    let mut test_jig = make_foo1234();

    // WHEN
    test_jig
        .cmd
        .arg("nameserver")
        .arg("--ldh")
        .arg("ns1.example.com")
        .arg("--registrant")
        .arg("foo1234");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[test]
fn GIVEN_domain_options_WHEN_create_data_THEN_success() {
    // GIVEN
    let mut test_jig = make_foo1234();
    test_jig
        .cmd
        .arg("nameserver")
        .arg("--ldh")
        .arg("ns1.example.com")
        .arg("--registrant")
        .arg("foo1234");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
    let mut test_jig = test_jig.new_cmd();

    // WHEN
    test_jig
        .cmd
        .arg("domain")
        .arg("--ldh")
        .arg("example.com")
        .arg("--registrant")
        .arg("foo1234");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[test]
fn GIVEN_domain_with_idn_WHEN_create_data_THEN_success() {
    // GIVEN
    let mut test_jig = make_foo1234();

    // WHEN
    test_jig
        .cmd
        .arg("domain")
        .arg("--ldh")
        .arg("example.com")
        .arg("--idn")
        .arg("example.com")
        .arg("--registrant")
        .arg("foo1234");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[test]
fn GIVEN_idn_WHEN_create_data_THEN_success() {
    // GIVEN
    let mut test_jig = make_foo1234();

    // WHEN
    test_jig
        .cmd
        .arg("domain")
        .arg("--idn")
        .arg("example.com")
        .arg("--registrant")
        .arg("foo1234");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[test]
fn GIVEN_autnum_options_WHEN_create_data_THEN_success() {
    // GIVEN
    let mut test_jig = make_foo1234();

    // WHEN
    test_jig
        .cmd
        .arg("autnum")
        .arg("--start-autnum")
        .arg("700")
        .arg("--end-autnum")
        .arg("710")
        .arg("--registrant")
        .arg("foo1234");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[test]
fn GIVEN_network_options_WHEN_create_data_THEN_success() {
    // GIVEN
    let mut test_jig = make_foo1234();

    // WHEN
    test_jig
        .cmd
        .arg("network")
        .arg("--cidr")
        .arg("10.0.0.0/24")
        .arg("--registrant")
        .arg("foo1234");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[test]
fn GIVEN_srvhelp_with_no_options_WHEN_create_srvhelp_THEN_success() {
    // GIVEN
    let mut test_jig = RdapSrvDataTestJig::new();

    // WHEN
    test_jig.cmd.arg("srv-help");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}
#[test]
fn GIVEN_srvhelp_with_notice_WHEN_create_srvhelp_THEN_success() {
    // GIVEN
    let mut test_jig = RdapSrvDataTestJig::new();

    // WHEN
    test_jig
        .cmd
        .arg("srv-help")
        .arg("--notice")
        .arg("\"A test notice\"");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[test]
fn GIVEN_srvhelp_with_host_WHEN_create_srvhelp_THEN_success() {
    // GIVEN
    let mut test_jig = RdapSrvDataTestJig::new();

    // WHEN
    test_jig
        .cmd
        .arg("srv-help")
        .arg("--host")
        .arg("foo.example.com");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

fn make_foo1234() -> RdapSrvDataTestJig {
    let mut test_jig = RdapSrvDataTestJig::new();
    test_jig
        .cmd
        .arg("entity")
        .arg("--handle")
        .arg("foo1234")
        .arg("--email")
        .arg("joe@example.com")
        .arg("--full-name")
        .arg("Joe User");
    let assert = test_jig.cmd.assert();
    assert.success();
    test_jig.new_cmd()
}

/// Returns the names of all files in the data directory.
fn data_dir_file_names(test_jig: &RdapSrvDataTestJig) -> Vec<String> {
    std::fs::read_dir(test_jig.data_dir.root())
        .expect("data directory does not exist")
        .filter_map(|entry| {
            entry
                .ok()
                .map(|e| e.file_name().to_string_lossy().into_owned())
        })
        .collect()
}

#[test]
fn GIVEN_json_argument_WHEN_create_data_THEN_data_stored_in_data_dir() {
    // GIVEN
    let mut test_jig = RdapSrvDataTestJig::new();
    let json = r#"{"rdapConformance":["rdap_level_0"],"objectClassName":"domain","ldhName":"example.com"}"#;

    // WHEN
    test_jig.cmd.arg("json").arg(json);

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
    let file_names = data_dir_file_names(&test_jig);
    assert_eq!(file_names.len(), 1);
    assert!(file_names[0].ends_with(".json"));

    // The written file must be loadable by the server as an RDAP domain document.
    let path = test_jig.data_dir.root().join(&file_names[0]);
    let content = std::fs::read_to_string(&path).expect("reading data file");
    let rdap: RdapResponse = serde_json::from_str(&content).expect("parsing written json");
    let domain = match rdap {
        RdapResponse::Domain(domain) => domain,
        other => panic!("expected domain document, got {other:?}"),
    };
    assert_eq!(domain.ldh_name.as_deref(), Some("example.com"));
}

#[test]
fn GIVEN_json_stdin_WHEN_create_data_THEN_data_stored_in_data_dir() {
    // GIVEN
    let mut test_jig = RdapSrvDataTestJig::new();
    let json = r#"{"rdapConformance":["rdap_level_0"],"objectClassName":"domain","ldhName":"example.com"}"#;

    // WHEN
    test_jig.cmd.arg("json").write_stdin(json);

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
    let file_names = data_dir_file_names(&test_jig);
    assert_eq!(file_names.len(), 1);
    assert!(file_names[0].ends_with(".json"));
}

#[test]
fn GIVEN_json_with_file_name_WHEN_create_data_THEN_data_stored_in_data_dir() {
    // GIVEN
    let mut test_jig = RdapSrvDataTestJig::new();
    let json = r#"{"rdapConformance":["rdap_level_0"],"objectClassName":"domain","ldhName":"example.com"}"#;

    // WHEN
    test_jig
        .cmd
        .arg("json")
        .arg("--file-name")
        .arg("foo")
        .arg(json);

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
    let file_names = data_dir_file_names(&test_jig);
    assert_eq!(file_names, vec!["foo.json".to_string()]);
}

#[test]
fn GIVEN_json_with_template_flag_WHEN_create_data_THEN_error() {
    // GIVEN
    let mut test_jig = RdapSrvDataTestJig::new();
    let json = r#"{"rdapConformance":["rdap_level_0"],"objectClassName":"domain","ldhName":"example.com"}"#;

    // WHEN
    test_jig.cmd.arg("--template").arg("json").arg(json);

    // THEN
    let assert = test_jig.cmd.assert();
    assert.failure();
}

#[test]
fn GIVEN_invalid_json_argument_WHEN_create_data_THEN_error() {
    // GIVEN
    let mut test_jig = RdapSrvDataTestJig::new();

    // WHEN
    test_jig
        .cmd
        .arg("json")
        .arg(r#"{"objectClassName":"domain","ldhName":""#);

    // THEN
    let assert = test_jig.cmd.assert();
    assert.failure();
}

#[test]
fn GIVEN_json_without_derivable_name_WHEN_create_data_THEN_error() {
    // GIVEN
    let mut test_jig = RdapSrvDataTestJig::new();
    let json = r#"{"rdapConformance":["rdap_level_0"],"objectClassName":"domain"}"#;

    // WHEN
    test_jig.cmd.arg("json").arg(json);

    // THEN
    let assert = test_jig.cmd.assert();
    assert.failure();
}

#[test]
fn GIVEN_json_argument_and_stdin_WHEN_create_data_THEN_argument_wins() {
    // GIVEN
    let mut test_jig = RdapSrvDataTestJig::new();
    let json = r#"{"rdapConformance":["rdap_level_0"],"objectClassName":"domain","ldhName":"example.com"}"#;
    let stdin_json =
        r#"{"rdapConformance":["rdap_level_0"],"objectClassName":"domain","ldhName":"other.com"}"#;

    // WHEN
    test_jig.cmd.arg("json").arg(json).write_stdin(stdin_json);

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
    let file_names = data_dir_file_names(&test_jig);
    assert_eq!(file_names, vec!["example_com.json".to_string()]);
}

#[test]
fn GIVEN_empty_stdin_WHEN_create_data_THEN_error() {
    // GIVEN
    let mut test_jig = RdapSrvDataTestJig::new();

    // WHEN
    test_jig.cmd.arg("json").write_stdin("");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.failure();
}

#[test]
fn GIVEN_help_json_WHEN_create_data_THEN_error() {
    // GIVEN
    let mut test_jig = RdapSrvDataTestJig::new();
    let json = r#"{"rdapConformance":["rdap_level_0"],"notices":[{"title":"Help"}]}"#;

    // WHEN
    test_jig.cmd.arg("json").arg(json);

    // THEN
    let assert = test_jig.cmd.assert();
    assert.failure();
}

#[test]
fn GIVEN_error_response_json_WHEN_create_data_THEN_error() {
    // GIVEN
    let mut test_jig = RdapSrvDataTestJig::new();
    let json = r#"{"rdapConformance":["rdap_level_0"],"errorCode":404,"title":"Not Found"}"#;

    // WHEN
    test_jig.cmd.arg("json").arg(json);

    // THEN
    let assert = test_jig.cmd.assert();
    assert.failure();
}
