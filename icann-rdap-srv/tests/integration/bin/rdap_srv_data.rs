#![allow(non_snake_case)]

use test_dir::DirBuilder;

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
    assert!(test_jig
        .source_dir
        .root()
        .read_dir()
        .expect("source directory does not exist")
        .next()
        .is_some());
    assert!(test_jig
        .data_dir
        .root()
        .read_dir()
        .expect("data directory does not exist")
        .next()
        .is_none());
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
    assert!(test_jig
        .source_dir
        .root()
        .read_dir()
        .expect("source directory does not exist")
        .next()
        .is_none());
    assert!(test_jig
        .data_dir
        .root()
        .read_dir()
        .expect("data directory does not exist")
        .next()
        .is_some());
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
