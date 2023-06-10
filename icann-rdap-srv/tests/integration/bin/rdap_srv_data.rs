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
