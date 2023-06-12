#![allow(non_snake_case)]

use test_dir::DirBuilder;

use crate::test_jig::RdapSrvStoreTestJig;

#[test]
fn GIVEN_source_dir_same_as_data_dir_WHEN_invoked_THEN_error() {
    // GIVEN
    let mut test_jig = RdapSrvStoreTestJig::new();

    // WHEN
    test_jig.cmd.arg(test_jig.data_dir.root());

    // THEN
    let assert = test_jig.cmd.assert();
    assert.failure();
}
