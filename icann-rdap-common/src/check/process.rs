//! Processes for running checks.

use crate::{httpdata::HttpData, prelude::RdapResponse};

use super::{Check, CheckParams, Checks, GetChecks};

pub fn get_checks(
    rdap: &RdapResponse,
    http_data: Option<HttpData>,
    expect_exts: Option<Vec<&str>>,
    allow_unreg_ext: bool,
) -> Checks {
    let check_params = CheckParams {
        root: rdap,
        parent_type: rdap.get_type(),
        allow_unreg_ext,
    };
    let mut checks = rdap.get_checks(check_params);

    if let Some(http_data) = http_data {
        // add these to the root check structure
        checks
            .items
            .append(&mut http_data.get_checks(check_params).items);
    }

    // add expected extension checks
    if let Some(expected_extensions) = expect_exts {
        for ext in expected_extensions {
            if !rdap_has_expected_extension(rdap, ext) {
                // add this to the root check structure
                checks
                    .items
                    .push(Check::ExpectedExtensionNotFound.check_item());
            }
        }
    }

    checks
}

fn rdap_has_expected_extension(rdap: &RdapResponse, ext: &str) -> bool {
    let count = ext.split('|').filter(|s| rdap.has_extension(s)).count();
    count > 0
}
