//! Processes for running checks.

use strum::{EnumMessage, VariantArray};

use crate::{httpdata::HttpData, prelude::RdapResponse};

use super::{traverse_checks, Check, CheckClass, CheckParams, CheckSummary, Checks, GetChecks};

pub fn do_check_processing(
    rdap: &RdapResponse,
    http_data: Option<&HttpData>,
    expect_exts: Option<&[String]>,
    allow_unreg_ext: bool,
) -> Checks {
    let check_params = CheckParams {
        root: rdap,
        parent_type: rdap.get_type(),
        allow_unreg_ext,
    };
    let mut checks = rdap.get_checks(None, check_params);

    if let Some(http_data) = http_data {
        // add these to the root check structure
        checks
            .items
            .append(&mut http_data.get_checks(None, check_params).items);
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

pub fn get_summaries(checks: &Checks, classes: Option<&[CheckClass]>) -> Vec<CheckSummary> {
    let mut summaries = vec![];
    let classes = classes.unwrap_or(CheckClass::VARIANTS);
    traverse_checks(checks, classes, None, &mut |struct_name, item| {
        let summary = CheckSummary {
            structure: struct_name.to_string(),
            code: item.check as usize,
            message: item
                .check
                .get_message()
                .unwrap_or("[Message Unavailable]")
                .to_string(),
            item: item.clone(),
        };
        summaries.push(summary);
    });
    summaries
}

#[cfg(test)]
mod tests {

    use crate::{
        check::process::rdap_has_expected_extension,
        prelude::{Domain, Extension, ToResponse},
    };

    #[test]
    fn test_expected_extension_rdap_has() {
        // GIVEN
        let domain = Domain::response_obj()
            .extension(Extension::from("foo0"))
            .ldh_name("foo.example.com")
            .build();
        let rdap = domain.to_response();

        // WHEN
        let actual = rdap_has_expected_extension(&rdap, "foo0");

        // THEN
        assert!(actual);
    }

    #[test]
    fn test_expected_extension_rdap_does_not_have() {
        // GIVEN
        let domain = Domain::response_obj()
            .extension(Extension::from("foo0"))
            .ldh_name("foo.example.com")
            .build();
        let rdap = domain.to_response();

        // WHEN
        let actual = rdap_has_expected_extension(&rdap, "foo1");

        // THEN
        assert!(!actual);
    }

    #[test]
    fn test_compound_expected_extension() {
        // GIVEN
        let domain = Domain::response_obj()
            .extension(Extension::from("foo0"))
            .ldh_name("foo.example.com")
            .build();
        let rdap = domain.to_response();

        // WHEN
        let actual = rdap_has_expected_extension(&rdap, "foo0|foo1");

        // THEN
        assert!(actual);
    }
}
