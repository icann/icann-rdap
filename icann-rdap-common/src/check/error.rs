use std::any::TypeId;

use crate::response::error::Rfc9083Error;

use super::{Check, CheckParams, Checks, GetChecks, GetGroupChecks};

impl GetChecks for Rfc9083Error {
    fn get_checks(&self, index: Option<usize>, params: CheckParams) -> super::Checks {
        let sub_checks = {
            GetGroupChecks::get_group_checks(&self.common, params.from_parent(TypeId::of::<Self>()))
        };

        let mut items = vec![];

        if self.error_code.is_string() {
            items.push(Check::ErrorCodeIsString.check_item());
        }

        if let Some(title) = &self.title {
            if title.is_number() || title.is_bool() {
                items.push(Check::TitleIsNotString.check_item());
            }
        }

        if let Some(desc) = &self.description {
            if desc.is_string() {
                items.push(Check::DescriptionIsString.check_item());
            }
        }

        Checks {
            rdap_struct: super::RdapStructure::Error,
            index,
            items,
            sub_checks,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::check::{Check, CheckParams, GetChecks, contains_check};
    use crate::response::{RdapResponse, ToResponse, error::Rfc9083Error};

    #[test]
    fn check_error_with_string_error_code() {
        // GIVEN
        let json = r#"{"errorCode": "404"}"#;
        let error = serde_json::from_str::<Rfc9083Error>(json).expect("parsing JSON");
        let rdap = error.to_response();

        // WHEN
        let checks = rdap.get_checks(None, CheckParams::for_rdap(&rdap));

        // THEN
        assert!(contains_check(Check::ErrorCodeIsString, &checks));
    }

    #[test]
    fn check_error_with_number_error_code() {
        // GIVEN
        let json = r#"{"errorCode": 404}"#;
        let rdap = serde_json::from_str::<RdapResponse>(json).expect("parsing JSON");

        // WHEN
        let checks = rdap.get_checks(None, CheckParams::for_rdap(&rdap));

        // THEN
        assert!(!contains_check(Check::ErrorCodeIsString, &checks));
    }

    #[test]
    fn check_error_with_number_title() {
        // GIVEN
        let json = r#"{"errorCode": 404, "title": 123}"#;
        let rdap = serde_json::from_str::<RdapResponse>(json).expect("parsing JSON");

        // WHEN
        let checks = rdap.get_checks(None, CheckParams::for_rdap(&rdap));

        // THEN
        assert!(contains_check(Check::TitleIsNotString, &checks));
    }

    #[test]
    fn check_error_with_bool_title() {
        // GIVEN
        let json = r#"{"errorCode": 404, "title": true}"#;
        let rdap = serde_json::from_str::<RdapResponse>(json).expect("parsing JSON");

        // WHEN
        let checks = rdap.get_checks(None, CheckParams::for_rdap(&rdap));

        // THEN
        assert!(contains_check(Check::TitleIsNotString, &checks));
    }

    #[test]
    fn check_error_with_string_title() {
        // GIVEN
        let json = r#"{"errorCode": 404, "title": "Not Found"}"#;
        let rdap = serde_json::from_str::<RdapResponse>(json).expect("parsing JSON");

        // WHEN
        let checks = rdap.get_checks(None, CheckParams::for_rdap(&rdap));

        // THEN
        assert!(!contains_check(Check::TitleIsNotString, &checks));
    }

    #[test]
    fn check_error_with_string_description() {
        // GIVEN
        let json = r#"{"errorCode": 404, "description": "Not found"}"#;
        let rdap = serde_json::from_str::<RdapResponse>(json).expect("parsing JSON");

        // WHEN
        let checks = rdap.get_checks(None, CheckParams::for_rdap(&rdap));

        // THEN
        assert!(contains_check(Check::DescriptionIsString, &checks));
    }

    #[test]
    fn check_error_with_array_description() {
        // GIVEN
        let json = r#"{"errorCode": 404, "description": ["Not found"]}"#;
        let rdap = serde_json::from_str::<RdapResponse>(json).expect("parsing JSON");

        // WHEN
        let checks = rdap.get_checks(None, CheckParams::for_rdap(&rdap));

        // THEN
        assert!(!contains_check(Check::DescriptionIsString, &checks));
    }
}
