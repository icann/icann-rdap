use std::any::TypeId;

use crate::response::autnum::Autnum;

use super::{
    string::StringCheck, Check, CheckParams, Checks, GetChecks, GetSubChecks, RdapStructure,
};

impl GetChecks for Autnum {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks = if params.do_subchecks {
            let mut sub_checks: Vec<Checks> = self
                .common
                .get_sub_checks(params.from_parent(TypeId::of::<Self>()));
            sub_checks.append(
                &mut self
                    .object_common
                    .get_sub_checks(params.from_parent(TypeId::of::<Self>())),
            );
            sub_checks
        } else {
            vec![]
        };

        let mut items = vec![];

        if self.start_autnum.is_none() || self.end_autnum.is_none() {
            items.push(Check::AutnumMissing.check_item())
        }

        if let Some(start_num) = &self.start_autnum.as_ref().and_then(|n| n.as_u32()) {
            if let Some(end_num) = &self.end_autnum.as_ref().and_then(|n| n.as_u32()) {
                if start_num > end_num {
                    items.push(Check::AutnumEndBeforeStart.check_item())
                }
                if is_autnum_reserved(*start_num) || is_autnum_reserved(*end_num) {
                    items.push(Check::AutnumReserved.check_item())
                }
                if is_autnum_documentation(*start_num) || is_autnum_documentation(*end_num) {
                    items.push(Check::AutnumDocumentation.check_item())
                }
                if is_autnum_private_use(*start_num) || is_autnum_private_use(*end_num) {
                    items.push(Check::AutnumPrivateUse.check_item())
                }
            }
        }

        if let Some(name) = &self.name {
            if name.is_whitespace_or_empty() {
                items.push(Check::NetworkOrAutnumNameIsEmpty.check_item())
            }
            if name.is_number() || name.is_bool() {
                items.push(Check::NetworkOrAutnumNameIsNotString.check_item())
            }
        }

        if let Some(autnum_type) = &self.autnum_type {
            if autnum_type.is_whitespace_or_empty() {
                items.push(Check::NetworkOrAutnumTypeIsEmpty.check_item())
            }
            if autnum_type.is_number() || autnum_type.is_bool() {
                items.push(Check::NetworkOrAutnumTypeIsNotString.check_item())
            }
        }

        Checks {
            rdap_struct: RdapStructure::Autnum,
            items,
            sub_checks,
        }
    }
}

/// Returns true if the autnum is reserved.
pub fn is_autnum_reserved(autnum: u32) -> bool {
    autnum == 0 || autnum == 65535 || autnum == 4294967295 || (65552..=131071).contains(&autnum)
}

/// Returns true if the autnum is for documentation.
pub fn is_autnum_documentation(autnum: u32) -> bool {
    (64496..=64511).contains(&autnum) || (65536..=65551).contains(&autnum)
}

/// Returns true if the autnum is private use.
pub fn is_autnum_private_use(autnum: u32) -> bool {
    (64512..=65534).contains(&autnum) || (4200000000..=4294967294).contains(&autnum)
}

#[cfg(test)]
mod tests {

    use rstest::rstest;

    use crate::prelude::ToResponse;

    use crate::{
        check::{Check, CheckParams, GetChecks},
        response::{autnum::Autnum, RdapResponse},
    };

    use super::*;

    #[test]
    fn check_autnum_with_empty_name() {
        // GIVEN
        let mut autnum = Autnum::builder().autnum_range(700..700).build();
        autnum.name = Some("".to_string().into());
        let rdap = autnum.to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::NetworkOrAutnumNameIsEmpty));
    }

    #[test]
    fn check_autnum_with_non_string_name() {
        // GIVEN
        let json = r#"
            {
              "objectClassName" : "autnum",
              "handle" : "XXXX-RIR",
              "startAutnum" : 65536,
              "endAutnum" : 65541,
              "name": 1234,
              "type" : "DIRECT ALLOCATION",
              "status" : [ "active" ],
              "country": "AU"
            }
        "#;
        let rdap = serde_json::from_str::<RdapResponse>(json).expect("parsing JSON");

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::NetworkOrAutnumNameIsNotString));
    }

    #[test]
    fn check_autnum_with_empty_type() {
        // GIVEN
        let mut autnum = Autnum::builder().autnum_range(700..700).build();
        autnum.autnum_type = Some("".to_string().into());
        let rdap = autnum.to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::NetworkOrAutnumTypeIsEmpty));
    }

    #[test]
    fn check_autnum_with_non_string_type() {
        // GIVEN
        let json = r#"
            {
              "objectClassName" : "autnum",
              "handle" : "XXXX-RIR",
              "startAutnum" : 65536,
              "endAutnum" : 65541,
              "name": "AS-RTR-1",
              "type" : 1234,
              "status" : [ "active" ],
              "country": "AU"
            }
        "#;
        let rdap = serde_json::from_str::<RdapResponse>(json).expect("parsing JSON");

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::NetworkOrAutnumTypeIsNotString));
    }

    #[rstest]
    #[case(0, true)]
    #[case(65535, true)]
    #[case(65552, true)]
    #[case(131071, true)]
    #[case(4294967295, true)]
    #[case(1, false)]
    #[case(65534, false)]
    #[case(65551, false)]
    #[case(131072, false)]
    #[case(4294967294, false)]
    fn check_autnum_is_reserved(#[case] autnum: u32, #[case] expected: bool) {
        // GIVEN in parameters

        // WHEN
        let actual = is_autnum_reserved(autnum);

        // THEN
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case(64496, true)]
    #[case(64511, true)]
    #[case(65536, true)]
    #[case(65551, true)]
    #[case(64495, false)]
    #[case(64512, false)]
    #[case(65535, false)]
    #[case(65552, false)]
    fn check_autnum_is_documentation(#[case] autnum: u32, #[case] expected: bool) {
        // GIVEN in parameters

        // WHEN
        let actual = is_autnum_documentation(autnum);

        // THEN
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case(64512, true)]
    #[case(65534, true)]
    #[case(4200000000, true)]
    #[case(4294967294, true)]
    #[case(65534, true)]
    #[case(64511, false)]
    #[case(65535, false)]
    #[case(4199999999, false)]
    #[case(4294967295, false)]
    fn check_autnum_is_private_use(#[case] autnum: u32, #[case] expected: bool) {
        // GIVEN in parameters

        // WHEN
        let actual = is_autnum_private_use(autnum);

        // THEN
        assert_eq!(actual, expected);
    }
}
