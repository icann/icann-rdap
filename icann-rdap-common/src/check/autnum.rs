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
                .get_sub_checks(params.from_parent(TypeId::of::<Autnum>()));
            sub_checks.append(
                &mut self
                    .object_common
                    .get_sub_checks(params.from_parent(TypeId::of::<Autnum>())),
            );
            sub_checks
        } else {
            Vec::new()
        };

        let mut items = Vec::new();

        if self.start_autnum.is_none() || self.end_autnum.is_none() {
            items.push(Check::AutnumMissing.check_item())
        }

        if let Some(start_num) = &self.start_autnum {
            if let Some(end_num) = &self.end_autnum {
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
        }

        if let Some(autnum_type) = &self.autnum_type {
            if autnum_type.is_whitespace_or_empty() {
                items.push(Check::NetworkOrAutnumTypeIsEmpty.check_item())
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
#[allow(non_snake_case)]
mod tests {

    use rstest::rstest;

    use crate::response::RdapResponse;

    use crate::check::{Check, CheckParams, GetChecks};
    use crate::response::autnum::Autnum;

    use super::*;

    #[test]
    fn GIVEN_autnum_with_empty_name_WHEN_checked_THEN_empty_name_check() {
        // GIVEN
        let mut autnum = Autnum::basic().autnum_range(700..700).build();
        autnum.name = Some("".to_string());
        let rdap = RdapResponse::Autnum(autnum);

        // WHEN
        let checks = rdap.get_checks(CheckParams {
            do_subchecks: true,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::NetworkOrAutnumNameIsEmpty));
    }

    #[test]
    fn GIVEN_autnum_with_empty_type_WHEN_checked_THEN_empty_type_check() {
        // GIVEN
        let mut autnum = Autnum::basic().autnum_range(700..700).build();
        autnum.autnum_type = Some("".to_string());
        let rdap = RdapResponse::Autnum(autnum);

        // WHEN
        let checks = rdap.get_checks(CheckParams {
            do_subchecks: true,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::NetworkOrAutnumTypeIsEmpty));
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
    fn GIVEN_autnum_WHEN_is_reserved_THEN_correct_result(
        #[case] autnum: u32,
        #[case] expected: bool,
    ) {
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
    fn GIVEN_autnum_WHEN_is_documentation_THEN_correct_result(
        #[case] autnum: u32,
        #[case] expected: bool,
    ) {
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
    fn GIVEN_autnum_WHEN_is_private_use_THEN_correct_result(
        #[case] autnum: u32,
        #[case] expected: bool,
    ) {
        // GIVEN in parameters

        // WHEN
        let actual = is_autnum_private_use(autnum);

        // THEN
        assert_eq!(actual, expected);
    }
}
