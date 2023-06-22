use std::any::TypeId;

use crate::response::autnum::Autnum;

use super::{string::StringCheck, CheckItem, CheckParams, Checks, GetChecks, GetSubChecks};

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

        if let Some(name) = &self.name {
            if name.is_whitespace_or_empty() {
                items.push(CheckItem::name_is_empty())
            }
        }

        if let Some(autnum_type) = &self.autnum_type {
            if autnum_type.is_whitespace_or_empty() {
                items.push(CheckItem::type_is_empty())
            }
        }

        Checks {
            struct_name: "Autnum",
            items,
            sub_checks,
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {

    use crate::response::RdapResponse;

    use crate::check::{Check, CheckParams, GetChecks};
    use crate::response::autnum::Autnum;

    #[test]
    fn GIVEN_autnum_with_empty_name_WHEN_checked_THEN_empty_name_check() {
        // GIVEN
        let mut autnum = Autnum::new_autnum(700);
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
        assert!(checks.items.iter().any(|c| c.check == Check::NameIsEmpty));
    }

    #[test]
    fn GIVEN_autnum_with_empty_type_WHEN_checked_THEN_empty_type_check() {
        // GIVEN
        let mut autnum = Autnum::new_autnum(700);
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
        assert!(checks.items.iter().any(|c| c.check == Check::TypeIsEmpty));
    }
}
