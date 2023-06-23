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

        if self.start_autnum.is_none() || self.end_autnum.is_none() {
            items.push(CheckItem::missing_autnum())
        }

        if let Some(start_num) = &self.start_autnum {
            if let Some(end_num) = &self.end_autnum {
                if start_num > end_num {
                    items.push(CheckItem::end_autnum_before_start_autnum())
                }
                if *start_num == 0
                    || *start_num == 65535
                    || *start_num == 4294967295
                    || *end_num == 0
                    || *end_num == 65535
                    || *end_num == 4294967295
                {
                    items.push(CheckItem::reserved_autnum())
                }
                if (64496..=64511).contains(start_num)
                    || (64496..=64511).contains(end_num)
                    || (65536..=65551).contains(start_num)
                    || (65536..=65551).contains(end_num)
                {
                    items.push(CheckItem::documentation_autnum())
                }
                if (64512..=65534).contains(start_num)
                    || (64512..=65534).contains(end_num)
                    || (64512..=65534).contains(start_num)
                    || (64512..=65534).contains(end_num)
                {
                    items.push(CheckItem::private_use_autnum())
                }
            }
        }

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
