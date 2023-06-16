use std::any::TypeId;

use crate::response::nameserver::Nameserver;

use super::{string::StringCheck, CheckItem, CheckParams, Checks, GetChecks, GetSubChecks};

impl GetChecks for Nameserver {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks = if params.do_subchecks {
            let mut sub_checks: Vec<Checks> = self
                .common
                .get_sub_checks(params.from_parent(TypeId::of::<Nameserver>()));
            sub_checks.append(
                &mut self
                    .object_common
                    .get_sub_checks(params.from_parent(TypeId::of::<Nameserver>())),
            );
            sub_checks
        } else {
            Vec::new()
        };

        let mut items = Vec::new();

        // check ldh
        if let Some(ldh) = &self.ldh_name {
            if !ldh.is_ldh_domain_name() {
                items.push(CheckItem::invalid_ldh_name());
            }
        }

        Checks {
            struct_name: "Nameserver",
            items,
            sub_checks,
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use crate::response::{nameserver::Nameserver, RdapResponse};
    use rstest::rstest;

    use crate::check::{Check, CheckParams, GetChecks};

    #[rstest]
    #[case("")]
    #[case("  ")]
    #[case("_.")]
    fn GIVEN_nameserver_with_bad_ldh_WHEN_checked_THEN_invalid_ldh(#[case] ldh: &str) {
        // GIVEN
        let ns = Nameserver::new_ldh(ldh);
        let rdap = RdapResponse::Nameserver(ns);

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
            .any(|c| c.check == Check::InvalidLdhName));
    }
}
