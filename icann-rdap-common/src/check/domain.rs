use std::any::TypeId;

use crate::response::domain::Domain;

use super::{string::StringCheck, Check, CheckParams, Checks, GetChecks, GetSubChecks};

impl GetChecks for Domain {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks = if params.do_subchecks {
            let mut sub_checks: Vec<Checks> = self
                .common
                .get_sub_checks(params.from_parent(TypeId::of::<Domain>()));
            sub_checks.append(
                &mut self
                    .object_common
                    .get_sub_checks(params.from_parent(TypeId::of::<Domain>())),
            );
            sub_checks
        } else {
            Vec::new()
        };

        let mut items = Vec::new();

        // check variants
        if let Some(variants) = &self.variants {
            let empty_count = variants
                .iter()
                .filter(|v| {
                    v.relation.is_none() && v.idn_table.is_none() && v.variant_names.is_none()
                })
                .count();
            if empty_count != 0 {
                items.push(Check::VariantEmptyDomain.check_item());
            };
        };

        // check ldh
        if let Some(ldh) = &self.ldh_name {
            if !ldh.is_ldh_domain_name() {
                items.push(Check::LdhNameInvalid.check_item());
            }
            let name = ldh.trim_end_matches('.');
            if name.eq("example")
                || name.ends_with(".example")
                || name.eq("example.com")
                || name.ends_with(".example.com")
                || name.eq("example.net")
                || name.ends_with(".example.net")
                || name.eq("example.org")
                || name.ends_with(".example.org")
            {
                items.push(Check::LdhNameDocumentation.check_item())
            }

            // if there is also a unicodeName
            if let Some(unicode_name) = &self.unicode_name {
                let expected = idna::domain_to_ascii(unicode_name);
                if let Ok(expected) = expected {
                    if !expected.eq_ignore_ascii_case(ldh) {
                        items.push(Check::LdhNameDoesNotMatchUnicode.check_item())
                    }
                }
            }
        }

        // check unicode_name
        if let Some(unicode_name) = &self.unicode_name {
            if !unicode_name.is_unicode_domain_name() {
                items.push(Check::UnicodeNameInvalidDomain.check_item());
            }
            let expected = idna::domain_to_ascii(unicode_name);
            if expected.is_err() {
                items.push(Check::UnicodeNameInvalidUnicode.check_item());
            }
        }

        Checks {
            struct_name: "Domain",
            items,
            sub_checks,
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use crate::response::{domain::Domain, RdapResponse};
    use rstest::rstest;

    use crate::check::{Check, CheckParams, GetChecks};

    #[rstest]
    #[case("")]
    #[case("  ")]
    #[case("_.")]
    fn GIVEN_domain_with_bad_ldh_WHEN_checked_THEN_invalid_ldh(#[case] ldh: &str) {
        // GIVEN
        let domain = Domain::basic().ldh_name(ldh).build();
        let rdap = RdapResponse::Domain(domain);

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
            .any(|c| c.check == Check::LdhNameInvalid));
    }

    #[rstest]
    #[case("")]
    #[case("  ")]
    fn GIVEN_domain_with_bad_unicode_WHEN_checked_THEN_invalid_ldh(#[case] unicode: &str) {
        // GIVEN
        let domain = Domain::idn().unicode_name(unicode).build();
        let rdap = RdapResponse::Domain(domain);

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
            .any(|c| c.check == Check::UnicodeNameInvalidDomain));
    }

    #[test]
    fn GIVEN_domain_with_mismatch_ldh_and_unicode_WHEN_checked_THEN_unicode_does_not_match() {
        // GIVEN
        let domain = Domain::idn()
            .unicode_name("foo.com")
            .ldh_name("xn--foo.com")
            .build();
        let rdap = RdapResponse::Domain(domain);

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
            .any(|c| c.check == Check::LdhNameDoesNotMatchUnicode));
    }
}
