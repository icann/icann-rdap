use std::any::TypeId;

use crate::response::domain::{Domain, SecureDns};

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
            if let Some(public_ids) = &self.public_ids {
                sub_checks.append(&mut public_ids.get_sub_checks(params));
            }
            if let Some(secure_dns) = &self.secure_dns {
                sub_checks.append(&mut secure_dns.get_sub_checks(params));
            }
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
            rdap_struct: super::RdapStructure::Domain,
            items,
            sub_checks,
        }
    }
}

impl GetSubChecks for SecureDns {
    fn get_sub_checks(&self, _params: CheckParams) -> Vec<Checks> {
        let mut sub_checks = Vec::new();
        if let Some(delegation_signed) = &self.delegation_signed {
            if delegation_signed.is_string() {
                sub_checks.push(Checks {
                    rdap_struct: super::RdapStructure::SecureDns,
                    items: vec![Check::DelegationSignedIsString.check_item()],
                    sub_checks: Vec::new(),
                });
            }
        }
        if let Some(zone_signed) = &self.zone_signed {
            if zone_signed.is_string() {
                sub_checks.push(Checks {
                    rdap_struct: super::RdapStructure::SecureDns,
                    items: vec![Check::ZoneSignedIsString.check_item()],
                    sub_checks: Vec::new(),
                });
            }
        }
        if let Some(max_sig_life) = &self.max_sig_life {
            if max_sig_life.is_string() {
                sub_checks.push(Checks {
                    rdap_struct: super::RdapStructure::SecureDns,
                    items: vec![Check::MaxSigLifeIsString.check_item()],
                    sub_checks: Vec::new(),
                });
            }
        }
        sub_checks
    }
}

#[cfg(test)]
mod tests {
    use std::any::TypeId;

    use crate::{
        check::GetSubChecks,
        response::{
            domain::{Domain, SecureDns},
            RdapResponse,
        },
    };
    use rstest::rstest;

    use crate::check::{Check, CheckParams, GetChecks};

    #[rstest]
    #[case("")]
    #[case("  ")]
    #[case("_.")]
    fn test_check_for_bad_ldh(#[case] ldh: &str) {
        // GIVEN
        let domain = Domain::basic().ldh_name(ldh).build();
        let rdap = RdapResponse::Domain(domain);

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

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
    fn test_check_for_bad_unicode(#[case] unicode: &str) {
        // GIVEN
        let domain = Domain::idn().unicode_name(unicode).build();
        let rdap = RdapResponse::Domain(domain);

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::UnicodeNameInvalidDomain));
    }

    #[test]
    fn test_check_for_ldh_unicode_mismatch() {
        // GIVEN
        let domain = Domain::idn()
            .unicode_name("foo.com")
            .ldh_name("xn--foo.com")
            .build();
        let rdap = RdapResponse::Domain(domain);

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::LdhNameDoesNotMatchUnicode));
    }

    #[test]
    fn test_delegation_signed_as_string() {
        // GIVEN
        let secure_dns = serde_json::from_str::<SecureDns>(
            r#"{
                "delegationSigned": "true"
            }"#,
        )
        .unwrap();

        // WHEN
        let checks = secure_dns.get_sub_checks(CheckParams {
            do_subchecks: false,
            root: &RdapResponse::Domain(Domain::basic().ldh_name("example.com").build()),
            parent_type: TypeId::of::<SecureDns>(),
            allow_unreg_ext: false,
        });

        // THEN
        assert_eq!(checks.len(), 1);
        assert!(checks[0]
            .items
            .iter()
            .any(|c| c.check == Check::DelegationSignedIsString));
    }

    #[test]
    fn test_delegation_signed_as_bool() {
        // GIVEN
        let secure_dns = serde_json::from_str::<SecureDns>(
            r#"{
                "delegationSigned": true
            }"#,
        )
        .unwrap();

        // WHEN
        let checks = secure_dns.get_sub_checks(CheckParams {
            do_subchecks: false,
            root: &RdapResponse::Domain(Domain::basic().ldh_name("example.com").build()),
            parent_type: TypeId::of::<SecureDns>(),
            allow_unreg_ext: false,
        });

        // THEN
        assert!(checks.is_empty());
    }

    #[test]
    fn test_zone_signed_as_string() {
        // GIVEN
        let secure_dns = serde_json::from_str::<SecureDns>(
            r#"{
                "zoneSigned": "false"
            }"#,
        )
        .unwrap();

        // WHEN
        let checks = secure_dns.get_sub_checks(CheckParams {
            do_subchecks: false,
            root: &RdapResponse::Domain(Domain::basic().ldh_name("example.com").build()),
            parent_type: TypeId::of::<SecureDns>(),
            allow_unreg_ext: false,
        });

        // THEN
        assert_eq!(checks.len(), 1);
        assert!(checks[0]
            .items
            .iter()
            .any(|c| c.check == Check::ZoneSignedIsString));
    }

    #[test]
    fn test_zone_signed_as_bool() {
        // GIVEN
        let secure_dns = serde_json::from_str::<SecureDns>(
            r#"{
                "zoneSigned": true
            }"#,
        )
        .unwrap();

        // WHEN
        let checks = secure_dns.get_sub_checks(CheckParams {
            do_subchecks: false,
            root: &RdapResponse::Domain(Domain::basic().ldh_name("example.com").build()),
            parent_type: TypeId::of::<SecureDns>(),
            allow_unreg_ext: false,
        });

        // THEN
        assert!(checks.is_empty());
    }

    #[test]
    fn test_max_sig_life_as_string() {
        // GIVEN
        let secure_dns = serde_json::from_str::<SecureDns>(
            r#"{
                "maxSigLife": "123"
            }"#,
        )
        .unwrap();

        // WHEN
        let checks = secure_dns.get_sub_checks(CheckParams {
            do_subchecks: false,
            root: &RdapResponse::Domain(Domain::basic().ldh_name("example.com").build()),
            parent_type: TypeId::of::<SecureDns>(),
            allow_unreg_ext: false,
        });

        // THEN
        assert_eq!(checks.len(), 1);
        assert!(checks[0]
            .items
            .iter()
            .any(|c| c.check == Check::MaxSigLifeIsString));
    }

    #[test]
    fn test_max_sig_life_as_number() {
        // GIVEN
        let secure_dns = serde_json::from_str::<SecureDns>(
            r#"{
                "maxSigLife": 123
            }"#,
        )
        .unwrap();

        // WHEN
        let checks = secure_dns.get_sub_checks(CheckParams {
            do_subchecks: false,
            root: &RdapResponse::Domain(Domain::basic().ldh_name("example.com").build()),
            parent_type: TypeId::of::<SecureDns>(),
            allow_unreg_ext: false,
        });

        // THEN
        assert!(checks.is_empty());
    }
}
