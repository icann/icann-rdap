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

        if let Some(key_data) = &self.key_data {
            for key_datum in key_data {
                if let Some(alg) = &key_datum.algorithm {
                    if alg.is_string() {
                        sub_checks.push(Checks {
                            rdap_struct: super::RdapStructure::SecureDns,
                            items: vec![Check::KeyDatumAlgorithmIsString.check_item()],
                            sub_checks: Vec::new(),
                        });
                    }
                    if alg.as_u8().is_none() {
                        sub_checks.push(Checks {
                            rdap_struct: super::RdapStructure::SecureDns,
                            items: vec![Check::KeyDatumAlgorithmIsOutOfRange.check_item()],
                            sub_checks: Vec::new(),
                        });
                    }
                }
                if let Some(flags) = &key_datum.flags {
                    if flags.is_string() {
                        sub_checks.push(Checks {
                            rdap_struct: super::RdapStructure::SecureDns,
                            items: vec![Check::KeyDatumFlagsIsString.check_item()],
                            sub_checks: Vec::new(),
                        });
                    }
                    if flags.as_u16().is_none() {
                        sub_checks.push(Checks {
                            rdap_struct: super::RdapStructure::SecureDns,
                            items: vec![Check::KeyDatumFlagsIsOutOfRange.check_item()],
                            sub_checks: Vec::new(),
                        });
                    }
                }
            }
        }

        if let Some(ds_data) = &self.ds_data {
            for ds_datum in ds_data {
                if let Some(alg) = &ds_datum.algorithm {
                    if alg.is_string() {
                        sub_checks.push(Checks {
                            rdap_struct: super::RdapStructure::SecureDns,
                            items: vec![Check::DsDatumAlgorithmIsString.check_item()],
                            sub_checks: Vec::new(),
                        });
                    }
                    if alg.as_u8().is_none() {
                        sub_checks.push(Checks {
                            rdap_struct: super::RdapStructure::SecureDns,
                            items: vec![Check::DsDatumAlgorithmIsOutOfRange.check_item()],
                            sub_checks: Vec::new(),
                        });
                    }
                }
                if let Some(key_tag) = &ds_datum.key_tag {
                    if key_tag.is_string() {
                        sub_checks.push(Checks {
                            rdap_struct: super::RdapStructure::SecureDns,
                            items: vec![Check::DsDatumKeyTagIsString.check_item()],
                            sub_checks: Vec::new(),
                        });
                    }
                    if key_tag.as_u32().is_none() {
                        sub_checks.push(Checks {
                            rdap_struct: super::RdapStructure::SecureDns,
                            items: vec![Check::DsDatumKeyTagIsOutOfRange.check_item()],
                            sub_checks: Vec::new(),
                        });
                    }
                }
                if let Some(digest_type) = &ds_datum.digest_type {
                    if digest_type.is_string() {
                        sub_checks.push(Checks {
                            rdap_struct: super::RdapStructure::SecureDns,
                            items: vec![Check::DsDatumDigestTypeIsString.check_item()],
                            sub_checks: Vec::new(),
                        });
                    }
                    if digest_type.as_u8().is_none() {
                        sub_checks.push(Checks {
                            rdap_struct: super::RdapStructure::SecureDns,
                            items: vec![Check::DsDatumDigestTypeIsOutOfRange.check_item()],
                            sub_checks: Vec::new(),
                        });
                    }
                }
            }
        }

        sub_checks
    }
}

#[cfg(test)]
mod tests {
    use std::any::TypeId;

    use crate::{
        check::{is_checked, is_checked_item, GetSubChecks},
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
        assert!(is_checked_item(Check::LdhNameInvalid, &checks));
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
        assert!(is_checked_item(Check::UnicodeNameInvalidDomain, &checks));
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
        assert!(is_checked_item(Check::LdhNameDoesNotMatchUnicode, &checks));
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
        assert!(is_checked(Check::DelegationSignedIsString, &checks));
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
        assert!(is_checked(Check::ZoneSignedIsString, &checks));
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
        assert!(is_checked(Check::MaxSigLifeIsString, &checks));
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

    #[test]
    fn test_key_data_attributes_as_string() {
        // GIVEN
        let secure_dns = serde_json::from_str::<SecureDns>(
            r#"{
                "keyData": [
                    {
                        "algorithm": "13",
                        "flags": "13"
                    }
                ]
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
        assert_eq!(checks.len(), 2);
        assert!(is_checked(Check::KeyDatumAlgorithmIsString, &checks));
        assert!(is_checked(Check::KeyDatumFlagsIsString, &checks));
    }

    #[test]
    fn test_key_data_attributes_as_number() {
        // GIVEN
        let secure_dns = serde_json::from_str::<SecureDns>(
            r#"{
                "keyData": [
                    {
                        "algorithm": 13,
                        "flags": 13
                    }
                ]
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
    fn test_key_data_attributes_out_of_range() {
        // GIVEN
        let secure_dns = serde_json::from_str::<SecureDns>(
            r#"{
                "keyData": [
                    {
                        "algorithm": 1300,
                        "flags": 130000
                    }
                ]
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
        assert_eq!(checks.len(), 2);
        assert!(is_checked(Check::KeyDatumAlgorithmIsOutOfRange, &checks));
        assert!(is_checked(Check::KeyDatumFlagsIsOutOfRange, &checks));
    }

    #[test]
    fn test_ds_data_attributes_as_string() {
        // GIVEN
        let secure_dns = serde_json::from_str::<SecureDns>(
            r#"{
                "dsData": [
                    {
                        "algorithm": "13",
                        "keyTag": "13",
                        "digestType": "13"
                    }
                ]
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
        assert_eq!(checks.len(), 3);
        assert!(is_checked(Check::DsDatumAlgorithmIsString, &checks));
        assert!(is_checked(Check::DsDatumKeyTagIsString, &checks));
        assert!(is_checked(Check::DsDatumDigestTypeIsString, &checks));
    }

    #[test]
    fn test_ds_data_attributes_as_number() {
        // GIVEN
        let secure_dns = serde_json::from_str::<SecureDns>(
            r#"{
                "dsData": [
                    {
                        "algorithm": 13,
                        "keyTag": 13
                    }
                ]
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
    fn test_ds_data_attributes_out_of_range() {
        // GIVEN
        let secure_dns = serde_json::from_str::<SecureDns>(
            r#"{
                "dsData": [
                    {
                        "algorithm": 1300,
                        "keyTag": 13000000000,
                        "digestType": 1300
                    }
                ]
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
        assert_eq!(checks.len(), 3);
        assert!(is_checked(Check::DsDatumAlgorithmIsOutOfRange, &checks));
        assert!(is_checked(Check::DsDatumKeyTagIsOutOfRange, &checks));
        assert!(is_checked(Check::DsDatumDigestTypeIsOutOfRange, &checks));
    }
}
