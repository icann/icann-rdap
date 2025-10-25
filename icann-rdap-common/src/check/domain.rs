use std::any::TypeId;

use crate::{
    prelude::ObjectCommonFields,
    response::domain::{Domain, SecureDns},
};

use super::{
    string::StringCheck, Check, CheckItem, CheckParams, Checks, GetChecks, GetGroupChecks,
};

impl GetChecks for Domain {
    fn get_checks(&self, index: Option<usize>, params: CheckParams) -> super::Checks {
        let sub_checks = {
            let mut sub_checks: Vec<Checks> = vec![];
            sub_checks.append(&mut GetGroupChecks::get_group_checks(
                &self.common,
                params.from_parent(TypeId::of::<Self>()),
            ));
            sub_checks.append(
                &mut self
                    .object_common
                    .get_group_checks(params.from_parent(TypeId::of::<Self>())),
            );
            if let Some(public_ids) = &self.public_ids {
                sub_checks.push(public_ids.get_checks(None, params));
            }
            if let Some(secure_dns) = &self.secure_dns {
                sub_checks.push(secure_dns.get_checks(None, params));
            }

            // entities
            for (i, entity) in self.entities().iter().enumerate() {
                sub_checks.push(entity.get_checks(Some(i), params));
            }

            // network
            if let Some(net) = self.network() {
                sub_checks.push(net.get_checks(None, params));
            }

            // nameservers
            for (i, ns) in self.nameservers().iter().enumerate() {
                sub_checks.push(ns.get_checks(Some(i), params));
            }

            sub_checks
        };

        let mut items = vec![];

        // check variants
        if let Some(variants) = &self.variants {
            let empty_count = variants
                .iter()
                .filter(|v| {
                    v.relations.is_none() && v.idn_table.is_none() && v.variant_names.is_none()
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
            index,
            items,
            sub_checks,
        }
    }
}

impl GetChecks for SecureDns {
    fn get_checks(&self, index: Option<usize>, params: CheckParams) -> Checks {
        let mut items: Vec<CheckItem> = vec![];
        if let Some(delegation_signed) = &self.delegation_signed {
            if delegation_signed.is_string() {
                items.push(Check::DelegationSignedIsString.check_item());
            }
        }
        if let Some(zone_signed) = &self.zone_signed {
            if zone_signed.is_string() {
                items.push(Check::ZoneSignedIsString.check_item());
            }
        }
        if let Some(max_sig_life) = &self.max_sig_life {
            if max_sig_life.is_string() {
                items.push(Check::MaxSigLifeIsString.check_item());
            }
        }

        let mut sub_checks = vec![];
        if let Some(key_data) = &self.key_data {
            for (i, key_datum) in key_data.iter().enumerate() {
                let mut items = vec![];
                if let Some(alg) = &key_datum.algorithm {
                    if alg.is_string() {
                        items.push(Check::KeyDatumAlgorithmIsString.check_item());
                    }
                    if alg.as_u8().is_none() {
                        items.push(Check::KeyDatumAlgorithmIsOutOfRange.check_item());
                    }
                }
                if let Some(flags) = &key_datum.flags {
                    if flags.is_string() {
                        items.push(Check::KeyDatumFlagsIsString.check_item());
                    }
                    if flags.as_u16().is_none() {
                        items.push(Check::KeyDatumFlagsIsOutOfRange.check_item());
                    }
                }
                if let Some(protocol) = &key_datum.protocol {
                    if protocol.is_string() {
                        items.push(Check::KeyDatumProtocolIsString.check_item());
                    }
                    if protocol.as_u8().is_none() {
                        items.push(Check::KeyDatumProtocolIsOutOfRange.check_item());
                    }
                }
                let mut event_checks = vec![];
                for (i, event) in key_datum.events().iter().enumerate() {
                    event_checks.push(event.get_checks(Some(i), params));
                }
                sub_checks.push(Checks {
                    rdap_struct: super::RdapStructure::KeyData,
                    index: Some(i),
                    items,
                    sub_checks: event_checks,
                });
            }
        }

        if let Some(ds_data) = &self.ds_data {
            for (i, ds_datum) in ds_data.iter().enumerate() {
                let mut items = vec![];
                if let Some(alg) = &ds_datum.algorithm {
                    if alg.is_string() {
                        items.push(Check::DsDatumAlgorithmIsString.check_item());
                    }
                    if alg.as_u8().is_none() {
                        items.push(Check::DsDatumAlgorithmIsOutOfRange.check_item());
                    }
                }
                if let Some(key_tag) = &ds_datum.key_tag {
                    if key_tag.is_string() {
                        items.push(Check::DsDatumKeyTagIsString.check_item());
                    }
                    if key_tag.as_u32().is_none() {
                        items.push(Check::DsDatumKeyTagIsOutOfRange.check_item());
                    }
                }
                if let Some(digest_type) = &ds_datum.digest_type {
                    if digest_type.is_string() {
                        items.push(Check::DsDatumDigestTypeIsString.check_item());
                    }
                    if digest_type.as_u8().is_none() {
                        items.push(Check::DsDatumDigestTypeIsOutOfRange.check_item());
                    }
                }
                let mut event_checks = vec![];
                for (i, event) in ds_datum.events().iter().enumerate() {
                    event_checks.push(event.get_checks(Some(i), params));
                }
                sub_checks.push(Checks {
                    rdap_struct: super::RdapStructure::DsData,
                    index: Some(i),
                    items,
                    sub_checks: event_checks,
                });
            }
        }

        Checks {
            rdap_struct: super::RdapStructure::SecureDns,
            index,
            items,
            sub_checks,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::any::TypeId;

    use {
        crate::{
            check::is_checked_item,
            prelude::ToResponse,
            response::domain::{Domain, SecureDns},
        },
        rstest::rstest,
    };

    use crate::{
        check::{contains_check, Check, CheckParams, GetChecks},
        prelude::{Entity, Nameserver, Network},
    };

    #[rstest]
    #[case("")]
    #[case("  ")]
    #[case("_.")]
    fn test_check_for_bad_ldh(#[case] ldh: &str) {
        // GIVEN
        let domain = Domain::builder().ldh_name(ldh).build();
        let rdap = domain.to_response();

        // WHEN
        let checks = rdap.get_checks(None, CheckParams::for_rdap(&rdap));

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
        let rdap = domain.to_response();

        // WHEN
        let checks = rdap.get_checks(None, CheckParams::for_rdap(&rdap));

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
        let rdap = domain.to_response();

        // WHEN
        let checks = rdap.get_checks(None, CheckParams::for_rdap(&rdap));

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
        let checks = secure_dns.get_checks(
            None,
            CheckParams {
                root: &Domain::builder()
                    .ldh_name("example.com")
                    .build()
                    .to_response(),
                parent_type: TypeId::of::<SecureDns>(),
                allow_unreg_ext: false,
            },
        );

        // THEN
        assert_eq!(checks.items.len(), 1);
        assert!(is_checked_item(Check::DelegationSignedIsString, &checks));
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
        let checks = secure_dns.get_checks(
            None,
            CheckParams {
                root: &Domain::builder()
                    .ldh_name("example.com")
                    .build()
                    .to_response(),
                parent_type: TypeId::of::<SecureDns>(),
                allow_unreg_ext: false,
            },
        );

        // THEN
        assert!(checks.items.is_empty());
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
        let checks = secure_dns.get_checks(
            None,
            CheckParams {
                root: &Domain::builder()
                    .ldh_name("example.com")
                    .build()
                    .to_response(),
                parent_type: TypeId::of::<SecureDns>(),
                allow_unreg_ext: false,
            },
        );

        // THEN
        assert_eq!(checks.items.len(), 1);
        assert!(is_checked_item(Check::ZoneSignedIsString, &checks));
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
        let checks = secure_dns.get_checks(
            None,
            CheckParams {
                root: &Domain::builder()
                    .ldh_name("example.com")
                    .build()
                    .to_response(),
                parent_type: TypeId::of::<SecureDns>(),
                allow_unreg_ext: false,
            },
        );

        // THEN
        assert!(checks.items.is_empty());
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
        let checks = secure_dns.get_checks(
            None,
            CheckParams {
                root: &Domain::builder()
                    .ldh_name("example.com")
                    .build()
                    .to_response(),
                parent_type: TypeId::of::<SecureDns>(),
                allow_unreg_ext: false,
            },
        );

        // THEN
        assert_eq!(checks.items.len(), 1);
        assert!(is_checked_item(Check::MaxSigLifeIsString, &checks));
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
        let checks = secure_dns.get_checks(
            None,
            CheckParams {
                root: &Domain::builder()
                    .ldh_name("example.com")
                    .build()
                    .to_response(),
                parent_type: TypeId::of::<SecureDns>(),
                allow_unreg_ext: false,
            },
        );

        // THEN
        assert!(checks.items.is_empty());
    }

    #[test]
    fn test_key_data_attributes_as_string() {
        // GIVEN
        let secure_dns = serde_json::from_str::<SecureDns>(
            r#"{
                "keyData": [
                    {
                        "algorithm": "13",
                        "flags": "13",
                        "protocol": "13"
                    }
                ]
            }"#,
        )
        .unwrap();

        // WHEN
        let checks = secure_dns.get_checks(
            None,
            CheckParams {
                root: &Domain::builder()
                    .ldh_name("example.com")
                    .build()
                    .to_response(),
                parent_type: TypeId::of::<SecureDns>(),
                allow_unreg_ext: false,
            },
        );

        // THEN
        assert!(contains_check(Check::KeyDatumAlgorithmIsString, &checks));
        assert!(contains_check(Check::KeyDatumFlagsIsString, &checks));
        assert!(contains_check(Check::KeyDatumProtocolIsString, &checks));
    }

    #[test]
    fn test_key_data_attributes_as_number() {
        // GIVEN
        let secure_dns = serde_json::from_str::<SecureDns>(
            r#"{
                "keyData": [
                    {
                        "algorithm": 13,
                        "flags": 13,
                        "protocol": 13
                    }
                ]
            }"#,
        )
        .unwrap();

        // WHEN
        let checks = secure_dns.get_checks(
            None,
            CheckParams {
                root: &Domain::builder()
                    .ldh_name("example.com")
                    .build()
                    .to_response(),
                parent_type: TypeId::of::<SecureDns>(),
                allow_unreg_ext: false,
            },
        );

        // THEN
        assert!(checks.items.is_empty());
    }

    #[test]
    fn test_key_data_attributes_out_of_range() {
        // GIVEN
        let secure_dns = serde_json::from_str::<SecureDns>(
            r#"{
                "keyData": [
                    {
                        "algorithm": 1300,
                        "flags": 130000,
                        "protocol": 1300
                    }
                ]
            }"#,
        )
        .unwrap();

        // WHEN
        let checks = secure_dns.get_checks(
            None,
            CheckParams {
                root: &Domain::builder()
                    .ldh_name("example.com")
                    .build()
                    .to_response(),
                parent_type: TypeId::of::<SecureDns>(),
                allow_unreg_ext: false,
            },
        );

        // THEN
        assert!(contains_check(
            Check::KeyDatumAlgorithmIsOutOfRange,
            &checks
        ));
        assert!(contains_check(Check::KeyDatumFlagsIsOutOfRange, &checks));
        assert!(contains_check(Check::KeyDatumProtocolIsOutOfRange, &checks));
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
        let checks = secure_dns.get_checks(
            None,
            CheckParams {
                root: &Domain::builder()
                    .ldh_name("example.com")
                    .build()
                    .to_response(),
                parent_type: TypeId::of::<SecureDns>(),
                allow_unreg_ext: false,
            },
        );

        // THEN
        assert!(contains_check(Check::DsDatumAlgorithmIsString, &checks));
        assert!(contains_check(Check::DsDatumKeyTagIsString, &checks));
        assert!(contains_check(Check::DsDatumDigestTypeIsString, &checks));
    }

    #[test]
    fn test_ds_data_attributes_as_number() {
        // GIVEN
        let secure_dns = serde_json::from_str::<SecureDns>(
            r#"{
                "dsData": [
                    {
                        "algorithm": 13,
                        "keyTag": 13,
                        "digestType": 13
                    }
                ]
            }"#,
        )
        .unwrap();

        // WHEN
        let checks = secure_dns.get_checks(
            None,
            CheckParams {
                root: &Domain::builder()
                    .ldh_name("example.com")
                    .build()
                    .to_response(),
                parent_type: TypeId::of::<SecureDns>(),
                allow_unreg_ext: false,
            },
        );

        // THEN
        assert!(checks.items.is_empty());
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
        let checks = secure_dns.get_checks(
            None,
            CheckParams {
                root: &Domain::builder()
                    .ldh_name("example.com")
                    .build()
                    .to_response(),
                parent_type: TypeId::of::<SecureDns>(),
                allow_unreg_ext: false,
            },
        );

        // THEN
        dbg!(&checks);
        assert!(contains_check(Check::DsDatumAlgorithmIsOutOfRange, &checks));
        assert!(contains_check(Check::DsDatumKeyTagIsOutOfRange, &checks));
        assert!(contains_check(
            Check::DsDatumDigestTypeIsOutOfRange,
            &checks
        ));
    }

    #[test]
    fn test_domain_with_entity_empty_handle() {
        // GIVEN
        let domain = Domain::builder()
            .ldh_name("foo.example")
            .entity(Entity::builder().handle("").build())
            .build()
            .to_response();

        // WHEN
        let checks = domain.get_checks(None, CheckParams::for_rdap(&domain));

        // THEN
        assert!(contains_check(Check::HandleIsEmpty, &checks));
    }

    #[test]
    fn test_domain_with_network_empty_handle() {
        // GIVEN
        let domain = Domain::builder()
            .ldh_name("foo.example")
            .network(
                Network::builder()
                    .cidr("10.0.0.0/8")
                    .handle("")
                    .build()
                    .unwrap(),
            )
            .build()
            .to_response();

        // WHEN
        let checks = domain.get_checks(None, CheckParams::for_rdap(&domain));

        // THEN
        assert!(contains_check(Check::HandleIsEmpty, &checks));
    }

    #[test]
    fn test_domain_with_ns_empty_handle() {
        // GIVEN
        let domain = Domain::builder()
            .ldh_name("foo.example")
            .nameserver(
                Nameserver::builder()
                    .ldh_name("ns.foo.example")
                    .handle("")
                    .build()
                    .unwrap(),
            )
            .build()
            .to_response();

        // WHEN
        let checks = domain.get_checks(None, CheckParams::for_rdap(&domain));

        // THEN
        assert!(contains_check(Check::HandleIsEmpty, &checks));
    }
}
