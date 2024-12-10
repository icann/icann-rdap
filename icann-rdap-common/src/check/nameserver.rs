use std::any::TypeId;
use std::net::IpAddr;
use std::str::FromStr;

use crate::response::nameserver::Nameserver;

use super::string::StringListCheck;
use super::{string::StringCheck, Check, CheckParams, Checks, GetChecks, GetSubChecks};

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
                items.push(Check::LdhNameInvalid.check_item());
            }
        }

        if let Some(ip_addresses) = &self.ip_addresses {
            if let Some(v6_addrs) = &ip_addresses.v6 {
                if v6_addrs.as_slice().is_empty_or_any_empty_or_whitespace() {
                    items.push(Check::IpAddressListIsEmpty.check_item())
                }
                if v6_addrs.iter().any(|ip| IpAddr::from_str(ip).is_err()) {
                    items.push(Check::IpAddressMalformed.check_item())
                }
            }
            if let Some(v4_addrs) = &ip_addresses.v4 {
                if v4_addrs.as_slice().is_empty_or_any_empty_or_whitespace() {
                    items.push(Check::IpAddressListIsEmpty.check_item())
                }
                if v4_addrs.iter().any(|ip| IpAddr::from_str(ip).is_err()) {
                    items.push(Check::IpAddressMalformed.check_item())
                }
            }
        }

        Checks {
            rdap_struct: super::CheckRdapStructure::Nameserver,
            items,
            sub_checks,
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use crate::response::{
        nameserver::{IpAddresses, Nameserver},
        types::{Common, ObjectCommon},
        RdapResponse,
    };
    use rstest::rstest;

    use crate::check::{Check, CheckParams, GetChecks};

    #[rstest]
    #[case("")]
    #[case("  ")]
    #[case("_.")]
    fn GIVEN_nameserver_with_bad_ldh_WHEN_checked_THEN_invalid_ldh(#[case] ldh: &str) {
        // GIVEN
        let ns = Nameserver::basic().ldh_name(ldh).build().unwrap();
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
            .any(|c| c.check == Check::LdhNameInvalid));
    }

    #[test]
    fn GIVEN_nameserver_with_empty_v6s_WHEN_checked_THEN_ip_list_is_empty_check() {
        // GIVEN
        let ns = Nameserver::builder()
            .ldh_name("ns1.example.com")
            .common(Common::builder().build())
            .object_common(ObjectCommon::nameserver().build())
            .ip_addresses(IpAddresses::builder().v6(vec![]).build())
            .build();
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
            .any(|c| c.check == Check::IpAddressListIsEmpty));
    }

    #[test]
    fn GIVEN_nameserver_with_empty_v4s_WHEN_checked_THEN_ip_list_is_empty_check() {
        // GIVEN
        let ns = Nameserver::builder()
            .ldh_name("ns1.example.com")
            .common(Common::builder().build())
            .object_common(ObjectCommon::nameserver().build())
            .ip_addresses(IpAddresses::builder().v4(vec![]).build())
            .build();
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
            .any(|c| c.check == Check::IpAddressListIsEmpty));
    }

    #[test]
    fn GIVEN_nameserver_with_bad_v6s_WHEN_checked_THEN_ip_list_is_empty_check() {
        // GIVEN
        let ns = Nameserver::builder()
            .ldh_name("ns1.example.com")
            .common(Common::builder().build())
            .object_common(ObjectCommon::nameserver().build())
            .ip_addresses(IpAddresses::builder().v6(vec!["__".to_string()]).build())
            .build();
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
            .any(|c| c.check == Check::IpAddressMalformed));
    }

    #[test]
    fn GIVEN_nameserver_with_bad_v4s_WHEN_checked_THEN_ip_list_is_empty_check() {
        // GIVEN
        let ns = Nameserver::builder()
            .ldh_name("ns1.example.com")
            .common(Common::builder().build())
            .object_common(ObjectCommon::nameserver().build())
            .ip_addresses(IpAddresses::builder().v4(vec!["___".to_string()]).build())
            .build();
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
            .any(|c| c.check == Check::IpAddressMalformed));
    }
}
