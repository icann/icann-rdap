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
                if v6_addrs.is_string() {
                    items.push(Check::IpAddressArrayIsString.check_item())
                }
                if v6_addrs.is_empty_or_any_empty_or_whitespace() {
                    items.push(Check::IpAddressListIsEmpty.check_item())
                }
                if v6_addrs
                    .vec()
                    .iter()
                    .any(|ip| IpAddr::from_str(ip).is_err())
                {
                    items.push(Check::IpAddressMalformed.check_item())
                }
            }
            if let Some(v4_addrs) = &ip_addresses.v4 {
                if v4_addrs.is_string() {
                    items.push(Check::IpAddressArrayIsString.check_item())
                }
                if v4_addrs.is_empty_or_any_empty_or_whitespace() {
                    items.push(Check::IpAddressListIsEmpty.check_item())
                }
                if v4_addrs
                    .vec()
                    .iter()
                    .any(|ip| IpAddr::from_str(ip).is_err())
                {
                    items.push(Check::IpAddressMalformed.check_item())
                }
            }
        }

        Checks {
            rdap_struct: super::RdapStructure::Nameserver,
            items,
            sub_checks,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use rstest::rstest;

    use crate::check::{Check, CheckParams, GetChecks};

    #[rstest]
    #[case("")]
    #[case("  ")]
    #[case("_.")]
    fn check_nameserver_with_bad_ldh(#[case] ldh: &str) {
        // GIVEN
        let rdap = Nameserver::builder()
            .ldh_name(ldh)
            .build()
            .unwrap()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::LdhNameInvalid));
    }

    #[test]
    fn check_nameserver_with_empty_v6s() {
        // GIVEN
        let ns = Nameserver::illegal()
            .ldh_name("ns1.example.com")
            .ip_addresses(IpAddresses::illegal().v6(vec![]).build())
            .build()
            .to_response();

        // WHEN
        let checks = ns.get_checks(CheckParams::for_rdap(&ns));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::IpAddressListIsEmpty));
    }

    #[test]
    fn check_nameserver_with_empty_v4s() {
        // GIVEN
        let ns = Nameserver::illegal()
            .ldh_name("ns1.example.com")
            .ip_addresses(IpAddresses::illegal().v4(vec![]).build())
            .build()
            .to_response();

        // WHEN
        let checks = ns.get_checks(CheckParams::for_rdap(&ns));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::IpAddressListIsEmpty));
    }

    #[test]
    fn check_nameserver_with_bad_v6s() {
        // GIVEN
        let ns = Nameserver::illegal()
            .ldh_name("ns1.example.com")
            .ip_addresses(IpAddresses::illegal().v6(vec!["__".to_string()]).build())
            .build()
            .to_response();

        // WHEN
        let checks = ns.get_checks(CheckParams::for_rdap(&ns));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::IpAddressMalformed));
    }

    #[test]
    fn check_nameserver_with_bad_v4s() {
        // GIVEN
        let ns = Nameserver::illegal()
            .ldh_name("ns1.example.com")
            .ip_addresses(IpAddresses::illegal().v4(vec!["___".to_string()]).build())
            .build()
            .to_response();

        // WHEN
        let checks = ns.get_checks(CheckParams::for_rdap(&ns));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::IpAddressMalformed));
    }
}
