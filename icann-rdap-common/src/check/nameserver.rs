use std::{any::TypeId, net::IpAddr, str::FromStr};

use crate::{prelude::ObjectCommonFields, response::nameserver::Nameserver};

use super::{
    string::{StringCheck, StringListCheck},
    Check, CheckParams, Checks, GetChecks, GetGroupChecks,
};

impl GetChecks for Nameserver {
    fn get_checks(&self, index: Option<usize>, params: CheckParams) -> super::Checks {
        let sub_checks = {
            let mut sub_checks: Vec<Checks> = GetGroupChecks::get_group_checks(
                &self.common,
                params.from_parent(TypeId::of::<Self>()),
            );
            sub_checks.append(
                &mut self
                    .object_common
                    .get_group_checks(params.from_parent(TypeId::of::<Self>())),
            );

            // entities
            for (i, entity) in self.entities().iter().enumerate() {
                sub_checks.push(entity.get_checks(Some(i), params));
            }

            sub_checks
        };

        let mut items = vec![];

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
            index,
            items,
            sub_checks,
        }
    }
}

#[cfg(test)]
mod tests {
    use {crate::prelude::*, rstest::rstest};

    use crate::check::{contains_check, Check, CheckParams, GetChecks};

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
        let checks = rdap.get_checks(None, CheckParams::for_rdap(&rdap));

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
        let checks = ns.get_checks(None, CheckParams::for_rdap(&ns));

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
        let checks = ns.get_checks(None, CheckParams::for_rdap(&ns));

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
        let checks = ns.get_checks(None, CheckParams::for_rdap(&ns));

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
        let checks = ns.get_checks(None, CheckParams::for_rdap(&ns));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::IpAddressMalformed));
    }

    #[test]
    fn test_ns_with_entity_empty_handle() {
        // GIVEN
        let ns = Nameserver::builder()
            .handle("foo")
            .ldh_name("ns.foo.example")
            .entity(Entity::builder().handle("").build())
            .build()
            .unwrap()
            .to_response();

        // WHEN
        let checks = ns.get_checks(None, CheckParams::for_rdap(&ns));

        // THEN
        assert!(contains_check(Check::HandleIsEmpty, &checks));
    }
}
