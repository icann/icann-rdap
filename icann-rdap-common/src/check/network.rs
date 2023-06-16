use std::{any::TypeId, net::IpAddr, str::FromStr};

use crate::response::network::Network;

use super::{string::StringCheck, CheckItem, CheckParams, Checks, GetChecks, GetSubChecks};

impl GetChecks for Network {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks = if params.do_subchecks {
            let mut sub_checks: Vec<Checks> = self
                .common
                .get_sub_checks(params.from_parent(TypeId::of::<Network>()));
            sub_checks.append(
                &mut self
                    .object_common
                    .get_sub_checks(params.from_parent(TypeId::of::<Network>())),
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

        if let Some(network_type) = &self.network_type {
            if network_type.is_whitespace_or_empty() {
                items.push(CheckItem::type_is_empty())
            }
        }

        if self.start_address.is_none() || self.end_address.is_none() {
            items.push(CheckItem::missing_ip_address())
        }

        if let Some(start_ip) = &self.start_address {
            let start_addr = IpAddr::from_str(start_ip);
            if start_addr.is_err() {
                items.push(CheckItem::malformed_ip_address())
            } else if self.end_address.is_some() {
                let Ok(start_addr) = start_addr else {panic!("ip result did not work")};
                let Some(end_ip) = &self.end_address else {panic!("end address unwrap failed")};
                if let Ok(end_addr) = IpAddr::from_str(end_ip) {
                    if start_addr > end_addr {
                        items.push(CheckItem::end_ip_before_start_ip())
                    }
                    if let Some(ip_version) = &self.ip_version {
                        if (ip_version == "v4" && (start_addr.is_ipv6() || end_addr.is_ipv6()))
                            || (ip_version == "v6" && (start_addr.is_ipv4() || end_addr.is_ipv4()))
                        {
                            items.push(CheckItem::ip_version_mismatch())
                        } else if ip_version != "v4" && ip_version != "v6" {
                            items.push(CheckItem::malfomred_ip_version())
                        }
                    }
                }
            }
        }

        if let Some(end_ip) = &self.end_address {
            let addr = IpAddr::from_str(end_ip);
            if addr.is_err() {
                items.push(CheckItem::malformed_ip_address())
            }
        }

        Checks {
            struct_name: "Network",
            items,
            sub_checks,
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use cidr_utils::cidr::IpCidr;
    use rstest::rstest;

    use crate::response::network::Network;
    use crate::response::RdapResponse;

    use crate::check::{Check, CheckParams, GetChecks};

    #[test]
    fn GIVEN_network_with_empty_name_WHEN_checked_THEN_empty_name_check() {
        // GIVEN
        let mut network =
            Network::new_network(IpCidr::from_str("10.0.0.0/8").expect("invalid ip cidr"));
        network.name = Some("".to_string());
        let rdap = RdapResponse::Network(network);

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
    fn GIVEN_network_with_empty_type_WHEN_checked_THEN_empty_type_check() {
        // GIVEN
        let mut network =
            Network::new_network(IpCidr::from_str("10.0.0.0/8").expect("invalid ip cidr"));
        network.network_type = Some("".to_string());
        let rdap = RdapResponse::Network(network);

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

    #[test]
    fn GIVEN_network_with_no_start_WHEN_checked_THEN_missing_ip_check() {
        // GIVEN
        let mut network =
            Network::new_network(IpCidr::from_str("10.0.0.0/8").expect("invalid ip cidr"));
        network.start_address = None;
        let rdap = RdapResponse::Network(network);

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
            .any(|c| c.check == Check::MissingIpAddress));
    }

    #[test]
    fn GIVEN_network_with_no_end_WHEN_checked_THEN_missing_ip_check() {
        // GIVEN
        let mut network =
            Network::new_network(IpCidr::from_str("10.0.0.0/8").expect("invalid ip cidr"));
        network.end_address = None;
        let rdap = RdapResponse::Network(network);

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
            .any(|c| c.check == Check::MissingIpAddress));
    }

    #[test]
    fn GIVEN_network_with_bad_start_WHEN_checked_THEN_malformed_ip_check() {
        // GIVEN
        let mut network =
            Network::new_network(IpCidr::from_str("10.0.0.0/8").expect("invalid ip cidr"));
        network.start_address = Some("____".to_string());
        let rdap = RdapResponse::Network(network);

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
            .any(|c| c.check == Check::MalformedIpAddress));
    }

    #[test]
    fn GIVEN_network_with_bad_end_WHEN_checked_THEN_malformed_ip_check() {
        // GIVEN
        let mut network =
            Network::new_network(IpCidr::from_str("10.0.0.0/8").expect("invalid ip cidr"));
        network.end_address = Some("___".to_string());
        let rdap = RdapResponse::Network(network);

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
            .any(|c| c.check == Check::MalformedIpAddress));
    }

    #[test]
    fn GIVEN_network_with_end_before_start_WHEN_checked_THEN_end_before_start_check() {
        // GIVEN
        let mut network =
            Network::new_network(IpCidr::from_str("10.0.0.0/8").expect("invalid ip cidr"));
        let swap = network.end_address.clone();
        network.end_address = network.start_address.clone();
        network.start_address = swap;
        let rdap = RdapResponse::Network(network);

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
            .any(|c| c.check == Check::EndIpBeforeStartIp));
    }

    #[rstest]
    #[case("10.0.0.0/8", "v6")]
    #[case("2000::/64", "v4")]
    fn GIVEN_network_with_ip_version_WHEN_checked_THEN_version_match_check(
        #[case] cidr: &str,
        #[case] version: &str,
    ) {
        // GIVEN
        let mut network = Network::new_network(IpCidr::from_str(cidr).expect("invalid ip cidr"));
        network.ip_version = Some(version.to_string());
        let rdap = RdapResponse::Network(network);

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
            .any(|c| c.check == Check::IpVersionMismatch));
    }

    #[rstest]
    #[case("10.0.0.0/8", "__")]
    #[case("2000::/64", "__")]
    #[case("10.0.0.0/8", "")]
    #[case("2000::/64", "")]
    fn GIVEN_network_with_bad_ip_version_WHEN_checked_THEN_version_match_check(
        #[case] cidr: &str,
        #[case] version: &str,
    ) {
        // GIVEN
        let mut network = Network::new_network(IpCidr::from_str(cidr).expect("invalid ip cidr"));
        network.ip_version = Some(version.to_string());
        let rdap = RdapResponse::Network(network);

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
            .any(|c| c.check == Check::MalformedIPVersion));
    }
}
