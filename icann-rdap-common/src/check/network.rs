use std::{any::TypeId, net::IpAddr, str::FromStr};

use cidr::IpCidr;

use crate::response::network::{Cidr0Cidr, Network};

use super::{string::StringCheck, Check, CheckParams, Checks, GetChecks, GetSubChecks};

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
            if let Some(cidr0) = &self.cidr0_cidrs {
                cidr0.iter().for_each(|cidr| match cidr {
                    Cidr0Cidr::V4Cidr(v4) => {
                        if v4.v4prefix.is_none() {
                            sub_checks.push(Checks {
                                rdap_struct: super::RdapStructure::Cidr0,
                                items: vec![Check::Cidr0V4PrefixIsAbsent.check_item()],
                                sub_checks: Vec::new(),
                            })
                        }
                        if v4.length.is_none() {
                            sub_checks.push(Checks {
                                rdap_struct: super::RdapStructure::Cidr0,
                                items: vec![Check::Cidr0V4LengthIsAbsent.check_item()],
                                sub_checks: Vec::new(),
                            })
                        }
                    }
                    Cidr0Cidr::V6Cidr(v6) => {
                        if v6.v6prefix.is_none() {
                            sub_checks.push(Checks {
                                rdap_struct: super::RdapStructure::Cidr0,
                                items: vec![Check::Cidr0V6PrefixIsAbsent.check_item()],
                                sub_checks: Vec::new(),
                            })
                        }
                        if v6.length.is_none() {
                            sub_checks.push(Checks {
                                rdap_struct: super::RdapStructure::Cidr0,
                                items: vec![Check::Cidr0V6LengthIsAbsent.check_item()],
                                sub_checks: Vec::new(),
                            })
                        }
                    }
                })
            }
            sub_checks
        } else {
            Vec::new()
        };

        let mut items = Vec::new();

        if let Some(name) = &self.name {
            if name.is_whitespace_or_empty() {
                items.push(Check::NetworkOrAutnumNameIsEmpty.check_item())
            }
        }

        if let Some(network_type) = &self.network_type {
            if network_type.is_whitespace_or_empty() {
                items.push(Check::NetworkOrAutnumTypeIsEmpty.check_item())
            }
        }

        if self.start_address.is_none() || self.end_address.is_none() {
            items.push(Check::IpAddressMissing.check_item())
        }

        if let Some(start_ip) = &self.start_address {
            let start_addr = IpAddr::from_str(start_ip);
            if start_addr.is_err() {
                items.push(Check::IpAddressMalformed.check_item())
            } else if self.end_address.is_some() {
                let Ok(start_addr) = start_addr else {
                    panic!("ip result did not work")
                };
                let Some(end_ip) = &self.end_address else {
                    panic!("end address unwrap failed")
                };
                if let Ok(end_addr) = IpAddr::from_str(end_ip) {
                    if start_addr > end_addr {
                        items.push(Check::IpAddressEndBeforeStart.check_item())
                    }
                    if let Some(ip_version) = &self.ip_version {
                        if (ip_version == "v4" && (start_addr.is_ipv6() || end_addr.is_ipv6()))
                            || (ip_version == "v6" && (start_addr.is_ipv4() || end_addr.is_ipv4()))
                        {
                            items.push(Check::IpAddressVersionMismatch.check_item())
                        } else if ip_version != "v4" && ip_version != "v6" {
                            items.push(Check::IpAddressMalformedVersion.check_item())
                        }
                    }
                    let this_network =
                        IpCidr::from_str("0.0.0.0/8").expect("incorrect this netowrk cidr");
                    if this_network.contains(&start_addr) && this_network.contains(&end_addr) {
                        items.push(Check::IpAddressThisNetwork.check_item())
                    }
                    let private_10 = IpCidr::from_str("10.0.0.0/8").expect("incorrect net 10 cidr");
                    let private_172 =
                        IpCidr::from_str("172.16.0.0/12").expect("incorrect net 172.16 cidr");
                    let private_192 =
                        IpCidr::from_str("192.168.0.0/16").expect("incorrect net 192.168 cidr");
                    if (private_10.contains(&start_addr) && private_10.contains(&end_addr))
                        || (private_172.contains(&start_addr) && private_172.contains(&end_addr))
                        || (private_192.contains(&start_addr) && private_192.contains(&end_addr))
                    {
                        items.push(Check::IpAddressPrivateUse.check_item())
                    }
                    let shared_nat =
                        IpCidr::from_str("100.64.0.0/10").expect("incorrect net 100 cidr");
                    if shared_nat.contains(&start_addr) && shared_nat.contains(&end_addr) {
                        items.push(Check::IpAddressSharedNat.check_item())
                    }
                    let loopback =
                        IpCidr::from_str("127.0.0.0/8").expect("incorrect loopback cidr");
                    if loopback.contains(&start_addr) && loopback.contains(&end_addr) {
                        items.push(Check::IpAddressLoopback.check_item())
                    }
                    let linklocal1 =
                        IpCidr::from_str("169.254.0.0/16").expect("incorrect linklocal1 cidr");
                    let linklocal2 =
                        IpCidr::from_str("fe80::/10").expect("incorrect linklocal2 cidr");
                    if (linklocal1.contains(&start_addr) && linklocal1.contains(&end_addr))
                        || (linklocal2.contains(&start_addr) && linklocal2.contains(&end_addr))
                    {
                        items.push(Check::IpAddressLinkLocal.check_item())
                    }
                    let uniquelocal =
                        IpCidr::from_str("fe80::/10").expect("incorrect unique local cidr");
                    if uniquelocal.contains(&start_addr) && uniquelocal.contains(&end_addr) {
                        items.push(Check::IpAddressUniqueLocal.check_item())
                    }
                    let doc1 = IpCidr::from_str("192.0.2.0/24").expect("incorrect doc1 cidr");
                    let doc2 = IpCidr::from_str("198.51.100.0/24").expect("incorrect doc2 cidr");
                    let doc3 = IpCidr::from_str("203.0.113.0/24").expect("incorrect doc3 cidr");
                    let doc4 = IpCidr::from_str("2001:db8::/32").expect("incorrect doc4 cidr");
                    if (doc1.contains(&start_addr) && doc1.contains(&end_addr))
                        || (doc2.contains(&start_addr) && doc2.contains(&end_addr))
                        || (doc3.contains(&start_addr) && doc3.contains(&end_addr))
                        || (doc4.contains(&start_addr) && doc4.contains(&end_addr))
                    {
                        items.push(Check::IpAddressDocumentationNet.check_item())
                    }
                    let reserved =
                        IpCidr::from_str("240.0.0.0/4").expect("incorrect reserved cidr");
                    if reserved.contains(&start_addr) && reserved.contains(&end_addr) {
                        items.push(Check::IpAddressLinkLocal.check_item())
                    }
                }
            }
        }

        if let Some(end_ip) = &self.end_address {
            let addr = IpAddr::from_str(end_ip);
            if addr.is_err() {
                items.push(Check::IpAddressMalformed.check_item())
            }
        }

        Checks {
            rdap_struct: super::RdapStructure::IpNetwork,
            items,
            sub_checks,
        }
    }
}

#[cfg(test)]
mod tests {

    use rstest::rstest;

    use crate::response::network::{Cidr0Cidr, Network, V4Cidr, V6Cidr};

    use crate::response::RdapResponse;

    use crate::check::{Check, CheckParams, GetChecks};

    #[test]
    fn check_network_with_empty_name() {
        // GIVEN
        let mut network = Network::builder()
            .cidr("10.0.0.0/8")
            .build()
            .expect("invalid ip cidr");
        network.name = Some("".to_string());
        let rdap = RdapResponse::Network(network);

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::NetworkOrAutnumNameIsEmpty));
    }

    #[test]
    fn check_network_with_empty_type() {
        // GIVEN
        let mut network = Network::builder()
            .cidr("10.0.0.0/8")
            .build()
            .expect("invalid ip cidr");
        network.network_type = Some("".to_string());
        let rdap = RdapResponse::Network(network);

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::NetworkOrAutnumTypeIsEmpty));
    }

    #[test]
    fn check_network_with_no_start() {
        // GIVEN
        let mut network = Network::builder()
            .cidr("10.0.0.0/8")
            .build()
            .expect("invalid ip cidr");
        network.start_address = None;
        let rdap = RdapResponse::Network(network);

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::IpAddressMissing));
    }

    #[test]
    fn check_network_with_no_end() {
        // GIVEN
        let mut network = Network::builder()
            .cidr("10.0.0.0/8")
            .build()
            .expect("invalid ip cidr");
        network.end_address = None;
        let rdap = RdapResponse::Network(network);

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::IpAddressMissing));
    }

    #[test]
    fn check_network_with_bad_start() {
        // GIVEN
        let mut network = Network::builder()
            .cidr("10.0.0.0/8")
            .build()
            .expect("invalid ip cidr");
        network.start_address = Some("____".to_string());
        let rdap = RdapResponse::Network(network);

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::IpAddressMalformed));
    }

    #[test]
    fn check_network_with_bad_end() {
        // GIVEN
        let mut network = Network::builder()
            .cidr("10.0.0.0/8")
            .build()
            .expect("invalid ip cidr");
        network.end_address = Some("___".to_string());
        let rdap = RdapResponse::Network(network);

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::IpAddressMalformed));
    }

    #[test]
    fn check_network_with_end_before_start() {
        // GIVEN
        let mut network = Network::builder()
            .cidr("10.0.0.0/8")
            .build()
            .expect("invalid ip cidr");
        let swap = network.end_address.clone();
        network.end_address = network.start_address.clone();
        network.start_address = swap;
        let rdap = RdapResponse::Network(network);

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::IpAddressEndBeforeStart));
    }

    #[rstest]
    #[case("10.0.0.0/8", "v6")]
    #[case("2000::/64", "v4")]
    fn check_network_with_ip_version(#[case] cidr: &str, #[case] version: &str) {
        // GIVEN
        let mut network = Network::builder()
            .cidr(cidr)
            .build()
            .expect("invalid ip cidr");
        network.ip_version = Some(version.to_string());
        let rdap = RdapResponse::Network(network);

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::IpAddressVersionMismatch));
    }

    #[rstest]
    #[case("10.0.0.0/8", "__")]
    #[case("2000::/64", "__")]
    #[case("10.0.0.0/8", "")]
    #[case("2000::/64", "")]
    fn check_network_with_bad_ip_version(#[case] cidr: &str, #[case] version: &str) {
        // GIVEN
        let mut network = Network::builder()
            .cidr(cidr)
            .build()
            .expect("invalid ip cidr");
        network.ip_version = Some(version.to_string());
        let rdap = RdapResponse::Network(network);

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::IpAddressMalformedVersion));
    }

    #[test]
    fn check_cidr0_with_v4_prefixex() {
        // GIVEN
        let network = Network::illegal()
            .cidr0_cidrs(vec![Cidr0Cidr::V4Cidr(V4Cidr {
                v4prefix: None,
                length: Some(0),
            })])
            .build();
        let rdap = RdapResponse::Network(network);

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .sub(crate::check::RdapStructure::Cidr0)
            .expect("Cidr0")
            .items
            .iter()
            .any(|c| c.check == Check::Cidr0V4PrefixIsAbsent));
    }

    #[test]
    fn check_cidr0_with_v6_prefixex() {
        // GIVEN
        let network = Network::illegal()
            .cidr0_cidrs(vec![Cidr0Cidr::V6Cidr(V6Cidr {
                v6prefix: None,
                length: Some(0),
            })])
            .build();
        let rdap = RdapResponse::Network(network);

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .sub(crate::check::RdapStructure::Cidr0)
            .expect("Cidr0")
            .items
            .iter()
            .any(|c| c.check == Check::Cidr0V6PrefixIsAbsent));
    }

    #[test]
    fn check_cidr0_with_v4_length() {
        // GIVEN
        let network = Network::illegal()
            .cidr0_cidrs(vec![Cidr0Cidr::V4Cidr(V4Cidr {
                v4prefix: Some("0.0.0.0".to_string()),
                length: None,
            })])
            .build();
        let rdap = RdapResponse::Network(network);

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .sub(crate::check::RdapStructure::Cidr0)
            .expect("Cidr0")
            .items
            .iter()
            .any(|c| c.check == Check::Cidr0V4LengthIsAbsent));
    }

    #[test]
    fn check_cidr0_with_v6_length() {
        // GIVEN
        let network = Network::illegal()
            .cidr0_cidrs(vec![Cidr0Cidr::V6Cidr(V6Cidr {
                v6prefix: Some("0.0.0.0".to_string()),
                length: None,
            })])
            .build();
        let rdap = RdapResponse::Network(network);

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(checks
            .sub(crate::check::RdapStructure::Cidr0)
            .expect("Cidr0")
            .items
            .iter()
            .any(|c| c.check == Check::Cidr0V6LengthIsAbsent));
    }
}
