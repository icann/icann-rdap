use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// Takes an IP address and creates a reverse DNS domain name.
pub fn ip_to_reverse_dns(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(ipv6) => {
            let octets = ipv6.octets();
            let mut nibbles = Vec::with_capacity(32);

            // Process bytes in reverse order for correct nibble sequence
            for &byte in octets.iter().rev() {
                nibbles.push(format!("{:x}", byte & 0x0F));
                nibbles.push(format!("{:x}", (byte >> 4) & 0x0F));
            }

            nibbles.join(".") + ".ip6.arpa"
        }
    }
}

/// Takes a reverse DNS domain name and creates an IP address.
pub fn reverse_dns_to_ip(dns_name: &str) -> Option<IpAddr> {
    let dns_name = dns_name.to_lowercase();

    if dns_name.ends_with(".in-addr.arpa") || dns_name.ends_with(".in-addr.arpa.") {
        // --- IPv4 Logic ---
        let parts: Vec<&str> = dns_name
            .trim_end_matches('.')
            .trim_end_matches(".in-addr.arpa")
            .split('.')
            .collect();

        if parts.len() != 4 {
            return None;
        }

        let mut octets = [0u8; 4];
        for i in 0..4 {
            // Reverse the order: the first DNS label is the last IP octet
            octets[i] = parts[3 - i].parse().ok()?;
        }
        Some(IpAddr::V4(Ipv4Addr::from(octets)))
    } else if dns_name.ends_with(".ip6.arpa") || dns_name.ends_with(".ip6.arpa.") {
        // --- IPv6 Logic ---
        let nibbles: Vec<u8> = dns_name
            .trim_end_matches('.')
            .trim_end_matches(".ip6.arpa")
            .split('.')
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();

        if nibbles.len() != 32 {
            return None;
        }

        // Reverse to get the correct order (DNS is least-significant nibble first)
        let mut reversed = nibbles;
        reversed.reverse();

        let mut octets = [0u8; 16];
        for i in 0..16 {
            // Combine two nibbles into one byte
            // Most significant nibble (left) and Least significant nibble (right)
            octets[i] = (reversed[i * 2] << 4) | reversed[i * 2 + 1];
        }
        Some(IpAddr::V6(Ipv6Addr::from(octets)))
    } else {
        None // Not a reverse DNS domain
    }
}

/// Converts a reverse DNS domain name to an IpNet (Ipv4Net or Ipv6Net).
/// Infers the prefix length from the number of labels:
/// - IPv4: 1 label = /8, 2 = /16, 3 = /24, 4 = /32
/// - IPv6: n nibbles = n * 4 bits
///
/// # Examples
/// - "10.in-addr.arpa" → Some(IpNet::V4(Ipv4Net::new(Ipv4Addr::from(10), 8)))
/// - "d.ip6.arpa" → Some(IpNet::V6(Ipv6Net::new(Ipv6Addr::from(0x000d), 4)))
pub fn reverse_dns_to_ipnet(dns_name: &str) -> Option<IpNet> {
    let dns_name = dns_name.to_lowercase();

    if dns_name.ends_with(".in-addr.arpa") || dns_name.ends_with(".in-addr.arpa.") {
        let parts: Vec<&str> = dns_name
            .trim_end_matches('.')
            .trim_end_matches(".in-addr.arpa")
            .split('.')
            .collect();

        let prefix_len = (parts.len() * 8) as u8;

        if prefix_len > 32 {
            return None;
        }

        let mut octets = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            if i < 4 {
                octets[i] = part.parse().ok()?;
            }
        }
        let ip = Ipv4Addr::from(octets);
        Ipv4Net::new(ip, prefix_len).map(IpNet::V4).ok()
    } else if dns_name.ends_with(".ip6.arpa") || dns_name.ends_with(".ip6.arpa.") {
        let nibbles: Vec<u8> = dns_name
            .trim_end_matches('.')
            .trim_end_matches(".ip6.arpa")
            .split('.')
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();

        let prefix_len = nibbles.len() * 4;

        if prefix_len > 128 {
            return None;
        }

        if nibbles.len() == 32 {
            let mut reversed = nibbles;
            reversed.reverse();
            let mut octets = [0u8; 16];
            for i in 0..16 {
                octets[i] = (reversed[i * 2] << 4) | reversed[i * 2 + 1];
            }
            let ip = Ipv6Addr::from(octets);
            return Ipv6Net::new(ip, prefix_len as u8).map(IpNet::V6).ok();
        }

        let mut padded: Vec<u8> = nibbles;
        while padded.len() < 32 {
            padded.push(0);
        }
        let mut octets = [0u8; 16];
        for i in 0..16 {
            octets[i] = (padded[i * 2] << 4) | padded[i * 2 + 1];
        }
        let ip = Ipv6Addr::from(octets);
        Ipv6Net::new(ip, prefix_len as u8).map(IpNet::V6).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_rdns_to_ipv4() {
        // GIVEN
        let v4_dns = "4.3.2.1.in-addr.arpa";

        // WHEN
        let actual = reverse_dns_to_ip(v4_dns).expect("reverse parse");

        // THEN
        assert_eq!(actual, IpAddr::from_str("1.2.3.4").expect("ip address"));
    }

    #[test]
    fn test_invalid_rdns_to_ipv4() {
        // GIVEN
        let v4_dns = "4.3.2.500.in-addr.arpa";

        // WHEN
        let actual = reverse_dns_to_ip(v4_dns);

        // THEN
        assert!(actual.is_none());
    }

    #[test]
    fn test_rdns_to_ipv6() {
        // GIVEN
        let v6_dns = "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";

        // WHEN
        let actual = reverse_dns_to_ip(v6_dns).expect("reverse parse");

        // THEN
        assert_eq!(
            actual,
            IpAddr::from_str("2001:db8::567:89ab").expect("ip address")
        );
    }

    #[test]
    fn test_invalid_rdns_to_ipv6() {
        // GIVEN
        let v6_dns = "h.a.h.a.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";

        // WHEN
        let actual = reverse_dns_to_ip(v6_dns);

        // THEN
        assert!(actual.is_none());
    }

    #[test]
    fn test_ipv4_to_reverse_dns() {
        // GIVEN
        let ip = IpAddr::from_str("1.2.3.4").expect("ip address");

        // WHEN
        let actual = ip_to_reverse_dns(&ip);

        // THEN
        assert_eq!(actual, "4.3.2.1.in-addr.arpa");
    }

    #[test]
    fn test_ipv6_to_reverse_dns() {
        // GIVEN
        let ip = IpAddr::from_str("2001:db8::567:89ab").expect("ip address");

        // WHEN
        let actual = ip_to_reverse_dns(&ip);

        // THEN
        assert_eq!(
            actual,
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn test_roundtrip_ipv4() {
        // GIVEN
        let original_ip = IpAddr::from_str("192.168.1.100").expect("ip address");

        // WHEN
        let reverse_dns = ip_to_reverse_dns(&original_ip);
        let converted_back = reverse_dns_to_ip(&reverse_dns);

        // THEN
        assert_eq!(Some(original_ip), converted_back);
    }

    #[test]
    fn test_roundtrip_ipv6() {
        // GIVEN
        let original_ip = IpAddr::from_str("2001:db8::1").expect("ip address");

        // WHEN
        let reverse_dns = ip_to_reverse_dns(&original_ip);
        let converted_back = reverse_dns_to_ip(&reverse_dns);

        // THEN
        assert_eq!(Some(original_ip), converted_back);
    }

    #[test]
    fn test_reverse_dns_to_ipnet_single_label_ipv4() {
        // GIVEN
        let dns_name = "10.in-addr.arpa";
        let expected: Ipv4Net = "10.0.0.0/8".parse().unwrap();

        // WHEN
        let result = reverse_dns_to_ipnet(dns_name).expect("should parse");

        // THEN
        if let IpNet::V4(net) = result {
            assert_eq!(net.network(), expected.network());
            assert_eq!(net.prefix_len(), expected.prefix_len());
        } else {
            panic!("expected V4");
        }
    }

    #[test]
    fn test_reverse_dns_to_ipnet_two_label_ipv4() {
        // GIVEN
        let dns_name = "1.10.in-addr.arpa";
        let expected: Ipv4Net = "1.10.0.0/16".parse().unwrap();

        // WHEN
        let result = reverse_dns_to_ipnet(dns_name).expect("should parse");

        // THEN
        if let IpNet::V4(net) = result {
            assert_eq!(net.network(), expected.network());
            assert_eq!(net.prefix_len(), expected.prefix_len());
        } else {
            panic!("expected V4");
        }
    }

    #[test]
    fn test_reverse_dns_to_ipnet_three_label_ipv4() {
        // GIVEN
        let dns_name = "1.2.3.in-addr.arpa";
        let expected: Ipv4Net = "1.2.3.0/24".parse().unwrap();

        // WHEN
        let result = reverse_dns_to_ipnet(dns_name).expect("should parse");

        // THEN
        if let IpNet::V4(net) = result {
            assert_eq!(net.network(), expected.network());
            assert_eq!(net.prefix_len(), expected.prefix_len());
        } else {
            panic!("expected V4");
        }
    }

    #[test]
    fn test_reverse_dns_to_ipnet_single_label_ipv6() {
        // GIVEN
        let dns_name = "d.ip6.arpa";
        let expected: Ipv6Net = "d000::/4".parse().unwrap();

        // WHEN
        let result = reverse_dns_to_ipnet(dns_name).expect("should parse");

        // THEN
        if let IpNet::V6(net) = result {
            assert_eq!(net.network(), expected.network());
            assert_eq!(net.prefix_len(), expected.prefix_len());
        } else {
            panic!("expected V6");
        }
    }

    #[test]
    fn test_reverse_dns_to_ipnet_four_label_ipv6() {
        // GIVEN
        let dns_name = "d.c.b.a.ip6.arpa";
        let expected: Ipv6Net = "dcba::/16".parse().unwrap();

        // WHEN
        let result = reverse_dns_to_ipnet(dns_name).expect("should parse");

        // THEN
        if let IpNet::V6(net) = result {
            assert_eq!(net.network(), expected.network());
            assert_eq!(net.prefix_len(), expected.prefix_len());
        } else {
            panic!("expected V6");
        }
    }

    #[test]
    fn test_reverse_dns_to_ipnet_not_rdns() {
        let result = reverse_dns_to_ipnet("example.com");
        assert!(result.is_none());
    }
}
