use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
}
