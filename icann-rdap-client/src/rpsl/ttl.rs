//! TTL0 extension display for RPSL.

use icann_rdap_common::prelude::ttl::Ttl0Data;

use crate::rpsl::{push_optional_attribute, push_remarks, AttrName};

pub fn push_ttl0(mut rpsl: String, ttl0_data: &Ttl0Data) -> String {
    // A record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data.a_value().map(|u| format!("a {u}")).as_deref(),
    );

    // AAAA record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data
            .aaaa_value()
            .map(|u| format!("aaaa {u}"))
            .as_deref(),
    );

    // NS record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data.ns_value().map(|u| format!("ns {u}")).as_deref(),
    );

    // DS record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data.ds_value().map(|u| format!("ds {u}")).as_deref(),
    );

    // MX record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data.mx_value().map(|u| format!("mx {u}")).as_deref(),
    );

    // PTR record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data.ptr_value().map(|u| format!("ptr {u}")).as_deref(),
    );

    // CNAME record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data
            .cname_value()
            .map(|u| format!("cname {u}"))
            .as_deref(),
    );

    // CDS record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data.cds_value().map(|u| format!("cds {u}")).as_deref(),
    );

    // CSYNC record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data
            .csync_value()
            .map(|u| format!("csync {u}"))
            .as_deref(),
    );

    // CAA record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data.caa_value().map(|u| format!("caa {u}")).as_deref(),
    );

    // DNSKEY record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data
            .dnskey_value()
            .map(|u| format!("dnskey {u}"))
            .as_deref(),
    );

    // CERT record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data
            .cert_value()
            .map(|u| format!("cert {u}"))
            .as_deref(),
    );

    // CDNSKEY record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data
            .cdnskey_value()
            .map(|u| format!("cdnskey {u}"))
            .as_deref(),
    );

    // HTTPS record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data
            .https_value()
            .map(|u| format!("https {u}"))
            .as_deref(),
    );

    // KEY record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data.key_value().map(|u| format!("key {u}")).as_deref(),
    );

    // NAPTR record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data
            .naptr_value()
            .map(|u| format!("naptr {u}"))
            .as_deref(),
    );

    // SRV record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data.srv_value().map(|u| format!("srv {u}")).as_deref(),
    );

    // SVCB record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data
            .svcb_value()
            .map(|u| format!("svcb {u}"))
            .as_deref(),
    );

    // TLSA record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data
            .tlsa_value()
            .map(|u| format!("tlsa {u}"))
            .as_deref(),
    );

    // TXT record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data.txt_value().map(|u| format!("txt {u}")).as_deref(),
    );

    // URI record
    rpsl = push_optional_attribute(
        rpsl,
        AttrName::Ttl,
        ttl0_data.uri_value().map(|u| format!("uri {u}")).as_deref(),
    );

    rpsl = push_remarks(rpsl, ttl0_data.remarks());

    rpsl
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use goldenfile::Mint;
    use icann_rdap_common::{httpdata::HttpData, prelude::Nameserver};

    use crate::rpsl::{RpslParams, ToRpsl};

    static MINT_PATH: &str = "src/test_files/rpsl/ttl";

    #[test]
    fn test_push_ttl0_with_records() {
        // GIVEN
        let ttl = Ttl0Data::builder()
            .a_value(300)
            .mx_value(500)
            .txt_value(2000)
            .build();

        // WHEN
        let rpsl = push_ttl0(String::new(), &ttl);

        // THEN
        assert!(rpsl.contains("dns-ttl"));
        assert!(rpsl.contains("a 300"));
        assert!(rpsl.contains("mx 500"));
        assert!(rpsl.contains("txt 2000"));
    }

    #[test]
    fn test_rpsl_nameserver_with_ttl0() {
        // GIVEN nameserver
        let ttl0 = Ttl0Data::builder()
            .a_value(300)
            .mx_value(500)
            .txt_value(2000)
            .build();
        let ns = Nameserver::builder()
            .ldh_name("foo.example.com")
            .ttl0_data(ttl0)
            .build()
            .unwrap();

        // WHEN represented as rpsl
        let http_data = HttpData::example().build();
        let params = RpslParams {
            http_data: &http_data,
        };
        let actual = ns.to_rpsl(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_ttl0.txt").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }
}
