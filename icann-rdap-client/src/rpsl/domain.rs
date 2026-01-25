use icann_rdap_common::prelude::{CommonFields, Domain, Nameserver, ObjectCommonFields};

use crate::rpsl::{ttl::push_ttl0, AttrName, RpslParams, ToRpsl};

use super::{
    push_entities, push_manditory_attribute, push_notices, push_obj_common,
    push_optional_attribute, push_public_ids, KeyRef,
};

impl ToRpsl for Domain {
    fn to_rpsl(&self, params: RpslParams) -> String {
        let mut rpsl = String::new();

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        // key
        let (key_name, key_value) = self.key_ref(params);
        rpsl = push_manditory_attribute(rpsl, key_name, &key_value);

        // name servers are embedded only for domains.
        rpsl.push_str(&nameservers(self.nameservers(), params));

        // push public ids
        rpsl = push_public_ids(rpsl, self.public_ids());

        // push variants
        for variant in self.variants() {
            for var_name in variant.variant_names() {
                rpsl = push_optional_attribute(rpsl, AttrName::Variant, var_name.ldh_name());
                rpsl = push_optional_attribute(rpsl, AttrName::Variant, var_name.unicode_name());
            }
        }

        //secure dns
        if let Some(sec_dns) = self.secure_dns() {
            rpsl = push_optional_attribute(
                rpsl,
                AttrName::MaxSigLife,
                sec_dns.max_sig_life().map(|m| m.to_string()).as_deref(),
            );
            rpsl = push_optional_attribute(
                rpsl,
                AttrName::DelegationSigned,
                sec_dns
                    .delegation_signed()
                    .map(|d| d.to_string())
                    .as_deref(),
            );
            rpsl = push_optional_attribute(
                rpsl,
                AttrName::ZoneSigned,
                sec_dns.zone_signed().map(|z| z.to_string()).as_deref(),
            );
            for ds in sec_dns.ds_data() {
                let str = format!(
                    "{} {} {} {}",
                    ds.key_tag().map(|u| u.to_string()).unwrap_or_default(),
                    ds.algorithm().map(|u| u.to_string()).unwrap_or_default(),
                    ds.digest_type().map(|u| u.to_string()).unwrap_or_default(),
                    ds.digest().map(|u| u.to_string()).unwrap_or_default(),
                );
                rpsl = push_optional_attribute(rpsl, AttrName::DsRdata, Some(&str));
            }
            for key in sec_dns.key_data() {
                let str = format!(
                    "{} {} {} {}",
                    key.flags().map(|u| u.to_string()).unwrap_or_default(),
                    key.protocol().map(|u| u.to_string()).unwrap_or_default(),
                    key.algorithm().map(|u| u.to_string()).unwrap_or_default(),
                    key.public_key().map(|u| u.to_string()).unwrap_or_default(),
                );
                rpsl = push_optional_attribute(rpsl, AttrName::KeyData, Some(&str));
            }
        }

        // push ttl0
        if let Some(ttl) = &self.ttl0_data {
            rpsl = push_ttl0(rpsl, ttl);
        }

        // push things common to object classes
        rpsl = push_obj_common(rpsl, params, self);

        //end
        rpsl.push('\n');

        // output entities
        rpsl = push_entities(rpsl, self.entities(), params);

        // output network
        if let Some(net) = self.network() {
            rpsl.push_str(&net.to_rpsl(params));
        }

        // return
        rpsl
    }
}

impl KeyRef for Domain {
    fn key_ref(&self, _params: RpslParams) -> (AttrName, String) {
        let value = self
            .ldh_name()
            .or_else(|| self.unicode_name())
            .unwrap_or("DOMAIN NAME UNAVAILABLE")
            .to_string();
        let name = AttrName::Domain;
        (name, value)
    }
}

fn nameservers(nameservers: &[Nameserver], params: RpslParams) -> String {
    let mut rpsl = String::new();
    for ns in nameservers {
        let (_name, value) = ns.key_ref(params);
        if let Some(ip) = ns.ip_addresses() {
            for v4 in ip.v4s() {
                rpsl = push_manditory_attribute(
                    rpsl,
                    AttrName::Nserver,
                    &format!("{value} ({v4}/32)"),
                );
            }
            for v6 in ip.v6s() {
                rpsl = push_manditory_attribute(
                    rpsl,
                    AttrName::Nserver,
                    &format!("{value} ({v6}/128)"),
                );
            }
        } else {
            rpsl = push_manditory_attribute(rpsl, AttrName::Nserver, &value);
        }
    }
    rpsl
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use goldenfile::Mint;
    use icann_rdap_common::{
        httpdata::HttpData,
        prelude::{Domain, Event},
    };

    use crate::rpsl::{RpslParams, ToRpsl};

    static MINT_PATH: &str = "src/test_files/rpsl/domain";

    #[test]
    fn test_rpsl_domain_with_ldh_and_handle_and_events() {
        // GIVEN domain
        let domain = Domain::builder()
            .ldh_name("foo.example.com")
            .handle("FOO-COM")
            .event(
                Event::builder()
                    .event_action("last changed")
                    .event_date("1990-12-31T23:59:59Z")
                    .build(),
            )
            .build();

        // WHEN represented as rpsl
        let http_data = HttpData::example().build();
        let params = RpslParams {
            http_data: &http_data,
        };
        let actual = domain.to_rpsl(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint
            .new_goldenfile("with_ldh_and_handle_and_events.txt")
            .unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }
}
