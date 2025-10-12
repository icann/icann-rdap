use icann_rdap_common::prelude::{CommonFields, Nameserver, ObjectCommonFields};

use crate::rpsl::{RpslParams, ToRpsl};

use super::{
    push_entities, push_manditory_attribute, push_notices, push_obj_common, AttrName, KeyRef,
};

impl ToRpsl for Nameserver {
    fn to_rpsl(&self, params: RpslParams) -> String {
        let mut rpsl = String::new();

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        // key
        let (key_name, key_value) = self.key_ref(params);
        rpsl = push_manditory_attribute(rpsl, key_name, &key_value);

        // ip addresses
        if let Some(ip) = self.ip_addresses() {
            for v4 in ip.v4s() {
                rpsl = push_manditory_attribute(rpsl, AttrName::Inetnum, &format!("{v4}/32"));
            }
            for v6 in ip.v6s() {
                rpsl = push_manditory_attribute(rpsl, AttrName::Inet6num, &format!("{v6}/128"));
            }
        }

        // push things common to object classes
        rpsl = push_obj_common(rpsl, params, self);

        //end
        rpsl.push('\n');

        // output entities
        rpsl = push_entities(rpsl, self.entities(), params);

        // return
        rpsl
    }
}

impl KeyRef for Nameserver {
    fn key_ref(&self, _params: RpslParams) -> (AttrName, String) {
        let value = self
            .ldh_name()
            .or_else(|| self.unicode_name())
            .unwrap_or("NAMESERVER NAME UNAVAILABLE")
            .to_string();
        let name = AttrName::Nserver;
        (name, value)
    }
}
#[cfg(test)]
mod tests {
    use std::io::Write;

    use goldenfile::Mint;
    use icann_rdap_common::{httpdata::HttpData, prelude::Nameserver};

    use crate::rpsl::{RpslParams, ToRpsl};

    static MINT_PATH: &str = "src/test_files/rpsl/nameserver";

    #[test]
    fn test_rpsl_nameserver_with_ldh_and_handle() {
        // GIVEN nameserver
        let ns = Nameserver::builder()
            .ldh_name("foo.example.com")
            .handle("123-ABC")
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
        let mut expected = mint.new_goldenfile("with_ldh_and_handle.txt").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }
}
