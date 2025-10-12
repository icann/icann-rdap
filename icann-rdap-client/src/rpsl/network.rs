use icann_rdap_common::prelude::{CommonFields, Network, ObjectCommonFields};

use crate::rpsl::{RpslParams, ToRpsl};

use super::{
    push_entities, push_manditory_attribute, push_notices, push_obj_common,
    push_optional_attribute, AttrName, KeyRef,
};

impl ToRpsl for Network {
    fn to_rpsl(&self, params: RpslParams) -> String {
        let mut rpsl = String::new();

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        // key
        let (key_name, key_value) = self.key_ref(params);
        rpsl = push_manditory_attribute(rpsl, key_name, &key_value);

        // type
        rpsl = push_optional_attribute(rpsl, AttrName::Type, self.network_type());

        // name
        rpsl = push_optional_attribute(rpsl, AttrName::NetName, self.name());

        // parent handle
        rpsl = push_optional_attribute(rpsl, AttrName::ParentHandle, self.parent_handle());

        // push things common to object classes
        rpsl = push_obj_common(rpsl, params, self);

        //end
        rpsl.push('\n');

        // output entities
        rpsl = push_entities(rpsl, self.entities(), params);

        //return
        rpsl
    }
}

impl KeyRef for Network {
    fn key_ref(&self, _params: RpslParams) -> (super::AttrName, String) {
        let mut name = AttrName::Inetnum;
        if let Some(ip_version) = self.ip_version() {
            if ip_version.eq_ignore_ascii_case("v6") {
                name = AttrName::Inet6num;
            }
        }
        let value = format!(
            "{} - {}",
            self.start_address().unwrap_or("NO START ADDR"),
            self.end_address().unwrap_or("NO END ADDR")
        );
        (name, value)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use goldenfile::Mint;
    use icann_rdap_common::{httpdata::HttpData, prelude::Network};

    use crate::rpsl::{RpslParams, ToRpsl};

    static MINT_PATH: &str = "src/test_files/rpsl/network";

    #[test]
    fn test_rpsl_network_with_cidr_and_handle() {
        // GIVEN network
        let network = Network::builder()
            .cidr("10.0.0.0/24")
            .handle("NET10-RIR")
            .build()
            .unwrap();

        // WHEN represented as rpsl
        let http_data = HttpData::example().build();
        let params = RpslParams {
            http_data: &http_data,
        };
        let actual = network.to_rpsl(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_cidr_and_handle.txt").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }
}
