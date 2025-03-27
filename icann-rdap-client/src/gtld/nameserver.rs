use {
    super::{GtldParams, ToGtldWhois},
    icann_rdap_common::response::Nameserver,
};

impl ToGtldWhois for Nameserver {
    fn to_gtld_whois(&self, _params: &mut GtldParams) -> String {
        let mut gtld = String::new();
        // header
        let header_text = if let Some(unicode_name) = &self.unicode_name {
            format!("Name Server: {unicode_name}\n")
        } else if let Some(ldh_name) = &self.ldh_name {
            format!("Name Server: {ldh_name}\n")
        } else if let Some(handle) = &self.object_common.handle {
            format!("Name Server: {handle}\n")
        } else {
            "Name Server: \n".to_string()
        };
        gtld.push_str(&header_text);
        gtld
    }
}
