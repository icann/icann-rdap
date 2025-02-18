use super::{GtldParams, ToGtldWhois};
use icann_rdap_common::response::Network;
use std::any::TypeId;

impl ToGtldWhois for Network {
    fn to_gtld_whois(&self, params: &mut GtldParams) -> String {
        let _typeid = TypeId::of::<Network>();
        let mut gtld = String::new();
        gtld.push_str(&self.common.to_gtld_whois(params));
        let header_text = if self.start_address.is_some() && self.end_address.is_some() {
            format!(
                "IP Network: {}-{}\n",
                &self.start_address.as_ref().unwrap(),
                &self.end_address.as_ref().unwrap()
            )
        } else if let Some(start_address) = &self.start_address {
            format!("IP Network: {start_address}\n")
        } else if let Some(handle) = &self.object_common.handle {
            format!("IP Network: {handle}\n")
        } else if let Some(name) = &self.name {
            format!("IP Network: {name}\n")
        } else {
            "IP Network:\n".to_string()
        };
        gtld.push_str(&header_text);
        gtld
    }
}
