use {
    super::{GtldParams, ToGtldWhois},
    icann_rdap_common::response::Network,
    std::any::TypeId,
};

impl ToGtldWhois for Network {
    fn to_gtld_whois(&self, params: &mut GtldParams) -> String {
        let _typeid = TypeId::of::<Self>();
        let mut gtld = String::new();
        gtld.push_str(&self.common.to_gtld_whois(params));
        let header_text = if let (Some(start_address), Some(end_address)) =
            (&self.start_address, &self.end_address)
        {
            format!("IP Network: {}-{},\n", start_address, end_address)
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
