use std::any::TypeId;

use icann_rdap_common::response::nameserver::Nameserver;

use crate::check::{CheckParams, GetChecks, GetSubChecks};

use super::{
    string::StringUtil,
    table::{MultiPartTable, ToMpTable},
    types::checks_to_table,
    MdParams, ToMd,
};

impl ToMd for Nameserver {
    fn to_md(&self, params: MdParams) -> String {
        let typeid = TypeId::of::<Nameserver>();
        let mut md = String::new();

        // other common stuff
        md.push_str(&self.common.to_md(params.from_parent(typeid)));

        // header
        let header_text = if let Some(unicode_name) = &self.unicode_name {
            format!("Nameserver {unicode_name}")
        } else if let Some(ldh_name) = &self.ldh_name {
            format!("Nameserver {ldh_name}")
        } else if let Some(handle) = &self.object_common.handle {
            format!("Nameserver {handle}")
        } else {
            "Domain".to_string()
        };
        md.push_str(&header_text.to_header(params.heading_level, params.options));

        // multipart data
        let mut table = MultiPartTable::new();

        // identifiers
        table = table
            .header(&"Identifiers")
            .and_data(&"LDH Name", &self.ldh_name)
            .and_data(&"Unicode Name", &self.unicode_name)
            .and_data(&"Handle", &self.object_common.handle);
        if let Some(addresses) = &self.ip_addresses {
            if let Some(v4) = &addresses.v4 {
                table = table.data_ul(&"Ipv4", v4.iter().collect());
            }
            if let Some(v6) = &addresses.v6 {
                table = table.data_ul(&"Ipv6", v6.iter().collect());
            }
        }

        // common object stuff
        table = self.object_common.add_to_mptable(table, params);

        // checks
        let check_params = CheckParams::from_md(params, typeid);
        let mut checks = self.object_common.get_sub_checks(check_params);
        checks.push(self.get_checks(check_params));
        table = checks_to_table(checks, table, params);

        // render table
        md.push_str(&table.to_md(params));

        // remarks
        md.push_str(&self.object_common.remarks.to_md(params.from_parent(typeid)));

        // entities
        md.push_str(
            &self
                .object_common
                .entities
                .to_md(params.from_parent(typeid)),
        );
        md.push('\n');
        md
    }
}
