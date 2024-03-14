use std::any::TypeId;

use icann_rdap_common::response::nameserver::Nameserver;

use icann_rdap_common::check::{CheckParams, GetChecks, GetSubChecks};

use super::FromMd;
use super::{
    string::StringUtil,
    table::{MultiPartTable, ToMpTable},
    types::checks_to_table,
    MdParams, ToMd, HR,
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
            .header_ref(&"Identifiers")
            .and_data_ref(&"LDH Name", &self.ldh_name)
            .and_data_ref(&"Unicode Name", &self.unicode_name)
            .and_data_ref(&"Handle", &self.object_common.handle);
        if let Some(addresses) = &self.ip_addresses {
            if let Some(v4) = &addresses.v4 {
                table = table.data_ul_ref(&"Ipv4", v4.iter().collect());
            }
            if let Some(v6) = &addresses.v6 {
                table = table.data_ul_ref(&"Ipv6", v6.iter().collect());
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

        // only other object classes from here
        md.push_str(HR);

        // entities
        md.push_str(
            &self
                .object_common
                .entities
                .to_md(params.from_parent(typeid)),
        );

        // redacted
        if let Some(redacted) = &self.object_common.redacted {
            md.push_str(&redacted.as_slice().to_md(params.from_parent(typeid)));
        }

        md.push('\n');
        md
    }
}
