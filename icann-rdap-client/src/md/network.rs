use std::any::TypeId;

use icann_rdap_common::{
    check::{CheckParams, GetChecks, GetSubChecks},
    response::network::Network,
};

use super::{
    string::StringUtil,
    table::{MultiPartTable, ToMpTable},
    types::checks_to_table,
    FromMd, MdParams, ToMd, HR,
};

impl ToMd for Network {
    fn to_md(&self, params: MdParams) -> String {
        let typeid = TypeId::of::<Network>();
        let mut md = String::new();
        md.push_str(&self.common.to_md(params));
        let header_text = if self.start_address.is_some() && self.end_address.is_some() {
            format!(
                "IP Network {}-{}",
                &self.start_address.as_ref().unwrap(),
                &self.end_address.as_ref().unwrap()
            )
        } else if let Some(start_address) = &self.start_address {
            format!("IP Network {start_address}")
        } else if let Some(handle) = &self.object_common.handle {
            format!("IP Network {handle}")
        } else if let Some(name) = &self.name {
            format!("IP Network {name}")
        } else {
            "IP Network".to_string()
        };
        md.push_str(&header_text.to_header(params.heading_level, params.options));

        // multipart data
        let mut table = MultiPartTable::new();

        // identifiers
        table = table
            .header_ref(&"Identifiers")
            .and_data_ref(&"Start Address", &self.start_address)
            .and_data_ref(&"End Address", &self.end_address)
            .and_data_ref(&"IP Version", &self.ip_version)
            .and_data_ul(&"CIDR", self.cidr0_cidrs.clone())
            .and_data_ref(&"Handle", &self.object_common.handle)
            .and_data_ref(&"Parent Handle", &self.parent_handle)
            .and_data_ref(&"Network Type", &self.network_type)
            .and_data_ref(&"Network Name", &self.name)
            .and_data_ref(&"Country", &self.country);

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
        md.push('\n');
        md
    }
}
