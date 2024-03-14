use std::any::TypeId;

use icann_rdap_common::{
    check::{CheckParams, GetChecks, GetSubChecks},
    response::autnum::Autnum,
};

use super::{
    string::StringUtil,
    table::{MultiPartTable, ToMpTable},
    types::checks_to_table,
    FromMd, MdParams, ToMd, HR,
};

impl ToMd for Autnum {
    fn to_md(&self, params: MdParams) -> String {
        let typeid = TypeId::of::<Autnum>();
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent(typeid)));
        let header_text = if self.start_autnum.is_some() && self.end_autnum.is_some() {
            format!(
                "Autonomous Systems {}-{}",
                &self.start_autnum.unwrap(),
                &self.end_autnum.unwrap()
            )
        } else if let Some(start_autnum) = &self.start_autnum {
            format!("Autonomous System {start_autnum}")
        } else if let Some(handle) = &self.object_common.handle {
            format!("Autonomous System {handle}")
        } else if let Some(name) = &self.name {
            format!("Autonomous System {name}")
        } else {
            "Autonomous System".to_string()
        };
        md.push_str(&header_text.to_header(params.heading_level, params.options));

        // multipart data
        let mut table = MultiPartTable::new();

        // identifiers
        table = table
            .header_ref(&"Identifiers")
            .and_data_ref(
                &"Start AS Number",
                &self.start_autnum.map(|n| n.to_string()),
            )
            .and_data_ref(&"End AS Number", &self.end_autnum.map(|n| n.to_string()))
            .and_data_ref(&"Handle", &self.object_common.handle)
            .and_data_ref(&"Autnum Type", &self.autnum_type)
            .and_data_ref(&"Autnum Name", &self.name)
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

        // redacted
        if let Some(redacted) = &self.object_common.redacted {
            md.push_str(&redacted.as_slice().to_md(params.from_parent(typeid)));
        }

        md.push('\n');
        md
    }
}
