use std::any::TypeId;

use icann_rdap_common::response::entity::Entity;

use crate::check::{CheckParams, GetChecks, GetSubChecks};

use super::{
    string::StringUtil,
    table::{MultiPartTable, ToMpTable},
    types::checks_to_table,
    MdParams, ToMd, HR,
};

impl ToMd for Entity {
    fn to_md(&self, params: MdParams) -> String {
        let typeid = TypeId::of::<Entity>();
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent(typeid)));

        // header
        let header_text = if let Some(roles) = &self.roles {
            roles.first().unwrap_or(&String::default()).to_title_case()
        } else {
            "Entity".to_string()
        };
        md.push_str(&header_text.to_header(params.heading_level, params.options));

        // multipart data
        let mut table = MultiPartTable::new();

        // identifiers
        table = table
            .header(&"Identifiers")
            .and_data(&"Handle", &self.object_common.handle);

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

impl ToMd for Option<Vec<Entity>> {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        if let Some(entities) = &self {
            entities
                .iter()
                .for_each(|entity| md.push_str(&entity.to_md(params.next_level())));
        }
        md
    }
}
