use std::any::TypeId;

use icann_rdap_common::response::domain::{Domain, Variant};

use crate::check::{CheckParams, GetChecks, GetSubChecks};

use super::{
    make_title_case_list,
    table::{MultiPartTable, ToMpTable},
    to_header, to_right_bold,
    types::checks_to_table,
    MdParams, ToMd,
};

impl ToMd for Domain {
    fn to_md(&self, params: MdParams) -> String {
        let typeid = TypeId::of::<Domain>();
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent(typeid)));

        // header
        let header_text = if let Some(unicode_name) = &self.unicode_name {
            format!("Domain {unicode_name}")
        } else if let Some(ldh_name) = &self.ldh_name {
            format!("Domain {ldh_name}")
        } else if let Some(handle) = &self.object_common.handle {
            format!("Domain {handle}")
        } else {
            "Domain".to_string()
        };
        md.push_str(&to_header(
            &header_text,
            params.heading_level,
            params.options,
        ));

        // multipart data
        let mut table = MultiPartTable::new();

        // identifiers
        table = table
            .header(&"Identifiers")
            .and_data(&"LDH Name", &self.ldh_name)
            .and_data(&"Unicode Name", &self.unicode_name)
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

        // variants require a custom table
        if let Some(variants) = &self.variants {
            md.push_str(&do_variants(variants, params))
        }

        // remarks
        md.push_str(&self.object_common.remarks.to_md(params.from_parent(typeid)));

        // entities
        md.push_str(
            &self
                .object_common
                .entities
                .to_md(params.from_parent(typeid)),
        );

        // nameservers
        if let Some(nameservers) = &self.nameservers {
            nameservers
                .iter()
                .for_each(|ns| md.push_str(&ns.to_md(params.next_level())));
        }
        md.push('\n');
        md
    }
}

fn do_variants(variants: &[Variant], params: MdParams) -> String {
    let mut md = String::new();
    md.push_str(&format!(
        "|:-:|\n|{}|\n",
        to_right_bold("Domain Variants", 8, params.options)
    ));
    md.push_str("|:-:|:-:|:-:|\n|Relations|IDN Table|Variant Names|\n");
    variants.iter().for_each(|v| {
        md.push_str(&format!(
            "|{}|{}|{}|",
            make_title_case_list(v.relation.as_deref().unwrap_or_default()),
            v.idn_table.as_deref().unwrap_or_default(),
            v.variant_names
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|dv| format!(
                    "ldh: '{}' utf:'{}'",
                    dv.ldh_name.as_deref().unwrap_or_default(),
                    dv.unicode_name.as_deref().unwrap_or_default()
                ))
                .collect::<Vec<String>>()
                .join(", "),
        ))
    });
    md.push_str("|\n");
    md
}
