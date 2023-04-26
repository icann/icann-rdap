use std::any::TypeId;

use icann_rdap_common::response::domain::{Domain, Variant};

use crate::check::{CheckParams, GetChecks};

use super::{
    checks_ul, make_title_case_list, to_header, to_right_bold, MdParams, SimpleTable, ToMd,
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

        let identifiers = SimpleTable::new("Indentifiers")
            .and_row(&"LDH Name", &self.ldh_name)
            .and_row(&"Unicode Name", &self.unicode_name)
            .and_row(&"Handle", &self.object_common.handle);
        md.push_str(&identifiers.to_md(params));

        if let Some(variants) = &self.variants {
            md.push_str(&do_variants(variants, params))
        }

        let checks = self.get_checks(CheckParams::from_md(params, typeid));
        md.push_str(&checks_ul(&checks, params));

        // Common Object
        md.push_str(&self.object_common.to_md(params.from_parent(typeid)));
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
