use icann_rdap_common::response::redacted::Redacted;

use super::{string::StringUtil, table::MultiPartTable, MdOptions, MdParams, ToMd};

impl ToMd for &[Redacted] {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();

        // header
        let header_text = "Redacted".to_string();
        md.push_str(&header_text.to_header(params.heading_level, params.options));

        // multipart data
        let mut table = MultiPartTable::new();
        table = table.header_ref(&"Fields");

        for (index, redacted) in self.iter().enumerate() {
            let options = MdOptions {
                text_style_char: '*',
                ..Default::default()
            };

            // make the name bold
            let name = "Redaction";
            let b_name = name.to_bold(&options);
            // build the table
            table = table.and_data_ref(&b_name, &Some((index + 1).to_string()));

            // Get the data itself
            let name_data = redacted
                .name
                .description
                .clone()
                .or(redacted.name.type_field.clone());
            let method_data = redacted.method.as_ref().map(|m| m.to_string());
            let reason_data = redacted.reason.as_ref().map(|m| m.to_string());

            // Special case the 'column' fields
            table = table
                .and_data_ref(&"name".to_title_case(), &name_data)
                .and_data_ref(&"prePath".to_title_case(), &redacted.pre_path)
                .and_data_ref(&"postPath".to_title_case(), &redacted.post_path)
                .and_data_ref(
                    &"replacementPath".to_title_case(),
                    &redacted.replacement_path,
                )
                .and_data_ref(&"pathLang".to_title_case(), &redacted.path_lang)
                .and_data_ref(&"method".to_title_case(), &method_data)
                .and_data_ref(&"reason".to_title_case(), &reason_data);

            // we don't have these right now but if we put them in later we will need them
            // let check_params = CheckParams::from_md(params, typeid);
            // let mut checks = redacted.object_common.get_sub_checks(check_params);
            // checks.push(redacted.get_checks(check_params));
            // table = checks_to_table(checks, table, params);
        }

        // render table
        md.push_str(&table.to_md(params));
        md.push('\n');
        md
    }
}
