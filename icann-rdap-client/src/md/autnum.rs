use icann_rdap_common::{prelude::ObjectCommonFields, response::Autnum};

use super::MdHeaderText;
use super::{
    string::StringUtil,
    table::{MultiPartTable, ToMpTable},
    MdParams, MdUtil, ToMd,
};

impl ToMd for Autnum {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent()));

        let header_text = self.get_header_text();
        md.push_str(
            &header_text
                .to_string()
                .to_header(params.heading_level, params.options),
        );

        // multipart data
        let mut table = if params.highlight_simple_redactions {
            MultiPartTable::new_with_value_hightlights_from_remarks(self.remarks())
        } else {
            MultiPartTable::new()
        };

        // summary
        table = table.summary(header_text);

        // identifiers
        table = table
            .header_ref(&"Identifiers")
            .and_nv_ref_maybe(
                &"Start AS Number",
                &self.start_autnum.as_ref().map(|n| n.to_string()),
            )
            .and_nv_ref_maybe(
                &"End AS Number",
                &self.end_autnum.as_ref().map(|n| n.to_string()),
            )
            .and_nv_ref_maybe(&"Handle", &self.object_common.handle)
            .and_nv_ref_maybe(&"Autnum Type", &self.autnum_type)
            .and_nv_ref_maybe(&"Autnum Name", &self.name)
            .and_nv_ref_maybe(&"Country", &self.country);

        // common object stuff
        table = self.object_common.add_to_mptable(table, params);

        // remarks
        table = self.remarks().add_to_mptable(table, params);

        // render table
        md.push_str(&table.to_md(params));

        // entities
        md.push_str(&self.object_common.entities.to_md(params.from_parent()));

        // redacted
        if params.show_rfc9537_redactions {
            if let Some(redacted) = &self.object_common.redacted {
                md.push_str(&redacted.as_slice().to_md(params.from_parent()));
            }
        }

        md.push('\n');
        md
    }
}

impl MdUtil for Autnum {
    fn get_header_text(&self) -> MdHeaderText {
        let header_text = if self.start_autnum.is_some() && self.end_autnum.is_some() {
            format!(
                "Autonomous Systems {} - {}",
                &self.start_autnum.as_ref().unwrap().replace_md_chars(),
                &self.end_autnum.as_ref().unwrap().replace_md_chars()
            )
        } else if let Some(start_autnum) = &self.start_autnum {
            format!("Autonomous System {}", start_autnum.replace_md_chars())
        } else if let Some(handle) = &self.object_common.handle {
            format!("Autonomous System {}", handle.replace_md_chars())
        } else if let Some(name) = &self.name {
            format!("Autonomous System {}", name.replace_md_chars())
        } else {
            "Autonomous System".to_string()
        };
        let mut header_text = MdHeaderText::builder().header_text(header_text);
        if let Some(entities) = &self.object_common.entities {
            for entity in entities {
                header_text = header_text.children_entry(entity.get_header_text());
            }
        };
        header_text.build()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use goldenfile::Mint;
    use icann_rdap_common::{
        httpdata::HttpData,
        prelude::{Autnum, Remark, ToResponse},
    };

    use crate::{
        md::{MdOptions, MdParams, ToMd},
        rdap::RequestData,
    };

    static MINT_PATH: &str = "src/test_files/md/autnum";

    #[test]
    fn test_md_autnum_with_handle_and_remarks() {
        // GIVEN autnum
        let autnum = Autnum::builder()
            .autnum_range(701..703)
            .handle("123-ABC")
            .remark(
                Remark::builder()
                    .title("AS Numbers Are Integers")
                    .description_entry("Autonomous System numbers are integers.")
                    .build(),
            )
            .remark(
                Remark::builder()
                    .title("AS Numbers Are Not Floats")
                    .nr_type("generated")
                    .description_entry("Autonomous System numbers are not floating point numbers.")
                    .description_entry("They are integers.")
                    .description_entry("This line has escaped markdown chars. * foo | bar # baz")
                    .build(),
            )
            .build();
        let response = autnum.clone().to_response();

        // WHEN represented as markdown
        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
            source_host: "example",
            source_type: crate::rdap::SourceType::DomainRegistry,
        };
        let params = MdParams {
            heading_level: 1,
            root: &response,
            http_data: &http_data,
            options: &MdOptions::default(),
            req_data: &req_data,
            show_rfc9537_redactions: false,
            highlight_simple_redactions: false,
        };
        let actual = autnum.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_handle_and_remarks.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }
}
