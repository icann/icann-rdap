use icann_rdap_common::{prelude::ObjectCommonFields, response::Network};

use super::{
    string::StringUtil,
    table::{MultiPartTable, ToMpTable},
    MdHeaderText, MdParams, MdUtil, ToMd,
};

impl ToMd for Network {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params));

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
            .and_nv_ref_maybe(&"Start Address", &self.start_address)
            .and_nv_ref_maybe(&"End Address", &self.end_address)
            .and_nv_ref_maybe(&"IP Version", &self.ip_version)
            .and_nv_ul(&"CIDR", self.cidr0_cidrs.clone())
            .and_nv_ref_maybe(&"Handle", &self.object_common.handle)
            .and_nv_ref_maybe(&"Parent Handle", &self.parent_handle)
            .and_nv_ref_maybe(&"Network Type", &self.network_type)
            .and_nv_ref_maybe(&"Network Name", &self.name)
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

impl MdUtil for Network {
    fn get_header_text(&self) -> MdHeaderText {
        let header_text = if self.start_address.is_some() && self.end_address.is_some() {
            format!(
                "IP Network {} - {}",
                &self.start_address.as_ref().unwrap().replace_md_chars(),
                &self.end_address.as_ref().unwrap().replace_md_chars()
            )
        } else if let Some(start_address) = &self.start_address {
            format!("IP Network {}", start_address.replace_md_chars())
        } else if let Some(handle) = &self.object_common.handle {
            format!("IP Network {}", handle.replace_md_chars())
        } else if let Some(name) = &self.name {
            format!("IP Network {}", name.replace_md_chars())
        } else {
            "IP Network".to_string()
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
        prelude::{
            redacted::{Method, Name, Redacted},
            Network, Remark, ToResponse,
        },
    };

    use crate::{
        md::{MdOptions, MdParams, ToMd},
        rdap::RequestData,
    };

    static MINT_PATH: &str = "src/test_files/md/network";

    #[test]
    fn test_md_network_with_handle_and_remarks() {
        // GIVEN autnum
        let net = Network::builder()
            .cidr("199.1.0.0/16")
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
                    .build(),
            )
            .build()
            .unwrap();
        let response = net.clone().to_response();

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
        let actual = net.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_handle_and_remarks.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_network_with_handle_and_redactions() {
        // GIVEN network
        let redactions = vec![
            Redacted::builder()
                .name(Name::builder().type_field("Tech Name").build())
                .method(Method::Removal)
                .build(),
            Redacted::builder()
                .name(Name::builder().type_field("Tech Email").build())
                .method(Method::Removal)
                .build(),
        ];
        let net = Network::builder()
            .handle("123-ABC")
            .cidr("199.1.0.0/16")
            .redacted(redactions)
            .build()
            .unwrap();
        let response = net.clone().to_response();

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
            show_rfc9537_redactions: true,
            highlight_simple_redactions: false,
        };
        let actual = net.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint
            .new_goldenfile("with_handle_and_redactions.md")
            .unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_network_with_handle_and_no_shwo_redactions() {
        // GIVEN network
        let redactions = vec![
            Redacted::builder()
                .name(Name::builder().type_field("Tech Name").build())
                .method(Method::Removal)
                .build(),
            Redacted::builder()
                .name(Name::builder().type_field("Tech Email").build())
                .method(Method::Removal)
                .build(),
        ];
        let net = Network::builder()
            .handle("123-ABC")
            .cidr("199.1.0.0/16")
            .redacted(redactions)
            .build()
            .unwrap();
        let response = net.clone().to_response();

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
        let actual = net.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint
            .new_goldenfile("with_handle_and_no_show_redactions.md")
            .unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }
}
