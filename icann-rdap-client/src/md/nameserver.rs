use std::any::TypeId;

use icann_rdap_common::prelude::ObjectCommonFields;
use icann_rdap_common::response::Nameserver;

use icann_rdap_common::check::{CheckParams, GetChecks, GetSubChecks};

use super::{
    string::StringUtil,
    table::{MultiPartTable, ToMpTable},
    types::checks_to_table,
    FromMd, MdHeaderText, MdParams, MdUtil, ToMd,
};

impl ToMd for Nameserver {
    fn to_md(&self, params: MdParams) -> String {
        let typeid = TypeId::of::<Self>();
        let mut md = String::new();

        // other common stuff
        md.push_str(&self.common.to_md(params.from_parent(typeid)));

        // header
        let header_text = self.get_header_text();
        md.push_str(
            &header_text
                .to_string()
                .to_header(params.heading_level, params.options),
        );

        // multipart data
        let mut table = MultiPartTable::new();

        // summary
        table = table.summary(header_text);

        // identifiers
        //
        // due to the nature of nameservers, we are guaranteed to have at least one of
        // ldhName or unicodeName.
        table = table
            .header_ref(&"Identifiers")
            .and_nv_ref_maybe(&"LDH Name", &self.ldh_name)
            .and_nv_ref_maybe(&"Unicode Name", &self.unicode_name)
            .and_nv_ref_maybe(&"Handle", &self.object_common.handle);
        if let Some(addresses) = &self.ip_addresses {
            if let Some(v4) = &addresses.v4 {
                table = table.nv_ul_ref(&"Ipv4", v4.vec().iter().collect());
            }
            if let Some(v6) = &addresses.v6 {
                table = table.nv_ul_ref(&"Ipv6", v6.vec().iter().collect());
            }
        }

        // common object stuff
        table = self.object_common.add_to_mptable(table, params);

        // remarks
        table = self.remarks().add_to_mptable(table, params);

        // checks
        let check_params = CheckParams::from_md(params, typeid);
        let mut checks = self.object_common.get_sub_checks(check_params);
        checks.push(self.get_checks(check_params));
        table = checks_to_table(checks, table, params);

        // render table
        md.push_str(&table.to_md(params));

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

impl MdUtil for Nameserver {
    fn get_header_text(&self) -> MdHeaderText {
        let header_text = if let Some(unicode_name) = &self.unicode_name {
            format!("Nameserver {}", unicode_name.replace_md_chars())
        } else if let Some(ldh_name) = &self.ldh_name {
            format!("Nameserver {}", ldh_name.replace_md_chars())
        } else if let Some(handle) = &self.object_common.handle {
            format!("Nameserver {}", handle.replace_md_chars())
        } else {
            "Domain".to_string()
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
    use std::{any::TypeId, io::Write};

    use goldenfile::Mint;
    use icann_rdap_common::{
        httpdata::HttpData,
        prelude::{Nameserver, ToResponse},
    };

    use crate::{
        md::{MdOptions, MdParams, ToMd},
        rdap::RequestData,
    };

    static MINT_PATH: &str = "src/test_files/md/nameserver";

    #[test]
    fn test_md_nameserver_with_ldh_and_handle() {
        // GIVEN nameserver
        let ns = Nameserver::builder()
            .ldh_name("foo.example.com")
            .handle("123-ABC")
            .build()
            .unwrap();
        let response = ns.clone().to_response();

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
            parent_type: TypeId::of::<Nameserver>(),
            check_types: &[],
            options: &MdOptions::default(),
            req_data: &req_data,
        };
        let actual = ns.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_ldh_and_handle.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_nameserver_with_ldh_only() {
        // GIVEN nameserver
        let ns = Nameserver::builder()
            .ldh_name("foo.example.com")
            .build()
            .unwrap();
        let response = ns.clone().to_response();

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
            parent_type: TypeId::of::<Nameserver>(),
            check_types: &[],
            options: &MdOptions::default(),
            req_data: &req_data,
        };
        let actual = ns.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_ldh_only.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }
}
