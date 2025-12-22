use icann_rdap_common::{
    contact::{NameParts, PostalAddress},
    prelude::ObjectCommonFields,
    response::Entity,
};

use super::{
    string::StringUtil,
    table::{MultiPartTable, ToMpTable},
    types::public_ids_to_table,
    MdHeaderText, MdParams, MdUtil, ToMd,
};

impl ToMd for Entity {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent()));

        // header
        let header_text = self.get_header_text();
        md.push_str(
            &header_text
                .to_string()
                .to_header(params.heading_level, params.options),
        );

        // multipart data
        let mut table = MultiPartTable::new_with_value_hightlights_from_remarks(self.remarks());

        // summary
        table = table.summary(header_text);

        // identifiers
        table = table
            .header_ref(&"Identifiers")
            .and_nv_ref_maybe(&"Handle", &self.handle())
            .and_nv_ul(&"Roles", Some(self.roles().to_vec()));
        if let Some(public_ids) = &self.public_ids {
            table = public_ids_to_table(public_ids, table);
        }

        if let Some(contact) = self.contact() {
            table = table
                .header_ref(&"Contact")
                .and_nv_ref_maybe(&"Kind", &contact.kind)
                .and_nv_ref_maybe(&"Full Name", &contact.full_name())
                .and_nv_ul(&"Titles", contact.titles)
                .and_nv_ul(&"Org Roles", contact.roles)
                .and_nv_ul(&"Nicknames", contact.nick_names);
            table = table.and_nv_ul(&"Organization Names", contact.organization_names);
            table = table.and_nv_ul(&"Languages", contact.langs);
            table = table.and_nv_ul(&"Phones", contact.phones);
            table = table.and_nv_ul(&"Emails", contact.emails);
            table = table
                .and_nv_ul(&"Web Contact", contact.contact_uris)
                .and_nv_ul(&"URLs", contact.urls);
            table = contact.postal_addresses.add_to_mptable(table, params);
            table = contact.name_parts.add_to_mptable(table, params)
        }

        // common object stuff
        table = self.object_common.add_to_mptable(table, params);

        // remarks
        table = self.remarks().add_to_mptable(table, params);

        // render table
        md.push_str(&table.to_md(params));

        // entities
        md.push_str(&self.object_common.entities.to_md(params.from_parent()));

        // redacted
        if let Some(redacted) = &self.object_common.redacted {
            md.push_str(&redacted.as_slice().to_md(params.from_parent()));
        }

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

impl ToMpTable for Option<Vec<PostalAddress>> {
    fn add_to_mptable(&self, mut table: MultiPartTable, params: MdParams) -> MultiPartTable {
        if let Some(addrs) = self {
            for addr in addrs {
                table = addr.add_to_mptable(table, params);
            }
        }
        table
    }
}

impl ToMpTable for PostalAddress {
    fn add_to_mptable(&self, mut table: MultiPartTable, _params: MdParams) -> MultiPartTable {
        if self.contexts.is_some() && self.preference.is_some() {
            table = table.nv(
                &"Address",
                format!(
                    "{} (pref: {})",
                    self.contexts.as_ref().unwrap().join(" "),
                    self.preference.unwrap()
                ),
            );
        } else if self.contexts.is_some() {
            table = table.nv(&"Address", self.contexts.as_ref().unwrap().join(" "));
        } else if self.preference.is_some() {
            table = table.nv(
                &"Address",
                format!("preference: {}", self.preference.unwrap()),
            );
        } else {
            table = table.nv(&"Address", "");
        }
        if let Some(street_parts) = &self.street_parts {
            table = table.nv_ul_ref(&"Street", street_parts.iter().collect());
        }
        if let Some(locality) = &self.locality {
            table = table.nv_ref(&"Locality", locality);
        }
        if self.region_name.is_some() && self.region_code.is_some() {
            table = table.nv(
                &"Region",
                format!(
                    "{} ({})",
                    self.region_name.as_ref().unwrap(),
                    self.region_code.as_ref().unwrap()
                ),
            );
        } else if let Some(region_name) = &self.region_name {
            table = table.nv_ref(&"Region", region_name);
        } else if let Some(region_code) = &self.region_code {
            table = table.nv_ref(&"Region", region_code);
        }
        if self.country_name.is_some() && self.country_code.is_some() {
            table = table.nv(
                &"Country",
                format!(
                    "{} ({})",
                    self.country_name.as_ref().unwrap(),
                    self.country_code.as_ref().unwrap()
                ),
            );
        } else if let Some(country_name) = &self.country_name {
            table = table.nv_ref(&"Country", country_name);
        } else if let Some(country_code) = &self.country_code {
            table = table.nv_ref(&"Country", country_code);
        }
        if let Some(postal_code) = &self.postal_code {
            table = table.nv_ref(&"Postal Code", postal_code);
        }
        if let Some(full_address) = &self.full_address {
            let parts = full_address.split('\n').collect::<Vec<&str>>();
            for (i, p) in parts.iter().enumerate() {
                table = table.nv_ref(&i.to_string(), p);
            }
        }
        table
    }
}

impl ToMpTable for Option<NameParts> {
    fn add_to_mptable(&self, mut table: MultiPartTable, _params: MdParams) -> MultiPartTable {
        if let Some(parts) = self {
            if let Some(prefixes) = &parts.prefixes {
                table = table.nv(&"Honorifics", prefixes.join(", "));
            }
            if let Some(given_names) = &parts.given_names {
                table = table.nv_ul(&"Given Names", given_names.to_vec());
            }
            if let Some(middle_names) = &parts.middle_names {
                table = table.nv_ul(&"Middle Names", middle_names.to_vec());
            }
            if let Some(surnames) = &parts.surnames {
                table = table.nv_ul(&"Surnames", surnames.to_vec());
            }
            if let Some(suffixes) = &parts.suffixes {
                table = table.nv(&"Suffixes", suffixes.join(", "));
            }
        }
        table
    }
}

impl MdUtil for Entity {
    fn get_header_text(&self) -> MdHeaderText {
        let role = self
            .roles()
            .first()
            .map(|s| s.replace_md_chars().to_title_case());
        let header_text = if let Some(handle) = &self.object_common.handle {
            if let Some(role) = role {
                format!("{} ({})", handle.replace_md_chars(), role)
            } else {
                format!("Entity {}", handle)
            }
        } else if let Some(role) = role {
            role.to_string()
        } else {
            "Entity".to_string()
        };
        let mut header_text = MdHeaderText::builder().header_text(header_text);
        if let Some(entities) = &self.object_common.entities {
            for entity in entities {
                header_text = header_text.children_entry(entity.get_header_text());
            }
        };
        if let Some(networks) = &self.networks {
            for network in networks {
                header_text = header_text.children_entry(network.get_header_text());
            }
        };
        if let Some(autnums) = &self.autnums {
            for autnum in autnums {
                header_text = header_text.children_entry(autnum.get_header_text());
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
            Entity, ToResponse,
        },
    };

    use crate::{
        md::{MdOptions, MdParams, ToMd},
        rdap::RequestData,
    };

    static MINT_PATH: &str = "src/test_files/md/entity";

    #[test]
    fn test_md_entity_with_handle() {
        // GIVEN entity
        let entity = Entity::builder().handle("123-ABC").build();
        let response = entity.clone().to_response();

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
        };
        let actual = entity.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_handle.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_entity_with_no_handle_but_roles() {
        // GIVEN entity
        let entity = Entity::builder::<String>().role("registrar").build();
        let response = entity.clone().to_response();

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
        };
        let actual = entity.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_no_handle_but_roles.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_entity_with_handle_and_redactions() {
        // GIVEN entity
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
        let entity = Entity::builder()
            .handle("123-ABC")
            .redacted(redactions)
            .build();
        let response = entity.clone().to_response();

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
        };
        let actual = entity.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint
            .new_goldenfile("with_handle_and_redactions.md")
            .unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }
}
