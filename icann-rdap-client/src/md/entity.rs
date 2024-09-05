use std::any::TypeId;

use icann_rdap_common::contact::{NameParts, PostalAddress};
use icann_rdap_common::response::entity::Entity;

use icann_rdap_common::check::{CheckParams, GetChecks, GetSubChecks};

use super::types::public_ids_to_table;
use super::FromMd;
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
            .header_ref(&"Identifiers")
            .and_data_ref(&"Handle", &self.object_common.handle);
        if let Some(public_ids) = &self.public_ids {
            table = public_ids_to_table(public_ids, table);
        }

        if let Some(contact) = self.contact() {
            table = table
                .header_ref(&"Contact")
                .and_data_ref_maybe(&"Kind", &contact.kind)
                .and_data_ref_maybe(&"Full Name", &contact.full_name)
                .and_data_ul(&"Titles", contact.titles)
                .and_data_ul(&"Org Roles", contact.roles)
                .and_data_ul(&"Nicknames", contact.nick_names)
                .and_data_ul(&"Organization Names", contact.organization_names)
                .and_data_ul(&"Languages", contact.langs)
                .and_data_ul(&"Phones", contact.phones)
                .and_data_ul(&"Emails", contact.emails)
                .and_data_ul(&"Web Contact", contact.contact_uris)
                .and_data_ul(&"URLs", contact.urls);
            table = contact.postal_addresses.add_to_mptable(table, params);
            table = contact.name_parts.add_to_mptable(table, params)
        }

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
            table = table.data(
                &"Address",
                format!(
                    "{} (pref: {})",
                    self.contexts.as_ref().unwrap().join(" "),
                    self.preference.unwrap()
                ),
            );
        } else if self.contexts.is_some() {
            table = table.data(&"Address", self.contexts.as_ref().unwrap().join(" "));
        } else if self.preference.is_some() {
            table = table.data(
                &"Address",
                format!("preference: {}", self.preference.unwrap()),
            );
        } else {
            table = table.data(&"Address", "");
        }
        if let Some(street_parts) = &self.street_parts {
            table = table.data_ul_ref(&"Street", street_parts.iter().collect());
        }
        if let Some(locality) = &self.locality {
            table = table.data_ref(&"Locality", locality);
        }
        if self.region_name.is_some() && self.region_code.is_some() {
            table = table.data(
                &"Region",
                format!(
                    "{} ({})",
                    self.region_name.as_ref().unwrap(),
                    self.region_code.as_ref().unwrap()
                ),
            );
        } else if let Some(region_name) = &self.region_name {
            table = table.data_ref(&"Region", region_name);
        } else if let Some(region_code) = &self.region_code {
            table = table.data_ref(&"Region", region_code);
        }
        if self.country_name.is_some() && self.country_code.is_some() {
            table = table.data(
                &"Country",
                format!(
                    "{} ({})",
                    self.country_name.as_ref().unwrap(),
                    self.country_code.as_ref().unwrap()
                ),
            );
        } else if let Some(country_name) = &self.country_name {
            table = table.data_ref(&"Country", country_name);
        } else if let Some(country_code) = &self.country_code {
            table = table.data_ref(&"Country", country_code);
        }
        if let Some(postal_code) = &self.postal_code {
            table = table.data_ref(&"Postal Code", postal_code);
        }
        if let Some(full_address) = &self.full_address {
            let parts = full_address.split('\n').collect::<Vec<&str>>();
            for (i, p) in parts.iter().enumerate() {
                table = table.data_ref(&i.to_string(), p);
            }
        }
        table
    }
}

impl ToMpTable for Option<NameParts> {
    fn add_to_mptable(&self, mut table: MultiPartTable, _params: MdParams) -> MultiPartTable {
        if let Some(parts) = self {
            if let Some(prefixes) = &parts.prefixes {
                table = table.data(&"Honorifics", prefixes.join(", "));
            }
            if let Some(given_names) = &parts.given_names {
                table = table.data_ul(&"Given Names", given_names.to_vec());
            }
            if let Some(middle_names) = &parts.middle_names {
                table = table.data_ul(&"Middle Names", middle_names.to_vec());
            }
            if let Some(surnames) = &parts.surnames {
                table = table.data_ul(&"Surnames", surnames.to_vec());
            }
            if let Some(suffixes) = &parts.suffixes {
                table = table.data(&"Suffixes", suffixes.join(", "));
            }
        }
        table
    }
}
