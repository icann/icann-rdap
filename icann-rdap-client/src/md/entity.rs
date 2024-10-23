use std::any::TypeId;

use icann_rdap_common::contact::{NameParts, PostalAddress};
use icann_rdap_common::response::entity::{Entity, EntityRole};

use icann_rdap_common::check::{CheckParams, GetChecks, GetSubChecks};

use crate::registered_redactions::{
    are_redactions_registered_for_roles, is_redaction_registered_for_role,
    text_or_registered_redaction_for_role, RedactedName,
};

use super::redacted::REDACTED_TEXT;
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

        // A note about the RFC 9537 redactions. A lot of this code is to do RFC 9537 redactions
        // that are registered with the IANA. As RFC 9537 is horribly broken, it is likely only
        // gTLD registries will use registered redactions, and when they do they will use all
        // of them. Therefore, as horribly complicated as this logic is, it attempts to simplify
        // things by assuming all the registrations will be used at once, which will be the case
        // in the gTLD space.

        // check if registrant or tech ids are RFC 9537 redacted
        let mut entity_handle = text_or_registered_redaction_for_role(
            params.root,
            &RedactedName::RegistryRegistrantId,
            self,
            &EntityRole::Registrant,
            &self.object_common.handle,
            REDACTED_TEXT,
        );
        entity_handle = text_or_registered_redaction_for_role(
            params.root,
            &RedactedName::RegistryTechId,
            self,
            &EntityRole::Technical,
            &entity_handle,
            REDACTED_TEXT,
        );

        // multipart data
        let mut table = MultiPartTable::new();

        // identifiers
        table = table
            .header_ref(&"Identifiers")
            .and_data_ref(&"Handle", &entity_handle);
        if let Some(public_ids) = &self.public_ids {
            table = public_ids_to_table(public_ids, table);
        }

        if let Some(contact) = self.contact() {
            // nutty RFC 9537 redaction stuff

            // check if registrant or tech name are redacted
            let mut registrant_name = text_or_registered_redaction_for_role(
                params.root,
                &RedactedName::RegistrantName,
                self,
                &EntityRole::Registrant,
                &contact.full_name,
                REDACTED_TEXT,
            );
            registrant_name = text_or_registered_redaction_for_role(
                params.root,
                &RedactedName::TechName,
                self,
                &EntityRole::Technical,
                &registrant_name,
                REDACTED_TEXT,
            );

            // check to see if registrant postal address parts are redacted
            let postal_addresses = if are_redactions_registered_for_roles(
                params.root,
                &[
                    &RedactedName::RegistrantStreet,
                    &RedactedName::RegistrantCity,
                    &RedactedName::RegistrantPostalCode,
                ],
                self,
                &[&EntityRole::Registrant],
            ) {
                let mut new_pas = contact.postal_addresses.clone();
                if let Some(ref mut new_pas) = new_pas {
                    new_pas.iter_mut().for_each(|pa| {
                        pa.street_parts = Some(vec![REDACTED_TEXT.to_string()]);
                        pa.locality = Some(REDACTED_TEXT.to_string());
                        pa.postal_code = Some(REDACTED_TEXT.to_string());
                    })
                }
                new_pas
            } else {
                contact.postal_addresses
            };

            table = table
                .header_ref(&"Contact")
                .and_data_ref_maybe(&"Kind", &contact.kind)
                .and_data_ref_maybe(&"Full Name", &registrant_name)
                .and_data_ul(&"Titles", contact.titles)
                .and_data_ul(&"Org Roles", contact.roles)
                .and_data_ul(&"Nicknames", contact.nick_names);
            if is_redaction_registered_for_role(
                params.root,
                &RedactedName::RegistrantOrganization,
                self,
                &EntityRole::Registrant,
            ) {
                table = table.data_ref(&"Organization Name", &REDACTED_TEXT.to_string());
            } else {
                table = table.and_data_ul(&"Organization Names", contact.organization_names);
            }
            table = table.and_data_ul(&"Languages", contact.langs);
            if are_redactions_registered_for_roles(
                params.root,
                &[
                    &RedactedName::RegistrantPhone,
                    &RedactedName::RegistrantPhoneExt,
                    &RedactedName::RegistrantFax,
                    &RedactedName::RegistrantFaxExt,
                    &RedactedName::TechPhone,
                    &RedactedName::TechPhoneExt,
                ],
                self,
                &[&EntityRole::Registrant, &EntityRole::Technical],
            ) {
                table = table.data_ref(&"Phones", &REDACTED_TEXT.to_string());
            } else {
                table = table.and_data_ul(&"Phones", contact.phones);
            }
            if are_redactions_registered_for_roles(
                params.root,
                &[&RedactedName::TechEmail, &RedactedName::RegistrantEmail],
                self,
                &[&EntityRole::Registrant, &EntityRole::Technical],
            ) {
                table = table.data_ref(&"Emails", &REDACTED_TEXT.to_string());
            } else {
                table = table.and_data_ul(&"Emails", contact.emails);
            }
            table = table
                .and_data_ul(&"Web Contact", contact.contact_uris)
                .and_data_ul(&"URLs", contact.urls);
            table = postal_addresses.add_to_mptable(table, params);
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
