use icann_rdap_common::prelude::{CommonFields, Entity, ObjectCommonFields};

use crate::rpsl::{AttrName, RpslParams, ToRpsl};

use super::{
    and_push_manditory_attribute, entity_value, push_entities, push_manditory_attribute,
    push_notices, push_obj_common, push_optional_attribute, push_public_ids,
};

impl ToRpsl for Entity {
    fn to_rpsl(&self, params: RpslParams) -> String {
        let mut rpsl = String::new();

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        // key
        let (key_name, key_value) = key(self);
        rpsl = push_manditory_attribute(rpsl, key_name, &key_value);

        // roles
        for role in self.roles() {
            rpsl = push_manditory_attribute(rpsl, AttrName::Role, role);
        }

        if let Some(contact) = self.contact() {
            rpsl = and_push_manditory_attribute(
                rpsl,
                AttrName::FullName,
                contact.full_name(),
                "NO FULL NAME",
            );
            for pa in contact.postal_addresses() {
                if let Some(full_address) = pa.full_address() {
                    for line in full_address.lines() {
                        rpsl = push_manditory_attribute(rpsl, AttrName::Address, line);
                    }
                }
                for street_part in pa.street_parts() {
                    rpsl = push_manditory_attribute(rpsl, AttrName::Address, street_part);
                }

                let mut adr = String::new();
                adr.push_str(pa.locality().unwrap_or_default());
                adr.push_str(
                    &pa.region_name()
                        .map(|s| format!(", {s}"))
                        .unwrap_or(",".to_string()),
                );
                adr.push_str(
                    &pa.region_code()
                        .map(|s| format!(" ({s})"))
                        .unwrap_or_default(),
                );
                adr.push_str(
                    &pa.country_name()
                        .map(|s| format!(", {s}"))
                        .unwrap_or(",".to_string()),
                );
                adr.push_str(
                    &pa.country_code()
                        .map(|s| format!(" ({s})"))
                        .unwrap_or_default(),
                );
                adr.push_str(
                    &pa.postal_code()
                        .map(|s| format!(" {s}"))
                        .unwrap_or_default(),
                );
                if pa.locality().is_some()
                    || pa.region_name().is_some()
                    || pa.country_name().is_some()
                    || pa.country_code().is_some()
                    || pa.postal_code().is_some()
                {
                    rpsl = push_optional_attribute(rpsl, AttrName::Address, Some(&adr));
                }
            }
            for email in contact.emails() {
                rpsl = push_manditory_attribute(rpsl, AttrName::Email, email.email());
            }
            for phone in contact.phones() {
                if phone.features().contains(&"fax".to_string()) {
                    rpsl = push_manditory_attribute(rpsl, AttrName::FaxNo, phone.phone());
                } else {
                    rpsl = push_manditory_attribute(rpsl, AttrName::Phone, phone.phone());
                }
            }
        }

        // push public ids
        rpsl = push_public_ids(rpsl, self.public_ids());

        // push things common to object classes
        rpsl = push_obj_common(rpsl, params, self);

        //end
        rpsl.push('\n');

        // output entities
        rpsl = push_entities(rpsl, self.entities(), params);

        // output autnums
        for an in self.autnums() {
            rpsl.push_str(&an.to_rpsl(params));
        }

        // output networks
        for net in self.networks() {
            rpsl.push_str(&net.to_rpsl(params));
        }

        //return
        rpsl
    }
}

fn key(entity: &Entity) -> (AttrName, String) {
    let contact = entity.contact();
    let name = if entity.roles().contains(&"registrant".to_string()) {
        AttrName::Registrant
    } else {
        contact
            .as_ref()
            .and_then(|c| c.kind())
            .filter(|k| k.eq_ignore_ascii_case("person"))
            .map(|_k| AttrName::Person)
            .unwrap_or(AttrName::Organization)
    };
    let value = entity_value(entity);
    (name, value)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use goldenfile::Mint;
    use icann_rdap_common::{httpdata::HttpData, prelude::Entity};

    use crate::rpsl::{RpslParams, ToRpsl};

    static MINT_PATH: &str = "src/test_files/rpsl/entity";

    #[test]
    fn test_rpsl_entity_with_handle() {
        // GIVEN entity
        let entity = Entity::builder().handle("123-ABC").build();

        // WHEN represented as rpsl
        let http_data = HttpData::example().build();
        let params = RpslParams {
            http_data: &http_data,
        };
        let actual = entity.to_rpsl(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_handle.txt").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }
}
