use super::{GtldParams, RoleInfo, ToGtldWhois};
use icann_rdap_common::contact::{Contact, PostalAddress};
use icann_rdap_common::response::entity::Entity;

impl ToGtldWhois for Option<Vec<Entity>> {
    fn to_gtld_whois(&self, params: &mut GtldParams) -> String {
        let mut front_formatted_data = String::new();
        let mut formatted_data = String::new();

        if let Some(entities) = self {
            for entity in entities {
                if let Some(roles) = &entity.roles {
                    for role in roles {
                        match role.as_str() {
                            "registrar" => {
                                if let Some(vcard_array) = &entity.vcard_array {
                                    let role_info = extract_role_info(role, vcard_array, params);
                                    // Now use role_info to append to formatted_data
                                    if !role_info.name.is_empty() {
                                        front_formatted_data +=
                                            &format!("{}: {}\n", cfl(role), role_info.name);
                                    }
                                    if !role_info.org.is_empty() {
                                        front_formatted_data += &format!(
                                            "{} Organization: {}\n",
                                            cfl(role),
                                            role_info.org
                                        );
                                    }
                                    if !role_info.adr.is_empty() {
                                        front_formatted_data += &role_info.adr;
                                    }
                                }
                                // Special Sauce for Registrar IANA ID and Abuse Contact
                                if let Some(public_ids) = &entity.public_ids {
                                    for public_id in public_ids {
                                        if public_id.id_type.as_str() == "IANA Registrar ID"
                                            && !public_id.identifier.is_empty()
                                        {
                                            front_formatted_data += &format!(
                                                "Registrar IANA ID: {}\n",
                                                public_id.identifier.clone()
                                            );
                                        }
                                    }
                                }
                                append_abuse_contact_info(entity, &mut front_formatted_data);
                            }
                            "technical" | "administrative" | "registrant" => {
                                if let Some(vcard_array) = &entity.vcard_array {
                                    let role_info = extract_role_info(role, vcard_array, params);
                                    // Now use role_info to append to formatted_data
                                    if !role_info.name.is_empty() {
                                        formatted_data +=
                                            &format!("{} Name: {}\n", cfl(role), role_info.name);
                                    }
                                    if !role_info.org.is_empty() {
                                        formatted_data += &format!(
                                            "{} Organization: {}\n",
                                            cfl(role),
                                            role_info.org
                                        );
                                    }
                                    if !role_info.adr.is_empty() {
                                        formatted_data += &role_info.adr;
                                    }
                                    if !role_info.email.is_empty() {
                                        formatted_data +=
                                            &format!("{} Email: {}\n", cfl(role), role_info.email);
                                    }
                                    if !role_info.phone.is_empty() {
                                        formatted_data +=
                                            &format!("{} Phone: {}\n", cfl(role), role_info.phone);
                                    }
                                    if !role_info.fax.is_empty() {
                                        formatted_data +=
                                            &format!("{} Fax: {}\n", cfl(role), role_info.fax);
                                    }
                                }
                            }
                            _ => {} // Are there any roles we are missing?
                        }
                    }
                }
            }
        }

        front_formatted_data += &formatted_data;
        front_formatted_data
    }
}

fn format_address_with_label(
    params: &mut GtldParams,
    address_components: &[serde_json::Value],
) -> String {
    // TODO once from_vcard is fixed to handle the way addressing is done, replace this with the normal builder.
    let postal_address = PostalAddress::builder()
        .street_parts(
            address_components
                .get(2)
                .and_then(|v| v.as_str())
                .map_or_else(Vec::new, |s| vec![s.to_string()]),
        )
        .locality(
            address_components
                .get(3)
                .and_then(|v| v.as_str())
                .map_or_else(String::new, String::from),
        )
        .region_name(
            address_components
                .get(4)
                .and_then(|v| v.as_str())
                .map_or_else(String::new, String::from),
        )
        .country_name(
            address_components
                .get(6)
                .and_then(|v| v.as_str())
                .map_or_else(String::new, String::from),
        )
        .country_code(
            address_components
                .get(6)
                .and_then(|v| v.as_str())
                .map_or_else(String::new, String::from),
        )
        .postal_code(
            address_components
                .get(5)
                .and_then(|v| v.as_str())
                .map_or_else(String::new, String::from),
        )
        .build();

    postal_address.to_gtld_whois(params).to_string()
}

fn extract_role_info(
    role: &str,
    vcard_array: &[serde_json::Value],
    params: &mut GtldParams,
) -> RoleInfo {
    let contact = match Contact::from_vcard(vcard_array) {
        Some(contact) => contact,
        None => return RoleInfo::default(),
    };
    let mut adr = String::new();
    let label = match role {
        "registrar" => "Registrar",
        "technical" => "Technical",
        "administrative" => "Admin",
        "registrant" => "Registrant",
        _ => "",
    };
    params.label = label.to_string();

    let name = contact.full_name.unwrap_or_default();
    let org = contact
        .organization_names
        .and_then(|orgs| orgs.first().cloned())
        .unwrap_or_default();

    // TODO this is a workout to get the address out of the contact. Replace this when from_vcard is fixed
    for vcard in vcard_array.iter() {
        if let Some(properties) = vcard.as_array() {
            for property in properties {
                if let Some(property) = property.as_array() {
                    if let "adr" = property[0].as_str().unwrap_or("") {
                        if let Some(address_components) = property[3].as_array() {
                            adr = format_address_with_label(params, address_components);
                        }
                    }
                }
            }
        }
    }

    let email = contact
        .emails
        .and_then(|emails| emails.first().map(|email| email.email.clone()))
        .unwrap_or_default();
    let phone = contact
        .phones
        .as_ref()
        .and_then(|phones| {
            phones
                .iter()
                .find(|phone| {
                    phone
                        .features
                        .as_ref()
                        .map_or(true, |features| !features.contains(&"fax".to_string()))
                })
                .map(|phone| phone.phone.clone())
        })
        .unwrap_or_default();
    let fax = contact
        .phones
        .as_ref()
        .and_then(|phones| {
            phones
                .iter()
                .find(|phone| {
                    phone
                        .features
                        .as_ref()
                        .map_or(false, |features| features.contains(&"fax".to_string()))
                })
                .map(|phone| phone.phone.clone())
        })
        .unwrap_or_default();

    RoleInfo {
        name,
        org,
        adr,
        email,
        phone,
        fax,
    }
}

fn append_abuse_contact_info(entity: &Entity, front_formatted_data: &mut String) {
    if let Some(entities) = &entity.object_common.entities {
        for entity in entities {
            if let Some(roles) = &entity.roles {
                for role in roles {
                    if role.as_str() == "abuse" {
                        if let Some(vcard_array) = &entity.vcard_array {
                            if let Some(contact) = Contact::from_vcard(vcard_array) {
                                // Emails
                                if let Some(emails) = &contact.emails {
                                    for email in emails {
                                        let abuse_contact_email = &email.email;
                                        if !abuse_contact_email.is_empty() {
                                            front_formatted_data.push_str(&format!(
                                                "Registrar Abuse Contact Email: {}\n",
                                                abuse_contact_email
                                            ));
                                        }
                                    }
                                }
                                // Phones
                                if let Some(phones) = &contact.phones {
                                    for phone in phones {
                                        let abuse_contact_phone = &phone.phone;
                                        if !abuse_contact_phone.is_empty() {
                                            front_formatted_data.push_str(&format!(
                                                "Registrar Abuse Contact Phone: {}\n",
                                                abuse_contact_phone
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// capitalize first letter
fn cfl(s: &str) -> String {
    s.char_indices()
        .next()
        .map(|(i, c)| c.to_uppercase().collect::<String>() + &s[i + 1..])
        .unwrap_or_default()
}
