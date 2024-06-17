use super::{GtldParams, RoleInfo, ToGtld};
use icann_rdap_common::contact::PostalAddress;
use icann_rdap_common::response::entity::Entity;

impl ToGtld for Option<Vec<Entity>> {
    fn to_gtld(&self, params: &mut GtldParams) -> String {
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
                                    if !role_info.url.is_empty() {
                                        front_formatted_data +=
                                            &format!("{} URL: {}\n", cfl(role), role_info.url);
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

    postal_address.to_gtld(params).to_string()
}

fn extract_role_info(
    role: &str,
    vcard_array: &[serde_json::Value],
    params: &mut GtldParams,
) -> RoleInfo {
    let mut name = String::new();
    let mut org = String::new();
    let mut url = String::new();
    let mut adr = String::new();

    let label = match role {
        "registrar" => "Registrar",
        "technical" => "Technical",
        "administrative" => "Admin",
        "registrant" => "Registrant",
        _ => "",
    };
    params.label = label.to_string();

    for vcard in vcard_array.iter() {
        if let Some(properties) = vcard.as_array() {
            for property in properties {
                if let Some(property) = property.as_array() {
                    match property[0].as_str().unwrap_or("") {
                        "fn" => name = property[3].as_str().unwrap_or("").to_string(),
                        "url" => url = property[3].as_str().unwrap_or("").to_string(),
                        "org" => org = property[3].as_str().unwrap_or("").to_string(),
                        "adr" => {
                            if let Some(address_components) = property[3].as_array() {
                                adr = format_address_with_label(params, address_components);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    RoleInfo {
        name,
        org,
        url,
        adr,
    }
}

fn append_abuse_contact_info(entity: &Entity, front_formatted_data: &mut String) {
    if let Some(entities) = &entity.object_common.entities {
        for entity in entities {
            if let Some(roles) = &entity.roles {
                for role in roles {
                    if role.as_str() == "abuse" {
                        if let Some(vcard_array) = &entity.vcard_array {
                            if let Some(properties) = vcard_array[1].as_array() {
                                for property in properties {
                                    if let Some(property) = property.as_array() {
                                        if property[0].as_str().unwrap_or("") == "tel" {
                                            let abuse_contact_phone =
                                                property[3].as_str().unwrap_or("").to_string();
                                            if !abuse_contact_phone.is_empty() {
                                                front_formatted_data.push_str(&format!(
                                                    "Registrar Abuse Contact Phone: {}\n",
                                                    abuse_contact_phone
                                                ));
                                            }
                                        } else if property[0].as_str().unwrap_or("") == "email" {
                                            let abuse_contact_email =
                                                property[3].as_str().unwrap_or("").to_string();
                                            if !abuse_contact_email.is_empty() {
                                                front_formatted_data.push_str(&format!(
                                                    "Registrar Abuse Contact Email: {}\n",
                                                    abuse_contact_email
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
}

// Where do we move this to?
// capitalize first letter
fn cfl(s: &str) -> String {
    s.char_indices()
        .next()
        .map(|(i, c)| c.to_uppercase().collect::<String>() + &s[i + 1..])
        .unwrap_or_default()
}
