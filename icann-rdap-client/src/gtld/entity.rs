use {
    super::{GtldParams, RoleInfo, ToGtldWhois},
    icann_rdap_common::{contact::Contact, response::Entity},
};

impl ToGtldWhois for Option<Vec<Entity>> {
    fn to_gtld_whois(&self, params: &mut GtldParams) -> String {
        let mut formatted_data = String::new();

        if let Some(entities) = self {
            for entity in entities {
                for role in entity.roles() {
                    let label = match role.as_str() {
                        "registrant" => "Registrant",
                        "technical" => "Tech",
                        "administrative" => "Admin",
                        "billing" => "Billing",
                        "registrar" => "Registrar",
                        "reseller" => "Reseller",
                        "sponsor" => "Sponsor",
                        "proxy" => "Proxy",
                        "notifications" => "Notifications",
                        "noc" => "NOC",
                        _ => continue,
                    };
                    params.label = label.to_string();

                    if let Some(contact) = &entity.contact() {
                        let role_info = extract_role_info(contact, params);
                        // Now use role_info to append to formatted_data
                        if !role_info.name.is_empty() {
                            if ["registrar", "reseller", "sponsor", "proxy"]
                                .contains(&role.as_str())
                            {
                                formatted_data +=
                                    &format!("{}: {}\n", params.label, role_info.name);
                            } else {
                                formatted_data +=
                                    &format!("{} Name: {}\n", params.label, role_info.name);
                            }
                        }
                        if !role_info.org.is_empty() {
                            formatted_data +=
                                &format!("{} Organization: {}\n", params.label, role_info.org);
                        }
                        if !role_info.adr.is_empty() {
                            formatted_data += &role_info.adr;
                        }
                        if !role_info.email.is_empty() {
                            formatted_data +=
                                &format!("{} Email: {}\n", params.label, role_info.email);
                        }
                        if !role_info.phone.is_empty() {
                            formatted_data +=
                                &format!("{} Phone: {}\n", params.label, role_info.phone);
                        }
                        if !role_info.fax.is_empty() {
                            formatted_data += &format!("{} Fax: {}\n", params.label, role_info.fax);
                        }

                        // Special Sauce for Registrar IANA ID and Abuse Contact
                        if role.as_str() == "registrar" {
                            if let Some(public_ids) = &entity.public_ids {
                                for public_id in public_ids {
                                    if let Some(id_type) = &public_id.id_type {
                                        if let Some(identifier) = &public_id.identifier {
                                            if id_type.as_ref() == "IANA Registrar ID"
                                                && !identifier.is_empty()
                                            {
                                                formatted_data += &format!(
                                                    "Registrar IANA ID: {}\n",
                                                    identifier.clone()
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            append_abuse_contact_info(entity, &mut formatted_data);
                        }
                    }
                }
            }
        }

        formatted_data
    }
}

fn extract_role_info(contact: &Contact, params: &mut GtldParams) -> RoleInfo {
    let adr = if let Some(pa) = contact.postal_address() {
        pa.to_gtld_whois(params).to_string()
    } else {
        String::default()
    };
    let name = contact.full_name().unwrap_or_default();
    let org = contact.organization_name().unwrap_or_default();

    let email = contact
        .email()
        .map(|email| email.email.clone())
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
                        .is_none_or(|features| !features.contains(&"fax".to_string()))
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
                        .is_some_and(|features| features.contains(&"fax".to_string()))
                })
                .map(|phone| phone.phone.clone())
        })
        .unwrap_or_default();

    RoleInfo {
        name: name.to_owned(),
        org: org.to_owned(),
        adr,
        email,
        phone,
        fax,
    }
}

fn append_abuse_contact_info(entity: &Entity, formatted_data: &mut String) {
    if let Some(entities) = &entity.object_common.entities {
        for entity in entities {
            for role in entity.roles() {
                if role.as_str() == "abuse" {
                    if let Some(vcard_array) = &entity.vcard_array {
                        if let Some(contact) = Contact::from_vcard(vcard_array) {
                            // Emails
                            if let Some(emails) = &contact.emails {
                                for email in emails {
                                    let abuse_contact_email = &email.email;
                                    if !abuse_contact_email.is_empty() {
                                        formatted_data.push_str(&format!(
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
                                        formatted_data.push_str(&format!(
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
