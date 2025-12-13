//! Simplify redaction of phones

use std::sync::LazyLock;

use icann_rdap_common::prelude::{Domain, EntityRole};
use regex::Regex;

use crate::rdap::redacted::add_remark;

static REDACTED_PHONE: &str = "////REDACTED_PHONE////";
static REDACTED_PHONE_DESC: &str = "Phone redacted.";

static REDACTED_PHONE_EXT: &str = "////REDACTED_PHONE_EXT////";
static REDACTED_PHONE_EXT_DESC: &str = "Phone extension redacted.";

static REDACTED_FAX: &str = "////REDACTED_FAX////";
static REDACTED_FAX_DESC: &str = "Fax redacted.";

static REDACTED_FAX_EXT: &str = "////REDACTED_FAX_EXT////";
static REDACTED_FAX_EXT_DESC: &str = "Fax extension redacted.";

pub(crate) fn simplify_registrant_phone(domain: Box<Domain>) -> Box<Domain> {
    simplify_phone(domain, &EntityRole::Registrant, "voice")
}

pub(crate) fn simplify_registrant_phone_ext(domain: Box<Domain>) -> Box<Domain> {
    simplify_phone_ext(domain, &EntityRole::Registrant, "voice")
}

pub(crate) fn simplify_registrant_fax(domain: Box<Domain>) -> Box<Domain> {
    simplify_phone(domain, &EntityRole::Registrant, "fax")
}

pub(crate) fn simplify_registrant_fax_ext(domain: Box<Domain>) -> Box<Domain> {
    simplify_phone_ext(domain, &EntityRole::Registrant, "fax")
}

pub(crate) fn simplify_tech_phone(domain: Box<Domain>) -> Box<Domain> {
    simplify_phone(domain, &EntityRole::Technical, "voice")
}

pub(crate) fn simplify_tech_phone_ext(domain: Box<Domain>) -> Box<Domain> {
    simplify_phone_ext(domain, &EntityRole::Technical, "voice")
}

fn simplify_phone(mut domain: Box<Domain>, role: &EntityRole, feature: &str) -> Box<Domain> {
    let (redaction, redaction_desc) = match feature {
        "fax" => (REDACTED_FAX, REDACTED_FAX_DESC),
        _ => (REDACTED_PHONE, REDACTED_PHONE_DESC),
    };
    if let Some(entities) = &mut domain.object_common.entities {
        for entity in entities.iter_mut() {
            if entity.is_entity_role(&role.to_string()) {
                let contact = entity.contact();
                if let Some(mut contact) = contact {
                    if let Some(mut phones) = contact.phones {
                        for phone in phones.iter_mut() {
                            if phone.features().contains(&feature.to_string()) {
                                phone.phone = redaction.to_string();
                                entity.object_common.remarks = add_remark(
                                    redaction,
                                    redaction_desc,
                                    entity.object_common.remarks.clone(),
                                );
                            }
                        }
                        contact.phones = Some(phones);
                    }
                    entity.vcard_array = Some(contact.to_vcard());
                    break; // Only modify first entity with role
                }
            }
        }
    }
    domain
}

fn simplify_phone_ext(mut domain: Box<Domain>, role: &EntityRole, feature: &str) -> Box<Domain> {
    let (redaction, redaction_desc) = match feature {
        "fax" => (REDACTED_FAX_EXT, REDACTED_FAX_EXT_DESC),
        _ => (REDACTED_PHONE_EXT, REDACTED_PHONE_EXT_DESC),
    };
    if let Some(entities) = &mut domain.object_common.entities {
        for entity in entities.iter_mut() {
            if entity.is_entity_role(&role.to_string()) {
                let contact = entity.contact();
                if let Some(mut contact) = contact {
                    if let Some(mut phones) = contact.phones {
                        for phone in phones.iter_mut() {
                            if phone.features().contains(&feature.to_string()) {
                                if phone.phone.contains(";ext=") {
                                    static EXT_RE: LazyLock<Regex> =
                                        LazyLock::new(|| Regex::new(r";ext=[^;]*").unwrap());
                                    phone.phone = EXT_RE
                                        .replace_all(&phone.phone, format!(";ext={}", redaction))
                                        .to_string();
                                } else {
                                    phone.phone = format!("{} {}", phone.phone, redaction);
                                }
                                entity.object_common.remarks = add_remark(
                                    redaction,
                                    redaction_desc,
                                    entity.object_common.remarks.clone(),
                                );
                            }
                        }
                        contact.phones = Some(phones);
                    }
                    entity.vcard_array = Some(contact.to_vcard());
                    break; // Only modify first entity with role
                }
            }
        }
    }
    domain
}

#[cfg(test)]
mod tests {
    use icann_rdap_common::prelude::*;

    use super::*;

    fn given_domain_with_phone_contact(
        role: &str,
        phone_number: &str,
        feature: &str,
    ) -> Box<Domain> {
        let json = format!(
            r#"
        {{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "entities": [
                {{
                    "objectClassName": "entity",
                    "handle": "test-entity",
                    "roles": ["{}"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {{}}, "text", "4.0"],
                            ["fn", {{}}, "text", "Test User"],
                            ["tel", {{"type": ["{}"]}}, "text", "{}"]
                        ]
                    ]
                }}
            ]
        }}
        "#,
            role, feature, phone_number
        );

        serde_json::from_str(&json).unwrap()
    }

    fn given_domain_without_entities() -> Box<Domain> {
        let json = r#"
        {
            "objectClassName": "domain",
            "ldhName": "example.com"
        }
        "#;

        serde_json::from_str(&json).unwrap()
    }

    fn given_domain_with_entity_without_contact(role: &str) -> Box<Domain> {
        let json = format!(
            r#"
        {{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "entities": [
                {{
                    "objectClassName": "entity",
                    "handle": "test-entity",
                    "roles": ["{}"]
                }}
            ]
        }}
        "#,
            role
        );

        serde_json::from_str(&json).unwrap()
    }

    fn given_domain_with_contact_without_phones(role: &str) -> Box<Domain> {
        let json = format!(
            r#"
        {{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "entities": [
                {{
                    "objectClassName": "entity",
                    "handle": "test-entity",
                    "roles": ["{}"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {{}}, "text", "4.0"],
                            ["fn", {{}}, "text", "Test User"]
                        ]
                    ]
                }}
            ]
        }}
        "#,
            role
        );

        serde_json::from_str(&json).unwrap()
    }

    fn given_domain_with_multiple_entities() -> Box<Domain> {
        let json = r#"
        {
            "objectClassName": "domain",
            "ldhName": "example.com",
            "entities": [
                {
                    "objectClassName": "entity",
                    "handle": "registrant-entity",
                    "roles": ["registrant"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Registrant User"],
                            ["tel", {"type": ["voice"]}, "text", "+1-555-111-1111"]
                        ]
                    ]
                },
                {
                    "objectClassName": "entity",
                    "handle": "admin-entity",
                    "roles": ["administrative"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Admin User"],
                            ["tel", {"type": ["voice"]}, "text", "+1-555-222-2222"]
                        ]
                    ]
                }
            ]
        }
        "#;

        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn given_registrant_with_voice_phone_when_simplify_registrant_phone_then_phone_is_redacted() {
        // GIVEN a domain with a registrant entity having a voice phone
        let domain = given_domain_with_phone_contact("registrant", "+1-555-123-4567", "voice");

        // WHEN simplifying registrant phone
        let result = simplify_registrant_phone(domain);

        // THEN the phone should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let contact = entity.contact().unwrap();
        let phones = contact.phones();

        assert_eq!(phones[0].phone(), REDACTED_PHONE);
        assert!(phones[0].features().contains(&"voice".to_string()));
    }

    #[test]
    fn given_registrant_with_fax_phone_when_simplify_registrant_fax_then_phone_is_redacted() {
        // GIVEN a domain with a registrant entity having a fax phone
        let domain = given_domain_with_phone_contact("registrant", "+1-555-123-4568", "fax");

        // WHEN simplifying registrant fax
        let result = simplify_registrant_fax(domain);

        // THEN the fax should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let contact = entity.contact().unwrap();
        let phones = contact.phones();

        assert_eq!(phones[0].phone(), REDACTED_FAX);
        assert!(phones[0].features().contains(&"fax".to_string()));
    }

    #[test]
    fn given_technical_with_voice_phone_when_simplify_tech_phone_then_phone_is_redacted() {
        // GIVEN a domain with a technical entity having a voice phone
        let domain = given_domain_with_phone_contact("technical", "+1-555-987-6543", "voice");

        // WHEN simplifying technical phone
        let result = simplify_tech_phone(domain);

        // THEN the phone should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let contact = entity.contact().unwrap();
        let phones = contact.phones();

        assert_eq!(phones[0].phone(), REDACTED_PHONE);
        assert!(phones[0].features().contains(&"voice".to_string()));
    }

    #[test]
    fn given_administrative_entity_when_simplify_registrant_phone_then_phone_is_not_redacted() {
        // GIVEN a domain with an administrative entity having a voice phone
        let domain = given_domain_with_phone_contact("administrative", "+1-555-123-4567", "voice");

        // WHEN simplifying registrant phone
        let result = simplify_registrant_phone(domain);

        // THEN the phone should not be redacted (role doesn't match)
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let contact = entity.contact().unwrap();
        let phones = contact.phones();

        assert_eq!(phones[0].phone(), "+1-555-123-4567");
        assert!(phones[0].features().contains(&"voice".to_string()));
    }

    #[test]
    fn given_registrant_with_sms_phone_when_simplify_registrant_phone_then_phone_is_not_redacted() {
        // GIVEN a domain with a registrant entity having an SMS phone
        let domain = given_domain_with_phone_contact("registrant", "+1-555-123-4567", "sms");

        // WHEN simplifying registrant phone
        let result = simplify_registrant_phone(domain);

        // THEN the phone should not be redacted (feature doesn't match)
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let contact = entity.contact().unwrap();
        let phones = contact.phones();

        assert_eq!(phones[0].phone(), "+1-555-123-4567");
        assert!(phones[0].features().contains(&"sms".to_string()));
    }

    #[test]
    fn given_domain_without_entities_when_simplify_registrant_phone_then_no_error_occurs() {
        // GIVEN a domain without any entities
        let domain = given_domain_without_entities();

        // WHEN simplifying registrant phone
        let result = simplify_registrant_phone(domain);

        // THEN no entities should be present and no error should occur
        assert!(result.object_common.entities.is_none());
    }

    #[test]
    fn given_entity_without_contact_when_simplify_registrant_phone_then_entity_is_preserved() {
        // GIVEN a domain with a registrant entity that has no contact information
        let domain = given_domain_with_entity_without_contact("registrant");

        // WHEN simplifying registrant phone
        let result = simplify_registrant_phone(domain);

        // THEN the entity should be preserved but have no contact
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        assert!(entities[0].contact().is_none());
    }

    #[test]
    fn given_contact_without_phones_when_simplify_registrant_phone_then_contact_is_preserved() {
        // GIVEN a domain with a registrant entity that has contact info but no phones
        let domain = given_domain_with_contact_without_phones("registrant");

        // WHEN simplifying registrant phone
        let result = simplify_registrant_phone(domain);

        // THEN the contact should be preserved but have no phones
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let contact = entity.contact().unwrap();
        assert!(contact.phones().is_empty());
    }

    #[test]
    fn given_multiple_entities_when_simplify_registrant_phone_then_only_registrant_is_redacted() {
        // GIVEN a domain with both registrant and administrative entities
        let domain = given_domain_with_multiple_entities();

        // WHEN simplifying registrant phone
        let result = simplify_registrant_phone(domain);
        let entities = result.object_common.entities.as_ref().unwrap();

        // THEN only the registrant entity's phone should be redacted
        let registrant_contact = entities[0].contact().unwrap();
        let registrant_phones = registrant_contact.phones();
        assert_eq!(registrant_phones[0].phone(), REDACTED_PHONE);

        // AND the administrative entity's phone should not be redacted
        let admin_contact = entities[1].contact().unwrap();
        let admin_phones = admin_contact.phones();
        assert_eq!(admin_phones[0].phone(), "+1-555-222-2222");
    }

    #[test]
    fn given_registrant_with_phone_when_simplify_registrant_phone_then_remark_is_added() {
        // GIVEN a domain with a registrant entity having a voice phone
        let domain = given_domain_with_phone_contact("registrant", "+1-555-123-4567", "voice");

        // WHEN simplifying registrant phone
        let result = simplify_registrant_phone(domain);

        // THEN a remark about phone redaction should be added
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let remarks = entity.object_common.remarks.as_ref().unwrap();

        assert!(!remarks.is_empty());
        let remark = &remarks[0];
        assert!(remark
            .description()
            .iter()
            .any(|desc| desc.contains("redacted")));
    }
}
