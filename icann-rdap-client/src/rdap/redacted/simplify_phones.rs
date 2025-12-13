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
    use crate::rdap::redacted::simplify_phones::{
        simplify_registrant_fax, simplify_registrant_fax_ext, simplify_registrant_phone,
        simplify_registrant_phone_ext, simplify_tech_phone, simplify_tech_phone_ext, REDACTED_FAX,
        REDACTED_PHONE,
    };
    use icann_rdap_common::prelude::{Contact, Domain, Entity, Phone};

    fn given_domain_with_phone_contact(
        role: &str,
        phone_number: &str,
        feature: &str,
    ) -> Box<Domain> {
        let phone = Phone::builder()
            .phone(phone_number.to_string())
            .features(vec![feature.to_string()])
            .build();

        let contact = Contact::builder()
            .full_name("Test User")
            .phone(phone)
            .build();

        let entity = Entity::builder()
            .handle("test-entity")
            .role(role.to_string())
            .contact(contact)
            .build();

        let domain = Domain::response_obj()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        Box::new(domain)
    }

    fn given_domain_without_entities() -> Box<Domain> {
        let domain = Domain::response_obj().ldh_name("example.com").build();

        Box::new(domain)
    }

    fn given_domain_with_entity_without_contact(role: &str) -> Box<Domain> {
        let entity = Entity::builder()
            .handle("test-entity")
            .role(role.to_string())
            .build();

        let domain = Domain::response_obj()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        Box::new(domain)
    }

    fn given_domain_with_contact_without_phones(role: &str) -> Box<Domain> {
        let contact = Contact::builder().full_name("Test User").build();

        let entity = Entity::builder()
            .handle("test-entity")
            .role(role.to_string())
            .contact(contact)
            .build();

        let domain = Domain::response_obj()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        Box::new(domain)
    }

    fn given_domain_with_multiple_entities() -> Box<Domain> {
        let registrant_phone = Phone::builder()
            .phone("+1-555-111-1111".to_string())
            .features(vec!["voice".to_string()])
            .build();

        let registrant_contact = Contact::builder()
            .full_name("Registrant User")
            .phone(registrant_phone)
            .build();

        let registrant_entity = Entity::builder()
            .handle("registrant-entity")
            .role("registrant".to_string())
            .contact(registrant_contact)
            .build();

        let admin_phone = Phone::builder()
            .phone("+1-555-222-2222".to_string())
            .features(vec!["voice".to_string()])
            .build();

        let admin_contact = Contact::builder()
            .full_name("Admin User")
            .phone(admin_phone)
            .build();

        let admin_entity = Entity::builder()
            .handle("admin-entity")
            .role("administrative".to_string())
            .contact(admin_contact)
            .build();

        let domain = Domain::response_obj()
            .ldh_name("example.com")
            .entity(registrant_entity)
            .entity(admin_entity)
            .build();

        Box::new(domain)
    }

    // Helper functions for phone extension tests
    fn given_domain_with_phone_extension(
        role: &str,
        phone_number: &str,
        feature: &str,
    ) -> Box<Domain> {
        let phone = Phone::builder()
            .phone(phone_number.to_string())
            .features(vec![feature.to_string()])
            .build();

        let contact = Contact::builder()
            .full_name("Test User")
            .phone(phone)
            .build();

        let entity = Entity::builder()
            .handle("test-entity")
            .role(role.to_string())
            .contact(contact)
            .build();

        let domain = Domain::response_obj()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        Box::new(domain)
    }

    fn given_domain_with_multiple_phones_with_extensions(role: &str) -> Box<Domain> {
        let phone_with_ext = Phone::builder()
            .phone("+1-555-111-1111;ext=123".to_string())
            .features(vec!["voice".to_string()])
            .build();

        let phone_without_ext = Phone::builder()
            .phone("+1-555-222-2222".to_string())
            .features(vec!["voice".to_string()])
            .build();

        let contact = Contact::builder()
            .full_name("Test User")
            .phone(phone_with_ext)
            .phone(phone_without_ext)
            .build();

        let entity = Entity::builder()
            .handle("test-entity")
            .role(role.to_string())
            .contact(contact)
            .build();

        let domain = Domain::response_obj()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        Box::new(domain)
    }

    fn given_domain_with_complex_phone_extensions(role: &str) -> Box<Domain> {
        let phone_with_ext = Phone::builder()
            .phone("+1-555-111-1111;ext=123;param=value".to_string())
            .features(vec!["voice".to_string()])
            .build();

        let contact = Contact::builder()
            .full_name("Test User")
            .phone(phone_with_ext)
            .build();

        let entity = Entity::builder()
            .handle("test-entity")
            .role(role.to_string())
            .contact(contact)
            .build();

        let domain = Domain::response_obj()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        Box::new(domain)
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

    // Tests for simplify_phone_ext function
    #[test]
    fn given_registrant_with_voice_phone_ext_when_simplify_registrant_phone_ext_then_extension_is_redacted(
    ) {
        // GIVEN a domain with a registrant entity having a voice phone with extension
        let domain =
            given_domain_with_phone_extension("registrant", "+1-555-123-4567;ext=123", "voice");

        // WHEN simplifying registrant phone extension
        let result = simplify_registrant_phone_ext(domain);

        // THEN the phone extension should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let contact = entity.contact().unwrap();
        let phones = contact.phones();

        assert_eq!(
            phones[0].phone(),
            "+1-555-123-4567;ext=////REDACTED_PHONE_EXT////"
        );
        assert!(phones[0].features().contains(&"voice".to_string()));
    }

    #[test]
    fn given_registrant_with_fax_phone_ext_when_simplify_registrant_fax_ext_then_extension_is_redacted(
    ) {
        // GIVEN a domain with a registrant entity having a fax phone with extension
        let domain =
            given_domain_with_phone_extension("registrant", "+1-555-123-4568;ext=456", "fax");

        // WHEN simplifying registrant fax extension
        let result = simplify_registrant_fax_ext(domain);

        // THEN the fax extension should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let contact = entity.contact().unwrap();
        let phones = contact.phones();

        assert_eq!(
            phones[0].phone(),
            "+1-555-123-4568;ext=////REDACTED_FAX_EXT////"
        );
        assert!(phones[0].features().contains(&"fax".to_string()));
    }

    #[test]
    fn given_technical_with_voice_phone_ext_when_simplify_tech_phone_ext_then_extension_is_redacted(
    ) {
        // GIVEN a domain with a technical entity having a voice phone with extension
        let domain =
            given_domain_with_phone_extension("technical", "+1-555-987-6543;ext=789", "voice");

        // WHEN simplifying technical phone extension
        let result = simplify_tech_phone_ext(domain);

        // THEN the phone extension should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let contact = entity.contact().unwrap();
        let phones = contact.phones();

        assert_eq!(
            phones[0].phone(),
            "+1-555-987-6543;ext=////REDACTED_PHONE_EXT////"
        );
        assert!(phones[0].features().contains(&"voice".to_string()));
    }

    #[test]
    fn given_registrant_with_voice_phone_no_ext_when_simplify_registrant_phone_ext_then_redaction_appended(
    ) {
        // GIVEN a domain with a registrant entity having a voice phone without extension
        let domain = given_domain_with_phone_extension("registrant", "+1-555-123-4567", "voice");

        // WHEN simplifying registrant phone extension
        let result = simplify_registrant_phone_ext(domain);

        // THEN the redaction should be appended to the phone number
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let contact = entity.contact().unwrap();
        let phones = contact.phones();

        assert_eq!(
            phones[0].phone(),
            "+1-555-123-4567 ////REDACTED_PHONE_EXT////"
        );
        assert!(phones[0].features().contains(&"voice".to_string()));
    }

    #[test]
    fn given_administrative_entity_when_simplify_registrant_phone_ext_then_extension_not_redacted()
    {
        // GIVEN a domain with an administrative entity having a voice phone with extension
        let domain =
            given_domain_with_phone_extension("administrative", "+1-555-123-4567;ext=123", "voice");

        // WHEN simplifying registrant phone extension
        let result = simplify_registrant_phone_ext(domain);

        // THEN the phone extension should not be redacted (role doesn't match)
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let contact = entity.contact().unwrap();
        let phones = contact.phones();

        assert_eq!(phones[0].phone(), "+1-555-123-4567;ext=123");
        assert!(phones[0].features().contains(&"voice".to_string()));
    }

    #[test]
    fn given_registrant_with_sms_phone_when_simplify_registrant_phone_ext_then_extension_not_redacted(
    ) {
        // GIVEN a domain with a registrant entity having an SMS phone with extension
        let domain =
            given_domain_with_phone_extension("registrant", "+1-555-123-4567;ext=123", "sms");

        // WHEN simplifying registrant phone extension
        let result = simplify_registrant_phone_ext(domain);

        // THEN the phone extension should not be redacted (feature doesn't match)
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let contact = entity.contact().unwrap();
        let phones = contact.phones();

        assert_eq!(phones[0].phone(), "+1-555-123-4567;ext=123");
        assert!(phones[0].features().contains(&"sms".to_string()));
    }

    #[test]
    fn given_multiple_phones_with_ext_when_simplify_registrant_phone_ext_then_only_matching_phones_modified(
    ) {
        // GIVEN a domain with multiple phones, some with extensions
        let domain = given_domain_with_multiple_phones_with_extensions("registrant");

        // WHEN simplifying registrant phone extension
        let result = simplify_registrant_phone_ext(domain);

        // THEN only phones with voice feature should be modified
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let contact = entity.contact().unwrap();
        let phones = contact.phones();

        // Both phones should be modified since they both have voice feature
        assert_eq!(
            phones[0].phone(),
            "+1-555-111-1111;ext=////REDACTED_PHONE_EXT////"
        );
        assert_eq!(
            phones[1].phone(),
            "+1-555-222-2222 ////REDACTED_PHONE_EXT////"
        );
    }

    #[test]
    fn given_complex_phone_extension_when_simplify_registrant_phone_ext_then_only_ext_replaced() {
        // GIVEN a domain with a phone having complex extension and other parameters
        let domain = given_domain_with_complex_phone_extensions("registrant");

        // WHEN simplifying registrant phone extension
        let result = simplify_registrant_phone_ext(domain);

        // THEN only the extension part should be redacted, other parameters preserved
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let contact = entity.contact().unwrap();
        let phones = contact.phones();

        assert_eq!(
            phones[0].phone(),
            "+1-555-111-1111;ext=////REDACTED_PHONE_EXT////;param=value"
        );
        assert!(phones[0].features().contains(&"voice".to_string()));
    }

    #[test]
    fn given_registrant_with_fax_phone_ext_when_simplify_registrant_phone_ext_then_extension_not_redacted(
    ) {
        // GIVEN a domain with a registrant entity having a fax phone with extension
        let domain =
            given_domain_with_phone_extension("registrant", "+1-555-123-4568;ext=456", "fax");

        // WHEN simplifying registrant voice phone extension (not fax)
        let result = simplify_registrant_phone_ext(domain);

        // THEN the fax extension should not be redacted (feature doesn't match voice)
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let contact = entity.contact().unwrap();
        let phones = contact.phones();

        assert_eq!(phones[0].phone(), "+1-555-123-4568;ext=456");
        assert!(phones[0].features().contains(&"fax".to_string()));
    }

    #[test]
    fn given_registrant_with_phone_ext_when_simplify_registrant_phone_ext_then_remark_is_added() {
        // GIVEN a domain with a registrant entity having a voice phone with extension
        let domain =
            given_domain_with_phone_extension("registrant", "+1-555-123-4567;ext=123", "voice");

        // WHEN simplifying registrant phone extension
        let result = simplify_registrant_phone_ext(domain);

        // THEN a remark about phone extension redaction should be added
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let remarks = entity.object_common.remarks.as_ref().unwrap();

        assert!(!remarks.is_empty());
        let remark = &remarks[0];
        assert!(remark
            .description()
            .iter()
            .any(|desc| desc.contains("extension redacted")));
    }

    #[test]
    fn given_domain_without_entities_when_simplify_registrant_phone_ext_then_no_error_occurs() {
        // GIVEN a domain without any entities
        let domain = given_domain_without_entities();

        // WHEN simplifying registrant phone extension
        let result = simplify_registrant_phone_ext(domain);

        // THEN no entities should be present and no error should occur
        assert!(result.object_common.entities.is_none());
    }

    #[test]
    fn given_entity_without_contact_when_simplify_registrant_phone_ext_then_entity_is_preserved() {
        // GIVEN a domain with a registrant entity that has no contact information
        let domain = given_domain_with_entity_without_contact("registrant");

        // WHEN simplifying registrant phone extension
        let result = simplify_registrant_phone_ext(domain);

        // THEN the entity should be preserved but have no contact
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        assert!(entities[0].contact().is_none());
    }

    #[test]
    fn given_contact_without_phones_when_simplify_registrant_phone_ext_then_contact_is_preserved() {
        // GIVEN a domain with a registrant entity that has contact info but no phones
        let domain = given_domain_with_contact_without_phones("registrant");

        // WHEN simplifying registrant phone extension
        let result = simplify_registrant_phone_ext(domain);

        // THEN the contact should be preserved but have no phones
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let contact = entity.contact().unwrap();
        assert!(contact.phones().is_empty());
    }

    #[test]
    fn given_multiple_entities_with_extensions_when_simplify_registrant_phone_ext_then_only_registrant_is_redacted(
    ) {
        // GIVEN a domain with both registrant and administrative entities with phone extensions
        let registrant_phone = Phone::builder()
            .phone("+1-555-111-1111;ext=123".to_string())
            .features(vec!["voice".to_string()])
            .build();

        let registrant_contact = Contact::builder()
            .full_name("Registrant User")
            .phone(registrant_phone)
            .build();

        let registrant_entity = Entity::builder()
            .handle("registrant-entity")
            .role("registrant".to_string())
            .contact(registrant_contact)
            .build();

        let admin_phone = Phone::builder()
            .phone("+1-555-222-2222;ext=456".to_string())
            .features(vec!["voice".to_string()])
            .build();

        let admin_contact = Contact::builder()
            .full_name("Admin User")
            .phone(admin_phone)
            .build();

        let admin_entity = Entity::builder()
            .handle("admin-entity")
            .role("administrative".to_string())
            .contact(admin_contact)
            .build();

        let domain = Domain::response_obj()
            .ldh_name("example.com")
            .entity(registrant_entity)
            .entity(admin_entity)
            .build();

        // WHEN simplifying registrant phone extension
        let result = simplify_registrant_phone_ext(Box::new(domain));
        let entities = result.object_common.entities.as_ref().unwrap();

        // THEN only the registrant entity's phone extension should be redacted
        let registrant_contact = entities[0].contact().unwrap();
        let registrant_phones = registrant_contact.phones();
        assert_eq!(
            registrant_phones[0].phone(),
            "+1-555-111-1111;ext=////REDACTED_PHONE_EXT////"
        );

        // AND the administrative entity's phone extension should not be redacted
        let admin_contact = entities[1].contact().unwrap();
        let admin_phones = admin_contact.phones();
        assert_eq!(admin_phones[0].phone(), "+1-555-222-2222;ext=456");
    }
}
