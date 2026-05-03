//! Simplify redaction of names

use icann_rdap_common::prelude::{redacted::Redacted, Domain, EntityRole};

use crate::rdap::redacted::add_remark;

static REDACTED_EMAIL: &str = "redacted_email@redacted.invalid";
static REDACTED_EMAIL_DESC: &str = "Email redacted.";

pub(crate) fn simplify_registrant_email(domain: Box<Domain>, redaction: &Redacted) -> Box<Domain> {
    simplify_email(domain, &EntityRole::Registrant, redaction)
}

pub(crate) fn simplify_tech_email(domain: Box<Domain>, redaction: &Redacted) -> Box<Domain> {
    simplify_email(domain, &EntityRole::Technical, redaction)
}

fn simplify_email(mut domain: Box<Domain>, role: &EntityRole, redaction: &Redacted) -> Box<Domain> {
    if let Some(entities) = &mut domain.object_common.entities {
        for entity in entities.iter_mut() {
            if entity.is_entity_role(&role.to_string()) {
                let contact = entity.contact();
                if let Some(mut contact) = contact {
                    let emails = contact.emails().to_vec();
                    let has_any_email = !emails.is_empty();
                    let has_valid_email = emails.iter().any(|e| !e.email.is_empty());
                    if has_any_email && !has_valid_email {
                        let mut emails = emails;
                        for email in emails.iter_mut() {
                            email.email = REDACTED_EMAIL.to_string();
                        }
                        contact = contact.with_emails(emails);
                        entity.object_common.remarks = add_remark(
                            REDACTED_EMAIL,
                            REDACTED_EMAIL_DESC,
                            redaction,
                            entity.object_common.remarks.clone(),
                        );
                    }
                    entity.with_contact_if_vcard(&contact);
                    entity.with_contact_if_jscontact(&contact);
                    break; // Only modify first entity
                }
            }
        }
    }
    domain
}

#[cfg(test)]
mod tests {
    use icann_rdap_common::prelude::redacted::Name;
    use icann_rdap_common::prelude::Remark;
    use icann_rdap_common::prelude::{Contact, Email, Entity};
    use icann_rdap_common::response::ObjectCommonFields;

    use super::*;

    fn get_test_redacted() -> Redacted {
        Redacted::builder()
            .name(Name::builder().type_field("Tech Email").build())
            .build()
    }

    #[test]
    fn test_simplify_registrant_email_with_registrant_entity_with_contact_and_emails() {
        // GIVEN a domain with a registrant entity that has a contact with valid emails
        let email1 = Email::builder()
            .preference(1)
            .contexts(vec!["work".to_string()])
            .email("john@example.com".to_string())
            .build();

        let email2 = Email::builder()
            .preference(2)
            .contexts(vec!["home".to_string()])
            .email("john@home.com".to_string())
            .build();

        let contact = Contact::builder().emails(vec![email1, email2]).build();

        let registrant_entity = Entity::builder()
            .handle("registrant_123")
            .role(EntityRole::Registrant.to_string())
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![registrant_entity])
            .build();

        // WHEN calling simplify_registrant_email
        let result = simplify_registrant_email(Box::new(domain), &get_test_redacted());

        // THEN the registrant's contact emails should NOT be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some("registrant_123"));

        // Check that contact emails are preserved
        if let Some(contact) = registrant.contact() {
            let emails = contact.emails();
            assert_eq!(emails.len(), 2);

            // Emails should be preserved, not redacted
            assert_eq!(emails[0].email, "john@example.com");
            assert_eq!(emails[1].email, "john@home.com");
        } else {
            panic!("Expected contact to be present");
        }

        // AND no remark should be added since emails are valid
        assert!(registrant.object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_registrant_email_with_registrant_entity_contact_no_emails() {
        // GIVEN a domain with a registrant entity with contact but no emails
        let contact = Contact::builder().full_name("John Doe").build();

        let registrant_entity = Entity::builder()
            .handle("registrant_123")
            .role(EntityRole::Registrant.to_string())
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![registrant_entity])
            .build();

        // WHEN calling simplify_registrant_email
        let result = simplify_registrant_email(Box::new(domain), &get_test_redacted());

        // THEN the domain should have vcard_array but no remark (no emails to redact)
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some("registrant_123"));
        assert!(registrant.contact().is_some()); // vcard_array should be created
        assert!(registrant.object_common.remarks.is_none()); // No remark since no emails to redact
    }

    #[test]
    fn test_simplify_registrant_email_with_registrant_entity_no_contact() {
        // GIVEN a domain with a registrant entity but no contact
        let registrant_entity = Entity::builder()
            .handle("registrant_123")
            .role(EntityRole::Registrant.to_string())
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![registrant_entity])
            .build();

        // WHEN calling simplify_registrant_email
        let result = simplify_registrant_email(Box::new(domain), &get_test_redacted());

        // THEN the domain should be unchanged (no contact to modify)
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some("registrant_123"));
        assert!(registrant.contact().is_none());
        assert!(registrant.object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_registrant_email_with_multiple_entities_first_is_registrant_with_contact_and_emails(
    ) {
        // GIVEN a domain with multiple entities, first is registrant with contact and valid emails
        let email = Email::builder()
            .email("jane@example.com".to_string())
            .build();

        let contact = Contact::builder().emails(vec![email]).build();

        let registrant_entity = Entity::builder()
            .handle("registrant_123")
            .role(EntityRole::Registrant.to_string())
            .contact(contact)
            .build();

        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![registrant_entity, tech_entity])
            .build();

        // WHEN calling simplify_registrant_email
        let result = simplify_registrant_email(Box::new(domain), &get_test_redacted());

        // THEN the registrant emails should NOT be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);

        // First entity (registrant) should have preserved emails
        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some("registrant_123"));
        assert!(registrant.contact().is_some());

        if let Some(contact) = registrant.contact() {
            assert_eq!(contact.emails()[0].email, "jane@example.com");
        }

        // No remark should be added
        assert!(registrant.object_common.remarks.is_none());

        // Second entity (tech) should be unchanged
        assert_eq!(entities[1].handle(), Some("tech_456"));
        assert!(entities[1].contact().is_none());
        assert!(entities[1].object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_registrant_email_with_multiple_entities_registrant_not_first() {
        // GIVEN a domain with multiple entities, registrant is second with valid emails
        let email = Email::builder()
            .email("bob@example.com".to_string())
            .build();

        let contact = Contact::builder().emails(vec![email]).build();

        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .build();

        let registrant_entity = Entity::builder()
            .handle("registrant_123")
            .role(EntityRole::Registrant.to_string())
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![tech_entity, registrant_entity])
            .build();

        // WHEN calling simplify_registrant_email
        let result = simplify_registrant_email(Box::new(domain), &get_test_redacted());

        // THEN the registrant emails should NOT be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);

        // First entity (tech) should be unchanged
        assert_eq!(entities[0].handle(), Some("tech_456"));
        assert!(entities[0].contact().is_none());

        // Second entity (registrant) should have preserved emails
        let registrant = &entities[1];
        assert_eq!(registrant.handle(), Some("registrant_123"));
        assert!(registrant.contact().is_some());

        if let Some(contact) = registrant.contact() {
            assert_eq!(contact.emails()[0].email, "bob@example.com");
        }

        // No remark should be added
        assert!(registrant.object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_registrant_email_with_no_registrant_entity() {
        // GIVEN a domain with no registrant entity
        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .build();

        let admin_entity = Entity::builder()
            .handle("admin_789")
            .role(EntityRole::Administrative.to_string())
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![tech_entity, admin_entity])
            .build();

        // WHEN calling simplify_registrant_email
        let result = simplify_registrant_email(Box::new(domain), &get_test_redacted());

        // THEN no entities should be modified
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);
        assert_eq!(entities[0].handle(), Some("tech_456"));
        assert_eq!(entities[1].handle(), Some("admin_789"));

        // AND no vcard_arrays or remarks should be added
        assert!(entities[0].contact().is_none());
        assert!(entities[1].contact().is_none());
        assert!(entities[0].object_common.remarks.is_none());
        assert!(entities[1].object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_registrant_email_with_no_entities() {
        // GIVEN a domain with no entities
        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .build();

        // WHEN calling simplify_registrant_email
        let result = simplify_registrant_email(Box::new(domain), &get_test_redacted());

        // THEN the domain should be unchanged
        assert!(result.object_common.entities.is_none());
        assert_eq!(result.handle(), Some("example_com-1"));
    }

    #[test]
    fn test_simplify_registrant_email_with_registrant_entity_with_same_redaction_remark() {
        // GIVEN a registrant entity with existing redaction remark and contact with valid emails
        let existing_remark = Remark::builder()
            .simple_redaction_keys(vec![REDACTED_EMAIL.to_string()])
            .description_entry("existing redaction description")
            .build();

        let email = Email::builder()
            .email("charlie@example.com".to_string())
            .build();

        let contact = Contact::builder().emails(vec![email]).build();

        let registrant_entity = Entity::builder()
            .handle("registrant_123")
            .role(EntityRole::Registrant.to_string())
            .contact(contact)
            .remarks(vec![existing_remark])
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![registrant_entity])
            .build();

        // WHEN calling simplify_registrant_email
        let result = simplify_registrant_email(Box::new(domain), &get_test_redacted());

        // THEN the registrant emails should be preserved and existing remark kept
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some("registrant_123"));
        assert!(registrant.contact().is_some());

        if let Some(contact) = registrant.contact() {
            assert_eq!(contact.emails()[0].email, "charlie@example.com");
        }

        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);

        // Existing remark preserved, no duplicate added
        assert!(remarks[0].has_simple_redaction_key(REDACTED_EMAIL));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing redaction description".to_string())
        );
    }

    #[test]
    fn test_simplify_registrant_email_with_entity_with_multiple_roles_including_registrant() {
        // GIVEN an entity with multiple roles including registrant and contact with valid emails
        let email = Email::builder()
            .email("diana@example.com".to_string())
            .build();

        let contact = Contact::builder().emails(vec![email]).build();

        let multi_role_entity = Entity::builder()
            .handle("multi_role_123")
            .roles(vec![
                EntityRole::Technical.to_string(),
                EntityRole::Registrant.to_string(),
                EntityRole::Administrative.to_string(),
            ])
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![multi_role_entity])
            .build();

        // WHEN calling simplify_registrant_email
        let result = simplify_registrant_email(Box::new(domain), &get_test_redacted());

        // THEN the entity emails should NOT be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let entity = &entities[0];
        assert_eq!(entity.handle(), Some("multi_role_123"));
        assert!(entity.contact().is_some());

        if let Some(contact) = entity.contact() {
            assert_eq!(contact.emails()[0].email, "diana@example.com");
        }

        // No remark should be added
        assert!(entity.object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_tech_email_with_tech_entity_with_contact_and_emails() {
        // GIVEN a domain with a technical entity that has a contact with valid emails
        let email = Email::builder()
            .email("tech@example.com".to_string())
            .build();

        let contact = Contact::builder().emails(vec![email]).build();

        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![tech_entity])
            .build();

        // WHEN calling simplify_tech_email
        let result = simplify_tech_email(Box::new(domain), &get_test_redacted());

        // THEN the technical entity's contact emails should NOT be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let tech = &entities[0];
        assert_eq!(tech.handle(), Some("tech_456"));

        // Check that contact emails are preserved
        if let Some(contact) = tech.contact() {
            let emails = contact.emails();
            assert_eq!(emails.len(), 1);

            // Email should be preserved
            assert_eq!(emails[0].email, "tech@example.com");
        } else {
            panic!("Expected contact to be present");
        }

        // AND no remark should be added since emails are valid
        assert!(tech.object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_tech_email_with_tech_entity_no_contact() {
        // GIVEN a domain with a technical entity but no contact
        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![tech_entity])
            .build();

        // WHEN calling simplify_tech_email
        let result = simplify_tech_email(Box::new(domain), &get_test_redacted());

        // THEN the domain should be unchanged (no contact to modify)
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let tech = &entities[0];
        assert_eq!(tech.handle(), Some("tech_456"));
        assert!(tech.contact().is_none());
        assert!(tech.object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_tech_email_with_multiple_entities_first_is_tech_with_contact_and_emails() {
        // GIVEN a domain with multiple entities, first is technical with contact and valid emails
        let email = Email::builder()
            .email("jane.tech@example.com".to_string())
            .build();

        let contact = Contact::builder().emails(vec![email]).build();

        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .contact(contact)
            .build();

        let registrant_entity = Entity::builder()
            .handle("registrant_123")
            .role(EntityRole::Registrant.to_string())
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![tech_entity, registrant_entity])
            .build();

        // WHEN calling simplify_tech_email
        let result = simplify_tech_email(Box::new(domain), &get_test_redacted());

        // THEN the tech emails should NOT be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);

        // First entity (tech) should have preserved emails
        let tech = &entities[0];
        assert_eq!(tech.handle(), Some("tech_456"));
        assert!(tech.contact().is_some());

        if let Some(contact) = tech.contact() {
            assert_eq!(contact.emails()[0].email, "jane.tech@example.com");
        }

        // No remark should be added
        assert!(tech.object_common.remarks.is_none());

        // Second entity (registrant) should be unchanged
        assert_eq!(entities[1].handle(), Some("registrant_123"));
        assert!(entities[1].contact().is_none());
        assert!(entities[1].object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_tech_email_with_multiple_entities_tech_not_first() {
        // GIVEN a domain with multiple entities, tech is second with valid emails
        let email = Email::builder()
            .email("bob.tech@example.com".to_string())
            .build();

        let contact = Contact::builder().emails(vec![email]).build();

        let registrant_entity = Entity::builder()
            .handle("registrant_123")
            .role(EntityRole::Registrant.to_string())
            .build();

        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![registrant_entity, tech_entity])
            .build();

        // WHEN calling simplify_tech_email
        let result = simplify_tech_email(Box::new(domain), &get_test_redacted());

        // THEN the technical entity emails should NOT be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);

        // First entity (registrant) should be unchanged
        assert_eq!(entities[0].handle(), Some("registrant_123"));
        assert!(entities[0].contact().is_none());

        // Second entity (tech) should have preserved emails
        let tech = &entities[1];
        assert_eq!(tech.handle(), Some("tech_456"));
        assert!(tech.contact().is_some());

        if let Some(contact) = tech.contact() {
            assert_eq!(contact.emails()[0].email, "bob.tech@example.com");
        }

        // No remark should be added
        assert!(tech.object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_tech_email_with_no_tech_entity() {
        // GIVEN a domain with no technical entity
        let registrant_entity = Entity::builder()
            .handle("registrant_123")
            .role(EntityRole::Registrant.to_string())
            .build();

        let admin_entity = Entity::builder()
            .handle("admin_789")
            .role(EntityRole::Administrative.to_string())
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![registrant_entity, admin_entity])
            .build();

        // WHEN calling simplify_tech_email
        let result = simplify_tech_email(Box::new(domain), &get_test_redacted());

        // THEN no entities should be modified
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);
        assert_eq!(entities[0].handle(), Some("registrant_123"));
        assert_eq!(entities[1].handle(), Some("admin_789"));

        // AND no vcard_arrays or remarks should be added
        assert!(entities[0].contact().is_none());
        assert!(entities[1].contact().is_none());
        assert!(entities[0].object_common.remarks.is_none());
        assert!(entities[1].object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_tech_email_with_no_entities() {
        // GIVEN a domain with no entities
        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .build();

        // WHEN calling simplify_tech_email
        let result = simplify_tech_email(Box::new(domain), &get_test_redacted());

        // THEN the domain should be unchanged
        assert!(result.object_common.entities.is_none());
        assert_eq!(result.handle(), Some("example_com-1"));
    }

    #[test]
    fn test_simplify_tech_email_with_tech_entity_with_same_redaction_remark() {
        // GIVEN a technical entity with existing redaction remark and contact with valid emails
        let existing_remark = Remark::builder()
            .simple_redaction_keys(vec![REDACTED_EMAIL.to_string()])
            .description_entry("existing redaction description")
            .build();

        let email = Email::builder()
            .email("charlie.tech@example.com".to_string())
            .build();

        let contact = Contact::builder().emails(vec![email]).build();

        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .contact(contact)
            .remarks(vec![existing_remark])
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![tech_entity])
            .build();

        // WHEN calling simplify_tech_email
        let result = simplify_tech_email(Box::new(domain), &get_test_redacted());

        // THEN the technical emails should be preserved and existing remark kept
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let tech = &entities[0];
        assert_eq!(tech.handle(), Some("tech_456"));
        assert!(tech.contact().is_some());

        if let Some(contact) = tech.contact() {
            assert_eq!(contact.emails()[0].email, "charlie.tech@example.com");
        }

        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);

        // Existing remark preserved, no duplicate added
        assert!(remarks[0].has_simple_redaction_key(REDACTED_EMAIL));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing redaction description".to_string())
        );
    }

    #[test]
    fn test_simplify_tech_email_with_entity_with_multiple_roles_including_tech() {
        // GIVEN an entity with multiple roles including technical and contact with valid emails
        let email = Email::builder()
            .email("diana.tech@example.com".to_string())
            .build();

        let contact = Contact::builder().emails(vec![email]).build();

        let multi_role_entity = Entity::builder()
            .handle("multi_role_123")
            .roles(vec![
                EntityRole::Registrant.to_string(),
                EntityRole::Technical.to_string(),
                EntityRole::Administrative.to_string(),
            ])
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![multi_role_entity])
            .build();

        // WHEN calling simplify_tech_email
        let result = simplify_tech_email(Box::new(domain), &get_test_redacted());

        // THEN the entity emails should NOT be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let entity = &entities[0];
        assert_eq!(entity.handle(), Some("multi_role_123"));
        assert!(entity.contact().is_some());

        if let Some(contact) = entity.contact() {
            assert_eq!(contact.emails()[0].email, "diana.tech@example.com");
        }

        // No remark should be added
        assert!(entity.object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_tech_email_with_tech_entity_contact_no_emails() {
        // GIVEN a technical entity with contact but no emails
        let contact = Contact::builder().kind("individual").build();

        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![tech_entity])
            .build();

        // WHEN calling simplify_tech_email
        let result = simplify_tech_email(Box::new(domain), &get_test_redacted());

        // THEN the technical entity's contact should have vcard_array but no remark
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let tech = &entities[0];
        assert_eq!(tech.handle(), Some("tech_456"));
        assert!(tech.contact().is_some()); // vcard_array should be created
        assert!(tech.object_common.remarks.is_none()); // No remark since no emails to redact
    }

    #[test]
    fn test_simplify_registrant_email_with_empty_email_string() {
        // GIVEN a registrant entity with contact containing an empty email
        let email = Email::builder().email("".to_string()).build();

        let contact = Contact::builder().emails(vec![email]).build();

        let registrant_entity = Entity::builder()
            .handle("registrant_123")
            .role(EntityRole::Registrant.to_string())
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![registrant_entity])
            .build();

        // WHEN calling simplify_registrant_email
        let result = simplify_registrant_email(Box::new(domain), &get_test_redacted());

        // THEN the empty email should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some("registrant_123"));

        if let Some(contact) = registrant.contact() {
            let emails = contact.emails();
            assert_eq!(emails.len(), 1);
            assert_eq!(emails[0].email, REDACTED_EMAIL);
        } else {
            panic!("Expected contact to be present");
        }

        // AND a remark should be added
        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_EMAIL));
    }

    #[test]
    fn test_simplify_registrant_email_with_all_empty_emails() {
        // GIVEN a registrant entity with multiple contacts all having empty emails
        let email1 = Email::builder().email("".to_string()).build();

        let email2 = Email::builder().email("".to_string()).build();

        let contact = Contact::builder().emails(vec![email1, email2]).build();

        let registrant_entity = Entity::builder()
            .handle("registrant_123")
            .role(EntityRole::Registrant.to_string())
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![registrant_entity])
            .build();

        // WHEN calling simplify_registrant_email
        let result = simplify_registrant_email(Box::new(domain), &get_test_redacted());

        // THEN all empty emails should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some("registrant_123"));

        if let Some(contact) = registrant.contact() {
            let emails = contact.emails();
            assert_eq!(emails.len(), 2);
            for email in emails {
                assert_eq!(email.email, REDACTED_EMAIL);
            }
        } else {
            panic!("Expected contact to be present");
        }

        // AND a remark should be added
        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_EMAIL));
    }

    #[test]
    fn test_simplify_registrant_email_with_non_empty_email_preserved() {
        // GIVEN a registrant entity with contact containing a valid non-empty email
        let email = Email::builder()
            .email("valid@example.com".to_string())
            .build();

        let contact = Contact::builder().emails(vec![email]).build();

        let registrant_entity = Entity::builder()
            .handle("registrant_123")
            .role(EntityRole::Registrant.to_string())
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![registrant_entity])
            .build();

        // WHEN calling simplify_registrant_email
        let result = simplify_registrant_email(Box::new(domain), &get_test_redacted());

        // THEN the email should be preserved, not redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some("registrant_123"));

        if let Some(contact) = registrant.contact() {
            let emails = contact.emails();
            assert_eq!(emails.len(), 1);
            assert_eq!(emails[0].email, "valid@example.com");
        } else {
            panic!("Expected contact to be present");
        }

        // AND no remark should be added
        assert!(registrant.object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_tech_email_with_empty_email_string() {
        // GIVEN a technical entity with contact containing an empty email
        let email = Email::builder().email("".to_string()).build();

        let contact = Contact::builder().emails(vec![email]).build();

        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![tech_entity])
            .build();

        // WHEN calling simplify_tech_email
        let result = simplify_tech_email(Box::new(domain), &get_test_redacted());

        // THEN the empty email should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let tech = &entities[0];
        assert_eq!(tech.handle(), Some("tech_456"));

        if let Some(contact) = tech.contact() {
            let emails = contact.emails();
            assert_eq!(emails.len(), 1);
            assert_eq!(emails[0].email, REDACTED_EMAIL);
        } else {
            panic!("Expected contact to be present");
        }

        // AND a remark should be added
        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_EMAIL));
    }

    #[test]
    fn test_simplify_tech_email_with_non_empty_email_preserved() {
        // GIVEN a technical entity with contact containing a valid non-empty email
        let email = Email::builder()
            .email("valid@example.com".to_string())
            .build();

        let contact = Contact::builder().emails(vec![email]).build();

        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![tech_entity])
            .build();

        // WHEN calling simplify_tech_email
        let result = simplify_tech_email(Box::new(domain), &get_test_redacted());

        // THEN the email should be preserved, not redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let tech = &entities[0];
        assert_eq!(tech.handle(), Some("tech_456"));

        if let Some(contact) = tech.contact() {
            let emails = contact.emails();
            assert_eq!(emails.len(), 1);
            assert_eq!(emails[0].email, "valid@example.com");
        } else {
            panic!("Expected contact to be present");
        }

        // AND no remark should be added
        assert!(tech.object_common.remarks.is_none());
    }
}
