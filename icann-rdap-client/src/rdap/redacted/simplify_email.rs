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
                    if !emails.is_empty() {
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
        // GIVEN a domain with a registrant entity that has a contact with emails
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

        // THEN the registrant's contact emails should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some("registrant_123"));

        // Check that contact emails were updated with redacted emails
        if let Some(contact) = registrant.contact() {
            let emails = contact.emails();
            assert_eq!(emails.len(), 2);

            // Both emails should be redacted
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
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&REDACTED_EMAIL_DESC.to_string())
        );
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
        // GIVEN a domain with multiple entities, first is registrant with contact and emails
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

        // THEN only the first registrant should be modified
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);

        // First entity (registrant) should have redacted emails
        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some("registrant_123"));
        assert!(registrant.contact().is_some());

        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_EMAIL));

        // Second entity (tech) should be unchanged
        assert_eq!(entities[1].handle(), Some("tech_456"));
        assert!(entities[1].contact().is_none());
        assert!(entities[1].object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_registrant_email_with_multiple_entities_registrant_not_first() {
        // GIVEN a domain with multiple entities, registrant is second
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

        // THEN the registrant entity should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);

        // First entity (tech) should be unchanged
        assert_eq!(entities[0].handle(), Some("tech_456"));
        assert!(entities[0].contact().is_none());

        // Second entity (registrant) should have redacted emails
        let registrant = &entities[1];
        assert_eq!(registrant.handle(), Some("registrant_123"));
        assert!(registrant.contact().is_some());

        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_EMAIL));
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
        // GIVEN a registrant entity with existing redaction remark and contact with emails
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

        // THEN the registrant should not have duplicate redaction remark
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some("registrant_123"));
        assert!(registrant.contact().is_some());

        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);

        // Should only have the existing remark (no duplicate)
        assert!(remarks[0].has_simple_redaction_key(REDACTED_EMAIL));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing redaction description".to_string())
        );
    }

    #[test]
    fn test_simplify_registrant_email_with_entity_with_multiple_roles_including_registrant() {
        // GIVEN an entity with multiple roles including registrant and contact with emails
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

        // THEN the entity should be redacted (it has registrant role)
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let entity = &entities[0];
        assert_eq!(entity.handle(), Some("multi_role_123"));
        assert!(entity.contact().is_some());

        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_EMAIL));
    }

    #[test]
    fn test_simplify_tech_email_with_tech_entity_with_contact_and_emails() {
        // GIVEN a domain with a technical entity that has a contact with emails
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

        // THEN the technical entity's contact emails should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let tech = &entities[0];
        assert_eq!(tech.handle(), Some("tech_456"));

        // Check that contact emails were updated with redacted emails
        if let Some(contact) = tech.contact() {
            let emails = contact.emails();
            assert_eq!(emails.len(), 1);

            // Email should be redacted
            assert_eq!(emails[0].email, REDACTED_EMAIL);
        } else {
            panic!("Expected contact to be present");
        }

        // AND a remark should be added
        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_EMAIL));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&REDACTED_EMAIL_DESC.to_string())
        );
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
        // GIVEN a domain with multiple entities, first is technical with contact and emails
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

        // THEN only the first technical entity should be modified
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);

        // First entity (tech) should have redacted emails
        let tech = &entities[0];
        assert_eq!(tech.handle(), Some("tech_456"));
        assert!(tech.contact().is_some());

        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_EMAIL));

        // Second entity (registrant) should be unchanged
        assert_eq!(entities[1].handle(), Some("registrant_123"));
        assert!(entities[1].contact().is_none());
        assert!(entities[1].object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_tech_email_with_multiple_entities_tech_not_first() {
        // GIVEN a domain with multiple entities, tech is second
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

        // THEN the technical entity should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);

        // First entity (registrant) should be unchanged
        assert_eq!(entities[0].handle(), Some("registrant_123"));
        assert!(entities[0].contact().is_none());

        // Second entity (tech) should have redacted emails
        let tech = &entities[1];
        assert_eq!(tech.handle(), Some("tech_456"));
        assert!(tech.contact().is_some());

        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_EMAIL));
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
        // GIVEN a technical entity with existing redaction remark and contact with emails
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

        // THEN the technical entity should not have duplicate redaction remark
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let tech = &entities[0];
        assert_eq!(tech.handle(), Some("tech_456"));
        assert!(tech.contact().is_some());

        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);

        // Should only have the existing remark (no duplicate)
        assert!(remarks[0].has_simple_redaction_key(REDACTED_EMAIL));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing redaction description".to_string())
        );
    }

    #[test]
    fn test_simplify_tech_email_with_entity_with_multiple_roles_including_tech() {
        // GIVEN an entity with multiple roles including technical and contact with emails
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

        // THEN the entity should be redacted (it has technical role)
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let entity = &entities[0];
        assert_eq!(entity.handle(), Some("multi_role_123"));
        assert!(entity.contact().is_some());

        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_EMAIL));
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
}
