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
    use rstest::rstest;

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

    fn multi_email_domain(roles: &[EntityRole], emails: &[&str], handles: &[&str]) -> Box<Domain> {
        let entities: Vec<Entity> = roles
            .iter()
            .zip(handles.iter())
            .map(|(role, handle)| {
                let contact = if emails.is_empty() {
                    Contact::builder().full_name("Test User").build()
                } else {
                    let idx = roles.iter().position(|r| r == role).unwrap();
                    let email_obj = Email::builder().email(emails[idx].to_string()).build();
                    Contact::builder().emails(vec![email_obj]).build()
                };
                Entity::builder()
                    .handle(handle.to_string())
                    .role(role.to_string())
                    .contact(contact)
                    .build()
            })
            .collect();
        Box::new(
            Domain::builder()
                .ldh_name("example.com")
                .handle("example_com-1")
                .entities(entities)
                .build(),
        )
    }

    fn empty_email_domain(role: EntityRole, handle: &str) -> Box<Domain> {
        let email_obj = Email::builder().email("".to_string()).build();
        let contact = Contact::builder().emails(vec![email_obj]).build();
        let entity = Entity::builder()
            .handle(handle.to_string())
            .role(role.to_string())
            .contact(contact)
            .build();
        Box::new(
            Domain::builder()
                .ldh_name("example.com")
                .handle("example_com-1")
                .entities(vec![entity])
                .build(),
        )
    }

    fn multi_empty_email_domain(role: EntityRole, handle: &str) -> Box<Domain> {
        let email1 = Email::builder().email("".to_string()).build();
        let email2 = Email::builder().email("".to_string()).build();
        let contact = Contact::builder().emails(vec![email1, email2]).build();
        let entity = Entity::builder()
            .handle(handle.to_string())
            .role(role.to_string())
            .contact(contact)
            .build();
        Box::new(
            Domain::builder()
                .ldh_name("example.com")
                .handle("example_com-1")
                .entities(vec![entity])
                .build(),
        )
    }

    fn no_contact_domain(role: EntityRole, handle: &str) -> Box<Domain> {
        let entity = Entity::builder()
            .handle(handle.to_string())
            .role(role.to_string())
            .build();
        Box::new(
            Domain::builder()
                .ldh_name("example.com")
                .handle("example_com-1")
                .entities(vec![entity])
                .build(),
        )
    }

    fn no_email_contact_domain(role: EntityRole, handle: &str) -> Box<Domain> {
        let contact = Contact::builder().kind("individual").build();
        let entity = Entity::builder()
            .handle(handle.to_string())
            .role(role.to_string())
            .contact(contact)
            .build();
        Box::new(
            Domain::builder()
                .ldh_name("example.com")
                .handle("example_com-1")
                .entities(vec![entity])
                .build(),
        )
    }

    fn no_matching_entity_domain(mismatched_roles: &[EntityRole], handles: &[&str]) -> Box<Domain> {
        let entities: Vec<Entity> = mismatched_roles
            .iter()
            .zip(handles.iter())
            .map(|(role, handle)| {
                Entity::builder()
                    .handle(handle.to_string())
                    .role(role.to_string())
                    .build()
            })
            .collect();
        Box::new(
            Domain::builder()
                .ldh_name("example.com")
                .handle("example_com-1")
                .entities(entities)
                .build(),
        )
    }

    fn no_entities_domain() -> Box<Domain> {
        Box::new(
            Domain::builder()
                .ldh_name("example.com")
                .handle("example_com-1")
                .build(),
        )
    }

    fn multi_role_domain(role: EntityRole, handle: &str) -> Box<Domain> {
        let email_obj = Email::builder()
            .email("multi@example.com".to_string())
            .build();
        let contact = Contact::builder().emails(vec![email_obj]).build();
        let entity = Entity::builder()
            .handle(handle.to_string())
            .roles(vec![
                EntityRole::Registrant.to_string(),
                role.to_string(),
                EntityRole::Administrative.to_string(),
            ])
            .contact(contact)
            .build();
        Box::new(
            Domain::builder()
                .ldh_name("example.com")
                .handle("example_com-1")
                .entities(vec![entity])
                .build(),
        )
    }

    fn existing_remark_domain(role: EntityRole, handle: &str, email: &str) -> Box<Domain> {
        let existing_remark = Remark::builder()
            .simple_redaction_keys(vec![REDACTED_EMAIL.to_string()])
            .description_entry("existing redaction description")
            .build();
        let email_obj = Email::builder().email(email.to_string()).build();
        let contact = Contact::builder().emails(vec![email_obj]).build();
        let entity = Entity::builder()
            .handle(handle.to_string())
            .role(role.to_string())
            .contact(contact)
            .remarks(vec![existing_remark])
            .build();
        Box::new(
            Domain::builder()
                .ldh_name("example.com")
                .handle("example_com-1")
                .entities(vec![entity])
                .build(),
        )
    }

    fn first_is_target_domain(
        target_email: &str,
        target_role: EntityRole,
        target_handle: &str,
        other_role: EntityRole,
        other_handle: &str,
    ) -> Box<Domain> {
        let target_contact = Contact::builder()
            .emails(vec![Email::builder()
                .email(target_email.to_string())
                .build()])
            .build();
        let target_entity = Entity::builder()
            .handle(target_handle.to_string())
            .role(target_role.to_string())
            .contact(target_contact)
            .build();
        let other_entity = Entity::builder()
            .handle(other_handle.to_string())
            .role(other_role.to_string())
            .build();
        Box::new(
            Domain::builder()
                .ldh_name("example.com")
                .handle("example_com-1")
                .entities(vec![target_entity, other_entity])
                .build(),
        )
    }

    fn second_is_target_domain(
        target_email: &str,
        target_role: EntityRole,
        target_handle: &str,
        other_role: EntityRole,
        other_handle: &str,
    ) -> Box<Domain> {
        let other_entity = Entity::builder()
            .handle(other_handle.to_string())
            .role(other_role.to_string())
            .build();
        let target_contact = Contact::builder()
            .emails(vec![Email::builder()
                .email(target_email.to_string())
                .build()])
            .build();
        let target_entity = Entity::builder()
            .handle(target_handle.to_string())
            .role(target_role.to_string())
            .contact(target_contact)
            .build();
        Box::new(
            Domain::builder()
                .ldh_name("example.com")
                .handle("example_com-1")
                .entities(vec![other_entity, target_entity])
                .build(),
        )
    }

    #[rstest]
    #[case(
        "john@example.com",
        EntityRole::Registrant,
        "registrant_123",
        simplify_registrant_email
    )]
    #[case(
        "tech@example.com",
        EntityRole::Technical,
        "tech_456",
        simplify_tech_email
    )]
    fn valid_emails_preserved(
        #[case] email: &str,
        #[case] role: EntityRole,
        #[case] handle: &str,
        #[case] func: fn(Box<Domain>, &Redacted) -> Box<Domain>,
    ) {
        // GIVEN a domain with an entity that has a contact with valid emails
        let domain = multi_email_domain(&[role], &[email], &[handle]);

        // WHEN calling the simplify function
        let result = func(domain, &get_test_redacted());

        // THEN the entity's contact emails should NOT be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let entity = &entities[0];
        assert_eq!(entity.handle(), Some(handle));

        if let Some(contact) = entity.contact() {
            let emails = contact.emails();
            assert_eq!(emails.len(), 1);
            assert_eq!(emails[0].email, email);
        } else {
            panic!("Expected contact to be present");
        }

        // AND no remark should be added since emails are valid
        assert!(entity.object_common.remarks.is_none());
    }

    #[rstest]
    #[case(EntityRole::Registrant, "registrant_123", simplify_registrant_email)]
    #[case(EntityRole::Technical, "tech_456", simplify_tech_email)]
    fn empty_email_redacted(
        #[case] role: EntityRole,
        #[case] handle: &str,
        #[case] func: fn(Box<Domain>, &Redacted) -> Box<Domain>,
    ) {
        // GIVEN an entity with contact containing an empty email
        let domain = empty_email_domain(role, handle);

        // WHEN calling the simplify function
        let result = func(domain, &get_test_redacted());

        // THEN the empty email should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let entity = &entities[0];
        assert_eq!(entity.handle(), Some(handle));

        if let Some(contact) = entity.contact() {
            let emails = contact.emails();
            assert_eq!(emails.len(), 1);
            assert_eq!(emails[0].email, REDACTED_EMAIL);
        } else {
            panic!("Expected contact to be present");
        }

        // AND a remark should be added
        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_EMAIL));
    }

    #[rstest]
    #[case(EntityRole::Registrant, "registrant_123", simplify_registrant_email)]
    #[case(EntityRole::Technical, "tech_456", simplify_tech_email)]
    fn no_contact_no_change(
        #[case] role: EntityRole,
        #[case] handle: &str,
        #[case] func: fn(Box<Domain>, &Redacted) -> Box<Domain>,
    ) {
        // GIVEN an entity but no contact
        let domain = no_contact_domain(role, handle);

        // WHEN calling the simplify function
        let result = func(domain, &get_test_redacted());

        // THEN the domain should be unchanged
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let entity = &entities[0];
        assert_eq!(entity.handle(), Some(handle));
        assert!(entity.contact().is_none());
        assert!(entity.object_common.remarks.is_none());
    }

    #[rstest]
    #[case(EntityRole::Registrant, "registrant_123", simplify_registrant_email)]
    #[case(EntityRole::Technical, "tech_456", simplify_tech_email)]
    fn no_emails_in_contact_no_change(
        #[case] role: EntityRole,
        #[case] handle: &str,
        #[case] func: fn(Box<Domain>, &Redacted) -> Box<Domain>,
    ) {
        // GIVEN an entity with contact but no emails
        let domain = no_email_contact_domain(role, handle);

        // WHEN calling the simplify function
        let result = func(domain, &get_test_redacted());

        // THEN the contact should be preserved but no remark added
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let entity = &entities[0];
        assert_eq!(entity.handle(), Some(handle));
        assert!(entity.contact().is_some());
        assert!(entity.object_common.remarks.is_none());
    }

    #[rstest]
    #[case(EntityRole::Registrant, simplify_registrant_email)]
    #[case(EntityRole::Technical, simplify_tech_email)]
    fn no_matching_entity_no_change(
        #[case] _target_role: EntityRole,
        #[case] func: fn(Box<Domain>, &Redacted) -> Box<Domain>,
    ) {
        // GIVEN a domain with no entity matching the target role
        let domain = no_matching_entity_domain(
            &[EntityRole::Technical, EntityRole::Administrative],
            &["tech_456", "admin_789"],
        );

        // WHEN calling the simplify function
        let result = func(domain, &get_test_redacted());

        // THEN no entities should be modified
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);
        assert_eq!(entities[0].handle(), Some("tech_456"));
        assert_eq!(entities[1].handle(), Some("admin_789"));
        assert!(entities[0].contact().is_none());
        assert!(entities[1].contact().is_none());
        assert!(entities[0].object_common.remarks.is_none());
        assert!(entities[1].object_common.remarks.is_none());
    }

    #[rstest]
    #[case(EntityRole::Registrant, simplify_registrant_email)]
    #[case(EntityRole::Technical, simplify_tech_email)]
    fn no_entities_no_change(
        #[case] _role: EntityRole,
        #[case] func: fn(Box<Domain>, &Redacted) -> Box<Domain>,
    ) {
        // GIVEN a domain with no entities
        let domain = no_entities_domain();

        // WHEN calling the simplify function
        let result = func(domain, &get_test_redacted());

        // THEN the domain should be unchanged
        assert!(result.object_common.entities.is_none());
        assert_eq!(result.handle(), Some("example_com-1"));
    }

    #[rstest]
    #[case("registrant_123", EntityRole::Registrant, simplify_registrant_email)]
    #[case("tech_456", EntityRole::Technical, simplify_tech_email)]
    fn existing_remark_preserved(
        #[case] handle: &str,
        #[case] role: EntityRole,
        #[case] func: fn(Box<Domain>, &Redacted) -> Box<Domain>,
    ) {
        // GIVEN an entity with existing redaction remark and valid emails
        let domain = existing_remark_domain(role, handle, "charlie@example.com");

        // WHEN calling the simplify function
        let result = func(domain, &get_test_redacted());

        // THEN the emails should be preserved and existing remark kept
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let entity = &entities[0];
        assert_eq!(entity.handle(), Some(handle));
        assert!(entity.contact().is_some());

        if let Some(contact) = entity.contact() {
            assert_eq!(contact.emails()[0].email, "charlie@example.com");
        }

        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_EMAIL));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing redaction description".to_string())
        );
    }

    #[rstest]
    #[case(EntityRole::Registrant, "multi_role_123", simplify_registrant_email)]
    #[case(EntityRole::Technical, "multi_role_123", simplify_tech_email)]
    fn multi_role_email_preserved(
        #[case] role: EntityRole,
        #[case] handle: &str,
        #[case] func: fn(Box<Domain>, &Redacted) -> Box<Domain>,
    ) {
        // GIVEN an entity with multiple roles including the target role
        let domain = multi_role_domain(role, handle);

        // WHEN calling the simplify function
        let result = func(domain, &get_test_redacted());

        // THEN the entity emails should NOT be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let entity = &entities[0];
        assert_eq!(entity.handle(), Some(handle));
        assert!(entity.contact().is_some());

        if let Some(contact) = entity.contact() {
            assert_eq!(contact.emails()[0].email, "multi@example.com");
        }

        // No remark should be added
        assert!(entity.object_common.remarks.is_none());
    }

    #[rstest]
    #[case(
        "jane@example.com",
        EntityRole::Registrant,
        "registrant_123",
        EntityRole::Technical,
        "tech_456",
        simplify_registrant_email
    )]
    #[case(
        "jane.tech@example.com",
        EntityRole::Technical,
        "tech_456",
        EntityRole::Registrant,
        "registrant_123",
        simplify_tech_email
    )]
    fn first_is_target(
        #[case] email: &str,
        #[case] target_role: EntityRole,
        #[case] target_handle: &str,
        #[case] other_role: EntityRole,
        #[case] other_handle: &str,
        #[case] func: fn(Box<Domain>, &Redacted) -> Box<Domain>,
    ) {
        // GIVEN a domain with multiple entities, first is the target with valid emails
        let domain =
            first_is_target_domain(email, target_role, target_handle, other_role, other_handle);

        // WHEN calling the simplify function
        let result = func(domain, &get_test_redacted());

        // THEN the target emails should NOT be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);

        let target = &entities[0];
        assert_eq!(target.handle(), Some(target_handle));
        assert!(target.contact().is_some());

        if let Some(contact) = target.contact() {
            assert_eq!(contact.emails()[0].email, email);
        }

        // No remark should be added
        assert!(target.object_common.remarks.is_none());

        // Second entity should be unchanged
        assert_eq!(entities[1].handle(), Some(other_handle));
        assert!(entities[1].contact().is_none());
        assert!(entities[1].object_common.remarks.is_none());
    }

    #[rstest]
    #[case(
        "bob@example.com",
        EntityRole::Registrant,
        "registrant_123",
        EntityRole::Technical,
        "tech_456",
        simplify_registrant_email
    )]
    #[case(
        "bob.tech@example.com",
        EntityRole::Technical,
        "tech_456",
        EntityRole::Registrant,
        "registrant_123",
        simplify_tech_email
    )]
    fn second_is_target(
        #[case] email: &str,
        #[case] target_role: EntityRole,
        #[case] target_handle: &str,
        #[case] other_role: EntityRole,
        #[case] other_handle: &str,
        #[case] func: fn(Box<Domain>, &Redacted) -> Box<Domain>,
    ) {
        // GIVEN a domain with multiple entities, target is second with valid emails
        let domain =
            second_is_target_domain(email, target_role, target_handle, other_role, other_handle);

        // WHEN calling the simplify function
        let result = func(domain, &get_test_redacted());

        // THEN the target emails should NOT be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);

        // First entity should be unchanged
        assert_eq!(entities[0].handle(), Some(other_handle));
        assert!(entities[0].contact().is_none());

        // Second entity (target) should have preserved emails
        let target = &entities[1];
        assert_eq!(target.handle(), Some(target_handle));
        assert!(target.contact().is_some());

        if let Some(contact) = target.contact() {
            assert_eq!(contact.emails()[0].email, email);
        }

        // No remark should be added
        assert!(target.object_common.remarks.is_none());
    }

    #[test]
    fn multi_empty_emails_all_redacted() {
        // GIVEN a registrant entity with multiple contacts all having empty emails
        let domain = multi_empty_email_domain(EntityRole::Registrant, "registrant_123");

        // WHEN calling simplify_registrant_email
        let result = simplify_registrant_email(domain, &get_test_redacted());

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
}
