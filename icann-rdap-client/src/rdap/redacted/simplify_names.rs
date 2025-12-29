//! Simplify redaction of names

use icann_rdap_common::prelude::{redacted::Redacted, Domain, EntityRole};

use crate::rdap::redacted::add_remark;

static REDACTED_NAME: &str = "////REDACTED_NAME////";
static REDACTED_NAME_DESC: &str = "Name redacted.";

pub(crate) fn simplify_registrant_name(
    mut domain: Box<Domain>,
    redaction: &Redacted,
) -> Box<Domain> {
    if let Some(entities) = &mut domain.object_common.entities {
        for entity in entities.iter_mut() {
            if entity.is_entity_role(&EntityRole::Registrant.to_string()) {
                let contact = entity.contact();
                if let Some(mut contact) = contact {
                    // First redact the main full name
                    contact = contact.set_full_name(REDACTED_NAME.to_string());

                    // Now redact full names in all localizations using mutable iterator
                    for (_lang, localizable) in contact.localizations_iter_mut() {
                        *localizable = localizable.clone().set_full_name(REDACTED_NAME.to_string());
                    }

                    entity.set_contact_if_vcard(&contact);
                    entity.set_contact_if_jscontact(&contact);
                    entity.object_common.remarks = add_remark(
                        REDACTED_NAME,
                        REDACTED_NAME_DESC,
                        redaction,
                        entity.object_common.remarks.clone(),
                    );
                    break; // Only modify first registrant
                }
            }
        }
    }
    domain
}

pub(crate) fn simplify_tech_name(mut domain: Box<Domain>, redaction: &Redacted) -> Box<Domain> {
    if let Some(entities) = &mut domain.object_common.entities {
        for entity in entities.iter_mut() {
            if entity.is_entity_role(&EntityRole::Technical.to_string()) {
                let contact = entity.contact();
                if let Some(mut contact) = contact {
                    // First redact main full name
                    contact = contact.set_full_name(REDACTED_NAME.to_string());

                    // Now redact full names in all localizations using mutable iterator
                    for (_lang, localizable) in contact.localizations_iter_mut() {
                        *localizable = localizable.clone().set_full_name(REDACTED_NAME.to_string());
                    }

                    entity.set_contact_if_vcard(&contact);
                    entity.set_contact_if_jscontact(&contact);
                    entity.object_common.remarks = add_remark(
                        REDACTED_NAME,
                        REDACTED_NAME_DESC,
                        redaction,
                        entity.object_common.remarks.clone(),
                    );
                    break; // Only modify first tech
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
    use icann_rdap_common::prelude::{Contact, Entity};
    use icann_rdap_common::response::ObjectCommonFields;

    use super::*;

    fn get_test_redacted() -> Redacted {
        Redacted::builder()
            .name(Name::builder().type_field("Tech Email").build())
            .build()
    }

    #[test]
    fn test_simplify_registrant_name_with_registrant_entity_with_contact() {
        // GIVEN a domain with a registrant entity that has a contact with full name
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

        // WHEN calling simplify_registrant_name
        let result = simplify_registrant_name(Box::new(domain), &get_test_redacted());

        // THEN the registrant's contact full name should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some("registrant_123"));

        // Check that contact full name was updated with redacted name
        if let Some(contact) = registrant.contact() {
            assert_eq!(contact.full_name(), Some(REDACTED_NAME));
        } else {
            panic!("Expected contact to be present");
        }

        // AND a remark should be added
        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_NAME));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&REDACTED_NAME_DESC.to_string())
        );
    }

    #[test]
    fn test_simplify_registrant_name_with_registrant_entity_no_contact() {
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

        // WHEN calling simplify_registrant_name
        let result = simplify_registrant_name(Box::new(domain), &get_test_redacted());

        // THEN the domain should be unchanged (no contact to modify)
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some("registrant_123"));
        assert!(registrant.contact().is_none());
        assert!(registrant.object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_registrant_name_with_multiple_entities_first_is_registrant_with_contact() {
        // GIVEN a domain with multiple entities, first is registrant with contact
        let contact = Contact::builder().full_name("Jane Smith").build();

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

        // WHEN calling simplify_registrant_name
        let result = simplify_registrant_name(Box::new(domain), &get_test_redacted());

        // THEN only the first registrant should be modified
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);

        // First entity (registrant) should have redacted name
        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some("registrant_123"));
        assert!(registrant.contact().is_some());

        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_NAME));

        // Second entity (tech) should be unchanged
        assert_eq!(entities[1].handle(), Some("tech_456"));
        assert!(entities[1].contact().is_none());
        assert!(entities[1].object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_registrant_name_with_multiple_entities_registrant_not_first() {
        // GIVEN a domain with multiple entities, registrant is second
        let contact = Contact::builder().full_name("Bob Johnson").build();

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

        // WHEN calling simplify_registrant_name
        let result = simplify_registrant_name(Box::new(domain), &get_test_redacted());

        // THEN the registrant entity should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);

        // First entity (tech) should be unchanged
        assert_eq!(entities[0].handle(), Some("tech_456"));
        assert!(entities[0].contact().is_none());

        // Second entity (registrant) should have redacted name
        let registrant = &entities[1];
        assert_eq!(registrant.handle(), Some("registrant_123"));
        assert!(registrant.contact().is_some());

        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_NAME));
    }

    #[test]
    fn test_simplify_registrant_name_with_no_registrant_entity() {
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

        // WHEN calling simplify_registrant_name
        let result = simplify_registrant_name(Box::new(domain), &get_test_redacted());

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
    fn test_simplify_registrant_name_with_no_entities() {
        // GIVEN a domain with no entities
        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .build();

        // WHEN calling simplify_registrant_name
        let result = simplify_registrant_name(Box::new(domain), &get_test_redacted());

        // THEN the domain should be unchanged
        assert!(result.object_common.entities.is_none());
        assert_eq!(result.handle(), Some("example_com-1"));
    }

    #[test]
    fn test_simplify_registrant_name_with_registrant_entity_with_same_redaction_remark() {
        // GIVEN a registrant entity with existing redaction remark and contact
        let existing_remark = Remark::builder()
            .simple_redaction_keys(vec![REDACTED_NAME.to_string()])
            .description_entry("existing redaction description")
            .build();

        let contact = Contact::builder().full_name("Charlie Brown").build();

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

        // WHEN calling simplify_registrant_name
        let result = simplify_registrant_name(Box::new(domain), &get_test_redacted());

        // THEN the registrant should not have duplicate redaction remark
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some("registrant_123"));
        assert!(registrant.contact().is_some());

        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);

        // Should only have the existing remark (no duplicate)
        assert!(remarks[0].has_simple_redaction_key(REDACTED_NAME));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing redaction description".to_string())
        );
    }

    #[test]
    fn test_simplify_registrant_name_with_entity_with_multiple_roles_including_registrant() {
        // GIVEN an entity with multiple roles including registrant and contact
        let contact = Contact::builder().full_name("Diana Prince").build();

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

        // WHEN calling simplify_registrant_name
        let result = simplify_registrant_name(Box::new(domain), &get_test_redacted());

        // THEN the entity should be redacted (it has registrant role)
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let entity = &entities[0];
        assert_eq!(entity.handle(), Some("multi_role_123"));
        assert!(entity.contact().is_some());

        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_NAME));
    }

    #[test]
    fn test_simplify_registrant_name_with_registrant_entity_contact_no_full_name() {
        // GIVEN a registrant entity with contact but no full name
        let contact = Contact::builder().kind("individual").build();

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

        // WHEN calling simplify_registrant_name
        let result = simplify_registrant_name(Box::new(domain), &get_test_redacted());

        // THEN the registrant's contact should have redacted full name
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some("registrant_123"));
        assert!(registrant.contact().is_some());

        // Check that contact full name was updated with redacted name
        if let Some(contact) = registrant.contact() {
            assert_eq!(contact.full_name(), Some(REDACTED_NAME));
        } else {
            panic!("Expected contact to be present");
        }

        // AND a remark should be added
        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_NAME));
    }

    #[test]
    fn test_simplify_tech_name_with_tech_entity_with_contact() {
        // GIVEN a domain with a technical entity that has a contact with full name
        let contact = Contact::builder().full_name("John Tech").build();

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

        // WHEN calling simplify_tech_name
        let result = simplify_tech_name(Box::new(domain), &get_test_redacted());

        // THEN the technical entity's contact full name should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let tech = &entities[0];
        assert_eq!(tech.handle(), Some("tech_456"));

        // Check that contact full name was updated with redacted name
        if let Some(contact) = tech.contact() {
            assert_eq!(contact.full_name(), Some(REDACTED_NAME));
        } else {
            panic!("Expected contact to be present");
        }

        // AND a remark should be added
        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_NAME));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&REDACTED_NAME_DESC.to_string())
        );
    }

    #[test]
    fn test_simplify_tech_name_with_tech_entity_no_contact() {
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

        // WHEN calling simplify_tech_name
        let result = simplify_tech_name(Box::new(domain), &get_test_redacted());

        // THEN the domain should be unchanged (no contact to modify)
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let tech = &entities[0];
        assert_eq!(tech.handle(), Some("tech_456"));
        assert!(tech.contact().is_none());
        assert!(tech.object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_tech_name_with_multiple_entities_first_is_tech_with_contact() {
        // GIVEN a domain with multiple entities, first is technical with contact
        let contact = Contact::builder().full_name("Jane Tech").build();

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

        // WHEN calling simplify_tech_name
        let result = simplify_tech_name(Box::new(domain), &get_test_redacted());

        // THEN only the first technical entity should be modified
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);

        // First entity (tech) should have redacted name
        let tech = &entities[0];
        assert_eq!(tech.handle(), Some("tech_456"));
        assert!(tech.contact().is_some());

        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_NAME));

        // Second entity (registrant) should be unchanged
        assert_eq!(entities[1].handle(), Some("registrant_123"));
        assert!(entities[1].contact().is_none());
        assert!(entities[1].object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_tech_name_with_multiple_entities_tech_not_first() {
        // GIVEN a domain with multiple entities, tech is second
        let contact = Contact::builder().full_name("Bob Tech").build();

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

        // WHEN calling simplify_tech_name
        let result = simplify_tech_name(Box::new(domain), &get_test_redacted());

        // THEN the technical entity should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);

        // First entity (registrant) should be unchanged
        assert_eq!(entities[0].handle(), Some("registrant_123"));
        assert!(entities[0].contact().is_none());

        // Second entity (tech) should have redacted name
        let tech = &entities[1];
        assert_eq!(tech.handle(), Some("tech_456"));
        assert!(tech.contact().is_some());

        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_NAME));
    }

    #[test]
    fn test_simplify_tech_name_with_no_tech_entity() {
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

        // WHEN calling simplify_tech_name
        let result = simplify_tech_name(Box::new(domain), &get_test_redacted());

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
    fn test_simplify_tech_name_with_no_entities() {
        // GIVEN a domain with no entities
        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .build();

        // WHEN calling simplify_tech_name
        let result = simplify_tech_name(Box::new(domain), &get_test_redacted());

        // THEN the domain should be unchanged
        assert!(result.object_common.entities.is_none());
        assert_eq!(result.handle(), Some("example_com-1"));
    }

    #[test]
    fn test_simplify_tech_name_with_tech_entity_with_same_redaction_remark() {
        // GIVEN a technical entity with existing redaction remark and contact
        let existing_remark = Remark::builder()
            .simple_redaction_keys(vec![REDACTED_NAME.to_string()])
            .description_entry("existing redaction description")
            .build();

        let contact = Contact::builder().full_name("Charlie Tech").build();

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

        // WHEN calling simplify_tech_name
        let result = simplify_tech_name(Box::new(domain), &get_test_redacted());

        // THEN the technical entity should not have duplicate redaction remark
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let tech = &entities[0];
        assert_eq!(tech.handle(), Some("tech_456"));
        assert!(tech.contact().is_some());

        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);

        // Should only have the existing remark (no duplicate)
        assert!(remarks[0].has_simple_redaction_key(REDACTED_NAME));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing redaction description".to_string())
        );
    }

    #[test]
    fn test_simplify_tech_name_with_entity_with_multiple_roles_including_tech() {
        // GIVEN an entity with multiple roles including technical and contact
        let contact = Contact::builder().full_name("Diana Tech").build();

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

        // WHEN calling simplify_tech_name
        let result = simplify_tech_name(Box::new(domain), &get_test_redacted());

        // THEN the entity should be redacted (it has technical role)
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let entity = &entities[0];
        assert_eq!(entity.handle(), Some("multi_role_123"));
        assert!(entity.contact().is_some());

        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_NAME));
    }

    #[test]
    fn test_simplify_tech_name_with_tech_entity_contact_no_full_name() {
        // GIVEN a technical entity with contact but no full name
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

        // WHEN calling simplify_tech_name
        let result = simplify_tech_name(Box::new(domain), &get_test_redacted());

        // THEN the technical entity's contact should have redacted full name
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let tech = &entities[0];
        assert_eq!(tech.handle(), Some("tech_456"));
        assert!(tech.contact().is_some());

        // Check that contact full name was updated with redacted name
        if let Some(contact) = tech.contact() {
            assert_eq!(contact.full_name(), Some(REDACTED_NAME));
        } else {
            panic!("Expected contact to be present");
        }

        // AND a remark should be added
        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_NAME));
    }

    #[test]
    fn test_simplify_registrant_name_with_registrant_entity_with_localizations() {
        // GIVEN a registrant entity with contact and localizations with different full names
        let mut contact = Contact::builder().full_name("John Doe").build();

        // Add a French localization with different full name
        let fr_localization = icann_rdap_common::contact::Localizable::builder()
            .full_name("Jean Dupont")
            .build();
        contact = contact.set_localization("fr".to_string(), fr_localization);

        // Add a Spanish localization with different full name
        let es_localization = icann_rdap_common::contact::Localizable::builder()
            .full_name("Juan Pérez")
            .build();
        contact = contact.set_localization("es".to_string(), es_localization);

        let registrant_entity = Entity::builder()
            .handle("registrant_123")
            .role(EntityRole::Registrant.to_string())
            .contact(contact)
            .jscontact(true)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![registrant_entity])
            .build();

        // WHEN calling simplify_registrant_name
        let result = simplify_registrant_name(Box::new(domain), &get_test_redacted());

        // THEN registrant's contact full name and localizations should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some("registrant_123"));

        // Check that contact full name was updated with redacted name
        if let Some(contact) = registrant.contact() {
            assert_eq!(contact.full_name(), Some(REDACTED_NAME));

            // French localization should be redacted
            if let Some(fr_local) = contact.localization("fr") {
                assert_eq!(fr_local.full_name(), Some(REDACTED_NAME));
            } else {
                panic!("French localization should exist");
            }

            // Spanish localization should be redacted
            if let Some(es_local) = contact.localization("es") {
                assert_eq!(es_local.full_name(), Some(REDACTED_NAME));
            } else {
                panic!("Spanish localization should exist");
            }
        } else {
            panic!("Expected contact to be present");
        }

        // AND a remark should be added
        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_NAME));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&REDACTED_NAME_DESC.to_string())
        );
    }

    #[test]
    fn test_simplify_tech_name_with_tech_entity_with_localizations() {
        // GIVEN a technical entity with contact and localizations with different full names
        let mut contact = Contact::builder().full_name("John Tech").build();

        // Add a French localization with different full name
        let fr_localization = icann_rdap_common::contact::Localizable::builder()
            .full_name("Jean Technique")
            .build();
        contact = contact.set_localization("fr".to_string(), fr_localization);

        // Add a Spanish localization with different full name
        let es_localization = icann_rdap_common::contact::Localizable::builder()
            .full_name("Juan Técnico")
            .build();
        contact = contact.set_localization("es".to_string(), es_localization);

        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .contact(contact)
            .jscontact(true)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![tech_entity])
            .build();

        // WHEN calling simplify_tech_name
        let result = simplify_tech_name(Box::new(domain), &get_test_redacted());

        // THEN technical entity's contact full name and localizations should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let tech = &entities[0];
        assert_eq!(tech.handle(), Some("tech_456"));

        // Check that contact full name was updated with redacted name
        if let Some(contact) = tech.contact() {
            assert_eq!(contact.full_name(), Some(REDACTED_NAME));

            // French localization should be redacted
            if let Some(fr_local) = contact.localization("fr") {
                assert_eq!(fr_local.full_name(), Some(REDACTED_NAME));
            } else {
                panic!("French localization should exist");
            }

            // Spanish localization should be redacted
            if let Some(es_local) = contact.localization("es") {
                assert_eq!(es_local.full_name(), Some(REDACTED_NAME));
            } else {
                panic!("Spanish localization should exist");
            }
        } else {
            panic!("Expected contact to be present");
        }

        // AND a remark should be added
        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_NAME));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&REDACTED_NAME_DESC.to_string())
        );
    }
}
