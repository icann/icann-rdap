//! Simplify redaction of names

use icann_rdap_common::prelude::{redacted::Redacted, Domain, EntityRole};

use crate::rdap::redacted::add_remark;

static REDACTED_ORG: &str = "////REDACTED_ORGANIZATION////";
static REDACTED_ORG_DESC: &str = "Organization redacted.";

pub(crate) fn simplify_registrant_org(
    mut domain: Box<Domain>,
    redaction: &Redacted,
) -> Box<Domain> {
    if let Some(entities) = &mut domain.object_common.entities {
        for entity in entities.iter_mut() {
            if entity.is_entity_role(&EntityRole::Registrant.to_string()) {
                let contact = entity.contact();
                if let Some(mut contact) = contact {
                    // Skip redaction if organization name is already present and non-empty
                    let has_non_empty_org = contact.organization_names().iter().any(|s| !s.is_empty())
                        || contact.localizations_iter().any(|(_, loc)| {
                            loc.organization_names().iter().any(|s| !s.is_empty())
                        });

                    if has_non_empty_org {
                        return domain;
                    }

                    // First redact the main organization name
                    contact = contact.with_organization_names(vec![REDACTED_ORG.to_string()]);

                    // Now redact organization names in all localizations using mutable iterator
                    for (_lang, localizable) in contact.localizations_iter_mut() {
                        *localizable = localizable
                            .clone()
                            .with_organization_names(vec![REDACTED_ORG.to_string()]);
                    }

                    entity.with_contact_if_vcard(&contact);
                    entity.with_contact_if_jscontact(&contact);
                    entity.object_common.remarks = add_remark(
                        REDACTED_ORG,
                        REDACTED_ORG_DESC,
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

#[cfg(test)]
mod tests {
    use icann_rdap_common::prelude::{redacted::Name, *};

    use super::*;

    fn get_test_redacted() -> Redacted {
        Redacted::builder()
            .name(Name::builder().type_field("Tech Email").build())
            .build()
    }

    #[test]
    fn org_redacts_when_empty() {
        // Given
        let contact = Contact::builder().organization_names(vec!["".to_string()]).build();

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_org(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        let entity = &entities[0];
        assert!(entity.is_entity_role(&EntityRole::Registrant.to_string()));

        if let Some(contact) = entity.contact() {
            assert_eq!(contact.organization_names(), &[REDACTED_ORG.to_string()]);
        }

        assert!(entity.object_common.remarks.is_some());
        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_ORG));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec()[0],
            REDACTED_ORG_DESC
        );
    }

    #[test]
    fn only_first_registrant_redacted() {
        // Given
        let registrant_contact = Contact::builder().organization_names(vec!["".to_string()]).build();

        let registrant = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(registrant_contact)
            .build();

        let admin_contact = Contact::builder().organization_name("Admin Org").build();

        let admin = Entity::builder()
            .handle("test-admin")
            .role("administrative")
            .contact(admin_contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(registrant)
            .entity(admin)
            .build();

        // When
        let result = simplify_registrant_org(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);

        // First entity (registrant) should be redacted
        let registrant_entity = &entities[0];
        if let Some(contact) = registrant_entity.contact() {
            assert_eq!(contact.organization_names(), &[REDACTED_ORG.to_string()]);
        } else {
            panic!("Registrant should have a contact");
        }

        // Second entity (admin) should remain unchanged
        let admin_entity = &entities[1];
        if let Some(contact) = admin_entity.contact() {
            assert_eq!(contact.organization_names(), &["Admin Org".to_string()]);
        }
    }

    #[test]
    fn no_entities_returns_unchanged() {
        // Given
        let domain = Domain::builder().ldh_name("example.com").build();

        // When
        let result = simplify_registrant_org(Box::new(domain), &get_test_redacted());

        // Then
        assert!(result.object_common.entities.is_none());
    }

    #[test]
    fn non_registrant_unchanged() {
        // Given
        let contact = Contact::builder().organization_name("Admin Org").build();

        let admin = Entity::builder()
            .handle("test-admin")
            .role("administrative")
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(admin)
            .build();

        // When
        let result = simplify_registrant_org(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        let entity = &entities[0];
        if let Some(contact) = entity.contact() {
            assert_eq!(contact.organization_names(), &["Admin Org".to_string()]);
        }
        assert!(entity.object_common.remarks.is_none());
    }

    #[test]
    fn no_contact_skips() {
        // Given
        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_org(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        let entity = &entities[0];
        assert!(entity.contact().is_none());
        assert!(entity.object_common.remarks.is_none());
    }

    #[test]
    fn remark_added_with_existing_remarks() {
        // Given
        let existing_remark = Remark::builder()
            .title("Existing Remark")
            .description_entry("Existing description")
            .build();

        let contact = Contact::builder().organization_names(vec!["".to_string()]).build();

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact)
            .remark(existing_remark)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_org(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 2);

        // First remark should be the existing one
        assert_eq!(remarks[0].title.as_ref().unwrap(), "Existing Remark");

        // Second remark should be the redaction remark
        assert!(remarks[1].has_simple_redaction_key(REDACTED_ORG));
        assert_eq!(
            remarks[1].description.as_ref().unwrap().vec()[0],
            REDACTED_ORG_DESC
        );
    }

    #[test]
    fn org_skips_when_present() {
        // Given
        let contact = Contact::builder().organization_name("Acme Corp").build();

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_org(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        let entity = &entities[0];
        if let Some(contact) = entity.contact() {
            assert_eq!(contact.organization_names(), &["Acme Corp".to_string()]);
        }
        assert!(entity.object_common.remarks.is_none());
    }

    #[test]
    fn org_redacts_when_only_empty_strings() {
        // Given
        let contact = Contact::builder().organization_names(vec!["".to_string()]).build();

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_org(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        let entity = &entities[0];
        if let Some(contact) = entity.contact() {
            assert_eq!(contact.organization_names(), &[REDACTED_ORG.to_string()]);
        }
        assert!(entity.object_common.remarks.is_some());
        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert!(remarks[0].has_simple_redaction_key(REDACTED_ORG));
    }

    #[test]
    fn org_skips_when_localized_present() {
        // Given
        let mut contact = Contact::builder().organization_names(vec!["".to_string()]).build();

        // Add a French localization with a non-empty organization name
        let fr_localization = icann_rdap_common::contact::Localizable::builder()
            .organization_names(vec!["Organisation Française".to_string()])
            .build();
        contact = contact.with_localization("fr".to_string(), fr_localization);

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact)
            .jscontact(true)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_org(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        let entity = &entities[0];
        if let Some(contact) = entity.contact() {
            assert_eq!(contact.organization_names(), &["".to_string()]);
            if let Some(fr_local) = contact.localization("fr") {
                assert_eq!(fr_local.organization_names(), &["Organisation Française".to_string()]);
            } else {
                panic!("French localization should exist");
            }
        }
        assert!(entity.object_common.remarks.is_none());
    }

    #[test]
    fn org_redacts_localized_when_empty() {
        // Given
        let mut contact = Contact::builder().organization_names(vec!["".to_string()]).build();

        // Add a French localization with empty organization name that should be redacted
        let fr_localization = icann_rdap_common::contact::Localizable::builder()
            .organization_names(vec!["".to_string()])
            .build();
        contact = contact.with_localization("fr".to_string(), fr_localization);

        // Add a Spanish localization with empty organization name that should be redacted
        let es_localization = icann_rdap_common::contact::Localizable::builder()
            .organization_names(vec!["".to_string()])
            .build();
        contact = contact.with_localization("es".to_string(), es_localization);

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact)
            .jscontact(true)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_org(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        if let Some(contact) = entity.contact() {
            // Main organization name should be redacted
            assert_eq!(contact.organization_names(), &[REDACTED_ORG.to_string()]);

            // French localization should be redacted
            if let Some(fr_local) = contact.localization("fr") {
                assert_eq!(fr_local.organization_names(), &[REDACTED_ORG.to_string()]);
            } else {
                panic!("French localization should exist");
            }

            // Spanish localization should be redacted
            if let Some(es_local) = contact.localization("es") {
                assert_eq!(es_local.organization_names(), &[REDACTED_ORG.to_string()]);
            } else {
                panic!("Spanish localization should exist");
            }
        }

        assert!(entity.object_common.remarks.is_some());
        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_ORG));
    }
}
