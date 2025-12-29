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
                    // First redact the main organization name
                    contact = contact.set_organization_names(vec![REDACTED_ORG.to_string()]);

                    // Now redact organization names in all localizations using mutable iterator
                    for (_lang, localizable) in contact.localizations_iter_mut() {
                        *localizable = localizable
                            .clone()
                            .set_organization_names(vec![REDACTED_ORG.to_string()]);
                    }

                    entity.set_contact_if_vcard(&contact);
                    entity.set_contact_if_jscontact(&contact);
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
    fn given_domain_with_registrant_entity_when_simplify_registrant_org_then_redacts_organization()
    {
        // Given
        let contact = Contact::builder().organization_name("Original Org").build();

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
    fn given_domain_with_multiple_entities_when_simplify_registrant_org_then_only_redacts_first_registrant(
    ) {
        // Given
        let registrant_contact = Contact::builder()
            .organization_name("Registrant Org")
            .build();

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
        }

        // Second entity (admin) should remain unchanged
        let admin_entity = &entities[1];
        if let Some(contact) = admin_entity.contact() {
            assert_eq!(contact.organization_names(), &["Admin Org".to_string()]);
        }
    }

    #[test]
    fn given_domain_without_entities_when_simplify_registrant_org_then_returns_unchanged() {
        // Given
        let domain = Domain::builder().ldh_name("example.com").build();

        // When
        let result = simplify_registrant_org(Box::new(domain), &get_test_redacted());

        // Then
        assert!(result.object_common.entities.is_none());
    }

    #[test]
    fn given_domain_with_non_registrant_entities_when_simplify_registrant_org_then_returns_unchanged(
    ) {
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
    fn given_registrant_entity_without_contact_when_simplify_registrant_org_then_skips_entity() {
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
    fn given_registrant_with_existing_remarks_when_simplify_registrant_org_then_adds_redaction_remark(
    ) {
        // Given
        let existing_remark = Remark::builder()
            .title("Existing Remark")
            .description_entry("Existing description")
            .build();

        let contact = Contact::builder().organization_name("Original Org").build();

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
    fn given_registrant_with_localizations_when_simplify_registrant_org_then_redacts_localized_org_names(
    ) {
        // Given
        let mut contact = Contact::builder().organization_name("Original Org").build();

        // Add a French localization with different organization name
        let fr_localization = icann_rdap_common::contact::Localizable::builder()
            .organization_names(vec!["Organisation Française".to_string()])
            .build();
        contact = contact.set_localization("fr".to_string(), fr_localization);

        // Add a Spanish localization with different organization name
        let es_localization = icann_rdap_common::contact::Localizable::builder()
            .organization_names(vec!["Organización Española".to_string()])
            .build();
        contact = contact.set_localization("es".to_string(), es_localization);

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact.clone())
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
