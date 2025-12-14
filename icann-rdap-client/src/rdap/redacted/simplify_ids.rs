//! Redaction of IDs (handles).

use icann_rdap_common::prelude::{redacted::Redacted, Domain, EntityRole};

use crate::rdap::redacted::add_remark;

static REDACTED_ID: &str = "////REDACTED_ID////";
static REDACTED_ID_DESC: &str = "Object ID redacted.";

pub(crate) fn simplify_registry_domain_id(
    mut domain: Box<Domain>,
    redaction: &Redacted,
) -> Box<Domain> {
    domain.object_common.handle = Some(REDACTED_ID.into());
    domain.object_common.remarks = add_remark(
        REDACTED_ID,
        REDACTED_ID_DESC,
        redaction,
        domain.object_common.remarks,
    );
    domain
}

pub(crate) fn simplify_registry_registrant_id(
    mut domain: Box<Domain>,
    redaction: &Redacted,
) -> Box<Domain> {
    if let Some(entities) = &mut domain.object_common.entities {
        for entity in entities.iter_mut() {
            if entity.is_entity_role(&EntityRole::Registrant.to_string()) {
                entity.object_common.handle = Some(REDACTED_ID.into());
                entity.object_common.remarks = add_remark(
                    REDACTED_ID,
                    REDACTED_ID_DESC,
                    redaction,
                    entity.object_common.remarks.clone(),
                );
                break; // Only modify first registrant
            }
        }
    }
    domain
}

pub(crate) fn simplify_registry_tech_id(
    mut domain: Box<Domain>,
    redaction: &Redacted,
) -> Box<Domain> {
    if let Some(entities) = &mut domain.object_common.entities {
        for entity in entities.iter_mut() {
            if entity.is_entity_role(&EntityRole::Technical.to_string()) {
                entity.object_common.handle = Some(REDACTED_ID.into());
                entity.object_common.remarks = add_remark(
                    REDACTED_ID,
                    REDACTED_ID_DESC,
                    redaction,
                    entity.object_common.remarks.clone(),
                );
                break; // Only modify first tech
            }
        }
    }
    domain
}

#[cfg(test)]
mod tests {
    use crate::rdap::redacted::simplify_ids::simplify_registry_tech_id;
    use icann_rdap_common::prelude::redacted::{Name, Redacted};
    use icann_rdap_common::prelude::{Domain, Entity, EntityRole, Remark};
    use icann_rdap_common::response::ObjectCommonFields;

    use crate::rdap::redacted::simplify_ids::{
        simplify_registry_domain_id, simplify_registry_registrant_id, REDACTED_ID, REDACTED_ID_DESC,
    };

    fn get_test_redacted() -> Redacted {
        Redacted::builder()
            .name(Name::builder().type_field("Tech Email").build())
            .build()
    }

    #[test]
    fn test_simplify_registry_domain_id_with_domain() {
        // GIVEN a domain with a handle
        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .build();

        // WHEN calling simplify_registry_domain_id
        let result = simplify_registry_domain_id(Box::new(domain), &get_test_redacted());

        // THEN the domain's handle should be redacted
        assert_eq!(result.handle(), Some(REDACTED_ID));

        // AND a remark should be added
        let remarks = result.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert_eq!(
            remarks[0].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&REDACTED_ID_DESC.to_string())
        );
    }

    #[test]
    fn test_simplify_registry_domain_id_with_domain_with_existing_remarks() {
        // GIVEN a domain with existing remarks
        let existing_remark = Remark::builder()
            .simple_redaction_key("existing_key")
            .description_entry("existing description")
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .remarks(vec![existing_remark])
            .build();

        // WHEN calling simplify_registry_domain_id
        let result = simplify_registry_domain_id(Box::new(domain), &get_test_redacted());

        // THEN the domain should have both existing and new remarks
        assert_eq!(result.handle(), Some(REDACTED_ID));

        let remarks = result.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 2);

        // First remark should be the existing one
        assert_eq!(
            remarks[0].simple_redaction_key.as_deref(),
            Some("existing_key")
        );
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing description".to_string())
        );

        // Second remark should be the redaction remark
        assert_eq!(
            remarks[1].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );
        assert_eq!(
            remarks[1].description.as_ref().unwrap().vec().first(),
            Some(&REDACTED_ID_DESC.to_string())
        );
    }

    #[test]
    fn test_simplify_registry_domain_id_with_domain_with_same_redaction_remark() {
        // GIVEN a domain with existing redaction remark
        let existing_remark = Remark::builder()
            .simple_redaction_key(REDACTED_ID)
            .description_entry("existing redaction description")
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .remarks(vec![existing_remark])
            .build();

        // WHEN calling simplify_registry_domain_id
        let result = simplify_registry_domain_id(Box::new(domain), &get_test_redacted());

        // THEN the domain should not have duplicate redaction remark
        assert_eq!(result.handle(), Some(REDACTED_ID));

        let remarks = result.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);

        // Should only have the existing remark (no duplicate)
        assert_eq!(
            remarks[0].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing redaction description".to_string())
        );
    }

    #[test]
    fn test_simplify_registry_domain_id_with_domain_no_handle() {
        // GIVEN a domain with no handle
        let domain = Domain::builder().ldh_name("example.com").build();

        // WHEN calling simplify_registry_domain_id
        let result = simplify_registry_domain_id(Box::new(domain), &get_test_redacted());

        // THEN the domain should have redacted handle
        assert_eq!(result.handle(), Some(REDACTED_ID));

        // AND a remark should be added
        let remarks = result.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert_eq!(
            remarks[0].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&REDACTED_ID_DESC.to_string())
        );
    }

    #[test]
    fn test_simplify_registry_domain_id_with_domain_no_remarks() {
        // GIVEN a domain with no remarks
        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .build();

        // WHEN calling simplify_registry_domain_id
        let result = simplify_registry_domain_id(Box::new(domain), &get_test_redacted());

        // THEN the domain should have redacted handle and remark
        assert_eq!(result.handle(), Some(REDACTED_ID));

        let remarks = result.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert_eq!(
            remarks[0].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&REDACTED_ID_DESC.to_string())
        );
    }

    #[test]
    fn test_simplify_registry_registrant_id_with_registrant_entity() {
        // GIVEN a domain with a registrant entity
        let registrant_entity = Entity::builder()
            .handle("registrant_123")
            .role(EntityRole::Registrant.to_string())
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![registrant_entity])
            .build();

        // WHEN calling simplify_registry_registrant_id
        let result = simplify_registry_registrant_id(Box::new(domain), &get_test_redacted());

        // THEN the registrant entity's handle should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some(REDACTED_ID));

        // AND a remark should be added
        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert_eq!(
            remarks[0].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&REDACTED_ID_DESC.to_string())
        );
    }

    #[test]
    fn test_simplify_registry_registrant_id_with_multiple_entities_first_is_registrant() {
        // GIVEN a domain with multiple entities, first is registrant
        let registrant_entity = Entity::builder()
            .handle("registrant_123")
            .role(EntityRole::Registrant.to_string())
            .build();

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
            .entities(vec![registrant_entity, tech_entity, admin_entity])
            .build();

        // WHEN calling simplify_registry_registrant_id
        let result = simplify_registry_registrant_id(Box::new(domain), &get_test_redacted());

        // THEN only the first registrant should be modified
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 3);

        // First entity (registrant) should be redacted
        assert_eq!(entities[0].handle(), Some(REDACTED_ID));
        let registrant_remarks = entities[0].object_common.remarks.as_ref().unwrap();
        assert_eq!(registrant_remarks.len(), 1);
        assert_eq!(
            registrant_remarks[0].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );

        // Other entities should be unchanged
        assert_eq!(entities[1].handle(), Some("tech_456"));
        assert_eq!(entities[2].handle(), Some("admin_789"));
    }

    #[test]
    fn test_simplify_registry_registrant_id_with_multiple_entities_registrant_not_first() {
        // GIVEN a domain with multiple entities, registrant is second
        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .build();

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
            .entities(vec![tech_entity, registrant_entity, admin_entity])
            .build();

        // WHEN calling simplify_registry_registrant_id
        let result = simplify_registry_registrant_id(Box::new(domain), &get_test_redacted());

        // THEN the registrant entity should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 3);

        // First entity (tech) should be unchanged
        assert_eq!(entities[0].handle(), Some("tech_456"));

        // Second entity (registrant) should be redacted
        assert_eq!(entities[1].handle(), Some(REDACTED_ID));
        let registrant_remarks = entities[1].object_common.remarks.as_ref().unwrap();
        assert_eq!(registrant_remarks.len(), 1);
        assert_eq!(
            registrant_remarks[0].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );

        // Third entity (admin) should be unchanged
        assert_eq!(entities[2].handle(), Some("admin_789"));
    }

    #[test]
    fn test_simplify_registry_registrant_id_with_no_registrant_entity() {
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

        // WHEN calling simplify_registry_registrant_id
        let result = simplify_registry_registrant_id(Box::new(domain), &get_test_redacted());

        // THEN no entities should be modified
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);
        assert_eq!(entities[0].handle(), Some("tech_456"));
        assert_eq!(entities[1].handle(), Some("admin_789"));

        // AND no remarks should be added
        assert!(entities[0].object_common.remarks.is_none());
        assert!(entities[1].object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_registry_registrant_id_with_no_entities() {
        // GIVEN a domain with no entities
        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .build();

        // WHEN calling simplify_registry_registrant_id
        let result = simplify_registry_registrant_id(Box::new(domain), &get_test_redacted());

        // THEN the domain should be unchanged
        assert!(result.object_common.entities.is_none());
        assert_eq!(result.handle(), Some("example_com-1"));
    }

    #[test]
    fn test_simplify_registry_registrant_id_with_entity_with_existing_remarks() {
        // GIVEN a registrant entity with existing remarks
        let existing_remark = Remark::builder()
            .simple_redaction_key("existing_key")
            .description_entry("existing description")
            .build();

        let registrant_entity = Entity::builder()
            .handle("registrant_123")
            .role(EntityRole::Registrant.to_string())
            .remarks(vec![existing_remark])
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![registrant_entity])
            .build();

        // WHEN calling simplify_registry_registrant_id
        let result = simplify_registry_registrant_id(Box::new(domain), &get_test_redacted());

        // THEN registrant should have both existing and new remarks
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some(REDACTED_ID));

        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 2);

        // First remark should be the existing one
        assert_eq!(
            remarks[0].simple_redaction_key.as_deref(),
            Some("existing_key")
        );
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing description".to_string())
        );

        // Second remark should be the redaction remark
        assert_eq!(
            remarks[1].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );
        assert_eq!(
            remarks[1].description.as_ref().unwrap().vec().first(),
            Some(&REDACTED_ID_DESC.to_string())
        );
    }

    #[test]
    fn test_simplify_registry_registrant_id_with_entity_with_same_redaction_remark() {
        // GIVEN a registrant entity with existing redaction remark
        let existing_remark = Remark::builder()
            .simple_redaction_key(REDACTED_ID)
            .description_entry("existing redaction description")
            .build();

        let registrant_entity = Entity::builder()
            .handle("registrant_123")
            .role(EntityRole::Registrant.to_string())
            .remarks(vec![existing_remark])
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![registrant_entity])
            .build();

        // WHEN calling simplify_registry_registrant_id
        let result = simplify_registry_registrant_id(Box::new(domain), &get_test_redacted());

        // THEN the registrant should not have duplicate redaction remark
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some(REDACTED_ID));

        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);

        // Should only have the existing remark (no duplicate)
        assert_eq!(
            remarks[0].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing redaction description".to_string())
        );
    }

    #[test]
    fn test_simplify_registry_registrant_id_with_entity_with_multiple_roles_including_registrant() {
        // GIVEN an entity with multiple roles including registrant
        let multi_role_entity = Entity::builder()
            .handle("multi_role_123")
            .roles(vec![
                EntityRole::Technical.to_string(),
                EntityRole::Registrant.to_string(),
                EntityRole::Administrative.to_string(),
            ])
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![multi_role_entity])
            .build();

        // WHEN calling simplify_registry_registrant_id
        let result = simplify_registry_registrant_id(Box::new(domain), &get_test_redacted());

        // THEN the entity should be redacted (it has registrant role)
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let entity = &entities[0];
        assert_eq!(entity.handle(), Some(REDACTED_ID));

        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert_eq!(
            remarks[0].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );
    }

    #[test]
    fn test_simplify_registry_registrant_id_with_entity_no_handle() {
        // GIVEN a registrant entity with no handle
        let registrant_entity = Entity::builder::<String>()
            .role(EntityRole::Registrant.to_string())
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![registrant_entity])
            .build();

        // WHEN calling simplify_registry_registrant_id
        let result = simplify_registry_registrant_id(Box::new(domain), &get_test_redacted());

        // THEN the registrant entity should have redacted handle
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some(REDACTED_ID));

        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert_eq!(
            remarks[0].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );
    }

    #[test]
    fn test_simplify_registry_tech_id_with_tech_entity() {
        // GIVEN a domain with a technical entity
        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![tech_entity])
            .build();

        // WHEN calling simplify_registry_tech_id
        let result = simplify_registry_tech_id(Box::new(domain), &get_test_redacted());

        // THEN the technical entity should have redacted handle
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let tech = &entities[0];
        assert_eq!(tech.handle(), Some(REDACTED_ID));

        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert_eq!(
            remarks[0].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );
    }

    #[test]
    fn test_simplify_registry_tech_id_with_multiple_entities_first_is_tech() {
        // GIVEN a domain with multiple entities, first is technical
        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .build();

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
            .entities(vec![tech_entity, registrant_entity, admin_entity])
            .build();

        // WHEN calling simplify_registry_tech_id
        let result = simplify_registry_tech_id(Box::new(domain), &get_test_redacted());

        // THEN only the first technical entity should be modified
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 3);

        // First entity (tech) should be redacted
        assert_eq!(entities[0].handle(), Some(REDACTED_ID));
        let tech_remarks = entities[0].object_common.remarks.as_ref().unwrap();
        assert_eq!(tech_remarks.len(), 1);
        assert_eq!(
            tech_remarks[0].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );

        // Other entities should be unchanged
        assert_eq!(entities[1].handle(), Some("registrant_123"));
        assert_eq!(entities[2].handle(), Some("admin_789"));
    }

    #[test]
    fn test_simplify_registry_tech_id_with_multiple_entities_tech_not_first() {
        // GIVEN a domain with multiple entities, tech is not first
        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .build();

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
            .entities(vec![registrant_entity, tech_entity, admin_entity])
            .build();

        // WHEN calling simplify_registry_tech_id
        let result = simplify_registry_tech_id(Box::new(domain), &get_test_redacted());

        // THEN only the technical entity should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 3);

        // First entity (registrant) should be unchanged
        assert_eq!(entities[0].handle(), Some("registrant_123"));

        // Second entity (tech) should be redacted
        assert_eq!(entities[1].handle(), Some(REDACTED_ID));
        let tech_remarks = entities[1].object_common.remarks.as_ref().unwrap();
        assert_eq!(tech_remarks.len(), 1);
        assert_eq!(
            tech_remarks[0].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );

        // Third entity (admin) should be unchanged
        assert_eq!(entities[2].handle(), Some("admin_789"));
    }

    #[test]
    fn test_simplify_registry_tech_id_with_no_tech_entity() {
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

        // WHEN calling simplify_registry_tech_id
        let result = simplify_registry_tech_id(Box::new(domain), &get_test_redacted());

        // THEN no entities should be modified
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);
        assert_eq!(entities[0].handle(), Some("registrant_123"));
        assert_eq!(entities[1].handle(), Some("admin_789"));

        // AND no remarks should be added
        assert!(entities[0].object_common.remarks.is_none());
        assert!(entities[1].object_common.remarks.is_none());
    }

    #[test]
    fn test_simplify_registry_tech_id_with_tech_entity_with_existing_remarks() {
        // GIVEN a technical entity with existing remarks
        let existing_remark = Remark::builder()
            .simple_redaction_key("existing_key")
            .description_entry("existing description")
            .build();

        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .remarks(vec![existing_remark])
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![tech_entity])
            .build();

        // WHEN calling simplify_registry_tech_id
        let result = simplify_registry_tech_id(Box::new(domain), &get_test_redacted());

        // THEN the technical entity should have both existing and new remarks
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let tech = &entities[0];
        assert_eq!(tech.handle(), Some(REDACTED_ID));

        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 2);

        // First remark should be the existing one
        assert_eq!(
            remarks[0].simple_redaction_key.as_deref(),
            Some("existing_key")
        );
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing description".to_string())
        );

        // Second remark should be the redaction remark
        assert_eq!(
            remarks[1].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );
        assert_eq!(
            remarks[1].description.as_ref().unwrap().vec().first(),
            Some(&REDACTED_ID_DESC.to_string())
        );
    }

    #[test]
    fn test_simplify_registry_tech_id_with_tech_entity_with_same_redaction_remark() {
        // GIVEN a technical entity with existing redaction remark
        let existing_remark = Remark::builder()
            .simple_redaction_key(REDACTED_ID)
            .description_entry("existing redaction description")
            .build();

        let tech_entity = Entity::builder()
            .handle("tech_456")
            .role(EntityRole::Technical.to_string())
            .remarks(vec![existing_remark])
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![tech_entity])
            .build();

        // WHEN calling simplify_registry_tech_id
        let result = simplify_registry_tech_id(Box::new(domain), &get_test_redacted());

        // THEN the technical entity should not have duplicate redaction remark
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let tech = &entities[0];
        assert_eq!(tech.handle(), Some(REDACTED_ID));

        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);

        // Should only have the existing remark (no duplicate)
        assert_eq!(
            remarks[0].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing redaction description".to_string())
        );
    }

    #[test]
    fn test_simplify_registry_tech_id_with_tech_entity_no_handle() {
        // GIVEN a technical entity with no handle
        let tech_entity = Entity::builder::<String>()
            .role(EntityRole::Technical.to_string())
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .entities(vec![tech_entity])
            .build();

        // WHEN calling simplify_registry_tech_id
        let result = simplify_registry_tech_id(Box::new(domain), &get_test_redacted());

        // THEN the technical entity should have redacted handle
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);

        let tech = &entities[0];
        assert_eq!(tech.handle(), Some(REDACTED_ID));

        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert_eq!(
            remarks[0].simple_redaction_key.as_deref(),
            Some(REDACTED_ID)
        );
    }
}
