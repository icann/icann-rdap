//! Changes RFC 9537 redactions to simple redactions

use std::str::FromStr;

use icann_rdap_common::prelude::{
    redacted::Redacted, Domain, EntityRole, RdapResponse, Remark, ToResponse,
};

use crate::rdap::redacted::RedactedName;

/// Takes in an RDAP response and creates Simple Redactions
/// from the RFC 9537 redactions.
///
/// # Arguments
///
/// * `rdap` is the [RdapResponse] which is altered.
/// * `only_pre_path` only create Simple Redactions when no path expression is given or the prePath expression is present.
pub fn simplify_redactions(rdap: RdapResponse, only_pre_path: bool) -> RdapResponse {
    match rdap {
        RdapResponse::Entity(entity) => {
            // no registered redactions are on plain entities. They must all
            // have roles.
            entity.to_response()
        }
        RdapResponse::Domain(domain) => simplify_domain_redactions(domain, only_pre_path),
        RdapResponse::Nameserver(nameserver) => {
            // no registered redactions on nameservers.
            nameserver.to_response()
        }
        RdapResponse::Autnum(autnum) => {
            // no registered redactions on autnums.
            autnum.to_response()
        }
        RdapResponse::Network(network) => {
            // no registered redactons on networks
            network.to_response()
        }
        _ => {
            // do nothing as RFC 9537 does not explain how or if its redacted
            // directives work against search results or other, non-object class responses.
            rdap
        }
    }
}

fn simplify_domain_redactions(mut domain: Box<Domain>, only_pre_path: bool) -> RdapResponse {
    let binding = domain.object_common.redacted.clone();
    let redactions = binding.as_deref().unwrap_or_default();
    for redaction in redactions {
        if !is_only_pre_path(only_pre_path, redaction) {
            continue;
        }
        if let Some(r_type) = redaction.name().type_field() {
            let r_name = RedactedName::from_str(r_type);
            if let Ok(registered_redaction) = r_name {
                domain = match registered_redaction {
                    RedactedName::RegistryDomainId => simplify_registry_domain_id(domain),
                    RedactedName::RegistryRegistrantId => simplify_registry_registrant_id(domain),
                    RedactedName::RegistrantName => todo!(),
                    RedactedName::RegistrantOrganization => todo!(),
                    RedactedName::RegistrantStreet => todo!(),
                    RedactedName::RegistrantCity => todo!(),
                    RedactedName::RegistrantPostalCode => todo!(),
                    RedactedName::RegistrantPhone => todo!(),
                    RedactedName::RegistrantPhoneExt => todo!(),
                    RedactedName::RegistrantFax => todo!(),
                    RedactedName::RegistrantFaxExt => todo!(),
                    RedactedName::RegistrantEmail => todo!(),
                    RedactedName::RegistryTechId => simplify_registry_tech_id(domain),
                    RedactedName::TechName => todo!(),
                    RedactedName::TechPhone => todo!(),
                    RedactedName::TechPhoneExt => todo!(),
                    RedactedName::TechEmail => todo!(),
                };
            }
        }
    }
    domain.to_response()
}

fn is_only_pre_path(only_pre_path: bool, redaction: &Redacted) -> bool {
    if only_pre_path
        && (redaction.pre_path().is_some()
            || (redaction.post_path().is_none() && redaction.replacement_path().is_none()))
    {
        return true;
    }
    false
}

static REDACTED_ID: &str = "////REDACTED_ID////";
static REDACTED_ID_DESC: &str = "Object ID redacted.";

fn simplify_registry_domain_id(mut domain: Box<Domain>) -> Box<Domain> {
    domain.object_common.handle = Some(REDACTED_ID.into());
    domain.object_common.remarks =
        add_remark(REDACTED_ID, REDACTED_ID_DESC, domain.object_common.remarks);
    domain
}

fn simplify_registry_registrant_id(mut domain: Box<Domain>) -> Box<Domain> {
    if let Some(entities) = &mut domain.object_common.entities {
        for entity in entities.iter_mut() {
            if entity
                .roles()
                .iter()
                .any(|r| r.eq(&EntityRole::Registrant.to_string()))
            {
                entity.object_common.handle = Some(REDACTED_ID.into());
                entity.object_common.remarks = add_remark(
                    REDACTED_ID,
                    REDACTED_ID_DESC,
                    entity.object_common.remarks.clone(),
                );
                break; // Only modify first registrant
            }
        }
    }
    domain
}

fn simplify_registry_tech_id(mut domain: Box<Domain>) -> Box<Domain> {
    if let Some(entities) = &mut domain.object_common.entities {
        for entity in entities.iter_mut() {
            if entity
                .roles()
                .iter()
                .any(|r| r.eq(&EntityRole::Technical.to_string()))
            {
                entity.object_common.handle = Some(REDACTED_ID.into());
                entity.object_common.remarks = add_remark(
                    REDACTED_ID,
                    REDACTED_ID_DESC,
                    entity.object_common.remarks.clone(),
                );
                break; // Only modify first registrant
            }
        }
    }
    domain
}

fn add_remark(key: &str, desc: &str, remarks: Option<Vec<Remark>>) -> Option<Vec<Remark>> {
    let mut remarks = remarks.unwrap_or_default();
    if !remarks.iter().any(|r| {
        r.simple_redaction_key
            .as_deref()
            .unwrap_or_default()
            .eq(key)
    }) {
        let remark = Remark::builder()
            .simple_redaction_key(key)
            .description_entry(desc)
            .build();
        remarks.push(remark);
    }
    Some(remarks)
}

#[cfg(test)]
mod tests {
    use super::{
        add_remark, is_only_pre_path, simplify_registry_registrant_id, simplify_registry_domain_id, simplify_registry_tech_id, REDACTED_ID, REDACTED_ID_DESC,
    };
    use icann_rdap_common::prelude::{Domain, Entity, EntityRole, Remark};
    use icann_rdap_common::response::ObjectCommonFields;
    use icann_rdap_common::response::redacted::{Name, Redacted};

    #[test]
    fn test_is_only_pre_path_returns_true_when_only_pre_path_and_pre_path_exists() {
        // GIVEN a redaction with only_pre_path=true and a pre_path
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .pre_path("$.test".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(true, &redaction);

        // THEN it should return true
        assert!(result);
    }

    #[test]
    fn test_is_only_pre_path_returns_true_when_minimal_redaction() {
        // GIVEN a minimal redaction with only_pre_path=true (no paths at all)
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(true, &redaction);

        // THEN it should return true (since post_path and replacement_path are both None)
        assert!(result);
    }

    #[test]
    fn test_is_only_pre_path_returns_false_when_only_pre_path_and_post_path_only() {
        // GIVEN a redaction with only_pre_path=true and post_path but no pre_path
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .post_path("$.post".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(true, &redaction);

        // THEN it should return false
        assert!(!result);
    }

    #[test]
    fn test_is_only_pre_path_returns_false_when_only_pre_path_and_replacement_path_only() {
        // GIVEN a redaction with only_pre_path=true and replacement_path but no pre_path
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .replacement_path("$.replacement".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(true, &redaction);

        // THEN it should return false
        assert!(!result);
    }

    #[test]
    fn test_is_only_pre_path_returns_false_when_only_pre_path_and_post_replacement_paths_no_pre() {
        // GIVEN a redaction with only_pre_path=true, post_path and replacement_path but no pre_path
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .post_path("$.post".to_string())
            .replacement_path("$.replacement".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(true, &redaction);

        // THEN it should return false
        assert!(!result);
    }

    #[test]
    fn test_is_only_pre_path_returns_false_when_only_pre_path_false_with_pre_path() {
        // GIVEN a redaction with only_pre_path=false and pre_path
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .pre_path("$.test".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(false, &redaction);

        // THEN it should return false
        assert!(!result);
    }

    #[test]
    fn test_is_only_pre_path_returns_false_when_only_pre_path_false_with_post_path() {
        // GIVEN a redaction with only_pre_path=false and post_path
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .post_path("$.post".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(false, &redaction);

        // THEN it should return false
        assert!(!result);
    }

    #[test]
    fn test_is_only_pre_path_returns_true_when_only_pre_path_false_with_post_path() {
        // GIVEN a redaction with only_pre_path=true and post_path
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .post_path("$.post".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(true, &redaction);

        // THEN it should return false
        assert!(!result);
    }

    #[test]
    fn test_is_only_pre_path_returns_true_when_only_pre_path_false_with_replacement_path() {
        // GIVEN a redaction with only_pre_path=true and replacement
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .replacement_path("$.post".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(true, &redaction);

        // THEN it should return false
        assert!(!result);
    }

    #[test]
    fn test_is_only_pre_path_returns_false_when_only_pre_path_false_minimal() {
        // GIVEN a minimal redaction with only_pre_path=false
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(false, &redaction);

        // THEN it should return false
        assert!(!result);
    }

    #[test]
    fn test_is_only_pre_path_returns_true_when_only_pre_path_and_all_paths_present() {
        // GIVEN a redaction with only_pre_path=true and all path types
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .pre_path("$.pre".to_string())
            .post_path("$.post".to_string())
            .replacement_path("$.replacement".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(true, &redaction);

        // THEN it should return true (because pre_path exists)
        assert!(result);
    }

    #[test]
    fn test_add_remark_with_none_remarks() {
        // GIVEN no existing remarks
        let key = "test_key";
        let desc = "test description";
        let remarks = None;

        // WHEN calling add_remark
        let result = add_remark(key, desc, remarks);

        // THEN it should return a vector with one remark
        assert!(result.is_some());
        let result_vec = result.unwrap();
        assert_eq!(result_vec.len(), 1);
        assert_eq!(result_vec[0].simple_redaction_key.as_deref(), Some(key));
        assert_eq!(
            result_vec[0].description.as_ref().unwrap().vec().first(),
            Some(&desc.to_string())
        );
    }

    #[test]
    fn test_add_remark_with_empty_remarks() {
        // GIVEN an empty remarks vector
        let key = "test_key";
        let desc = "test description";
        let remarks = Some(vec![]);

        // WHEN calling add_remark
        let result = add_remark(key, desc, remarks);

        // THEN it should return a vector with one remark
        assert!(result.is_some());
        let result_vec = result.unwrap();
        assert_eq!(result_vec.len(), 1);
        assert_eq!(result_vec[0].simple_redaction_key.as_deref(), Some(key));
        assert_eq!(
            result_vec[0].description.as_ref().unwrap().vec().first(),
            Some(&desc.to_string())
        );
    }

    #[test]
    fn test_add_remark_with_existing_different_key() {
        // GIVEN existing remarks with different keys
        let key = "new_key";
        let desc = "new description";
        let existing_remark = icann_rdap_common::prelude::Remark::builder()
            .simple_redaction_key("existing_key")
            .description_entry("existing description")
            .build();
        let remarks = Some(vec![existing_remark]);

        // WHEN calling add_remark
        let result = add_remark(key, desc, remarks);

        // THEN it should return a vector with two remarks
        assert!(result.is_some());
        let result_vec = result.unwrap();
        assert_eq!(result_vec.len(), 2);
        assert_eq!(
            result_vec[0].simple_redaction_key.as_deref(),
            Some("existing_key")
        );
        assert_eq!(result_vec[1].simple_redaction_key.as_deref(), Some(key));
        assert_eq!(
            result_vec[1].description.as_ref().unwrap().vec().first(),
            Some(&desc.to_string())
        );
    }

    #[test]
    fn test_add_remark_with_existing_same_key() {
        // GIVEN existing remarks with the same key
        let key = "test_key";
        let desc = "new description";
        let existing_remark = icann_rdap_common::prelude::Remark::builder()
            .simple_redaction_key(key)
            .description_entry("existing description")
            .build();
        let remarks = Some(vec![existing_remark]);

        // WHEN calling add_remark
        let result = add_remark(key, desc, remarks);

        // THEN it should return the original vector unchanged (no duplicate key)
        assert!(result.is_some());
        let result_vec = result.unwrap();
        assert_eq!(result_vec.len(), 1);
        assert_eq!(result_vec[0].simple_redaction_key.as_deref(), Some(key));
        assert_eq!(
            result_vec[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing description".to_string())
        );
    }

    #[test]
    fn test_add_remark_with_multiple_existing_remarks_no_duplicate() {
        // GIVEN multiple existing remarks with different keys
        let key = "new_key";
        let desc = "new description";
        let remark1 = icann_rdap_common::prelude::Remark::builder()
            .simple_redaction_key("key1")
            .description_entry("description1")
            .build();
        let remark2 = icann_rdap_common::prelude::Remark::builder()
            .simple_redaction_key("key2")
            .description_entry("description2")
            .build();
        let remarks = Some(vec![remark1, remark2]);

        // WHEN calling add_remark
        let result = add_remark(key, desc, remarks);

        // THEN it should return a vector with three remarks
        assert!(result.is_some());
        let result_vec = result.unwrap();
        assert_eq!(result_vec.len(), 3);
        assert_eq!(result_vec[0].simple_redaction_key.as_deref(), Some("key1"));
        assert_eq!(result_vec[1].simple_redaction_key.as_deref(), Some("key2"));
        assert_eq!(result_vec[2].simple_redaction_key.as_deref(), Some(key));
        assert_eq!(
            result_vec[2].description.as_ref().unwrap().vec().first(),
            Some(&desc.to_string())
        );
    }

    #[test]
    fn test_add_remark_with_multiple_existing_remarks_with_duplicate() {
        // GIVEN multiple existing remarks including one with the same key
        let key = "key2";
        let desc = "new description";
        let remark1 = icann_rdap_common::prelude::Remark::builder()
            .simple_redaction_key("key1")
            .description_entry("description1")
            .build();
        let remark2 = icann_rdap_common::prelude::Remark::builder()
            .simple_redaction_key(key)
            .description_entry("existing description")
            .build();
        let remarks = Some(vec![remark1, remark2]);

        // WHEN calling add_remark
        let result = add_remark(key, desc, remarks);

        // THEN it should return the original vector unchanged (no duplicate key)
        assert!(result.is_some());
        let result_vec = result.unwrap();
        assert_eq!(result_vec.len(), 2);
        assert_eq!(result_vec[0].simple_redaction_key.as_deref(), Some("key1"));
        assert_eq!(result_vec[1].simple_redaction_key.as_deref(), Some(key));
        assert_eq!(
            result_vec[1].description.as_ref().unwrap().vec().first(),
            Some(&"existing description".to_string())
        );
    }

    #[test]
    fn test_add_remark_with_existing_remark_no_simple_redaction_key() {
        // GIVEN existing remarks without simple_redaction_key
        let key = "test_key";
        let desc = "test description";
        let existing_remark = icann_rdap_common::prelude::Remark::builder()
            .description_entry("existing description")
            .build();
        let remarks = Some(vec![existing_remark]);

        // WHEN calling add_remark
        let result = add_remark(key, desc, remarks);

        // THEN it should add the new remark since no existing remark has the same key
        assert!(result.is_some());
        let result_vec = result.unwrap();
        assert_eq!(result_vec.len(), 2);
        assert_eq!(result_vec[0].simple_redaction_key.as_deref(), None);
        assert_eq!(result_vec[1].simple_redaction_key.as_deref(), Some(key));
        assert_eq!(
            result_vec[1].description.as_ref().unwrap().vec().first(),
            Some(&desc.to_string())
        );
    }

    #[test]
    fn test_add_remark_with_empty_key_and_description() {
        // GIVEN empty key and description
        let key = "";
        let desc = "";
        let remarks = None;

        // WHEN calling add_remark
        let result = add_remark(key, desc, remarks);

        // THEN it should still create a remark with empty strings
        assert!(result.is_some());
        let result_vec = result.unwrap();
        assert_eq!(result_vec.len(), 1);
        assert_eq!(result_vec[0].simple_redaction_key.as_deref(), Some(key));
        assert_eq!(
            result_vec[0].description.as_ref().unwrap().vec().first(),
            Some(&desc.to_string())
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
        let result = simplify_registry_registrant_id(Box::new(domain));

        // THEN the registrant entity's handle should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        
        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some(REDACTED_ID));
        
        // AND a remark should be added
        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert_eq!(remarks[0].simple_redaction_key.as_deref(), Some(REDACTED_ID));
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
        let result = simplify_registry_registrant_id(Box::new(domain));

        // THEN only the first registrant should be modified
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 3);
        
        // First entity (registrant) should be redacted
        assert_eq!(entities[0].handle(), Some(REDACTED_ID));
        let registrant_remarks = entities[0].object_common.remarks.as_ref().unwrap();
        assert_eq!(registrant_remarks.len(), 1);
        assert_eq!(registrant_remarks[0].simple_redaction_key.as_deref(), Some(REDACTED_ID));
        
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
        let result = simplify_registry_registrant_id(Box::new(domain));

        // THEN the registrant entity should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 3);
        
        // First entity (tech) should be unchanged
        assert_eq!(entities[0].handle(), Some("tech_456"));
        
        // Second entity (registrant) should be redacted
        assert_eq!(entities[1].handle(), Some(REDACTED_ID));
        let registrant_remarks = entities[1].object_common.remarks.as_ref().unwrap();
        assert_eq!(registrant_remarks.len(), 1);
        assert_eq!(registrant_remarks[0].simple_redaction_key.as_deref(), Some(REDACTED_ID));
        
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
        let result = simplify_registry_registrant_id(Box::new(domain));

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
        let result = simplify_registry_registrant_id(Box::new(domain));

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
        let result = simplify_registry_registrant_id(Box::new(domain));

        // THEN registrant should have both existing and new remarks
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        
        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some(REDACTED_ID));
        
        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 2);
        
        // First remark should be the existing one
        assert_eq!(remarks[0].simple_redaction_key.as_deref(), Some("existing_key"));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing description".to_string())
        );
        
        // Second remark should be the redaction remark
        assert_eq!(remarks[1].simple_redaction_key.as_deref(), Some(REDACTED_ID));
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
        let result = simplify_registry_registrant_id(Box::new(domain));

        // THEN the registrant should not have duplicate redaction remark
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        
        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some(REDACTED_ID));
        
        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        
        // Should only have the existing remark (no duplicate)
        assert_eq!(remarks[0].simple_redaction_key.as_deref(), Some(REDACTED_ID));
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
        let result = simplify_registry_registrant_id(Box::new(domain));

        // THEN the entity should be redacted (it has registrant role)
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        
        let entity = &entities[0];
        assert_eq!(entity.handle(), Some(REDACTED_ID));
        
        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert_eq!(remarks[0].simple_redaction_key.as_deref(), Some(REDACTED_ID));
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
        let result = simplify_registry_registrant_id(Box::new(domain));

        // THEN the registrant entity should have redacted handle
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        
        let registrant = &entities[0];
        assert_eq!(registrant.handle(), Some(REDACTED_ID));
        
        let remarks = registrant.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert_eq!(remarks[0].simple_redaction_key.as_deref(), Some(REDACTED_ID));
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
        let result = simplify_registry_tech_id(Box::new(domain));

        // THEN the technical entity should have redacted handle
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        
        let tech = &entities[0];
        assert_eq!(tech.handle(), Some(REDACTED_ID));
        
        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert_eq!(remarks[0].simple_redaction_key.as_deref(), Some(REDACTED_ID));
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
        let result = simplify_registry_tech_id(Box::new(domain));

        // THEN only the first technical entity should be modified
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 3);
        
        // First entity (tech) should be redacted
        assert_eq!(entities[0].handle(), Some(REDACTED_ID));
        let tech_remarks = entities[0].object_common.remarks.as_ref().unwrap();
        assert_eq!(tech_remarks.len(), 1);
        assert_eq!(tech_remarks[0].simple_redaction_key.as_deref(), Some(REDACTED_ID));
        
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
        let result = simplify_registry_tech_id(Box::new(domain));

        // THEN only the technical entity should be redacted
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 3);
        
        // First entity (registrant) should be unchanged
        assert_eq!(entities[0].handle(), Some("registrant_123"));
        
        // Second entity (tech) should be redacted
        assert_eq!(entities[1].handle(), Some(REDACTED_ID));
        let tech_remarks = entities[1].object_common.remarks.as_ref().unwrap();
        assert_eq!(tech_remarks.len(), 1);
        assert_eq!(tech_remarks[0].simple_redaction_key.as_deref(), Some(REDACTED_ID));
        
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
        let result = simplify_registry_tech_id(Box::new(domain));

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
        let result = simplify_registry_tech_id(Box::new(domain));

        // THEN the technical entity should have both existing and new remarks
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        
        let tech = &entities[0];
        assert_eq!(tech.handle(), Some(REDACTED_ID));
        
        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 2);
        
        // First remark should be the existing one
        assert_eq!(remarks[0].simple_redaction_key.as_deref(), Some("existing_key"));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing description".to_string())
        );
        
        // Second remark should be the redaction remark
        assert_eq!(remarks[1].simple_redaction_key.as_deref(), Some(REDACTED_ID));
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
        let result = simplify_registry_tech_id(Box::new(domain));

        // THEN the technical entity should not have duplicate redaction remark
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        
        let tech = &entities[0];
        assert_eq!(tech.handle(), Some(REDACTED_ID));
        
        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        
        // Should only have the existing remark (no duplicate)
        assert_eq!(remarks[0].simple_redaction_key.as_deref(), Some(REDACTED_ID));
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
        let result = simplify_registry_tech_id(Box::new(domain));

        // THEN the technical entity should have redacted handle
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        
        let tech = &entities[0];
        assert_eq!(tech.handle(), Some(REDACTED_ID));
        
        let remarks = tech.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert_eq!(remarks[0].simple_redaction_key.as_deref(), Some(REDACTED_ID));
    }

    #[test]
    fn test_simplify_registry_domain_id_with_domain() {
        // GIVEN a domain with a handle
        let domain = Domain::builder()
            .ldh_name("example.com")
            .handle("example_com-1")
            .build();

        // WHEN calling simplify_registry_domain_id
        let result = simplify_registry_domain_id(Box::new(domain));

        // THEN the domain's handle should be redacted
        assert_eq!(result.handle(), Some(REDACTED_ID));
        
        // AND a remark should be added
        let remarks = result.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert_eq!(remarks[0].simple_redaction_key.as_deref(), Some(REDACTED_ID));
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
        let result = simplify_registry_domain_id(Box::new(domain));

        // THEN the domain should have both existing and new remarks
        assert_eq!(result.handle(), Some(REDACTED_ID));
        
        let remarks = result.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 2);
        
        // First remark should be the existing one
        assert_eq!(remarks[0].simple_redaction_key.as_deref(), Some("existing_key"));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing description".to_string())
        );
        
        // Second remark should be the redaction remark
        assert_eq!(remarks[1].simple_redaction_key.as_deref(), Some(REDACTED_ID));
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
        let result = simplify_registry_domain_id(Box::new(domain));

        // THEN the domain should not have duplicate redaction remark
        assert_eq!(result.handle(), Some(REDACTED_ID));
        
        let remarks = result.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        
        // Should only have the existing remark (no duplicate)
        assert_eq!(remarks[0].simple_redaction_key.as_deref(), Some(REDACTED_ID));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing redaction description".to_string())
        );
    }

    #[test]
    fn test_simplify_registry_domain_id_with_domain_no_handle() {
        // GIVEN a domain with no handle
        let domain = Domain::builder()
            .ldh_name("example.com")
            .build();

        // WHEN calling simplify_registry_domain_id
        let result = simplify_registry_domain_id(Box::new(domain));

        // THEN the domain should have redacted handle
        assert_eq!(result.handle(), Some(REDACTED_ID));
        
        // AND a remark should be added
        let remarks = result.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert_eq!(remarks[0].simple_redaction_key.as_deref(), Some(REDACTED_ID));
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
        let result = simplify_registry_domain_id(Box::new(domain));

        // THEN the domain should have redacted handle and remark
        assert_eq!(result.handle(), Some(REDACTED_ID));
        
        let remarks = result.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert_eq!(remarks[0].simple_redaction_key.as_deref(), Some(REDACTED_ID));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec().first(),
            Some(&REDACTED_ID_DESC.to_string())
        );
    }
}
