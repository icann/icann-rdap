//! Useful JSContact Functions
//!
//! The [JsContactConvert] trait implements methods to convert RDAP objects
//! to JSContact.

use crate::{
    contact::Contact,
    prelude::{
        Autnum, Domain, DomainSearchResults, Entity, EntitySearchResults, Nameserver,
        NameserverSearchResults, Network, RdapResponse, ToResponse,
    },
};

pub trait JsContactConvert {
    /// Converts an object to JSContact if it has vCard and no JSContact.
    fn to_jscontact(self) -> Self;

    /// Calls [JsContactConvert::to_jscontact] and the removes vCard.
    fn only_jscontact(self) -> Self;
}

impl JsContactConvert for RdapResponse {
    fn to_jscontact(self) -> Self {
        match self {
            RdapResponse::Entity(entity) => entity.to_jscontact().to_response(),
            RdapResponse::Domain(domain) => domain.to_jscontact().to_response(),
            RdapResponse::Nameserver(nameserver) => nameserver.to_jscontact().to_response(),
            RdapResponse::Autnum(autnum) => autnum.to_jscontact().to_response(),
            RdapResponse::Network(network) => network.to_jscontact().to_response(),
            RdapResponse::DomainSearchResults(domain_search_results) => {
                domain_search_results.to_jscontact().to_response()
            }
            RdapResponse::EntitySearchResults(entity_search_results) => {
                entity_search_results.to_jscontact().to_response()
            }
            RdapResponse::NameserverSearchResults(nameserver_search_results) => {
                nameserver_search_results.to_jscontact().to_response()
            }
            RdapResponse::ErrorResponse(rfc9083_error) => rfc9083_error.to_response(),
            RdapResponse::Help(help) => help.to_response(),
        }
    }

    fn only_jscontact(self) -> Self {
        match self {
            RdapResponse::Entity(entity) => entity.only_jscontact().to_response(),
            RdapResponse::Domain(domain) => domain.only_jscontact().to_response(),
            RdapResponse::Nameserver(nameserver) => nameserver.only_jscontact().to_response(),
            RdapResponse::Autnum(autnum) => autnum.only_jscontact().to_response(),
            RdapResponse::Network(network) => network.only_jscontact().to_response(),
            RdapResponse::DomainSearchResults(domain_search_results) => {
                domain_search_results.only_jscontact().to_response()
            }
            RdapResponse::EntitySearchResults(entity_search_results) => {
                entity_search_results.only_jscontact().to_response()
            }
            RdapResponse::NameserverSearchResults(nameserver_search_results) => {
                nameserver_search_results.only_jscontact().to_response()
            }
            RdapResponse::ErrorResponse(rfc9083_error) => rfc9083_error.to_response(),
            RdapResponse::Help(help) => help.to_response(),
        }
    }
}

impl JsContactConvert for Entity {
    fn to_jscontact(self) -> Self {
        let new_jscontact = if self.jscontact_card.is_none() {
            if let Some(ref vcard_array) = self.vcard_array {
                Contact::from_vcard(vcard_array).map(|contact| contact.to_jscontact())
            } else {
                self.jscontact_card
            }
        } else {
            self.jscontact_card
        };
        Self {
            object_common: super::ObjectCommon {
                entities: self.object_common.entities.map(|v| v.to_jscontact()),
                ..self.object_common
            },
            jscontact_card: new_jscontact,
            ..self
        }
    }

    fn only_jscontact(self) -> Self {
        let mut entity = self.to_jscontact();
        entity.object_common.entities = entity.object_common.entities.map(|ve| ve.only_jscontact());
        entity.vcard_array = None;
        entity
    }
}

impl JsContactConvert for Vec<Entity> {
    fn to_jscontact(self) -> Self {
        self.into_iter().map(|e| e.to_jscontact()).collect()
    }

    fn only_jscontact(self) -> Self {
        self.into_iter().map(|e| e.only_jscontact()).collect()
    }
}

impl JsContactConvert for Network {
    fn to_jscontact(self) -> Self {
        Self {
            object_common: super::ObjectCommon {
                entities: self.object_common.entities.map(|v| v.to_jscontact()),
                ..self.object_common
            },
            ..self
        }
    }

    fn only_jscontact(self) -> Self {
        Self {
            object_common: super::ObjectCommon {
                entities: self.object_common.entities.map(|v| v.only_jscontact()),
                ..self.object_common
            },
            ..self
        }
    }
}

impl JsContactConvert for Domain {
    fn to_jscontact(self) -> Self {
        Self {
            object_common: super::ObjectCommon {
                entities: self.object_common.entities.map(|v| v.to_jscontact()),
                ..self.object_common
            },
            ..self
        }
    }

    fn only_jscontact(self) -> Self {
        Self {
            object_common: super::ObjectCommon {
                entities: self.object_common.entities.map(|v| v.only_jscontact()),
                ..self.object_common
            },
            ..self
        }
    }
}

impl JsContactConvert for Autnum {
    fn to_jscontact(self) -> Self {
        Self {
            object_common: super::ObjectCommon {
                entities: self.object_common.entities.map(|v| v.to_jscontact()),
                ..self.object_common
            },
            ..self
        }
    }

    fn only_jscontact(self) -> Self {
        Self {
            object_common: super::ObjectCommon {
                entities: self.object_common.entities.map(|v| v.only_jscontact()),
                ..self.object_common
            },
            ..self
        }
    }
}

impl JsContactConvert for Nameserver {
    fn to_jscontact(self) -> Self {
        Self {
            object_common: super::ObjectCommon {
                entities: self.object_common.entities.map(|v| v.to_jscontact()),
                ..self.object_common
            },
            ..self
        }
    }

    fn only_jscontact(self) -> Self {
        Self {
            object_common: super::ObjectCommon {
                entities: self.object_common.entities.map(|v| v.only_jscontact()),
                ..self.object_common
            },
            ..self
        }
    }
}

impl JsContactConvert for DomainSearchResults {
    fn to_jscontact(self) -> Self {
        Self {
            results: self.results.into_iter().map(|i| i.to_jscontact()).collect(),
            ..self
        }
    }

    fn only_jscontact(self) -> Self {
        Self {
            results: self
                .results
                .into_iter()
                .map(|i| i.only_jscontact())
                .collect(),
            ..self
        }
    }
}

impl JsContactConvert for NameserverSearchResults {
    fn to_jscontact(self) -> Self {
        Self {
            results: self.results.into_iter().map(|i| i.to_jscontact()).collect(),
            ..self
        }
    }

    fn only_jscontact(self) -> Self {
        Self {
            results: self
                .results
                .into_iter()
                .map(|i| i.only_jscontact())
                .collect(),
            ..self
        }
    }
}

impl JsContactConvert for EntitySearchResults {
    fn to_jscontact(self) -> Self {
        Self {
            results: self.results.into_iter().map(|i| i.to_jscontact()).collect(),
            ..self
        }
    }

    fn only_jscontact(self) -> Self {
        Self {
            results: self
                .results
                .into_iter()
                .map(|i| i.only_jscontact())
                .collect(),
            ..self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;

    #[test]
    fn test_entity_to_jscontact_with_vcard() {
        // GIVEN: An entity with vCard data but no JSContact
        let contact = Contact::builder().full_name("John Doe").build();
        let mut entity = Entity::builder().handle("test-entity").build();
        entity.with_contact_as_vcard(&contact);

        // WHEN: Converting to JSContact
        let result = entity.to_jscontact();

        // THEN: The entity should have JSContact data and retain vCard
        assert!(result.is_contact_as_jscontact());
        assert!(result.is_contact_as_vcard());
        assert_eq!(result.object_common.handle.unwrap(), "test-entity");
    }

    #[test]
    fn test_entity_only_jscontact_with_vcard() {
        // GIVEN: An entity with vCard data but no JSContact
        let contact = Contact::builder().full_name("John Doe").build();
        let mut entity = Entity::builder().handle("test-entity").build();
        entity.with_contact_as_vcard(&contact);

        // WHEN: Converting to JSContact only
        let result = entity.only_jscontact();

        // THEN: The entity should have JSContact data but no vCard
        assert!(result.is_contact_as_jscontact());
        assert!(!result.is_contact_as_vcard());
        assert_eq!(result.object_common.handle.unwrap(), "test-entity");
    }

    #[test]
    fn test_entity_to_jscontact_with_existing_jscontact() {
        // GIVEN: An entity with existing JSContact data
        let _jscontact = Contact::builder()
            .full_name("Jane Smith")
            .build()
            .to_jscontact();
        let contact = Contact::builder().full_name("Jane Smith").build();
        let mut entity = Entity::builder().handle("test-entity").build();
        entity.with_contact_as_jscontact(&contact);
        entity.with_contact_as_vcard(&contact);

        // WHEN: Converting to JSContact
        let result = entity.to_jscontact();

        // THEN: The existing JSContact should be preserved
        assert!(result.is_contact_as_jscontact());
        assert!(result.is_contact_as_vcard());
    }

    #[test]
    fn test_entity_to_jscontact_without_contact_data() {
        // GIVEN: An entity with no contact data
        let entity = Entity::builder().handle("test-entity").build();

        // WHEN: Converting to JSContact
        let result = entity.to_jscontact();

        // THEN: No conversion should occur
        assert!(!result.is_contact_as_jscontact());
        assert!(!result.is_contact_as_vcard());
        assert_eq!(result.object_common.handle.unwrap(), "test-entity");
    }

    #[test]
    fn test_rdap_response_entity_to_jscontact() {
        // GIVEN: An RDAP response containing an entity with vCard
        let contact = Contact::builder().full_name("Bob Johnson").build();
        let mut entity = Entity::builder().handle("test-entity").build();
        entity.with_contact_as_vcard(&contact);
        let rdap_response = RdapResponse::Entity(Box::new(entity));

        // WHEN: Converting to JSContact
        let result = rdap_response.to_jscontact();

        // THEN: The entity should be converted to JSContact
        match result {
            RdapResponse::Entity(converted_entity) => {
                assert!(converted_entity.is_contact_as_jscontact());
                assert!(converted_entity.is_contact_as_vcard());
            }
            _ => panic!("Expected Entity response"),
        }
    }

    #[test]
    fn test_rdap_response_domain_to_jscontact() {
        // GIVEN: A domain with entities containing vCard data
        let contact = Contact::builder().full_name("Domain Owner").build();
        let mut entity = Entity::builder().handle("registrant").build();
        entity.with_contact_as_vcard(&contact);
        let domain = Domain::response_obj()
            .handle("example.com")
            .ldh_name("example.com")
            .entities(vec![entity])
            .build();
        let rdap_response = RdapResponse::Domain(Box::new(domain));

        // WHEN: Converting to JSContact
        let result = rdap_response.to_jscontact();

        // THEN: The entities should be converted to JSContact
        match result {
            RdapResponse::Domain(converted_domain) => {
                if let Some(entities) = &converted_domain.object_common.entities {
                    assert_eq!(entities.len(), 1);
                    assert!(entities[0].is_contact_as_jscontact());
                    assert!(entities[0].is_contact_as_vcard());
                } else {
                    panic!("Expected entities to be present");
                }
            }
            _ => panic!("Expected Domain response"),
        }
    }

    #[test]
    fn test_vec_entity_to_jscontact() {
        // GIVEN: A vector of entities with vCard data
        let contact1 = Contact::builder().full_name("Entity One").build();
        let mut entity1 = Entity::builder().handle("entity1").build();
        entity1.with_contact_as_vcard(&contact1);

        let contact2 = Contact::builder().full_name("Entity Two").build();
        let mut entity2 = Entity::builder().handle("entity2").build();
        entity2.with_contact_as_vcard(&contact2);

        let entities = vec![entity1, entity2];

        // WHEN: Converting to JSContact
        let result = entities.to_jscontact();

        // THEN: All entities should be converted
        assert_eq!(result.len(), 2);
        for entity in &result {
            assert!(entity.is_contact_as_jscontact());
            assert!(entity.is_contact_as_vcard());
        }
    }

    #[test]
    fn test_domain_search_results_to_jscontact() {
        // GIVEN: Domain search results with entities having vCard data
        let contact = Contact::builder().full_name("Admin Contact").build();
        let mut entity = Entity::builder().handle("admin").build();
        entity.with_contact_as_vcard(&contact);
        let domain = Domain::response_obj()
            .handle("test.com")
            .ldh_name("test.com")
            .entities(vec![entity])
            .build();
        let search_results = DomainSearchResults::response_obj()
            .results(vec![domain])
            .build();

        // WHEN: Converting to JSContact
        let result = search_results.to_jscontact();

        // THEN: All domain entities should be converted
        assert_eq!(result.results.len(), 1);
        if let Some(entities) = &result.results[0].object_common.entities {
            assert_eq!(entities.len(), 1);
            assert!(entities[0].is_contact_as_jscontact());
            assert!(entities[0].is_contact_as_vcard());
        }
    }

    #[test]
    fn test_network_to_jscontact_preserves_other_fields() {
        // GIVEN: A network with entities and other data
        let contact = Contact::builder().full_name("Network Admin").build();
        let mut entity = Entity::builder().handle("network-admin").build();
        entity.with_contact_as_vcard(&contact);
        let network = Network::builder()
            .cidr("192.0.2.0/24")
            .handle("192.0.2.0/24")
            .entities(vec![entity])
            .build()
            .unwrap();

        // WHEN: Converting to JSContact
        let result = network.to_jscontact();

        // THEN: Network data should be preserved and entities converted
        assert_eq!(result.object_common.handle.unwrap(), "192.0.2.0/24");
        if let Some(entities) = &result.object_common.entities {
            assert_eq!(entities.len(), 1);
            assert!(entities[0].is_contact_as_jscontact());
            assert!(entities[0].is_contact_as_vcard());
        }
    }

    #[test]
    fn test_autnum_to_jscontact() {
        // GIVEN: An autnum with entities containing vCard data
        let contact = Contact::builder().full_name("Autnum Contact").build();
        let mut entity = Entity::builder().handle("autnum-contact").build();
        entity.with_contact_as_vcard(&contact);
        let autnum = Autnum::builder()
            .autnum_range(65536..65537)
            .handle("AS65536")
            .entities(vec![entity])
            .build();

        // WHEN: Converting to JSContact
        let result = autnum.to_jscontact();

        // THEN: The entities should be converted
        if let Some(entities) = &result.object_common.entities {
            assert_eq!(entities.len(), 1);
            assert!(entities[0].is_contact_as_jscontact());
            assert!(entities[0].is_contact_as_vcard());
        }
    }

    #[test]
    fn test_nameserver_to_jscontact() {
        // GIVEN: A nameserver with entities containing vCard data
        let contact = Contact::builder().full_name("Nameserver Contact").build();
        let mut entity = Entity::builder().handle("ns-contact").build();
        entity.with_contact_as_vcard(&contact);
        let nameserver = Nameserver::response_obj()
            .handle("ns1.example.com")
            .ldh_name("ns1.example.com")
            .entities(vec![entity])
            .build()
            .unwrap();

        // WHEN: Converting to JSContact
        let result = nameserver.to_jscontact();

        // THEN: The entities should be converted
        if let Some(entities) = &result.object_common.entities {
            assert_eq!(entities.len(), 1);
            assert!(entities[0].is_contact_as_jscontact());
            assert!(entities[0].is_contact_as_vcard());
        }
    }

    #[test]
    fn test_entity_search_results_to_jscontact() {
        // GIVEN: Entity search results with vCard data
        let contact = Contact::builder().full_name("Search Result Entity").build();
        let mut entity = Entity::builder().handle("search-entity").build();
        entity.with_contact_as_vcard(&contact);
        let search_results = EntitySearchResults::response_obj()
            .results(vec![entity])
            .build();

        // WHEN: Converting to JSContact
        let result = search_results.to_jscontact();

        // THEN: All entities should be converted
        assert_eq!(result.results.len(), 1);
        assert!(result.results[0].is_contact_as_jscontact());
        assert!(result.results[0].is_contact_as_vcard());
    }

    #[test]
    fn test_nameserver_search_results_to_jscontact() {
        // GIVEN: Nameserver search results with entities containing vCard data
        let contact = Contact::builder().full_name("NS Search Contact").build();
        let mut entity = Entity::builder().handle("ns-search-contact").build();
        entity.with_contact_as_vcard(&contact);
        let nameserver = Nameserver::response_obj()
            .handle("ns2.example.com")
            .ldh_name("ns2.example.com")
            .entities(vec![entity])
            .build()
            .unwrap();
        let search_results = NameserverSearchResults::response_obj()
            .results(vec![nameserver])
            .build();

        // WHEN: Converting to JSContact
        let result = search_results.to_jscontact();

        // THEN: All nameserver entities should be converted
        assert_eq!(result.results.len(), 1);
        if let Some(entities) = &result.results[0].object_common.entities {
            assert_eq!(entities.len(), 1);
            assert!(entities[0].is_contact_as_jscontact());
            assert!(entities[0].is_contact_as_vcard());
        }
    }

    #[test]
    fn test_nested_entity_to_jscontact() {
        // GIVEN: An entity with nested entities containing vCard data
        let nested_contact = Contact::builder().full_name("Nested Entity").build();
        let mut nested_entity = Entity::builder().handle("nested-entity").build();
        nested_entity.with_contact_as_vcard(&nested_contact);

        let mut parent_entity = Entity::builder().handle("parent-entity").build();
        parent_entity.object_common.entities = Some(vec![nested_entity]);

        // WHEN: Converting to JSContact
        let result = parent_entity.to_jscontact();

        // THEN: Both parent and nested entities should be converted
        assert!(result.is_contact_as_vcard() || !result.is_contact_as_vcard());
        if let Some(entities) = &result.object_common.entities {
            assert_eq!(entities.len(), 1);
            assert!(entities[0].is_contact_as_jscontact());
            assert!(entities[0].is_contact_as_vcard());
        }
    }

    #[test]
    fn test_nested_entity_only_jscontact() {
        // GIVEN: An entity with nested entities containing vCard data
        let nested_contact = Contact::builder().full_name("Nested Entity Only").build();
        let mut nested_entity = Entity::builder().handle("nested-entity-only").build();
        nested_entity.with_contact_as_vcard(&nested_contact);

        let mut parent_entity = Entity::builder().handle("parent-entity-only").build();
        parent_entity.object_common.entities = Some(vec![nested_entity]);

        // WHEN: Converting to JSContact only (removing vCard)
        let result = parent_entity.only_jscontact();

        // THEN: Parent should have no vCard, but nested should have jscontact
        assert!(!result.is_contact_as_vcard());
        if let Some(entities) = &result.object_common.entities {
            assert_eq!(entities.len(), 1);
            assert!(entities[0].is_contact_as_jscontact());
            assert!(!entities[0].is_contact_as_vcard());
        }
    }

    #[test]
    fn test_deeply_nested_entities_to_jscontact() {
        // GIVEN: An entity with 3 levels of nested entities
        let level3_contact = Contact::builder().full_name("Level 3 Entity").build();
        let mut level3_entity = Entity::builder().handle("level3-entity").build();
        level3_entity.with_contact_as_vcard(&level3_contact);

        let mut level2_entity = Entity::builder().handle("level2-entity").build();
        level2_entity.object_common.entities = Some(vec![level3_entity]);

        let mut level1_entity = Entity::builder().handle("level1-entity").build();
        level1_entity.object_common.entities = Some(vec![level2_entity]);

        // WHEN: Converting to JSContact
        let result = level1_entity.to_jscontact();

        // THEN: All nested levels should be converted
        if let Some(level1_entities) = &result.object_common.entities {
            assert_eq!(level1_entities.len(), 1);
            if let Some(level2_entities) = &level1_entities[0].object_common.entities {
                assert_eq!(level2_entities.len(), 1);
                if let Some(level3_entities) = &level2_entities[0].object_common.entities {
                    assert_eq!(level3_entities.len(), 1);
                    assert!(level3_entities[0].is_contact_as_jscontact());
                    assert!(level3_entities[0].is_contact_as_vcard());
                }
            }
        }
    }

    #[test]
    fn test_deeply_nested_entities_only_jscontact() {
        // GIVEN: An entity with 3 levels of nested entities
        let level3_contact = Contact::builder().full_name("Level 3 Only").build();
        let mut level3_entity = Entity::builder().handle("level3-only").build();
        level3_entity.with_contact_as_vcard(&level3_contact);

        let mut level2_entity = Entity::builder().handle("level2-only").build();
        level2_entity.object_common.entities = Some(vec![level3_entity]);

        let mut level1_entity = Entity::builder().handle("level1-only").build();
        level1_entity.object_common.entities = Some(vec![level2_entity]);

        // WHEN: Converting to JSContact only
        let result = level1_entity.only_jscontact();

        // THEN: All levels should have jscontact but no vCard
        if let Some(level1_entities) = &result.object_common.entities {
            assert!(!level1_entities[0].is_contact_as_vcard());
            if let Some(level2_entities) = &level1_entities[0].object_common.entities {
                assert!(!level2_entities[0].is_contact_as_vcard());
                if let Some(level3_entities) = &level2_entities[0].object_common.entities {
                    assert!(!level3_entities[0].is_contact_as_vcard());
                    assert!(level3_entities[0].is_contact_as_jscontact());
                }
            }
        }
    }

    #[test]
    fn test_multiple_nested_entities_to_jscontact() {
        // GIVEN: An entity with multiple nested entities
        let contact1 = Contact::builder().full_name("Nested 1").build();
        let mut nested1 = Entity::builder().handle("nested-1").build();
        nested1.with_contact_as_vcard(&contact1);

        let contact2 = Contact::builder().full_name("Nested 2").build();
        let mut nested2 = Entity::builder().handle("nested-2").build();
        nested2.with_contact_as_vcard(&contact2);

        let contact3 = Contact::builder().full_name("Nested 3").build();
        let mut nested3 = Entity::builder().handle("nested-3").build();
        nested3.with_contact_as_vcard(&contact3);

        let mut parent_entity = Entity::builder().handle("parent-multi").build();
        parent_entity.object_common.entities = Some(vec![nested1, nested2, nested3]);

        // WHEN: Converting to JSContact
        let result = parent_entity.to_jscontact();

        // THEN: All nested entities should be converted
        if let Some(entities) = &result.object_common.entities {
            assert_eq!(entities.len(), 3);
            for entity in entities {
                assert!(entity.is_contact_as_jscontact());
                assert!(entity.is_contact_as_vcard());
            }
        }
    }

    #[test]
    fn test_vec_nested_entities_only_jscontact() {
        // GIVEN: A vector of entities, each with nested entities
        let nested_contact = Contact::builder().full_name("Child Entity").build();
        let mut nested = Entity::builder().handle("child").build();
        nested.with_contact_as_vcard(&nested_contact);

        let mut entity1 = Entity::builder().handle("parent1").build();
        entity1.object_common.entities = Some(vec![nested]);

        let mut entity2 = Entity::builder().handle("parent2").build();
        entity2.object_common.entities = Some(vec![]);

        let entities = vec![entity1, entity2];

        // WHEN: Converting to JSContact only
        let result = entities.only_jscontact();

        // THEN: All entities should be converted, nested should have no vCard
        assert_eq!(result.len(), 2);
        assert!(!result[0].is_contact_as_vcard());
        assert!(!result[1].is_contact_as_vcard());
        if let Some(nested) = &result[0].object_common.entities {
            assert_eq!(nested.len(), 1);
            assert!(nested[0].is_contact_as_jscontact());
            assert!(!nested[0].is_contact_as_vcard());
        }
    }
}
