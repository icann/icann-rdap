use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::prelude::ContentExtensions;

use super::{
    redacted::Redacted, to_opt_vectorstringish, Entity, Event, Events, Link, Links, Port43, Remark,
    Remarks, Stringish, VectorStringish,
};

/// Holds those types that are common in all object classes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ObjectCommon {
    #[serde(rename = "objectClassName")]
    pub object_class_name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<Stringish>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub remarks: Option<Remarks>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Events>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<VectorStringish>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "port43")]
    pub port_43: Option<Port43>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub entities: Option<Vec<Entity>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted: Option<Vec<Redacted>>,
}

#[buildstructor::buildstructor]
impl ObjectCommon {
    /// Builds [ObjectCommon] for a [crate::response::domain::Domain].
    #[builder(entry = "domain", visibility = "pub(crate)")]
    fn new_domain(
        handle: Option<String>,
        remarks: Option<Remarks>,
        links: Option<Links>,
        events: Option<Events>,
        status: Option<Vec<String>>,
        port_43: Option<Port43>,
        entities: Option<Vec<Entity>>,
        redacted: Option<Vec<Redacted>>,
    ) -> Self {
        Self {
            object_class_name: "domain".to_string(),
            handle: handle.map(|s| s.into()),
            remarks,
            links,
            events,
            status: to_opt_vectorstringish(status.unwrap_or_default()),
            port_43,
            entities,
            redacted,
        }
    }

    /// Builds [ObjectCommon] for a [crate::response::network::Network].
    #[builder(entry = "ip_network", visibility = "pub(crate)")]
    fn new_ip_network(
        handle: Option<String>,
        remarks: Option<Remarks>,
        links: Option<Links>,
        events: Option<Events>,
        status: Option<Vec<String>>,
        port_43: Option<Port43>,
        entities: Option<Vec<Entity>>,
        redacted: Option<Vec<Redacted>>,
    ) -> Self {
        Self {
            object_class_name: "ip network".to_string(),
            handle: handle.map(|s| s.into()),
            remarks,
            links,
            events,
            status: to_opt_vectorstringish(status.unwrap_or_default()),
            port_43,
            entities,
            redacted,
        }
    }

    /// Builds an [ObjectCommon] for an [crate::response::autnum::Autnum].
    #[builder(entry = "autnum", visibility = "pub(crate)")]
    fn new_autnum(
        handle: Option<String>,
        remarks: Option<Remarks>,
        links: Option<Links>,
        events: Option<Events>,
        status: Option<Vec<String>>,
        port_43: Option<Port43>,
        entities: Option<Vec<Entity>>,
        redacted: Option<Vec<Redacted>>,
    ) -> Self {
        Self {
            object_class_name: "autnum".to_string(),
            handle: handle.map(|s| s.into()),
            remarks,
            links,
            events,
            status: to_opt_vectorstringish(status.unwrap_or_default()),
            port_43,
            entities,
            redacted,
        }
    }

    /// Builds an [ObjectCommon] for a [crate::response::nameserver::Nameserver].
    #[builder(entry = "nameserver", visibility = "pub(crate)")]
    fn new_nameserver(
        handle: Option<String>,
        remarks: Option<Remarks>,
        links: Option<Links>,
        events: Option<Events>,
        status: Option<Vec<String>>,
        port_43: Option<Port43>,
        entities: Option<Vec<Entity>>,
        redacted: Option<Vec<Redacted>>,
    ) -> Self {
        Self {
            object_class_name: "nameserver".to_string(),
            handle: handle.map(|s| s.into()),
            remarks,
            links,
            events,
            status: to_opt_vectorstringish(status.unwrap_or_default()),
            port_43,
            entities,
            redacted,
        }
    }

    /// Builds an [ObjectCommon] for an [crate::response::entity::Entity].
    #[builder(entry = "entity", visibility = "pub(crate)")]
    fn new_entity(
        handle: Option<String>,
        remarks: Option<Remarks>,
        links: Option<Links>,
        events: Option<Events>,
        status: Option<Vec<String>>,
        port_43: Option<Port43>,
        entities: Option<Vec<Entity>>,
        redacted: Option<Vec<Redacted>>,
    ) -> Self {
        Self {
            object_class_name: "entity".to_string(),
            handle: handle.map(|s| s.into()),
            remarks,
            links,
            events,
            status: to_opt_vectorstringish(status.unwrap_or_default()),
            port_43,
            entities,
            redacted,
        }
    }

    /// This will remove all other self links and place the provided link
    /// into the Links. This method will also set the "rel" attribute
    /// to "self" on the provided link.
    pub fn with_self_link(mut self, mut link: Link) -> Self {
        link.rel = Some("self".to_string());
        if let Some(links) = self.links {
            let mut new_links = links
                .into_iter()
                .filter(|link| !link.is_relation("self"))
                .collect::<Vec<Link>>();
            new_links.push(link);
            self.links = Some(new_links);
        } else {
            self.links = Some(vec![link]);
        }
        self
    }

    /// Get the link with a `rel` of "self".
    pub fn self_link(&self) -> Option<&Link> {
        if let Some(links) = &self.links {
            links.iter().find(|link| link.is_relation("self"))
        } else {
            None
        }
    }

    /// Gets the first entity by the given role.
    ///
    /// Use [crate::response::EntityRole] to get registered role names.
    pub fn entity_by_role(&self, role: &str) -> Option<&Entity> {
        self.entities
            .as_deref()
            .unwrap_or_default()
            .iter()
            .find(|e| e.roles().iter().any(|r| r.eq(role)))
    }
}

/// Convenience methods for fields in [ObjectCommon].
pub trait ObjectCommonFields {
    /// Getter for [ObjectCommon].
    fn object_common(&self) -> &ObjectCommon;

    /// Returns the object class name.
    fn object_class_name(&self) -> &str {
        &self.object_common().object_class_name
    }

    /// Returns the handle, if present.
    fn handle(&self) -> Option<&str> {
        self.object_common().handle.as_deref()
    }

    /// Returns the port 43 information, if present.
    fn port_43(&self) -> Option<&Port43> {
        self.object_common().port_43.as_ref()
    }

    /// Getter for list of [Remark]s.
    fn remarks(&self) -> &[Remark] {
        self.object_common().remarks.as_deref().unwrap_or_default()
    }

    /// Getter for list of [Link]s.
    fn links(&self) -> &[Link] {
        self.object_common().links.as_deref().unwrap_or_default()
    }

    /// Getter for list of [Event]s.
    fn events(&self) -> &[Event] {
        self.object_common().events.as_deref().unwrap_or_default()
    }

    /// Getter for status.
    fn status(&self) -> &[String] {
        self.object_common()
            .status
            .as_ref()
            .map(|v| v.vec().as_ref())
            .unwrap_or_default()
    }

    /// Getter for list of [Entity].
    fn entities(&self) -> &[Entity] {
        self.object_common().entities.as_deref().unwrap_or_default()
    }

    /// Gets the first entity by the given role.
    ///
    /// See [ObjectCommon::get_entity_by_role].
    fn get_entity_by_role(&self, role: &str) -> Option<&Entity> {
        self.object_common().entity_by_role(role)
    }
}

impl ContentExtensions for ObjectCommon {
    fn content_extensions(&self) -> std::collections::HashSet<super::ExtensionId> {
        let mut exts = HashSet::new();
        self.remarks
            .as_deref()
            .unwrap_or_default()
            .iter()
            .for_each(|remark| {
                exts.extend(remark.content_extensions());
            });
        exts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_entity(handle: &str, roles: Vec<&str>) -> Entity {
        Entity::builder()
            .handle(handle)
            .roles(roles.into_iter().map(|s| s.to_string()).collect())
            .build()
    }

    #[test]
    fn test_get_entity_by_role_found() {
        // GIVEN
        let entity1 = create_test_entity("entity1", vec!["registrant", "administrative"]);
        let entity2 = create_test_entity("entity2", vec!["registrar", "technical"]);
        let entity3 = create_test_entity("entity3", vec!["abuse"]);

        let obj_common = ObjectCommon::entity()
            .and_entities(Some(vec![entity1, entity2, entity3]))
            .build();

        // WHEN
        let result = obj_common.entity_by_role("registrar");

        // THEN
        assert!(result.is_some());
        assert_eq!(result.unwrap().handle(), Some("entity2"));
    }

    #[test]
    fn test_get_entity_by_role_not_found() {
        // GIVEN
        let entity1 = create_test_entity("entity1", vec!["registrant", "administrative"]);
        let entity2 = create_test_entity("entity2", vec!["registrar", "technical"]);

        let obj_common = ObjectCommon::entity()
            .and_entities(Some(vec![entity1, entity2]))
            .build();

        // WHEN
        let result = obj_common.entity_by_role("abuse");

        // THEN
        assert!(result.is_none());
    }

    #[test]
    fn test_get_entity_by_role_no_entities() {
        // GIVEN
        let obj_common = ObjectCommon::entity().build();

        // WHEN
        let result = obj_common.entity_by_role("registrant");

        // THEN
        assert!(result.is_none());
    }

    #[test]
    fn test_get_entity_by_role_empty_entities() {
        // GIVEN
        let obj_common = ObjectCommon::entity().and_entities(Some(vec![])).build();

        // WHEN
        let result = obj_common.entity_by_role("registrant");

        // THEN
        assert!(result.is_none());
    }

    #[test]
    fn test_get_entity_by_role_multiple_matches_returns_first() {
        // GIVEN
        let entity1 = create_test_entity("entity1", vec!["registrar", "technical"]);
        let entity2 = create_test_entity("entity2", vec!["registrar", "administrative"]);
        let entity3 = create_test_entity("entity3", vec!["abuse"]);

        let obj_common = ObjectCommon::entity()
            .and_entities(Some(vec![entity1, entity2, entity3]))
            .build();

        // WHEN
        let result = obj_common.entity_by_role("registrar");

        // THEN
        assert!(result.is_some());
        assert_eq!(result.unwrap().handle(), Some("entity1"));
    }

    #[test]
    fn test_get_entity_by_role_entity_with_no_roles() {
        // GIVEN
        let entity1 = create_test_entity("entity1", vec![]);
        let entity2 = create_test_entity("entity2", vec!["registrar"]);

        let obj_common = ObjectCommon::entity()
            .and_entities(Some(vec![entity1, entity2]))
            .build();

        // WHEN
        let result = obj_common.entity_by_role("registrar");

        // THEN
        assert!(result.is_some());
        assert_eq!(result.unwrap().handle(), Some("entity2"));
    }

    #[test]
    fn test_get_entity_by_role_case_sensitive() {
        // GIVEN
        let entity1 = create_test_entity("entity1", vec!["Registrar"]);
        let entity2 = create_test_entity("entity2", vec!["registrar"]);

        let obj_common = ObjectCommon::entity()
            .and_entities(Some(vec![entity1, entity2]))
            .build();

        // WHEN
        let result_lower = obj_common.entity_by_role("registrar");
        let result_upper = obj_common.entity_by_role("Registrar");

        // THEN
        assert!(result_lower.is_some());
        assert_eq!(result_lower.unwrap().handle(), Some("entity2"));

        assert!(result_upper.is_some());
        assert_eq!(result_upper.unwrap().handle(), Some("entity1"));
    }

    #[test]
    fn test_get_entity_by_role_with_domain_object() {
        // GIVEN
        let entity1 = create_test_entity("entity1", vec!["registrant"]);
        let entity2 = create_test_entity("entity2", vec!["registrar"]);

        let obj_common = ObjectCommon::domain()
            .and_entities(Some(vec![entity1, entity2]))
            .build();

        // WHEN
        let result = obj_common.entity_by_role("registrant");

        // THEN
        assert!(result.is_some());
        assert_eq!(result.unwrap().handle(), Some("entity1"));
    }
}
