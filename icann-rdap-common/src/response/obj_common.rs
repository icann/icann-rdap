use serde::{Deserialize, Serialize};

use super::{
    redacted::Redacted, to_opt_vectorstringish, Entity, Events, Link, Links, Port43, Remarks,
    Stringish, VectorStringish, EMPTY_VEC_STRING,
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
    pub fn set_self_link(mut self, mut link: Link) -> Self {
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
    pub fn get_self_link(&self) -> Option<&Link> {
        if let Some(links) = &self.links {
            links.iter().find(|link| link.is_relation("self"))
        } else {
            None
        }
    }
}

/// Empty Remarks.
static EMPTY_REMARKS: Remarks = vec![];
/// Empty Links.
static EMPTY_LINKS: Links = vec![];
/// Empty Events.
static EMPTY_EVENTS: Events = vec![];
/// Empty Entities.
static EMPTY_ENTITIES: Vec<Entity> = vec![];

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

    /// Getter for [Remarks].
    fn remarks(&self) -> &Remarks {
        self.object_common()
            .remarks
            .as_ref()
            .unwrap_or(&EMPTY_REMARKS)
    }

    /// Getter for [Links].
    fn links(&self) -> &Links {
        self.object_common().links.as_ref().unwrap_or(&EMPTY_LINKS)
    }

    /// Getter for [Events].
    fn events(&self) -> &Events {
        self.object_common()
            .events
            .as_ref()
            .unwrap_or(&EMPTY_EVENTS)
    }

    /// Getter for status.
    fn status(&self) -> &Vec<String> {
        self.object_common()
            .status
            .as_ref()
            .map(|v| v.vec())
            .unwrap_or(&EMPTY_VEC_STRING)
    }

    /// Getter for Vec of [Entity].
    fn entities(&self) -> &Vec<Entity> {
        self.object_common()
            .entities
            .as_ref()
            .unwrap_or(&EMPTY_ENTITIES)
    }
}
