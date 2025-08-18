//! Entity object class.
use {
    crate::{
        contact::Contact,
        prelude::{Common, Extension, ObjectCommon},
    },
    serde::{Deserialize, Serialize},
    serde_json::Value,
    strum_macros::{Display, EnumString},
};

use super::{
    autnum::Autnum,
    network::Network,
    to_opt_vec, to_opt_vectorstringish,
    types::{Events, Link, PublicIds},
    CommonFields, Event, GetSelfLink, Notice, ObjectCommonFields, Port43, PublicId, Remark,
    SelfLink, ToChild, ToResponse, VectorStringish,
};

/// Represents an RDAP [entity](https://rdap.rcode3.com/protocol/object_classes.html#entity) response.
///
/// Use of the builder is recommended when constructing this structure as it
/// will fill-in the mandatory fields.
/// The following is an example.
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let contact = Contact::builder()
///   .kind("individual")
///   .full_name("Bob Smurd")
///   .build();
///
/// let entity = Entity::builder()
///   .handle("foo_example_com-1")
///   .status("active")
///   .role("registrant")
///   .contact(contact)
///   .build();
/// let c = serde_json::to_string_pretty(&entity).unwrap();
/// eprintln!("{c}");
/// ```
///
/// This will produce the following.
///
/// ```norust
/// {
///   "rdapConformance": [
///     "rdap_level_0"
///   ],
///   "objectClassName": "entity",
///   "handle": "foo_example_com-1",
///   "status": [
///     "active"
///   ],
///   "vcardArray": [
///     "vcard",
///     [
///       [
///         "version",
///         {},
///         "text",
///         "4.0"
///       ],
///       [
///         "fn",
///         {},
///         "text",
///         "Bob Smurd"
///       ],
///       [
///         "kind",
///         {},
///         "text",
///         "individual"
///       ]
///     ]
///   ],
///   "roles": [
///     "registrant"
///   ]
/// }
/// ```
///
/// Use the getter functions to get the data in the entity. Because
/// data from vCard can be difficult to handle, you can use the [Contact]
/// abstraction for address information.
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let entity = Entity::builder()
///   .handle("foo_example_com-1")
///   // ...
///   .build();
///
/// // get the information
/// let contact = entity.contact();
/// let public_ids = entity.public_ids();
/// // ...
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Entity {
    #[serde(flatten)]
    pub common: Common,

    #[serde(flatten)]
    pub object_common: ObjectCommon,

    #[serde(rename = "vcardArray")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcard_array: Option<Vec<Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<VectorStringish>,

    #[serde(rename = "publicIds")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ids: Option<PublicIds>,

    #[serde(rename = "asEventActor")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_event_actor: Option<Events>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub autnums: Option<Vec<Autnum>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub networks: Option<Vec<Network>>,
}

#[buildstructor::buildstructor]
impl Entity {
    /// Builds a basic entity object.
    ///
    /// ```rust
    /// use icann_rdap_common::prelude::*;
    ///
    /// let contact = Contact::builder()
    ///   .kind("individual")
    ///   .full_name("Bob Smurd")
    ///   .build();
    ///
    /// let entity = Entity::builder()
    ///   .handle("foo_example_com-1")
    ///   .status("active")
    ///   .role("registrant")
    ///   .contact(contact)
    ///   .build();
    /// ```
    ///
    /// An entity without a handle can be
    /// built if a generic type is specified.
    ///
    /// ```rust
    /// use icann_rdap_common::prelude::*;
    ///
    /// let entity = Entity::builder::<String>()
    ///   .status("active")
    ///   .build();
    /// ```
    #[builder(visibility = "pub")]
    fn new<T: Into<String>>(
        handle: Option<T>,
        remarks: Vec<Remark>,
        links: Vec<Link>,
        events: Vec<Event>,
        statuses: Vec<String>,
        port_43: Option<Port43>,
        entities: Vec<Entity>,
        as_event_actors: Vec<Event>,
        contact: Option<Contact>,
        roles: Vec<String>,
        public_ids: Vec<PublicId>,
        notices: Vec<Notice>,
        networks: Vec<Network>,
        autnums: Vec<Autnum>,
        extensions: Vec<Extension>,
        redacted: Option<Vec<crate::response::redacted::Redacted>>,
    ) -> Self {
        Self {
            common: Common::level0()
                .extensions(extensions)
                .and_notices(to_opt_vec(notices))
                .build(),
            object_common: ObjectCommon::entity()
                .and_handle(handle.map(|h| h.into()))
                .and_remarks(to_opt_vec(remarks))
                .and_links(to_opt_vec(links))
                .and_events(to_opt_vec(events))
                .status(statuses)
                .and_port_43(port_43)
                .and_entities(to_opt_vec(entities))
                .and_redacted(redacted)
                .build(),
            vcard_array: contact.map(|c| c.to_vcard()),
            roles: to_opt_vectorstringish(roles),
            public_ids: to_opt_vec(public_ids),
            as_event_actor: to_opt_vec(as_event_actors),
            autnums: to_opt_vec(autnums),
            networks: to_opt_vec(networks),
        }
    }

    /// Get a [Contact] from the impentrable vCard.
    pub fn contact(&self) -> Option<Contact> {
        let vcard = self.vcard_array.as_ref()?;
        Contact::from_vcard(vcard)
    }

    /// Get the roles.
    pub fn roles(&self) -> &[String] {
        self.roles
            .as_ref()
            .map(|v| v.vec().as_ref())
            .unwrap_or_default()
    }

    /// Get the public IDs.
    pub fn public_ids(&self) -> &[PublicId] {
        self.public_ids.as_deref().unwrap_or_default()
    }

    /// Get the events this entity acted on.
    pub fn as_event_actors(&self) -> &[Event] {
        self.as_event_actor.as_deref().unwrap_or_default()
    }

    /// Get the autnums.
    pub fn autnums(&self) -> &[Autnum] {
        self.autnums.as_deref().unwrap_or_default()
    }

    /// Get the networks.
    pub fn networks(&self) -> &[Network] {
        self.networks.as_deref().unwrap_or_default()
    }
}

impl ToResponse for Entity {
    fn to_response(self) -> super::RdapResponse {
        super::RdapResponse::Entity(Box::new(self))
    }
}

impl GetSelfLink for Entity {
    fn get_self_link(&self) -> Option<&Link> {
        self.object_common.get_self_link()
    }
}

impl SelfLink for Entity {
    fn set_self_link(mut self, link: Link) -> Self {
        self.object_common = self.object_common.set_self_link(link);
        self
    }
}

impl ToChild for Entity {
    fn to_child(mut self) -> Self {
        self.common = Common {
            rdap_conformance: None,
            notices: None,
        };
        self
    }
}

impl CommonFields for Entity {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ObjectCommonFields for Entity {
    fn object_common(&self) -> &ObjectCommon {
        &self.object_common
    }
}

/// IANA registered roles for entities.
#[derive(PartialEq, Eq, Debug, EnumString, Display)]
#[strum(serialize_all = "lowercase")]
pub enum EntityRole {
    Registrant,
    Technical,
    Administrative,
    Abuse,
    Billing,
    Registrar,
    Reseller,
    Sponsor,
    Proxy,
    Notifications,
    Noc,
}

#[cfg(test)]
mod tests {
    use super::Entity;

    #[test]
    fn test_entity_deserialize() {
        // GIVEN
        let expected = r#"
            {
              "objectClassName" : "entity",
              "handle":"XXXX",
              "vcardArray":[
                "vcard",
                [
                  ["version", {}, "text", "4.0"],
                  ["fn", {}, "text", "Joe User"],
                  ["n", {}, "text",
                    ["User", "Joe", "", "", ["ing. jr", "M.Sc."]]
                  ],
                  ["kind", {}, "text", "individual"],
                  ["lang", {
                    "pref":"1"
                  }, "language-tag", "fr"],
                  ["lang", {
                    "pref":"2"
                  }, "language-tag", "en"],
                  ["org", {
                    "type":"work"
                  }, "text", "Example"],
                  ["title", {}, "text", "Research Scientist"],
                  ["role", {}, "text", "Project Lead"],
                  ["adr",
                    { "type":"work" },
                    "text",
                    [
                      "",
                      "Suite 1234",
                      "4321 Rue Somewhere",
                      "Quebec",
                      "QC",
                      "G1V 2M2",
                      "Canada"
                    ]
                  ],
                  ["adr",
                    {
                      "type":"home",
                      "label":"123 Maple Ave\nSuite 90001\nVancouver\nBC\n1239\n"
                    },
                    "text",
                    [
                      "", "", "", "", "", "", ""
                    ]
                  ],
                  ["tel",
                    {
                      "type":["work", "voice"],
                      "pref":"1"
                    },
                    "uri",
                    "tel:+1-555-555-1234;ext=102"
                  ],
                  ["tel",
                    { "type":["work", "cell", "voice", "video", "text"] },
                    "uri",
                    "tel:+1-555-555-4321"
                  ],
                  ["email",
                    { "type":"work" },
                    "text",
                    "joe.user@example.com"
                  ],
                  ["geo", {
                    "type":"work"
                  }, "uri", "geo:46.772673,-71.282945"],
                  ["key",
                    { "type":"work" },
                    "uri",
                    "https://www.example.com/joe.user/joe.asc"
                  ],
                  ["tz", {},
                    "utc-offset", "-05:00"],
                  ["url", { "type":"home" },
                    "uri", "https://example.org"]
                ]
              ],
              "roles":[ "registrar" ],
              "publicIds":[
                {
                  "type":"IANA Registrar ID",
                  "identifier":"1"
                }
              ],
              "remarks":[
                {
                  "description":[
                    "She sells sea shells down by the sea shore.",
                    "Originally written by Terry Sullivan."
                  ]
                }
              ],
              "links":[
                {
                  "value":"https://example.com/entity/XXXX",
                  "rel":"self",
                  "href":"https://example.com/entity/XXXX",
                  "type" : "application/rdap+json"
                }
              ],
              "events":[
                {
                  "eventAction":"registration",
                  "eventDate":"1990-12-31T23:59:59Z"
                }
              ],
              "asEventActor":[

                {
                  "eventAction":"last changed",
                  "eventDate":"1991-12-31T23:59:59Z"
                }
              ]
            }
        "#;

        // WHEN
        let actual = serde_json::from_str::<Entity>(expected);

        // THEN
        let actual = actual.unwrap();
        assert_eq!(actual.object_common.object_class_name, "entity");
        assert!(actual.object_common.handle.is_some());
        assert!(actual.vcard_array.is_some());
        assert!(actual.roles.is_some());
        assert!(actual.public_ids.is_some());
        assert!(actual.object_common.remarks.is_some());
        assert!(actual.object_common.links.is_some());
        assert!(actual.object_common.events.is_some());
        assert!(actual.as_event_actor.is_some());
    }
}
