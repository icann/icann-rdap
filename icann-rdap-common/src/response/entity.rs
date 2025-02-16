//! Entity object class.
use crate::contact::Contact;
use crate::prelude::Common;
use crate::prelude::Extension;
use crate::prelude::ObjectCommon;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum_macros::{Display, EnumString};

use super::CommonFields;
use super::ObjectCommonFields;
use super::{
    autnum::Autnum,
    network::Network,
    to_opt_vec,
    types::{to_option_status, Events, Link, PublicIds},
    Event, GetSelfLink, Notice, Port43, PublicId, Remark, SelfLink, ToChild,
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
    pub roles: Option<Vec<String>>,

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

lazy_static! {
    static ref EMPTY_ROLES: Vec<String> = vec![];
    static ref EMPTY_PUBLIC_IDS: Vec<PublicId> = vec![];
    static ref EMPTY_AS_EVENT_ACTORS: Vec<Event> = vec![];
    static ref EMPTY_AUTNUMS: Vec<Autnum> = vec![];
    static ref EMPTY_NETWORKS: Vec<Network> = vec![];
}

#[buildstructor::buildstructor]
impl Entity {
    /// Builds a basic autnum object.
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
    #[builder(visibility = "pub")]
    #[allow(clippy::too_many_arguments)]
    fn new<T: Into<String>>(
        handle: T,
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
                .handle(handle.into())
                .and_remarks(to_opt_vec(remarks))
                .and_links(to_opt_vec(links))
                .and_events(to_opt_vec(events))
                .and_status(to_option_status(statuses))
                .and_port_43(port_43)
                .and_entities(to_opt_vec(entities))
                .and_redacted(redacted)
                .build(),
            vcard_array: contact.map(|c| c.to_vcard()),
            roles: to_opt_vec(roles),
            public_ids: to_opt_vec(public_ids),
            as_event_actor: to_opt_vec(as_event_actors),
            autnums: to_opt_vec(autnums),
            networks: to_opt_vec(networks),
        }
    }

    /// Convenience method to get a [Contact] from the impentrable vCard.
    pub fn contact(&self) -> Option<Contact> {
        let vcard = self.vcard_array.as_ref()?;
        Contact::from_vcard(vcard)
    }

    /// Convenience method to get the roles.
    pub fn roles(&self) -> &Vec<String> {
        self.roles.as_ref().unwrap_or(&EMPTY_ROLES)
    }

    /// Convenience method to get the public IDs.
    pub fn public_ids(&self) -> &Vec<PublicId> {
        self.public_ids.as_ref().unwrap_or(&EMPTY_PUBLIC_IDS)
    }

    /// Convenience method to get the events this entity acted on.
    pub fn as_event_actors(&self) -> &Vec<Event> {
        self.as_event_actor
            .as_ref()
            .unwrap_or(&EMPTY_AS_EVENT_ACTORS)
    }

    /// Convenience method to get the autnums.
    pub fn autnums(&self) -> &Vec<Autnum> {
        self.autnums.as_ref().unwrap_or(&EMPTY_AUTNUMS)
    }

    /// Convenience method to get the networks.
    pub fn networks(&self) -> &Vec<Network> {
        self.networks.as_ref().unwrap_or(&EMPTY_NETWORKS)
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
#[allow(non_snake_case)]
mod tests {
    use super::Entity;

    #[test]
    fn GIVEN_entity_WHEN_deserialize_THEN_success() {
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
