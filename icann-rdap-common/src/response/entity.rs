use crate::contact::Contact;
use buildstructor::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    autnum::Autnum,
    network::Network,
    types::{to_option_status, Common, Events, Link, ObjectCommon, PublicIds},
    GetSelfLink, SelfLink, ToChild,
};

/// Represents an RDAP entity response.
#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
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

#[buildstructor::buildstructor]
impl Entity {
    /// Builds a basic autnum object.
    ///
    /// ```rust
    /// use icann_rdap_common::response::entity::Entity;
    /// use icann_rdap_common::response::types::StatusValue;
    /// use icann_rdap_common::contact::Contact;
    ///
    /// let contact = Contact::builder()
    ///   .kind("individual")
    ///   .full_name("Bob Smurd")
    ///   .build();
    ///
    /// let entity = Entity::basic()
    ///   .handle("foo_example_com-1")
    ///   .status("active")
    ///   .role("registrant")
    ///   .contact(contact)
    ///   .build();
    /// ```
    #[builder(entry = "basic")]
    pub fn new_handle<T: Into<String>>(
        handle: T,
        remarks: Vec<crate::response::types::Remark>,
        links: Vec<crate::response::types::Link>,
        events: Vec<crate::response::types::Event>,
        statuses: Vec<String>,
        port_43: Option<crate::response::types::Port43>,
        entities: Vec<Entity>,
        contact: Option<Contact>,
        roles: Vec<String>,
        public_ids: Option<PublicIds>,
    ) -> Self {
        let roles = (!roles.is_empty()).then_some(roles);
        let entities = (!entities.is_empty()).then_some(entities);
        let remarks = (!remarks.is_empty()).then_some(remarks);
        let links = (!links.is_empty()).then_some(links);
        let events = (!events.is_empty()).then_some(events);
        Self {
            common: Common::builder().build(),
            object_common: ObjectCommon::entity()
                .handle(handle.into())
                .and_remarks(remarks)
                .and_links(links)
                .and_events(events)
                .and_status(to_option_status(statuses))
                .and_port_43(port_43)
                .and_entities(entities)
                .build(),
            vcard_array: contact.map(|c| c.to_vcard()),
            roles,
            public_ids,
            as_event_actor: None,
            autnums: None,
            networks: None,
        }
    }

    pub fn contact(&self) -> Option<Contact> {
        let Some(vcard) = &self.vcard_array else {return None};
        Contact::from_vcard(vcard)
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
        self.common = Common::builder().build();
        self
    }
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
