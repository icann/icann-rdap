use buildstructor::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    autnum::Autnum,
    network::Network,
    types::{Common, Events, ObjectCommon, PublicIds, Status},
};

/// Represents an RDAP entity response.
#[derive(Serialize, Deserialize, Builder, Clone)]
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
    pub status: Option<Status>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub autnums: Option<Vec<Autnum>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub networks: Option<Vec<Network>>,
}

#[buildstructor::buildstructor]
impl Entity {
    #[builder(entry = "basic")]
    pub fn new_handle<T: Into<String>>(handle: T) -> Self {
        Self {
            common: Common::builder().build(),
            object_common: ObjectCommon::builder()
                .object_class_name("entity")
                .handle(handle.into())
                .build(),
            vcard_array: None,
            roles: None,
            public_ids: None,
            as_event_actor: None,
            status: None,
            autnums: None,
            networks: None,
        }
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
