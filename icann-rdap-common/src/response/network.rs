use buildstructor::Builder;
use serde::{Deserialize, Serialize};

use super::{
    entity::Entity,
    types::{Events, Links, Port43, Remarks, Status},
};

#[derive(Serialize, Deserialize, Builder)]
pub struct Network {
    #[serde(rename = "objectClassName")]
    pub object_class_name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,

    #[serde(rename = "startAddress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_address: Option<String>,

    #[serde(rename = "endAddress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_address: Option<String>,

    #[serde(rename = "ipVersion")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_type: Option<String>,

    #[serde(rename = "parentHandle")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_handle: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "port43")]
    pub port_43: Option<Port43>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub remarks: Option<Remarks>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Events>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub entities: Option<Vec<Entity>>,
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use crate::response::network::Network;

    #[test]
    fn GIVEN_network_WHEN_deserialize_THEN_success() {
        let expected = r#"
        {
          "objectClassName" : "ip network",
          "handle" : "XXXX-RIR",
          "startAddress" : "2001:db8::",
          "endAddress" : "2001:db8:0:ffff:ffff:ffff:ffff:ffff",
          "ipVersion" : "v6",
          "name": "NET-RTR-1",
          "type" : "DIRECT ALLOCATION",
          "country" : "AU",
          "parentHandle" : "YYYY-RIR",
          "status" : [ "active" ],
          "remarks" :
          [
            {
              "description" :
              [
                "She sells sea shells down by the sea shore.",
                "Originally written by Terry Sullivan."
              ]
            }
          ],
          "links" :
          [
            {
              "value" : "https://example.net/ip/2001:db8::/48",
              "rel" : "self",
              "href" : "https://example.net/ip/2001:db8::/48",
              "type" : "application/rdap+json"
            },
            {
              "value" : "https://example.net/ip/2001:db8::/48",
              "rel" : "up",
              "href" : "https://example.net/ip/2001:db8::/32",
              "type" : "application/rdap+json"
            }
          ],
          "events" :
          [
            {
              "eventAction" : "registration",
              "eventDate" : "1990-12-31T23:59:59Z"
            },
            {
              "eventAction" : "last changed",
              "eventDate" : "1991-12-31T23:59:59Z"
            }
          ],
          "entities" :
          [
            {
              "objectClassName" : "entity",
              "handle" : "XXXX",
              "vcardArray":[
                "vcard",
                [
                  ["version", {}, "text", "4.0"],
                  ["fn", {}, "text", "Joe User"],
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
                  ["tel",
                    { "type":["work", "voice"], "pref":"1" },
                    "uri", "tel:+1-555-555-1234;ext=102"
                  ],
                  ["email",
                    { "type":"work" },
                    "text", "joe.user@example.com"
                  ]
                ]
              ],
              "roles" : [ "registrant" ],
              "remarks" :
              [
                {
                  "description" :
                  [
                    "She sells sea shells down by the sea shore.",
                    "Originally written by Terry Sullivan."
                  ]
                }
              ],
              "links" :
              [
                {
                  "value" : "https://example.net/entity/xxxx",
                  "rel" : "self",
                  "href" : "https://example.net/entity/xxxx",
                  "type" : "application/rdap+json"
                }
              ],
              "events" :
              [
                {
                  "eventAction" : "registration",
                  "eventDate" : "1990-12-31T23:59:59Z"

                },
                {
                  "eventAction" : "last changed",
                  "eventDate" : "1991-12-31T23:59:59Z"
                }
              ]
            }
          ]
        }
        "#;

        // WHEN
        let actual = serde_json::from_str::<Network>(expected);

        // THEN
        let actual = actual.unwrap();
        assert_eq!(actual.object_class_name, "ip network");
        assert!(actual.handle.is_some());
        assert!(actual.start_address.is_some());
        assert!(actual.end_address.is_some());
        assert!(actual.ip_version.is_some());
        assert!(actual.name.is_some());
        assert!(actual.network_type.is_some());
        assert!(actual.parent_handle.is_some());
        assert!(actual.status.is_some());
        assert!(actual.country.is_some());
        assert!(actual.remarks.is_some());
        assert!(actual.links.is_some());
        assert!(actual.events.is_some());
        assert!(actual.entities.is_some());
    }
}
