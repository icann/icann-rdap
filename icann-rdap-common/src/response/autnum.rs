use buildstructor::Builder;
use serde::{Deserialize, Serialize};

use super::types::{to_option_status, Common, Link, ObjectCommon};

/// Represents an RDAP autnum object response.
#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
pub struct Autnum {
    #[serde(flatten)]
    pub common: Common,

    #[serde(flatten)]
    pub object_common: ObjectCommon,

    #[serde(rename = "startAutnum")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_autnum: Option<u32>,

    #[serde(rename = "endAutnum")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_autnum: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autnum_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[buildstructor::buildstructor]
impl Autnum {
    /// Builds a basic autnum object.
    ///
    /// ```rust
    /// use icann_rdap_common::response::autnum::Autnum;
    /// use icann_rdap_common::response::types::StatusValue;
    ///
    /// let autnum = Autnum::basic()
    ///   .autnum_range(700..710)
    ///   .handle("AS700-1")
    ///   .status("active")
    ///   .build();
    /// ```
    #[builder(entry = "basic")]
    pub fn new_autnum(
        autnum_range: std::ops::Range<u32>,
        handle: Option<String>,
        remarks: Vec<crate::response::types::Remark>,
        links: Vec<crate::response::types::Link>,
        events: Vec<crate::response::types::Event>,
        statuses: Vec<String>,
        port_43: Option<crate::response::types::Port43>,
        entities: Vec<crate::response::entity::Entity>,
    ) -> Self {
        let entities = (!entities.is_empty()).then_some(entities);
        let remarks = (!remarks.is_empty()).then_some(remarks);
        let links = (!links.is_empty()).then_some(links);
        let events = (!events.is_empty()).then_some(events);
        Self {
            common: Common::builder().build(),
            object_common: ObjectCommon::autnum()
                .and_handle(handle)
                .and_remarks(remarks)
                .and_links(links)
                .and_events(events)
                .and_status(to_option_status(statuses))
                .and_port_43(port_43)
                .and_entities(entities)
                .build(),
            start_autnum: Some(autnum_range.start),
            end_autnum: Some(autnum_range.end),
            name: None,
            autnum_type: None,
            country: None,
        }
    }

    /// See [ObjectCommon::set_self_link()].
    pub fn set_self_link(mut self, link: Link) -> Self {
        self.object_common = self.object_common.set_self_link(link);
        self
    }

    /// See [ObjectCommon::get_self_link()].
    pub fn get_self_link(&self) -> Option<&Link> {
        self.object_common.get_self_link()
    }

    /// Removes notices and rdapConformance so this object can be a child
    /// of another object.
    pub fn to_child(mut self) -> Self {
        self.common = Common::builder().build();
        self
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::Autnum;

    #[test]
    fn GIVEN_autnum_WHEN_deserialize_THEN_success() {
        // GIVEN
        let expected = r#"
            {
              "objectClassName" : "autnum",
              "handle" : "XXXX-RIR",
              "startAutnum" : 65536,
              "endAutnum" : 65541,
              "name": "AS-RTR-1",
              "type" : "DIRECT ALLOCATION",
              "status" : [ "active" ],
              "country": "AU",
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
                  "value" : "https://example.net/autnum/65537",
                  "rel" : "self",
                  "href" : "https://example.net/autnum/65537",
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
                      "value" : "https://example.net/entity/XXXX",
                      "rel" : "self",
                      "href" : "https://example.net/entity/XXXX",
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
        let actual = serde_json::from_str::<Autnum>(expected);

        // THEN
        let actual = actual.unwrap();
        assert_eq!(actual.object_common.object_class_name, "autnum");
        assert!(actual.object_common.handle.is_some());
        assert!(actual.start_autnum.is_some());
        assert!(actual.end_autnum.is_some());
        assert!(actual.name.is_some());
        assert!(actual.autnum_type.is_some());
        assert!(actual.object_common.status.is_some());
        assert!(actual.country.is_some());
        assert!(actual.object_common.remarks.is_some());
        assert!(actual.object_common.links.is_some());
        assert!(actual.object_common.events.is_some());
        assert!(actual.object_common.entities.is_some());
    }
}
