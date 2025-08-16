//! RDAP Autonomous System Number.
use {
    crate::prelude::{Common, Extension, ObjectCommon},
    serde::{Deserialize, Serialize},
};

use super::{
    to_opt_vec,
    types::Link,
    CommonFields, Entity, Event, GetSelfLink, Notice, Numberish, ObjectCommonFields, Port43,
    Remark, SelfLink, Stringish, ToChild, ToResponse,
};

/// Represents an RDAP [autnum](https://rdap.rcode3.com/protocol/object_classes.html#autnum) object response.
///
/// Using the builder to construct this structure is recommended
/// as it will fill-in many of the mandatory fields.
/// The following is an example.
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let autnum = Autnum::builder()
///   .autnum_range(700..710) // the range of autnums
///   .handle("AS700-1")
///   .status("active")
///   .build();
/// let c = serde_json::to_string_pretty(&autnum).unwrap();
/// eprintln!("{c}");
/// ```
/// This will produce the following.
///
/// ```norust
/// {
///   "rdapConformance": [
///     "rdap_level_0"
///   ],
///   "objectClassName": "autnum",
///   "handle": "AS700-1",
///   "status": [
///     "active"
///   ],
///   "startAutnum": 700,
///   "endAutnum": 710
/// }
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Autnum {
    #[serde(flatten)]
    pub common: Common,

    #[serde(flatten)]
    pub object_common: ObjectCommon,

    #[serde(rename = "startAutnum")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_autnum: Option<Numberish<u32>>,

    #[serde(rename = "endAutnum")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_autnum: Option<Numberish<u32>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Stringish>,

    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autnum_type: Option<Stringish>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[buildstructor::buildstructor]
impl Autnum {
    /// Builds a basic autnum object.
    ///
    /// ```rust
    /// use icann_rdap_common::prelude::*;
    ///
    /// let autnum = Autnum::builder()
    ///   .autnum_range(700..710)
    ///   .handle("AS700-1")
    ///   .status("active")
    ///   .build();
    /// ```
    #[builder(visibility = "pub")]
    fn new(
        autnum_range: std::ops::Range<u32>,
        handle: Option<Stringish>,
        remarks: Vec<Remark>,
        links: Vec<Link>,
        events: Vec<Event>,
        statuses: Vec<String>,
        port_43: Option<Port43>,
        entities: Vec<Entity>,
        notices: Vec<Notice>,
        country: Option<String>,
        autnum_type: Option<Stringish>,
        name: Option<Stringish>,
        extensions: Vec<Extension>,
        redacted: Option<Vec<crate::response::redacted::Redacted>>,
    ) -> Self {
        Self {
            common: Common::level0()
                .extensions(extensions)
                .and_notices(to_opt_vec(notices))
                .build(),
            object_common: ObjectCommon::autnum()
                .and_handle(handle)
                .and_remarks(to_opt_vec(remarks))
                .and_links(to_opt_vec(links))
                .and_events(to_opt_vec(events))
                .status(statuses)
                .and_port_43(port_43)
                .and_entities(to_opt_vec(entities))
                .and_redacted(redacted)
                .build(),
            start_autnum: Some(Numberish::<u32>::from(autnum_range.start)),
            end_autnum: Some(Numberish::<u32>::from(autnum_range.end)),
            name,
            autnum_type,
            country,
        }
    }

    /// Returns the starting ASN of the range.
    pub fn start_autnum(&self) -> Option<u32> {
        self.start_autnum.as_ref().and_then(|n| n.as_u32())
    }

    /// Returns the ending ASN of the range.
    pub fn end_autnum(&self) -> Option<u32> {
        self.end_autnum.as_ref().and_then(|n| n.as_u32())
    }

    /// Returns the name of the ASN.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the type of the ASN.
    pub fn autnum_type(&self) -> Option<&str> {
        self.autnum_type.as_deref()
    }

    /// Returns the country of the ASN.
    pub fn country(&self) -> Option<&str> {
        self.country.as_deref()
    }
}

impl ToResponse for Autnum {
    fn to_response(self) -> super::RdapResponse {
        super::RdapResponse::Autnum(Box::new(self))
    }
}

impl GetSelfLink for Autnum {
    fn get_self_link(&self) -> Option<&Link> {
        self.object_common.get_self_link()
    }
}

impl SelfLink for Autnum {
    fn set_self_link(mut self, link: Link) -> Self {
        self.object_common = self.object_common.set_self_link(link);
        self
    }
}

impl ToChild for Autnum {
    fn to_child(mut self) -> Self {
        self.common = Common {
            rdap_conformance: None,
            notices: None,
        };
        self
    }
}

impl CommonFields for Autnum {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ObjectCommonFields for Autnum {
    fn object_common(&self) -> &ObjectCommon {
        &self.object_common
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
