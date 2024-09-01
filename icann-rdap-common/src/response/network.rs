use std::str::FromStr;

use buildstructor::Builder;
use cidr_utils::cidr::IpInet;
use serde::{Deserialize, Serialize};

use super::{
    types::{to_option_status, Common, Link, ObjectCommon},
    GetSelfLink, RdapResponseError, SelfLink, ToChild,
};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum Cidr0Cidr {
    V4Cidr(V4Cidr),
    V6Cidr(V6Cidr),
}

impl std::fmt::Display for Cidr0Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cidr0Cidr::V4Cidr(cidr) => cidr.fmt(f),
            Cidr0Cidr::V6Cidr(cidr) => cidr.fmt(f),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct V4Cidr {
    pub v4prefix: Option<String>,
    pub length: Option<u8>,
}

#[buildstructor::buildstructor]
impl V4Cidr {
    #[builder]
    pub fn new(v4prefix: String, length: u8) -> Self {
        V4Cidr {
            v4prefix: Some(v4prefix),
            length: Some(length),
        }
    }
}

impl std::fmt::Display for V4Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let length_s = if let Some(length) = self.length {
            length.to_string()
        } else {
            "not_given".to_string()
        };
        write!(
            f,
            "{}/{}",
            self.v4prefix.as_ref().unwrap_or(&"not_given".to_string()),
            length_s
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct V6Cidr {
    pub v6prefix: Option<String>,
    pub length: Option<u8>,
}

#[buildstructor::buildstructor]
impl V6Cidr {
    #[builder]
    pub fn new(v6prefix: String, length: u8) -> Self {
        V6Cidr {
            v6prefix: Some(v6prefix),
            length: Some(length),
        }
    }
}

impl std::fmt::Display for V6Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let length_s = if let Some(length) = self.length {
            length.to_string()
        } else {
            "not_given".to_string()
        };
        write!(
            f,
            "{}/{}",
            self.v6prefix.as_ref().unwrap_or(&"not_given".to_string()),
            length_s
        )
    }
}

/// Represents an RDAP network response.
#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
pub struct Network {
    #[serde(flatten)]
    pub common: Common,

    #[serde(flatten)]
    pub object_common: ObjectCommon,

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
    pub country: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cidr0_cidrs: Option<Vec<Cidr0Cidr>>,
}

#[buildstructor::buildstructor]
impl Network {
    /// Builds a basic IP network object.
    ///
    /// ```rust
    /// use icann_rdap_common::response::network::Network;
    /// use icann_rdap_common::response::types::StatusValue;
    ///
    /// let net = Network::basic()
    ///   .cidr("10.0.0.0/24")
    ///   .handle("NET-10-0-0-0")
    ///   .status("active")
    ///   .build().unwrap();
    /// ```
    #[builder(entry = "basic")]
    pub fn new_network(
        cidr: String,
        handle: Option<String>,
        country: Option<String>,
        name: Option<String>,
        network_type: Option<String>,
        parent_handle: Option<String>,
        remarks: Vec<crate::response::types::Remark>,
        links: Vec<crate::response::types::Link>,
        events: Vec<crate::response::types::Event>,
        statuses: Vec<String>,
        port_43: Option<crate::response::types::Port43>,
        entities: Vec<crate::response::entity::Entity>,
        notices: Vec<crate::response::types::Notice>,
        redacted: Option<Vec<crate::response::redacted::Redacted>>,
    ) -> Result<Self, RdapResponseError> {
        let entities = (!entities.is_empty()).then_some(entities);
        let remarks = (!remarks.is_empty()).then_some(remarks);
        let statuses = to_option_status(statuses);
        let links = (!links.is_empty()).then_some(links);
        let events = (!events.is_empty()).then_some(events);
        let notices = (!notices.is_empty()).then_some(notices);
        Network::new_network_with_options(
            cidr,
            handle,
            country,
            name,
            network_type,
            parent_handle,
            remarks,
            links,
            events,
            statuses,
            port_43,
            entities,
            notices,
            redacted,
        )
    }

    #[builder(entry = "with_options")]
    pub fn new_network_with_options(
        cidr: String,
        handle: Option<String>,
        country: Option<String>,
        name: Option<String>,
        network_type: Option<String>,
        parent_handle: Option<String>,
        remarks: Option<Vec<crate::response::types::Remark>>,
        links: Option<Vec<crate::response::types::Link>>,
        events: Option<Vec<crate::response::types::Event>>,
        status: Option<Vec<crate::response::types::StatusValue>>,
        port_43: Option<crate::response::types::Port43>,
        entities: Option<Vec<crate::response::entity::Entity>>,
        notices: Option<Vec<crate::response::types::Notice>>,
        redacted: Option<Vec<crate::response::redacted::Redacted>>,
    ) -> Result<Self, RdapResponseError> {
        let cidr = IpInet::from_str(&cidr)?;
        Ok(Self {
            common: Common::level0_with_options()
                .extension("cidr0")
                .and_notices(notices)
                .build(),
            object_common: ObjectCommon::ip_network()
                .and_handle(handle)
                .and_remarks(remarks)
                .and_links(links)
                .and_events(events)
                .and_status(status)
                .and_port_43(port_43)
                .and_entities(entities)
                .and_redacted(redacted)
                .build(),
            start_address: Some(cidr.first_address().to_string()),
            end_address: Some(cidr.last_address().to_string()),
            ip_version: match cidr {
                IpInet::V4(_) => Some("v4".to_string()),
                IpInet::V6(_) => Some("v6".to_string()),
            },
            name,
            network_type,
            parent_handle,
            country,
            cidr0_cidrs: match cidr {
                IpInet::V4(cidr) => Some(vec![Cidr0Cidr::V4Cidr(V4Cidr {
                    v4prefix: Some(cidr.first_address().to_string()),
                    length: Some(cidr.network_length()),
                })]),
                IpInet::V6(cidr) => Some(vec![Cidr0Cidr::V6Cidr(V6Cidr {
                    v6prefix: Some(cidr.first_address().to_string()),
                    length: Some(cidr.network_length()),
                })]),
            },
        })
    }
}

impl GetSelfLink for Network {
    fn get_self_link(&self) -> Option<&Link> {
        self.object_common.get_self_link()
    }
}

impl SelfLink for Network {
    fn set_self_link(mut self, link: Link) -> Self {
        self.object_common = self.object_common.set_self_link(link);
        self
    }
}

impl ToChild for Network {
    fn to_child(mut self) -> Self {
        self.common = Common::builder().build();
        self
    }
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
        assert_eq!(actual.object_common.object_class_name, "ip network");
        assert!(actual.object_common.handle.is_some());
        assert!(actual.start_address.is_some());
        assert!(actual.end_address.is_some());
        assert!(actual.ip_version.is_some());
        assert!(actual.name.is_some());
        assert!(actual.network_type.is_some());
        assert!(actual.parent_handle.is_some());
        assert!(actual.object_common.status.is_some());
        assert!(actual.country.is_some());
        assert!(actual.object_common.remarks.is_some());
        assert!(actual.object_common.links.is_some());
        assert!(actual.object_common.events.is_some());
        assert!(actual.object_common.entities.is_some());
    }
}
