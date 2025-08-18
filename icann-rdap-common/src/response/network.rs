//! RDAP IP Network.
use {
    crate::prelude::{Common, Extension, ObjectCommon},
    std::str::FromStr,
};

use {
    cidr::IpInet,
    serde::{Deserialize, Serialize},
};

use super::{
    to_opt_vec,
    types::{ExtensionId, Link},
    CommonFields, Entity, Event, GetSelfLink, Notice, Numberish, ObjectCommonFields, Port43,
    RdapResponseError, Remark, SelfLink, Stringish, ToChild, ToResponse,
};

/// Cidr0 structure from the Cidr0 extension.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum Cidr0Cidr {
    V4Cidr(V4Cidr),
    V6Cidr(V6Cidr),
}

impl std::fmt::Display for Cidr0Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V4Cidr(cidr) => cidr.fmt(f),
            Self::V6Cidr(cidr) => cidr.fmt(f),
        }
    }
}

/// Represents a CIDR0 V4 CIDR.
///
/// This structure allow both the prefix
/// and length to be optional to handle misbehaving servers, however
/// both are required according to the CIDR0 RDAP extension. To create
/// a valid stucture, use the builder.
///
/// However, it is recommended to use the builder on `Network` which will
/// create the appropriate CIDR0 structure.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct V4Cidr {
    pub v4prefix: Option<String>,
    pub length: Option<Numberish<u8>>,
}

#[buildstructor::buildstructor]
impl V4Cidr {
    /// Builds an Ipv4 CIDR0.
    #[builder(visibility = "pub")]
    fn new(v4prefix: String, length: u8) -> Self {
        Self {
            v4prefix: Some(v4prefix),
            length: Some(Numberish::<u8>::from(length)),
        }
    }

    // Get the v4Prefix.
    pub fn v4prefix(&self) -> Option<&str> {
        self.v4prefix.as_deref()
    }

    // Get the length.
    pub fn length(&self) -> Option<u8> {
        self.length.as_ref().and_then(|n| n.as_u8())
    }
}

impl std::fmt::Display for V4Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let length_s = if let Some(length) = &self.length {
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

/// Represents a CIDR0 V6 CIDR.
///
/// This structure allow both the prefix
/// and length to be optional to handle misbehaving servers, however
/// both are required according to the CIDR0 RDAP extension. To create
/// a valid stucture, use the builder.
///
/// However, it is recommended to use the builder on `Network` which will
/// create the appropriate CIDR0 structure.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct V6Cidr {
    pub v6prefix: Option<String>,
    pub length: Option<Numberish<u8>>,
}

#[buildstructor::buildstructor]
impl V6Cidr {
    /// Builds an IPv6 CIDR0.
    #[builder(visibility = "pub")]
    fn new(v6prefix: String, length: u8) -> Self {
        Self {
            v6prefix: Some(v6prefix),
            length: Some(Numberish::<u8>::from(length)),
        }
    }

    // Get the v6Prefix.
    pub fn v6prefix(&self) -> Option<&str> {
        self.v6prefix.as_deref()
    }

    // Get the length.
    pub fn length(&self) -> Option<u8> {
        self.length.as_ref().and_then(|n| n.as_u8())
    }
}

impl std::fmt::Display for V6Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let length_s = if let Some(length) = &self.length {
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

/// Represents an RDAP [IP network](https://rdap.rcode3.com/protocol/object_classes.html#ip-network) response.
///
/// Use of the builder is recommended to create this structure.
/// The builder will create the appropriate CIDR0 structures and
/// is easier than specifying start and end IP addresses.
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let net = Network::builder()
///   .cidr("10.0.0.0/24")
///   .handle("NET-10-0-0-0")
///   .status("active")
///   .build().unwrap();
/// ```
///
/// This will create the following RDAP structure.
///
/// ```norust
/// {
///   "rdapConformance": [
///     "cidr0",
///     "rdap_level_0"
///   ],
///   "objectClassName": "ip network",
///   "handle": "NET-10-0-0-0",
///   "status": [
///     "active"
///   ],
///   "startAddress": "10.0.0.0",
///   "endAddress": "10.0.0.255",
///   "ipVersion": "v4",
///   "cidr0_cidrs": [
///     {
///       "v4prefix": "10.0.0.0",
///       "length": 24
///     }
///   ]
/// }
/// ```
/// Use the getter functions to access the information in the network.
/// See [CommonFields] and [ObjectCommonFields] for common getter functions.
/// ```rust
/// # use icann_rdap_common::prelude::*;
/// # let net = Network::builder()
/// #   .cidr("10.0.0.0/24")
/// #   .build().unwrap();
/// let handle = net.handle();
/// let start_address = net.start_address();
/// let end_address = net.end_address();
/// let parent_handle = net.parent_handle();
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
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
    pub ip_version: Option<Stringish>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Stringish>,

    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_type: Option<Stringish>,

    #[serde(rename = "parentHandle")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_handle: Option<Stringish>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<Stringish>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cidr0_cidrs: Option<Vec<Cidr0Cidr>>,
}

#[buildstructor::buildstructor]
impl Network {
    /// Builds a basic IP network object.
    ///
    /// ```rust
    /// use icann_rdap_common::prelude::*;
    ///
    /// let net = Network::builder()
    ///   .cidr("10.0.0.0/24")
    ///   .handle("NET-10-0-0-0")
    ///   .status("active")
    ///   .build().unwrap();
    /// ```
    #[builder(visibility = "pub")]
    fn new(
        cidr: String,
        handle: Option<String>,
        country: Option<String>,
        name: Option<String>,
        network_type: Option<String>,
        parent_handle: Option<String>,
        remarks: Vec<Remark>,
        links: Vec<Link>,
        events: Vec<Event>,
        statuses: Vec<String>,
        port_43: Option<Port43>,
        entities: Vec<Entity>,
        notices: Vec<Notice>,
        mut extensions: Vec<Extension>,
        redacted: Option<Vec<crate::response::redacted::Redacted>>,
    ) -> Result<Self, RdapResponseError> {
        let mut net_exts = vec![ExtensionId::Cidr0.to_extension()];
        net_exts.append(&mut extensions);
        let cidr = IpInet::from_str(&cidr)?;
        Ok(Self {
            common: Common::level0()
                .extensions(net_exts)
                .and_notices(to_opt_vec(notices))
                .build(),
            object_common: ObjectCommon::ip_network()
                .and_handle(handle.map(|s| s.into()) as Option<Stringish>)
                .and_remarks(to_opt_vec(remarks))
                .and_links(to_opt_vec(links))
                .and_events(to_opt_vec(events))
                .status(statuses)
                .and_port_43(port_43)
                .and_entities(to_opt_vec(entities))
                .and_redacted(redacted)
                .build(),
            start_address: Some(cidr.first_address().to_string()),
            end_address: Some(cidr.last_address().to_string()),
            ip_version: Some(
                match cidr {
                    IpInet::V4(_) => "v4",
                    IpInet::V6(_) => "v6",
                }
                .to_string()
                .into(),
            ),
            name: name.map(|s| s.into()),
            network_type: network_type.map(|s| s.into()),
            parent_handle: parent_handle.map(|s| s.into()),
            country: country.map(|s| s.into()),
            cidr0_cidrs: match cidr {
                IpInet::V4(cidr) => Some(vec![Cidr0Cidr::V4Cidr(V4Cidr {
                    v4prefix: Some(cidr.first_address().to_string()),
                    length: Some(Numberish::<u8>::from(cidr.network_length())),
                })]),
                IpInet::V6(cidr) => Some(vec![Cidr0Cidr::V6Cidr(V6Cidr {
                    v6prefix: Some(cidr.first_address().to_string()),
                    length: Some(Numberish::<u8>::from(cidr.network_length())),
                })]),
            },
        })
    }

    #[builder(entry = "illegal", visibility = "pub(crate)")]
    #[allow(dead_code)]
    fn new_illegal(
        start_address: Option<String>,
        end_address: Option<String>,
        ip_version: Option<Stringish>,
        cidr0_cidrs: Option<Vec<Cidr0Cidr>>,
        country: Option<String>,
        name: Option<String>,
        network_type: Option<String>,
        parent_handle: Option<String>,
        notices: Vec<Notice>,
    ) -> Self {
        Self {
            common: Common::level0()
                .extension(ExtensionId::Cidr0.to_extension())
                .and_notices(to_opt_vec(notices))
                .build(),
            object_common: ObjectCommon::ip_network().build(),
            start_address,
            end_address,
            ip_version,
            name: name.map(|s| s.into()),
            network_type: network_type.map(|s| s.into()),
            parent_handle: parent_handle.map(|s| s.into()),
            country: country.map(|s| s.into()),
            cidr0_cidrs,
        }
    }

    /// Returns the start address of the network.
    pub fn start_address(&self) -> Option<&str> {
        self.start_address.as_deref()
    }

    /// Returns the end address of the network.
    pub fn end_address(&self) -> Option<&str> {
        self.end_address.as_deref()
    }

    /// Returns the IP version of the network.
    pub fn ip_version(&self) -> Option<&str> {
        self.ip_version.as_deref()
    }

    /// Returns the name of the network.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the type of the network.
    pub fn network_type(&self) -> Option<&str> {
        self.network_type.as_deref()
    }

    /// Returns the parent handle of the network.
    pub fn parent_handle(&self) -> Option<&str> {
        self.parent_handle.as_deref()
    }

    /// Returns the country of the network.
    pub fn country(&self) -> Option<&str> {
        self.country.as_deref()
    }

    /// Returns the CIDR0 CIDRs of the network.
    pub fn cidr0_cidrs(&self) -> &[Cidr0Cidr] {
        self.cidr0_cidrs.as_deref().unwrap_or_default()
    }
}

impl ToResponse for Network {
    fn to_response(self) -> super::RdapResponse {
        super::RdapResponse::Network(Box::new(self))
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
        self.common = Common {
            rdap_conformance: None,
            notices: None,
        };
        self
    }
}

impl CommonFields for Network {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ObjectCommonFields for Network {
    fn object_common(&self) -> &ObjectCommon {
        &self.object_common
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
