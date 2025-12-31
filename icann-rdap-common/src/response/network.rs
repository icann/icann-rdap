//! RDAP IP Network.
use std::collections::HashSet;

use crate::prelude::ContentExtensions;

use {
    crate::prelude::{Common, Extension, ObjectCommon},
    std::str::FromStr,
};

use {
    cidr::IpInet,
    serde::{Deserialize, Serialize},
};

use super::{
    to_opt_vec, types::Link, CommonFields, Entity, Event, ExtensionId, GetSelfLink, Notice,
    Numberish, ObjectCommonFields, Port43, RdapResponseError, Remark, SelfLink, Stringish, ToChild,
    ToResponse,
};

/// Cidr0 structure from the Cidr0 extension.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Cidr0Cidr {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub prefix: Option<Cidr0CidrPrefix>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<Numberish<u8>>,
}

#[buildstructor::buildstructor]
impl Cidr0Cidr {
    /// Builds a CIDR0.
    #[builder(visibility = "pub")]
    #[allow(clippy::needless_lifetimes)]
    fn new<'a>(
        network_type: &'a str,
        prefix: String,
        length: u8,
    ) -> Result<Self, RdapResponseError> {
        let prefix = match network_type {
            "v4" | "V4" => Ok(Cidr0CidrPrefix::V4Prefix(prefix)),
            "v6" | "V6" => Ok(Cidr0CidrPrefix::V6Prefix(prefix)),
            _ => Err(RdapResponseError::InvalidNetworkType),
        }?;
        Ok(Self {
            length: Some(Numberish::<u8>::from(length)),
            prefix: Some(prefix),
        })
    }

    /// Builds an Ipv4 CIDR0.
    #[builder(entry = "v4", visibility = "pub")]
    fn new_v4(prefix: String, length: u8) -> Self {
        Self {
            length: Some(Numberish::<u8>::from(length)),
            prefix: Some(Cidr0CidrPrefix::V4Prefix(prefix)),
        }
    }

    /// Builds an Ipv6 CIDR0.
    #[builder(entry = "v6", visibility = "pub")]
    fn new_v6(prefix: String, length: u8) -> Self {
        Self {
            length: Some(Numberish::<u8>::from(length)),
            prefix: Some(Cidr0CidrPrefix::V6Prefix(prefix)),
        }
    }

    // Get prefix as enum.
    pub fn cidr0cidr_prefix(&self) -> Option<&Cidr0CidrPrefix> {
        self.prefix.as_ref()
    }

    // Get the prefix.
    pub fn prefix(&self) -> Option<String> {
        self.prefix.clone().map(|p| match p {
            Cidr0CidrPrefix::V4Prefix(prefix) => prefix.clone(),
            Cidr0CidrPrefix::V6Prefix(prefix) => prefix.clone(),
        })
    }

    // Get the length.
    pub fn length(&self) -> Option<u8> {
        self.length.as_ref().and_then(|n| n.as_u8())
    }
}

impl std::fmt::Display for Cidr0Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let length_s = if let Some(length) = &self.length {
            length.to_string()
        } else {
            "not_given".to_string()
        };
        write!(
            f,
            "{}/{}",
            self.prefix().unwrap_or("not_given".to_string()),
            length_s
        )
    }
}

// Represents the prefix choices
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Cidr0CidrPrefix {
    #[serde(rename = "v4prefix")]
    V4Prefix(String),
    #[serde(rename = "v6prefix")]
    V6Prefix(String),
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
/// let net = Network::response_obj()
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
    /// Builds a basic IP network object for use with embedding in other objects.
    ///
    /// ```rust
    /// use icann_rdap_common::prelude::*;
    ///
    /// let net = Network::builder()
    ///   .cidr("10.0.0.0/24")     //required for this builder
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
        redacted: Option<Vec<crate::response::redacted::Redacted>>,
    ) -> Result<Self, RdapResponseError> {
        let cidr = IpInet::from_str(&cidr)?;
        Ok(Self {
            common: Common::builder().build(),
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
                IpInet::V4(cidr) => Some(vec![Cidr0Cidr::v4()
                    .length(cidr.network_length())
                    .prefix(cidr.first_address().to_string())
                    .build()]),
                IpInet::V6(cidr) => Some(vec![Cidr0Cidr::v6()
                    .length(cidr.network_length())
                    .prefix(cidr.first_address().to_string())
                    .build()]),
            },
        })
    }

    /// Builds an IP network object for a resopnse.
    ///
    /// ```rust
    /// use icann_rdap_common::prelude::*;
    ///
    /// let net = Network::response_obj()
    ///   .cidr("10.0.0.0/24")     //required for this builder
    ///   .handle("NET-10-0-0-0")
    ///   .status("active")
    ///   .extension(ExtensionId::NroRdapProfile0.as_ref())
    ///   .notice(Notice::builder().title("test").build())
    ///   .build().unwrap();
    /// ```
    #[builder(entry = "response_obj", visibility = "pub")]
    fn new_response_obj(
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
        let common = Common::level0()
            .extensions(net_exts)
            .and_notices(to_opt_vec(notices))
            .build();
        let mut net = Network::builder()
            .cidr(cidr)
            .and_handle(handle)
            .and_country(country)
            .and_name(name)
            .and_network_type(network_type)
            .and_parent_handle(parent_handle)
            .remarks(remarks)
            .links(links)
            .events(events)
            .statuses(statuses)
            .and_port_43(port_43)
            .entities(entities)
            .and_redacted(redacted)
            .build()?;
        net.common = common;
        Ok(net)
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
    fn self_link(&self) -> Option<&Link> {
        self.object_common.self_link()
    }
}

impl SelfLink for Network {
    fn with_self_link(mut self, link: Link) -> Self {
        self.object_common = self.object_common.with_self_link(link);
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

impl ContentExtensions for Network {
    fn content_extensions(&self) -> std::collections::HashSet<super::ExtensionId> {
        let mut exts = HashSet::new();
        exts.extend(self.common().content_extensions());
        exts.extend(self.object_common().content_extensions());
        if self.cidr0_cidrs.is_some() {
            exts.insert(super::ExtensionId::Cidr0);
        }
        exts
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        prelude::{Cidr0Cidr, Cidr0CidrPrefix, Common, ObjectCommon},
        response::network::Network,
    };

    #[test]
    fn test_cidr0_v4_round_trip() {
        // GIVEN network with cidr0
        let expected = r#"{"objectClassName":"ip network","cidr0_cidrs":[{"v4prefix":"10.0.0.0","length":8}]}"#;

        // WHEN deserialize
        let net = serde_json::from_str::<Network>(expected).expect("deserialize network");

        // WHEN serialize
        let actual = serde_json::to_string(&net).expect("serialize network");

        // THEN expected and actual match
        assert_eq!(expected, &actual);
    }

    #[test]
    fn test_cidr0_v4_deserialize() {
        // GIVEN network with cidr0
        let expected = r#"{"objectClassName":"ip network","cidr0_cidrs":[{"v4prefix":"10.0.0.0","length":8}]}"#;

        // WHEN deserialize
        let actual = serde_json::from_str::<Network>(expected).expect("deserialize network");

        // THEN prefix and length are as expected
        let cidr0 = actual.cidr0_cidrs().first().expect("cidr0 present");
        assert_eq!(&cidr0.prefix().expect("prefix"), "10.0.0.0");
        assert_eq!(cidr0.length().expect("length"), 8);
    }

    #[test]
    fn test_cidr0_v6_round_trip() {
        // GIVEN network with cidr0
        let expected = r#"{"objectClassName":"ip network","cidr0_cidrs":[{"v6prefix":"2620:1EC::","length":36}]}"#;

        // WHEN deserialize
        let net = serde_json::from_str::<Network>(expected).expect("deserialize network");

        // WHEN serialize
        let actual = serde_json::to_string(&net).expect("serialize network");

        // THEN expected and actual match
        assert_eq!(expected, &actual);
    }

    #[test]
    fn test_cidr0_v6_deserialize() {
        // GIVEN network with cidr0
        let expected = r#"{"objectClassName":"ip network","cidr0_cidrs":[{"v6prefix":"2620:1EC::","length":36}]}"#;

        // WHEN deserialize
        let actual = serde_json::from_str::<Network>(expected).expect("deserialize network");

        // THEN prefix and length are as expected
        let cidr0 = actual.cidr0_cidrs().first().expect("cidr0 present");
        assert_eq!(&cidr0.prefix().expect("prefix"), "2620:1EC::");
        assert_eq!(cidr0.length().expect("length"), 36);
    }

    #[test]
    fn test_cidr0_v4_serialize() {
        // GIVEN network with cidr0
        let net = Network {
            common: Common {
                rdap_conformance: None,
                notices: None,
            },
            object_common: ObjectCommon {
                object_class_name: "ip network".to_string(),
                handle: None,
                remarks: None,
                links: None,
                events: None,
                status: None,
                port_43: None,
                entities: None,
                redacted: None,
            },
            start_address: None,
            end_address: None,
            ip_version: None,
            name: None,
            network_type: None,
            parent_handle: None,
            country: None,
            cidr0_cidrs: Some(vec![Cidr0Cidr {
                prefix: Some(Cidr0CidrPrefix::V4Prefix("10.0.0.0".to_string())),
                length: Some(8.into()),
            }]),
        };

        // WHEN serialize
        let actual = serde_json::to_string(&net).expect("network serialize");

        // THEN expected = actual
        let expected = r#"{"objectClassName":"ip network","cidr0_cidrs":[{"v4prefix":"10.0.0.0","length":8}]}"#;
        assert_eq!(&actual, expected);
    }

    #[test]
    fn test_big_network_deserializion() {
        // GIVEN a big network
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
