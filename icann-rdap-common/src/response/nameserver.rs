//! RDAP Nameserver object class.
use crate::prelude::Common;
use crate::prelude::Extension;
use crate::prelude::ObjectCommon;
use std::{net::IpAddr, str::FromStr};

use serde::{Deserialize, Serialize};

use super::to_opt_vec;
use super::to_opt_vectorstringish;
use super::CommonFields;
use super::ObjectCommonFields;
use super::VectorStringish;
use super::{
    types::Link, Entity, Event, GetSelfLink, Notice, Port43, RdapResponseError, Remark, SelfLink,
    ToChild,
};

/// Represents an IP address set for nameservers.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct IpAddresses {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v6: Option<VectorStringish>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub v4: Option<VectorStringish>,
}

#[buildstructor::buildstructor]
impl IpAddresses {
    /// Builds nameserver IP address.
    #[builder(visibility = "pub")]
    fn new(addresses: Vec<String>) -> Result<Self, RdapResponseError> {
        let mut v4: Vec<String> = Vec::new();
        let mut v6: Vec<String> = Vec::new();
        for addr in addresses {
            let ip = IpAddr::from_str(&addr)?;
            match ip {
                IpAddr::V4(_) => v4.push(addr),
                IpAddr::V6(_) => v6.push(addr),
            }
        }
        Ok(Self {
            v4: to_opt_vectorstringish(v4),
            v6: to_opt_vectorstringish(v6),
        })
    }

    #[allow(dead_code)]
    #[builder(entry = "illegal", visibility = "pub(crate)")]
    fn new_illegal(v6: Option<Vec<String>>, v4: Option<Vec<String>>) -> Self {
        Self {
            v4: v4.map(VectorStringish::from),
            v6: v6.map(VectorStringish::from),
        }
    }

    /// Get the IPv6 addresses.
    pub fn v6s(&self) -> Vec<String> {
        self.v6
            .as_ref()
            .map(|v| v.into_vec_string_owned())
            .unwrap_or_default()
    }

    /// Get the IPv4 addresses.
    pub fn v4s(&self) -> Vec<String> {
        self.v4
            .as_ref()
            .map(|v| v.into_vec_string_owned())
            .unwrap_or_default()
    }
}

/// Represents an RDAP [nameserver](https://rdap.rcode3.com/protocol/object_classes.html#nameserver) response.
///
/// Using the builder is recommended to construct this structure as it
/// will fill-in many of the mandatory fields.
/// The following is an example.
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let ns = Nameserver::builder()
///   .ldh_name("ns1.example.com")
///   .handle("ns1_example_com-1")
///   .status("active")
///   .address("10.0.0.1")
///   .address("10.0.0.2")
///   .entity(Entity::builder().handle("FOO").build())
///   .build().unwrap();
/// let c = serde_json::to_string_pretty(&ns).unwrap();
/// eprintln!("{c}");
/// ```
///
/// This will produce the following.
///
/// ```norust
///   {
///     "rdapConformance": [
///       "rdap_level_0"
///     ],
///     "objectClassName": "nameserver",
///     "handle": "ns1_example_com-1",
///     "status": [
///       "active"
///     ],
///     "entities": [
///       {
///         "rdapConformance": [
///           "rdap_level_0"
///         ],
///         "objectClassName": "entity",
///         "handle": "FOO"
///       }
///     ],
///     "ldhName": "ns1.example.com",
///     "ipAddresses": {
///       "v4": [
///         "10.0.0.1",
///         "10.0.0.2"
///       ]
///     }
///   }
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Nameserver {
    #[serde(flatten)]
    pub common: Common,

    #[serde(flatten)]
    pub object_common: ObjectCommon,

    #[serde(rename = "ldhName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ldh_name: Option<String>,

    #[serde(rename = "unicodeName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unicode_name: Option<String>,

    #[serde(rename = "ipAddresses")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_addresses: Option<IpAddresses>,
}

#[buildstructor::buildstructor]
impl Nameserver {
    /// Builds a basic nameserver object.
    ///
    /// ```rust
    /// use icann_rdap_common::prelude::*;
    ///
    /// let ns = Nameserver::builder()
    ///   .ldh_name("ns1.example.com")
    ///   .handle("ns1_example_com-1")
    ///   .status("active")
    ///   .address("10.0.0.1")
    ///   .address("10.0.0.2")
    ///   .entity(Entity::builder().handle("FOO").build())
    ///   .build().unwrap();
    /// ```
    #[builder(visibility = "pub")]
    #[allow(clippy::too_many_arguments)]
    fn new<T: Into<String>>(
        ldh_name: T,
        addresses: Vec<String>,
        handle: Option<String>,
        remarks: Vec<Remark>,
        links: Vec<Link>,
        events: Vec<Event>,
        statuses: Vec<String>,
        port_43: Option<Port43>,
        entities: Vec<Entity>,
        notices: Vec<Notice>,
        extensions: Vec<Extension>,
        redacted: Option<Vec<crate::response::redacted::Redacted>>,
    ) -> Result<Self, RdapResponseError> {
        let ip_addresses = if !addresses.is_empty() {
            Some(IpAddresses::builder().addresses(addresses).build()?)
        } else {
            None
        };
        Ok(Self {
            common: Common::level0()
                .extensions(extensions)
                .and_notices(to_opt_vec(notices))
                .build(),
            object_common: ObjectCommon::nameserver()
                .and_handle(handle)
                .and_remarks(to_opt_vec(remarks))
                .and_links(to_opt_vec(links))
                .and_events(to_opt_vec(events))
                .status(statuses)
                .and_port_43(port_43)
                .and_entities(to_opt_vec(entities))
                .and_redacted(redacted)
                .build(),
            ldh_name: Some(ldh_name.into()),
            unicode_name: None,
            ip_addresses,
        })
    }

    #[builder(entry = "illegal", visibility = "pub(crate)")]
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    fn new_illegal(ldh_name: Option<String>, ip_addresses: Option<IpAddresses>) -> Self {
        Self {
            common: Common::level0().build(),
            object_common: ObjectCommon::nameserver().build(),
            ldh_name,
            unicode_name: None,
            ip_addresses,
        }
    }

    /// Get the LDH name.
    pub fn ldh_name(&self) -> Option<&str> {
        self.ldh_name.as_deref()
    }

    /// Get the Unicode name.
    pub fn unicode_name(&self) -> Option<&str> {
        self.unicode_name.as_deref()
    }

    /// Get the IP addresses.
    pub fn ip_addresses(&self) -> Option<&IpAddresses> {
        self.ip_addresses.as_ref()
    }
}

impl GetSelfLink for Nameserver {
    fn get_self_link(&self) -> Option<&Link> {
        self.object_common.get_self_link()
    }
}

impl SelfLink for Nameserver {
    fn set_self_link(mut self, link: Link) -> Self {
        self.object_common = self.object_common.set_self_link(link);
        self
    }
}

impl ToChild for Nameserver {
    fn to_child(mut self) -> Self {
        self.common = Common {
            rdap_conformance: None,
            notices: None,
        };
        self
    }
}

impl CommonFields for Nameserver {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ObjectCommonFields for Nameserver {
    fn object_common(&self) -> &ObjectCommon {
        &self.object_common
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::Nameserver;

    #[test]
    fn GIVEN_nameserver_WHEN_deserialize_THEN_success() {
        // GIVEN
        let expected = r#"
        {
            "objectClassName" : "nameserver",
            "handle" : "XXXX",
            "ldhName" : "ns1.xn--fo-5ja.example",
            "unicodeName" : "ns.fóo.example",
            "status" : [ "active" ],
            "ipAddresses" :
            {
              "v4": [ "192.0.2.1", "192.0.2.2" ],
              "v6": [ "2001:db8::123" ]
            },
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
                "value" : "https://example.net/nameserver/ns1.xn--fo-5ja.example",
                "rel" : "self",
                "href" : "https://example.net/nameserver/ns1.xn--fo-5ja.example",
                "type" : "application/rdap+json"
              }
            ],
            "port43" : "whois.example.net",
            "events" :
            [
              {
                "eventAction" : "registration",
                "eventDate" : "1990-12-31T23:59:59Z"
              },
              {
                "eventAction" : "last changed",
                "eventDate" : "1991-12-31T23:59:59Z",
                "eventActor" : "joe@example.com"
              }
            ]
        }
        "#;

        // WHEN
        let actual = serde_json::from_str::<Nameserver>(expected);

        // THEN
        let actual = actual.unwrap();
        assert_eq!(actual.object_common.object_class_name, "nameserver");
        assert!(actual.object_common.handle.is_some());
        assert!(actual.ldh_name.is_some());
        assert!(actual.unicode_name.is_some());
        assert!(actual.ip_addresses.is_some());
        assert!(actual.object_common.remarks.is_some());
        assert!(actual.object_common.status.is_some());
        assert!(actual.object_common.links.is_some());
        assert!(actual.object_common.events.is_some());
    }
}
