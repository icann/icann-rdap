//! RDAP Nameserver object class.
use std::{net::IpAddr, str::FromStr};

use buildstructor::Builder;
use serde::{Deserialize, Serialize};

use super::{
    types::{to_option_status, Common, Link, ObjectCommon},
    GetSelfLink, RdapResponseError, SelfLink, ToChild,
};

/// Represents an IP address set for nameservers.
#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
pub struct IpAddresses {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v6: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub v4: Option<Vec<String>>,
}

#[buildstructor::buildstructor]
impl IpAddresses {
    /// Builds nameserver IP address.
    #[builder(entry = "basic", visibility = "pub")]
    fn new_basic(addresses: Vec<String>) -> Result<Self, RdapResponseError> {
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
            v4: (!v4.is_empty()).then_some(v4),
            v6: (!v6.is_empty()).then_some(v6),
        })
    }
}

/// Represents an RDAP [nameserver](https://rdap.rcode3.com/protocol/object_classes.html#nameserver) response.
///
/// Using the builder is recommended to construct this structure as it
/// will fill-in many of the mandatory fields.
/// The following is an example.
///
/// ```rust
/// use icann_rdap_common::response::nameserver::Nameserver;
/// use icann_rdap_common::response::entity::Entity;
/// use icann_rdap_common::response::types::StatusValue;
///
/// let ns = Nameserver::basic()
///   .ldh_name("ns1.example.com")
///   .handle("ns1_example_com-1")
///   .status("active")
///   .address("10.0.0.1")
///   .address("10.0.0.2")
///   .entity(Entity::basic().handle("FOO").build())
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
#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
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
    /// use icann_rdap_common::response::nameserver::Nameserver;
    /// use icann_rdap_common::response::entity::Entity;
    /// use icann_rdap_common::response::types::StatusValue;
    ///
    /// let ns = Nameserver::basic()
    ///   .ldh_name("ns1.example.com")
    ///   .handle("ns1_example_com-1")
    ///   .status("active")
    ///   .address("10.0.0.1")
    ///   .address("10.0.0.2")
    ///   .entity(Entity::basic().handle("FOO").build())
    ///   .build().unwrap();
    /// ```
    #[builder(entry = "basic", visibility = "pub")]
    #[allow(clippy::too_many_arguments)]
    fn new_ldh<T: Into<String>>(
        ldh_name: T,
        addresses: Vec<String>,
        handle: Option<String>,
        remarks: Vec<crate::response::types::Remark>,
        links: Vec<crate::response::types::Link>,
        events: Vec<crate::response::types::Event>,
        statuses: Vec<String>,
        port_43: Option<crate::response::types::Port43>,
        entities: Vec<crate::response::entity::Entity>,
        notices: Vec<crate::response::types::Notice>,
        redacted: Option<Vec<crate::response::redacted::Redacted>>,
    ) -> Result<Self, RdapResponseError> {
        let ip_addresses = if !addresses.is_empty() {
            Some(IpAddresses::basic().addresses(addresses).build()?)
        } else {
            None
        };
        let entities = (!entities.is_empty()).then_some(entities);
        let remarks = (!remarks.is_empty()).then_some(remarks);
        let links = (!links.is_empty()).then_some(links);
        let events = (!events.is_empty()).then_some(events);
        let notices = (!notices.is_empty()).then_some(notices);
        Ok(Self {
            common: Common::level0_with_options().and_notices(notices).build(),
            object_common: ObjectCommon::nameserver()
                .and_handle(handle)
                .and_remarks(remarks)
                .and_links(links)
                .and_events(events)
                .and_status(to_option_status(statuses))
                .and_port_43(port_43)
                .and_entities(entities)
                .and_redacted(redacted)
                .build(),
            ldh_name: Some(ldh_name.into()),
            unicode_name: None,
            ip_addresses,
        })
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
        self.common = Common::builder().build();
        self
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
