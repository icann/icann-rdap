use buildstructor::Builder;
use serde::{Deserialize, Serialize};

use super::{
    entity::Entity,
    types::{Events, Links, Port43, Remarks, Status},
};

/// Represents an IP address set for nameservers.
#[derive(Serialize, Deserialize, Builder)]
pub struct IpAddresses {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v6: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub v4: Option<Vec<String>>,
}

/// Represents an RDAP nameserver.
#[derive(Serialize, Deserialize, Builder)]
pub struct Nameserver {
    #[serde(rename = "objectClassName")]
    pub object_class_name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,

    #[serde(rename = "ldhName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ldh_name: Option<String>,

    #[serde(rename = "unicodeName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unicode_name: Option<String>,

    #[serde(rename = "ipAddresses")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_addresses: Option<IpAddresses>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub remarks: Option<Remarks>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Events>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "port43")]
    pub port_43: Option<Port43>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub entities: Option<Vec<Entity>>,
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
        assert_eq!(actual.object_class_name, "nameserver");
        assert!(actual.handle.is_some());
        assert!(actual.ldh_name.is_some());
        assert!(actual.unicode_name.is_some());
        assert!(actual.ip_addresses.is_some());
        assert!(actual.remarks.is_some());
        assert!(actual.status.is_some());
        assert!(actual.links.is_some());
        assert!(actual.events.is_some());
    }
}
