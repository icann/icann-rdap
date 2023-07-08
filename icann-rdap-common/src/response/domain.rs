use buildstructor::Builder;
use serde::{Deserialize, Serialize};

use super::{
    nameserver::Nameserver,
    network::Network,
    types::{to_option_status, Common, Events, Links, ObjectCommon, PublicIds},
};

/// Represents an RDAP variant name.
#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
pub struct VariantName {
    #[serde(rename = "ldhName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ldh_name: Option<String>,

    #[serde(rename = "unicodeName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unicode_name: Option<String>,
}

/// Represents an RDAP IDN variant.
#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
pub struct Variant {
    pub relation: Option<Vec<String>>,

    #[serde(rename = "idnTable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idn_table: Option<String>,

    #[serde(rename = "variantNames")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant_names: Option<Vec<VariantName>>,
}

#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
pub struct DsDatum {
    #[serde(rename = "keyTag")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_tag: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,

    #[serde(rename = "digestType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_type: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Events>,
}

#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
pub struct KeyDatum {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<u8>,

    #[serde(rename = "publicKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Events>,
}

/// Represents the DNSSEC information of a domain.
#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
pub struct SecureDns {
    #[serde(rename = "zoneSigned")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_signed: Option<bool>,

    #[serde(rename = "delegationSigned")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_signed: Option<bool>,

    #[serde(rename = "maxSigLife")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_sig_life: Option<u64>,

    #[serde(rename = "dsData")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_data: Option<Vec<DsDatum>>,

    #[serde(rename = "keyData")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_data: Option<Vec<KeyDatum>>,
}

/// Represents an RDAP domain response.
#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
pub struct Domain {
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

    #[serde(skip_serializing_if = "Option::is_none")]
    pub variants: Option<Vec<Variant>>,

    #[serde(rename = "secureDNS")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_dns: Option<SecureDns>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub nameservers: Option<Vec<Nameserver>>,

    #[serde(rename = "publicIds")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ids: Option<PublicIds>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
}

#[buildstructor::buildstructor]
impl Domain {
    /// Builds a basic domain object.
    ///
    /// ```rust
    /// use icann_rdap_common::response::domain::Domain;
    /// use icann_rdap_common::response::types::StatusValue;
    ///
    /// let domain = Domain::basic()
    ///   .ldh_name("foo.example.com")
    ///   .handle("foo_example_com-1")
    ///   .status("active")
    ///   .build();
    /// ```
    #[builder(entry = "basic")]
    pub fn new_ldh<T: Into<String>>(
        ldh_name: T,
        nameservers: Option<Vec<Nameserver>>,
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
            object_common: ObjectCommon::domain()
                .and_handle(handle)
                .and_remarks(remarks)
                .and_links(links)
                .and_events(events)
                .and_status(to_option_status(statuses))
                .and_port_43(port_43)
                .and_entities(entities)
                .build(),
            ldh_name: Some(ldh_name.into()),
            unicode_name: None,
            variants: None,
            secure_dns: None,
            nameservers,
            public_ids: None,
            network: None,
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::Domain;

    #[test]
    fn GIVEN_domain_WHEN_deserialize_THEN_success() {
        // GIVEN
        let expected = r#"
        {
          "objectClassName" : "domain",
          "handle" : "XXXX",
          "ldhName" : "xn--fo-5ja.example",
          "unicodeName" : "fóo.example",
          "variants" :
          [
            {
              "relation" : [ "registered", "conjoined" ],
              "variantNames" :
              [
                {
                  "ldhName" : "xn--fo-cka.example",
                  "unicodeName" : "fõo.example"
                },
                {
                  "ldhName" : "xn--fo-fka.example",
                  "unicodeName" : "föo.example"
                }
              ]
            },
            {
              "relation" : [ "unregistered", "registration restricted" ],
              "idnTable": ".EXAMPLE Swedish",
              "variantNames" :
              [
                {
                  "ldhName": "xn--fo-8ja.example",
                  "unicodeName" : "fôo.example"
                }
              ]

            }
          ],
          "status" : [ "locked", "transfer prohibited" ],
          "publicIds":[
            {
              "type":"ENS_Auth ID",
              "identifier":"1234567890"
            }
          ],
          "nameservers" :
          [
            {
              "objectClassName" : "nameserver",
              "handle" : "XXXX",
              "ldhName" : "ns1.example.com",
              "status" : [ "active" ],
              "ipAddresses" :
              {
                "v6": [ "2001:db8::123", "2001:db8::124" ],
                "v4": [ "192.0.2.1", "192.0.2.2" ]
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
                  "value" : "https://example.net/nameserver/ns1.example.com",
                  "rel" : "self",
                  "href" : "https://example.net/nameserver/ns1.example.com",
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
            },
            {
              "objectClassName" : "nameserver",
              "handle" : "XXXX",
              "ldhName" : "ns2.example.com",
              "status" : [ "active" ],
              "ipAddresses" :
              {
                "v6" : [ "2001:db8::125", "2001:db8::126" ],
                "v4" : [ "192.0.2.3", "192.0.2.4" ]
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
                  "value" : "https://example.net/nameserver/ns2.example.com",
                  "rel" : "self",
                  "href" : "https://example.net/nameserver/ns2.example.com",
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
          ],
          "secureDNS":
          {

             "zoneSigned": true,
             "delegationSigned": true,
             "maxSigLife": 604800,
             "keyData":
             [
               {
                 "flags": 257,
                 "protocol": 3,
                 "algorithm": 8,
                 "publicKey": "AwEAAa6eDzronzjEDbT...Jg1M5N rBSPkuXpdFE=",
                 "events":
                 [
                   {
                     "eventAction": "last changed",
                     "eventDate": "2012-07-23T05:15:47Z"
                   }
                 ]
               }
             ]
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
              "value": "https://example.net/domain/xn--fo-5ja.example",
              "rel" : "self",
              "href" : "https://example.net/domain/xn--fo-5ja.example",
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
            },
            {
              "eventAction" : "transfer",
              "eventDate" : "1991-12-31T23:59:59Z",
              "eventActor" : "joe@example.com"
            },
            {
              "eventAction" : "expiration",
              "eventDate" : "2016-12-31T23:59:59Z",
              "eventActor" : "joe@example.com"
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
              "status" : [ "validated", "locked" ],
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
        let actual = serde_json::from_str::<Domain>(expected);

        // THEN
        let actual = actual.unwrap();
        assert_eq!(actual.object_common.object_class_name, "domain");
        assert!(actual.object_common.handle.is_some());
        assert!(actual.ldh_name.is_some());
        assert!(actual.unicode_name.is_some());
        assert!(actual.variants.is_some());
        assert!(actual.public_ids.is_some());
        assert!(actual.object_common.remarks.is_some());
        assert!(actual.object_common.links.is_some());
        assert!(actual.object_common.events.is_some());
        assert!(actual.object_common.port_43.is_some());
        assert!(actual.object_common.entities.is_some());
        assert!(actual.secure_dns.is_some());
    }
}
