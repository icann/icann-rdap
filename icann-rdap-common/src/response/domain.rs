//! RDAP Domain Object Class
use crate::prelude::{Common, Extension, ObjectCommon};
use buildstructor::Builder;
use serde::{Deserialize, Serialize};

use super::{
    lenient::{Boolish, Numberish},
    nameserver::Nameserver,
    network::Network,
    to_opt_vec, to_opt_vectorstringish,
    types::{Events, Link, Links, PublicIds},
    CommonFields, Entity, Event, GetSelfLink, Notice, ObjectCommonFields, Port43, PublicId, Remark,
    SelfLink, ToChild, ToResponse, VectorStringish, EMPTY_VEC_STRING,
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

impl VariantName {
    /// Convenience method.
    pub fn ldh_name(&self) -> Option<&str> {
        self.ldh_name.as_deref()
    }

    /// Convenience method.
    pub fn unicode_name(&self) -> Option<&str> {
        self.unicode_name.as_deref()
    }
}

/// Represents an RDAP IDN variant.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Variant {
    #[serde(rename = "relation")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relations: Option<VectorStringish>,

    #[serde(rename = "idnTable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idn_table: Option<String>,

    #[serde(rename = "variantNames")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant_names: Option<Vec<VariantName>>,
}

static EMPTY_VARIANT_NAMES: Vec<VariantName> = vec![];

#[buildstructor::buildstructor]
impl Variant {
    #[builder(visibility = "pub")]
    fn new(
        relations: Vec<String>,
        idn_table: Option<String>,
        variant_names: Vec<VariantName>,
    ) -> Self {
        Self {
            relations: to_opt_vectorstringish(relations),
            idn_table,
            variant_names: to_opt_vec(variant_names),
        }
    }

    /// Convenience method to get relations.
    pub fn relations(&self) -> &Vec<String> {
        self.relations
            .as_ref()
            .map(|v| v.vec())
            .unwrap_or(&EMPTY_VEC_STRING)
    }

    /// Convenience method to get variant names.
    pub fn variant_names(&self) -> &Vec<VariantName> {
        self.variant_names.as_ref().unwrap_or(&EMPTY_VARIANT_NAMES)
    }

    /// Convenience method.
    pub fn idn_table(&self) -> Option<&str> {
        self.idn_table.as_deref()
    }
}

static EMPTY_LINKS: Vec<Link> = vec![];
static EMPTY_EVENTS: Vec<Event> = vec![];

/// Represents `dsData`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DsDatum {
    #[serde(rename = "keyTag")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_tag: Option<Numberish<u32>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<Numberish<u8>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,

    #[serde(rename = "digestType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_type: Option<Numberish<u8>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Events>,
}

#[buildstructor::buildstructor]
impl DsDatum {
    /// Builder for `dsData`
    #[builder(visibility = "pub")]
    fn new(
        key_tag: Option<u32>,
        algorithm: Option<u8>,
        digest: Option<String>,
        digest_type: Option<u8>,
        links: Vec<Link>,
        events: Vec<Event>,
    ) -> Self {
        Self {
            key_tag: key_tag.map(Numberish::<u32>::from),
            algorithm: algorithm.map(Numberish::<u8>::from),
            digest,
            digest_type: digest_type.map(Numberish::<u8>::from),
            links: to_opt_vec(links),
            events: to_opt_vec(events),
        }
    }

    /// Convenience method to get links.
    pub fn links(&self) -> &Vec<Link> {
        self.links.as_ref().unwrap_or(&EMPTY_LINKS)
    }

    /// Convenience method to get events.
    pub fn events(&self) -> &Vec<Event> {
        self.events.as_ref().unwrap_or(&EMPTY_EVENTS)
    }

    /// Returns a u32 if it was given, otherwise None.
    pub fn key_tag(&self) -> Option<u32> {
        self.key_tag.as_ref().and_then(|n| n.as_u32())
    }

    /// Returns a u8 if it was given, otherwise None.
    pub fn digest_type(&self) -> Option<u8> {
        self.digest_type.as_ref().and_then(|n| n.as_u8())
    }

    /// Convenience method.
    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }
}

/// Represents `keyData`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KeyDatum {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<Numberish<u16>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Numberish<u8>>,

    #[serde(rename = "publicKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<Numberish<u8>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Events>,
}

#[buildstructor::buildstructor]
impl KeyDatum {
    /// Builder for `keyData`
    #[builder(visibility = "pub")]
    fn new(
        flags: Option<u16>,
        protocol: Option<u8>,
        public_key: Option<String>,
        algorithm: Option<u8>,
        links: Vec<Link>,
        events: Vec<Event>,
    ) -> Self {
        Self {
            flags: flags.map(Numberish::<u16>::from),
            protocol: protocol.map(Numberish::<u8>::from),
            public_key,
            algorithm: algorithm.map(Numberish::<u8>::from),
            links: to_opt_vec(links),
            events: to_opt_vec(events),
        }
    }

    /// Convenience method to get links.
    pub fn links(&self) -> &Vec<Link> {
        self.links.as_ref().unwrap_or(&EMPTY_LINKS)
    }

    /// Convenience method to get events.
    pub fn events(&self) -> &Vec<Event> {
        self.events.as_ref().unwrap_or(&EMPTY_EVENTS)
    }

    /// Returns a u16 if it was given, otherwise None.
    pub fn flags(&self) -> Option<u16> {
        self.flags.as_ref().and_then(|n| n.as_u16())
    }

    /// Returns a u8 if it was given, otherwise None.
    pub fn protocol(&self) -> Option<u8> {
        self.protocol.as_ref().and_then(|n| n.as_u8())
    }

    /// Returns a u8 if it was given, otherwise None.
    pub fn algorithm(&self) -> Option<u8> {
        self.algorithm.as_ref().and_then(|n| n.as_u8())
    }

    /// Convenience method.
    pub fn public_key(&self) -> Option<&str> {
        self.public_key.as_deref()
    }
}

static EMPTY_DS_DATA: Vec<DsDatum> = vec![];
static EMPTY_KEY_DATA: Vec<KeyDatum> = vec![];

/// Represents the DNSSEC information of a domain.
///
/// The following shows how to use the builders to
/// create a domain with secure DNS informaiton.
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// // Builds DNS security `keyData`.
/// let key_datum = KeyDatum::builder()
///     .flags(257)
///     .protocol(3)
///     .algorithm(8)
///     .public_key("AwEAAa6eDzronzjEDbT...Jg1M5N rBSPkuXpdFE=")
///     .build();
///
/// // Builds DNS security `dsData`.
/// let ds_datum = DsDatum::builder()
///     .algorithm(13)
///     .key_tag(20149)
///     .digest_type(2)
///     .digest("cf066bceadb799a27b62e3e82dc2e4da314c1807db98f13d82f0043b1418cf4e")
///     .build();
///
/// // Builds DNS security.
/// let secure_dns = SecureDns::builder()
///     .ds_data(ds_datum)
///     .key_data(key_datum)
///     .zone_signed(true)
///     .delegation_signed(false)
///     .max_sig_life(604800)
///     .build();
///
/// // Builds `domain` with DNS security.
/// let domain = Domain::builder()
///     .ldh_name("example.com")
///     .handle("EXAMPLE-DOMAIN")
///     .status("active")
///     .secure_dns(secure_dns)
///     .build();
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SecureDns {
    #[serde(rename = "zoneSigned")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_signed: Option<Boolish>,

    #[serde(rename = "delegationSigned")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_signed: Option<Boolish>,

    #[serde(rename = "maxSigLife")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_sig_life: Option<Numberish<u64>>,

    #[serde(rename = "dsData")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_data: Option<Vec<DsDatum>>,

    #[serde(rename = "keyData")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_data: Option<Vec<KeyDatum>>,
}

#[buildstructor::buildstructor]
impl SecureDns {
    /// Builder for `secureDNS`.
    #[builder(visibility = "pub")]
    fn new(
        zone_signed: Option<bool>,
        delegation_signed: Option<bool>,
        max_sig_life: Option<u64>,
        ds_datas: Vec<DsDatum>,
        key_datas: Vec<KeyDatum>,
    ) -> Self {
        Self {
            zone_signed: zone_signed.map(Boolish::from),
            delegation_signed: delegation_signed.map(Boolish::from),
            max_sig_life: max_sig_life.map(Numberish::<u64>::from),
            ds_data: to_opt_vec(ds_datas),
            key_data: to_opt_vec(key_datas),
        }
    }

    /// Convenience method to get ds data.
    pub fn ds_data(&self) -> &Vec<DsDatum> {
        self.ds_data.as_ref().unwrap_or(&EMPTY_DS_DATA)
    }

    /// Convenience method to get key data.
    pub fn key_data(&self) -> &Vec<KeyDatum> {
        self.key_data.as_ref().unwrap_or(&EMPTY_KEY_DATA)
    }

    /// Returns true if a truish value was given, otherwise false.
    pub fn zone_signed(&self) -> bool {
        self.zone_signed.as_ref().map_or(false, |b| b.into_bool())
    }

    /// Returns true if a truish value was given, otherwise false.
    pub fn delegation_signed(&self) -> bool {
        self.delegation_signed
            .as_ref()
            .map_or(false, |b| b.into_bool())
    }

    /// Returns max_sig_life as a u64 if it was given, otherwise None.
    pub fn max_sig_life(&self) -> Option<u64> {
        self.max_sig_life.as_ref().and_then(|n| n.as_u64())
    }
}

static EMPTY_PUBLIC_IDS: Vec<PublicId> = vec![];
static EMPTY_NAMESERVERS: Vec<Nameserver> = vec![];

/// Represents an RDAP [domain](https://rdap.rcode3.com/protocol/object_classes.html#domain) response.
///
/// Using the builder is recommended to construct this structure as it
/// will fill-in many of the mandatory fields.
/// The following is an example.
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let domain = Domain::builder()
///   .ldh_name("foo.example.com")
///   .handle("foo_example_com-1")
///   .status("active")
///   .build();
/// let c = serde_json::to_string_pretty(&domain).unwrap();
/// eprintln!("{c}");
/// ```
///
/// This will produce the following.
///
/// ```norust
/// {
///   "rdapConformance": [
///     "rdap_level_0"
///   ],
///   "objectClassName": "domain",
///   "handle": "foo_example_com-1",
///   "status": [
///     "active"
///   ],
///   "ldhName": "foo.example.com"
/// }
/// ```
///
/// Domains have many sub-structures that are also constructed
/// using builders, which may then be passed into a Domain
/// builder.
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let nameservers = vec![
///     Nameserver::builder()
///         .ldh_name("ns1.example.com")
///         .address("127.0.0.1")
///         .build()
///         .unwrap(),
///     Nameserver::builder()
///         .ldh_name("ns2.example.com")
///         .build()
///         .unwrap(),
/// ];
///
/// let ds_datum = DsDatum::builder()
///         .algorithm(13)
///         .key_tag(20149)
///         .digest_type(2)
///         .digest("cf066bceadb799a27b62e3e82dc2e4da314c1807db98f13d82f0043b1418cf4e")
///         .build();
///
/// let secure_dns = SecureDns::builder()
///         .ds_data(ds_datum)
///         .zone_signed(true)
///         .delegation_signed(false)
///         .build();
///
/// let domain = Domain::builder()
///   .ldh_name("foo.example.com")
///   .handle("foo_example_com-3")
///   .status("active")
///   .nameservers(nameservers)
///   .secure_dns(secure_dns)
///   .build();
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
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
    /// use icann_rdap_common::prelude::*;
    ///
    /// let domain = Domain::builder()
    ///   .ldh_name("foo.example.com")
    ///   .handle("foo_example_com-1")
    ///   .status("active")
    ///   .build();
    /// ```
    #[builder(visibility = "pub")]
    #[allow(clippy::too_many_arguments)]
    fn new<T: Into<String>>(
        ldh_name: T,
        unicode_name: Option<String>,
        nameservers: Vec<Nameserver>,
        handle: Option<String>,
        remarks: Vec<Remark>,
        links: Vec<Link>,
        events: Vec<Event>,
        statuses: Vec<String>,
        port_43: Option<Port43>,
        entities: Vec<Entity>,
        notices: Vec<Notice>,
        public_ids: Vec<PublicId>,
        secure_dns: Option<SecureDns>,
        variants: Vec<Variant>,
        network: Option<Network>,
        extensions: Vec<Extension>,
        redacted: Option<Vec<crate::response::redacted::Redacted>>,
    ) -> Self {
        Self {
            common: Common::level0()
                .extensions(extensions)
                .and_notices(to_opt_vec(notices))
                .build(),
            object_common: ObjectCommon::domain()
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
            unicode_name,
            variants: to_opt_vec(variants),
            secure_dns,
            nameservers: to_opt_vec(nameservers),
            public_ids: to_opt_vec(public_ids),
            network,
        }
    }

    /// Builds an IDN object.
    ///
    /// ```rust
    /// use icann_rdap_common::prelude::*;
    ///
    /// let domain = Domain::idn()
    ///   .unicode_name("foo.example.com")
    ///   .handle("foo_example_com-1")
    ///   .status("active")
    ///   .build();
    /// ```
    #[builder(entry = "idn", visibility = "pub")]
    #[allow(clippy::too_many_arguments)]
    fn new_idn<T: Into<String>>(
        ldh_name: Option<String>,
        unicode_name: T,
        nameservers: Vec<Nameserver>,
        handle: Option<String>,
        remarks: Vec<Remark>,
        links: Vec<Link>,
        events: Vec<Event>,
        statuses: Vec<String>,
        port_43: Option<Port43>,
        entities: Vec<Entity>,
        notices: Vec<Notice>,
        public_ids: Vec<PublicId>,
        secure_dns: Option<SecureDns>,
        variants: Vec<Variant>,
        network: Option<Network>,
        extensions: Vec<Extension>,
    ) -> Self {
        Self {
            common: Common::level0()
                .extensions(extensions)
                .and_notices(to_opt_vec(notices))
                .build(),
            object_common: ObjectCommon::domain()
                .and_handle(handle)
                .and_remarks(to_opt_vec(remarks))
                .and_links(to_opt_vec(links))
                .and_events(to_opt_vec(events))
                .status(statuses)
                .and_port_43(port_43)
                .and_entities(to_opt_vec(entities))
                .build(),
            ldh_name,
            unicode_name: Some(unicode_name.into()),
            variants: to_opt_vec(variants),
            secure_dns,
            nameservers: to_opt_vec(nameservers),
            public_ids: to_opt_vec(public_ids),
            network,
        }
    }

    /// Convenience method to get the public IDs.
    pub fn public_ids(&self) -> &Vec<PublicId> {
        self.public_ids.as_ref().unwrap_or(&EMPTY_PUBLIC_IDS)
    }

    /// Convenience method to get the nameservers.
    pub fn nameservers(&self) -> &Vec<Nameserver> {
        self.nameservers.as_ref().unwrap_or(&EMPTY_NAMESERVERS)
    }

    /// Convenience method.
    pub fn ldh_name(&self) -> Option<&str> {
        self.ldh_name.as_deref()
    }

    /// Convenience method.
    pub fn unicode_name(&self) -> Option<&str> {
        self.unicode_name.as_deref()
    }
}

impl ToResponse for Domain {
    fn to_response(self) -> super::RdapResponse {
        super::RdapResponse::Domain(Box::new(self))
    }
}

impl GetSelfLink for Domain {
    fn get_self_link(&self) -> Option<&Link> {
        self.object_common.get_self_link()
    }
}

impl SelfLink for Domain {
    fn set_self_link(mut self, link: Link) -> Self {
        self.object_common = self.object_common.set_self_link(link);
        self
    }
}

impl ToChild for Domain {
    fn to_child(mut self) -> Self {
        self.common = Common {
            rdap_conformance: None,
            notices: None,
        };
        self
    }
}

impl CommonFields for Domain {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ObjectCommonFields for Domain {
    fn object_common(&self) -> &ObjectCommon {
        &self.object_common
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use crate::response::{types::Link, SelfLink};

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

    #[test]
    fn GIVEN_no_self_links_WHEN_set_self_link_THEN_link_is_only_one() {
        // GIVEN
        let mut domain = Domain::builder()
            .ldh_name("foo.example")
            .link(
                Link::builder()
                    .href("http://bar.example")
                    .value("http://bar.example")
                    .rel("unknown")
                    .build(),
            )
            .build();

        // WHEN
        domain = domain.set_self_link(
            Link::builder()
                .href("http://foo.example")
                .value("http://foo.example")
                .rel("unknown")
                .build(),
        );

        // THEN
        assert_eq!(
            domain
                .object_common
                .links
                .expect("links are empty")
                .iter()
                .filter(|link| link.is_relation("self"))
                .count(),
            1
        );
    }
}
