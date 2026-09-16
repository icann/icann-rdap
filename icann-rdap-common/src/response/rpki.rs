//! RDAP RPKI Extension (draft-ietf-regext-rdap-rpki)
//!
//! This module implements the RDAP extension for accessing RPKI registration data
//! including Route Origin Authorization (ROA), Autonomous System Provider Authorization (ASPA),
//! and X.509 Resource Certificate objects.
//!
//! See [draft-ietf-regext-rdap-rpki](https://www.ietf.org/archive/id/draft-ietf-regext-rdap-rpki-04.txt)

use std::collections::HashSet;

use crate::prelude::ContentExtensions;

use {
    crate::prelude::{Common, Extension, ObjectCommon},
    serde::{Deserialize, Serialize},
};

use super::{
    CommonFields, Entity, Event, ExtensionId, GetSelfLink, Notice, Numberish, ObjectCommonFields,
    Remark, SelfLink, ToChild, ToResponse, to_opt_vec, types::Link,
};

// Common data members for all RPKI objects (Section 3)

/// Represents a digest of an RPKI object.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Rpk1Digest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,

    #[serde(rename = "digestAlgorithm")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_algorithm: Option<String>,
}

#[buildstructor::buildstructor]
impl Rpk1Digest {
    #[builder(visibility = "pub")]
    fn new(digest: String, digest_algorithm: String) -> Self {
        Self {
            digest: Some(digest),
            digest_algorithm: Some(digest_algorithm),
        }
    }
}

/// ROA IP address block within a ROA.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Rpk1RoaIp {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,

    #[serde(rename = "maxLength")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_length: Option<Numberish<u8>>,
}

#[buildstructor::buildstructor]
impl Rpk1RoaIp {
    #[builder(visibility = "pub")]
    fn new(ip: String, max_length: u8) -> Self {
        Self {
            ip: Some(ip),
            max_length: Some(Numberish::<u8>::from(max_length)),
        }
    }
}

/// Subject public key information for X.509 certificates.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Rpk1SubjectPublicKeyInfo {
    #[serde(rename = "publicKeyAlgorithm")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_algorithm: Option<String>,

    #[serde(rename = "publicKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

#[buildstructor::buildstructor]
impl Rpk1SubjectPublicKeyInfo {
    #[builder(visibility = "pub")]
    fn new(public_key_algorithm: String, public_key: String) -> Self {
        Self {
            public_key_algorithm: Some(public_key_algorithm),
            public_key: Some(public_key),
        }
    }
}

/// RPKI type indicating the relationship between repository and CA.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, strum::AsRefStr, strum::Display)]
#[serde(rename_all = "snake_case")]
pub enum Rpk1RpkiType {
    Hosted,
    Delegated,
    Hybrid,
}

// ROA Object Class (Section 4.1)

/// Route Origin Authorization object.
///
/// See [draft-ietf-regext-rdap-rpki Section 4.1](https://www.ietf.org/archive/id/draft-ietf-regext-rdap-rpki-04.html#section-4.1)
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let roa = Rpk1Roa::response_obj()
///   .handle("ROA-1")
///   .roa_ip(Rpk1RoaIp::builder().ip("2001:db8::/48".to_string()).max_length(64).build())
///   .origin_autnum(65536)
///   .build();
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Rpk1Roa {
    #[serde(flatten)]
    pub common: Common,

    #[serde(flatten)]
    pub object_common: ObjectCommon,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub digests: Option<Vec<Rpk1Digest>>,

    #[serde(rename = "notValidBefore")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_valid_before: Option<String>,

    #[serde(rename = "notValidAfter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_valid_after: Option<String>,

    #[serde(rename = "publicationUri")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publication_uri: Option<String>,

    #[serde(rename = "notificationUri")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_uri: Option<String>,

    #[serde(rename = "rpkiType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpki_type: Option<Rpk1RpkiType>,

    #[serde(rename = "roaIps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roa_ips: Option<Vec<Rpk1RoaIp>>,

    #[serde(rename = "originAutnum")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_autnum: Option<Numberish<u32>>,
}

#[buildstructor::buildstructor]
impl Rpk1Roa {
    /// Builds a basic ROA object for embedding.
    #[builder(visibility = "pub")]
    #[allow(clippy::too_many_arguments)]
    fn new(
        handle: Option<String>,
        name: Option<String>,
        digests: Vec<Rpk1Digest>,
        not_valid_before: Option<String>,
        not_valid_after: Option<String>,
        publication_uri: Option<String>,
        notification_uri: Option<String>,
        entities: Vec<Entity>,
        rpki_type: Option<Rpk1RpkiType>,
        roa_ips: Vec<Rpk1RoaIp>,
        origin_autnum: Option<u32>,
        remarks: Vec<Remark>,
        links: Vec<Link>,
        events: Vec<Event>,
        statuses: Vec<String>,
        redacted: Option<Vec<crate::response::redacted::Redacted>>,
    ) -> Self {
        Self {
            common: Common::builder().build(),
            object_common: ObjectCommon::entity()
                .and_handle(handle)
                .and_remarks(to_opt_vec(remarks.clone()))
                .and_links(to_opt_vec(links.clone()))
                .and_events(to_opt_vec(events.clone()))
                .status(statuses.clone())
                .and_entities(to_opt_vec(entities.clone()))
                .and_redacted(redacted.clone())
                .build(),
            name: name.clone(),
            digests: if !digests.is_empty() {
                Some(digests)
            } else {
                None
            },
            not_valid_before,
            not_valid_after,
            publication_uri,
            notification_uri,
            rpki_type,
            roa_ips: if !roa_ips.is_empty() {
                Some(roa_ips)
            } else {
                None
            },
            origin_autnum: origin_autnum.map(Numberish::from),
        }
    }

    /// Builds a ROA object for a response.
    #[builder(entry = "response_obj", visibility = "pub")]
    #[allow(clippy::too_many_arguments)]
    fn new_response_obj(
        handle: Option<String>,
        name: Option<String>,
        digests: Vec<Rpk1Digest>,
        not_valid_before: Option<String>,
        not_valid_after: Option<String>,
        publication_uri: Option<String>,
        notification_uri: Option<String>,
        entities: Vec<Entity>,
        rpki_type: Option<Rpk1RpkiType>,
        roa_ips: Vec<Rpk1RoaIp>,
        origin_autnum: Option<u32>,
        remarks: Vec<Remark>,
        links: Vec<Link>,
        events: Vec<Event>,
        statuses: Vec<String>,
        notices: Vec<Notice>,
        extensions: Vec<Extension>,
        redacted: Option<Vec<crate::response::redacted::Redacted>>,
    ) -> Self {
        let mut rpki_exts = vec![ExtensionId::Rpki1.to_extension()];
        rpki_exts.extend(extensions);
        let common = Common::level0()
            .extensions(rpki_exts)
            .and_notices(to_opt_vec(notices))
            .build();
        let mut roa = Rpk1Roa::builder()
            .and_handle(handle)
            .and_name(name)
            .digests(digests)
            .and_not_valid_before(not_valid_before)
            .and_not_valid_after(not_valid_after)
            .and_publication_uri(publication_uri)
            .and_notification_uri(notification_uri)
            .entities(entities)
            .and_rpki_type(rpki_type)
            .roa_ips(roa_ips)
            .and_origin_autnum(origin_autnum)
            .remarks(remarks)
            .links(links)
            .events(events)
            .statuses(statuses)
            .and_redacted(redacted)
            .build();
        roa.common = common;
        roa
    }

    #[builder(entry = "illegal", visibility = "pub(crate)")]
    #[allow(dead_code)]
    fn new_illegal(
        handle: Option<String>,
        name: Option<String>,
        digests: Option<Vec<Rpk1Digest>>,
        not_valid_before: Option<String>,
        not_valid_after: Option<String>,
        publication_uri: Option<String>,
        notification_uri: Option<String>,
        _entities: Option<Vec<Entity>>,
        rpki_type: Option<Rpk1RpkiType>,
        roa_ips: Option<Vec<Rpk1RoaIp>>,
        origin_autnum: Option<u32>,
    ) -> Self {
        Self {
            common: Common::level0()
                .extension(ExtensionId::Rpki1.to_extension())
                .build(),
            object_common: ObjectCommon {
                object_class_name: "rpki1_roa".to_string(),
                handle: handle.map(|s| s.into()),
                remarks: None,
                links: None,
                events: None,
                status: None,
                port_43: None,
                entities: _entities,
                redacted: None,
            },
            name,
            digests,
            not_valid_before,
            not_valid_after,
            publication_uri,
            notification_uri,
            rpki_type,
            roa_ips,
            origin_autnum: origin_autnum.map(Numberish::from),
        }
    }

    pub fn roa_ips(&self) -> &[Rpk1RoaIp] {
        self.roa_ips.as_deref().unwrap_or_default()
    }

    pub fn origin_autnum(&self) -> Option<u32> {
        self.origin_autnum.as_ref().and_then(|n| n.as_u32())
    }
}

impl ToResponse for Rpk1Roa {
    fn to_response(self) -> super::RdapResponse {
        super::RdapResponse::Rpki1Roa(Box::new(self))
    }
}

impl GetSelfLink for Rpk1Roa {
    fn self_link(&self) -> Option<&Link> {
        self.object_common.self_link()
    }
}

impl SelfLink for Rpk1Roa {
    fn with_self_link(mut self, link: Link) -> Self {
        self.object_common = self.object_common.with_self_link(link);
        self
    }
}

impl ToChild for Rpk1Roa {
    fn to_child(mut self) -> Self {
        self.common = Common {
            rdap_conformance: None,
            notices: None,
        };
        self
    }
}

impl CommonFields for Rpk1Roa {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ObjectCommonFields for Rpk1Roa {
    fn object_common(&self) -> &ObjectCommon {
        &self.object_common
    }
}

impl ContentExtensions for Rpk1Roa {
    fn content_extensions(&self) -> HashSet<ExtensionId> {
        let mut exts = HashSet::new();
        exts.insert(ExtensionId::Rpki1);
        exts.extend(self.common().content_extensions());
        exts.extend(self.object_common().content_extensions());
        exts
    }
}

// ASPA Object Class (Section 5.1)

/// Autonomous System Provider Authorization object.
///
/// See [draft-ietf-regext-rdap-rpki Section 5.1](https://www.ietf.org/archive/id/draft-ietf-regext-rdap-rpki-04.html#section-5.1)
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let aspa = Rpk1Aspa::response_obj()
///   .handle("ASPA-1")
///   .customer_autnum(65536)
///   .provider_autnum(65542)
///   .build();
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Rpk1Aspa {
    #[serde(flatten)]
    pub common: Common,

    #[serde(flatten)]
    pub object_common: ObjectCommon,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub digests: Option<Vec<Rpk1Digest>>,

    #[serde(rename = "notValidBefore")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_valid_before: Option<String>,

    #[serde(rename = "notValidAfter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_valid_after: Option<String>,

    #[serde(rename = "publicationUri")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publication_uri: Option<String>,

    #[serde(rename = "notificationUri")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_uri: Option<String>,

    #[serde(rename = "rpkiType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpki_type: Option<Rpk1RpkiType>,

    #[serde(rename = "customerAutnum")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_autnum: Option<Numberish<u32>>,

    #[serde(rename = "providerAutnums")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_autnums: Option<Vec<Numberish<u32>>>,
}

#[buildstructor::buildstructor]
impl Rpk1Aspa {
    /// Builds a basic ASPA object for embedding.
    #[builder(visibility = "pub")]
    #[allow(clippy::too_many_arguments)]
    fn new(
        handle: Option<String>,
        name: Option<String>,
        digests: Vec<Rpk1Digest>,
        not_valid_before: Option<String>,
        not_valid_after: Option<String>,
        publication_uri: Option<String>,
        notification_uri: Option<String>,
        entities: Vec<Entity>,
        rpki_type: Option<Rpk1RpkiType>,
        customer_autnum: Option<u32>,
        provider_autnums: Vec<u32>,
        remarks: Vec<Remark>,
        links: Vec<Link>,
        events: Vec<Event>,
        statuses: Vec<String>,
        redacted: Option<Vec<crate::response::redacted::Redacted>>,
    ) -> Self {
        Self {
            common: Common::builder().build(),
            object_common: ObjectCommon::entity()
                .and_handle(handle)
                .and_remarks(to_opt_vec(remarks.clone()))
                .and_links(to_opt_vec(links.clone()))
                .and_events(to_opt_vec(events.clone()))
                .status(statuses.clone())
                .and_entities(to_opt_vec(entities.clone()))
                .and_redacted(redacted.clone())
                .build(),
            name: name.clone(),
            digests: if !digests.is_empty() {
                Some(digests)
            } else {
                None
            },
            not_valid_before,
            not_valid_after,
            publication_uri,
            notification_uri,
            rpki_type,
            customer_autnum: customer_autnum.map(Numberish::from),
            provider_autnums: if !provider_autnums.is_empty() {
                Some(provider_autnums.into_iter().map(Numberish::from).collect())
            } else {
                None
            },
        }
    }

    /// Builds an ASPA object for a response.
    #[builder(entry = "response_obj", visibility = "pub")]
    #[allow(clippy::too_many_arguments)]
    fn new_response_obj(
        handle: Option<String>,
        name: Option<String>,
        digests: Vec<Rpk1Digest>,
        not_valid_before: Option<String>,
        not_valid_after: Option<String>,
        publication_uri: Option<String>,
        notification_uri: Option<String>,
        entities: Vec<Entity>,
        rpki_type: Option<Rpk1RpkiType>,
        customer_autnum: Option<u32>,
        provider_autnums: Vec<u32>,
        remarks: Vec<Remark>,
        links: Vec<Link>,
        events: Vec<Event>,
        statuses: Vec<String>,
        notices: Vec<Notice>,
        extensions: Vec<Extension>,
        redacted: Option<Vec<crate::response::redacted::Redacted>>,
    ) -> Self {
        let mut rpki_exts = vec![ExtensionId::Rpki1.to_extension()];
        rpki_exts.extend(extensions);
        let common = Common::level0()
            .extensions(rpki_exts)
            .and_notices(to_opt_vec(notices))
            .build();
        let mut aspa = Rpk1Aspa::builder()
            .and_handle(handle)
            .and_name(name)
            .digests(digests)
            .and_not_valid_before(not_valid_before)
            .and_not_valid_after(not_valid_after)
            .and_publication_uri(publication_uri)
            .and_notification_uri(notification_uri)
            .entities(entities)
            .and_rpki_type(rpki_type)
            .and_customer_autnum(customer_autnum)
            .provider_autnums(provider_autnums)
            .remarks(remarks)
            .links(links)
            .events(events)
            .statuses(statuses)
            .and_redacted(redacted)
            .build();
        aspa.common = common;
        aspa
    }

    #[builder(entry = "illegal", visibility = "pub(crate)")]
    #[allow(dead_code)]
    fn new_illegal(
        handle: Option<String>,
        name: Option<String>,
        digests: Option<Vec<Rpk1Digest>>,
        not_valid_before: Option<String>,
        not_valid_after: Option<String>,
        publication_uri: Option<String>,
        notification_uri: Option<String>,
        _entities: Option<Vec<Entity>>,
        rpki_type: Option<Rpk1RpkiType>,
        customer_autnum: Option<u32>,
        provider_autnums: Option<Vec<u32>>,
    ) -> Self {
        Self {
            common: Common::level0()
                .extension(ExtensionId::Rpki1.to_extension())
                .build(),
            object_common: ObjectCommon {
                object_class_name: "rpki1_aspa".to_string(),
                handle: handle.map(|s| s.into()),
                remarks: None,
                links: None,
                events: None,
                status: None,
                port_43: None,
                entities: _entities,
                redacted: None,
            },
            name,
            digests,
            not_valid_before,
            not_valid_after,
            publication_uri,
            notification_uri,
            rpki_type,
            customer_autnum: customer_autnum.map(Numberish::from),
            provider_autnums: provider_autnums
                .map(|a| a.into_iter().map(Numberish::from).collect()),
        }
    }

    pub fn customer_autnum(&self) -> Option<u32> {
        self.customer_autnum.as_ref().and_then(|n| n.as_u32())
    }

    pub fn provider_autnums(&self) -> Vec<u32> {
        self.provider_autnums
            .as_ref()
            .map(|a| a.iter().filter_map(|n| n.as_u32()).collect())
            .unwrap_or_default()
    }
}

impl ToResponse for Rpk1Aspa {
    fn to_response(self) -> super::RdapResponse {
        super::RdapResponse::Rpki1Aspa(Box::new(self))
    }
}

impl GetSelfLink for Rpk1Aspa {
    fn self_link(&self) -> Option<&Link> {
        self.object_common.self_link()
    }
}

impl SelfLink for Rpk1Aspa {
    fn with_self_link(mut self, link: Link) -> Self {
        self.object_common = self.object_common.with_self_link(link);
        self
    }
}

impl ToChild for Rpk1Aspa {
    fn to_child(mut self) -> Self {
        self.common = Common {
            rdap_conformance: None,
            notices: None,
        };
        self
    }
}

impl CommonFields for Rpk1Aspa {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ObjectCommonFields for Rpk1Aspa {
    fn object_common(&self) -> &ObjectCommon {
        &self.object_common
    }
}

impl ContentExtensions for Rpk1Aspa {
    fn content_extensions(&self) -> HashSet<ExtensionId> {
        let mut exts = HashSet::new();
        exts.insert(ExtensionId::Rpki1);
        exts.extend(self.common().content_extensions());
        exts.extend(self.object_common().content_extensions());
        exts
    }
}

// X.509 Resource Certificate Object Class (Section 6.1)

/// X.509 Resource Certificate object.
///
/// See [draft-ietf-regext-rdap-rpki Section 6.1](https://www.ietf.org/archive/id/draft-ietf-regext-rdap-rpki-04.html#section-6.1)
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let cert = Rpk1X509ResourceCert::response_obj()
///   .handle("CERT-1")
///   .serial_number("1234")
///   .issuer("CN=RIR-CA")
///   .subject("CN=ISP-CA")
///   .build();
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Rpk1X509ResourceCert {
    #[serde(flatten)]
    pub common: Common,

    #[serde(flatten)]
    pub object_common: ObjectCommon,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub digests: Option<Vec<Rpk1Digest>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "serialNumber")]
    pub serial_number: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    #[serde(rename = "signatureAlgorithm")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    #[serde(rename = "subjectPublicKeyInfo")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_public_key_info: Option<Rpk1SubjectPublicKeyInfo>,

    #[serde(rename = "subjectKeyIdentifier")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_key_identifier: Option<String>,

    #[serde(rename = "notValidBefore")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_valid_before: Option<String>,

    #[serde(rename = "notValidAfter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_valid_after: Option<String>,

    #[serde(rename = "publicationUri")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publication_uri: Option<String>,

    #[serde(rename = "notificationUri")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_uri: Option<String>,

    #[serde(rename = "rpkiType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpki_type: Option<Rpk1RpkiType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ips: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub autnums: Option<Vec<Numberish<u32>>>,
}

#[buildstructor::buildstructor]
impl Rpk1X509ResourceCert {
    /// Builds a basic X.509 Resource Certificate object for embedding.
    #[builder(visibility = "pub")]
    #[allow(clippy::too_many_arguments)]
    fn new(
        handle: Option<String>,
        digests: Vec<Rpk1Digest>,
        serial_number: Option<String>,
        issuer: Option<String>,
        signature_algorithm: Option<String>,
        subject: Option<String>,
        subject_public_key_info: Option<Rpk1SubjectPublicKeyInfo>,
        subject_key_identifier: Option<String>,
        ips: Vec<String>,
        autnums: Vec<u32>,
        not_valid_before: Option<String>,
        not_valid_after: Option<String>,
        publication_uri: Option<String>,
        notification_uri: Option<String>,
        entities: Vec<Entity>,
        rpki_type: Option<Rpk1RpkiType>,
        remarks: Vec<Remark>,
        links: Vec<Link>,
        events: Vec<Event>,
        statuses: Vec<String>,
        redacted: Option<Vec<crate::response::redacted::Redacted>>,
    ) -> Self {
        Self {
            common: Common::builder().build(),
            object_common: ObjectCommon::entity()
                .and_handle(handle)
                .and_remarks(to_opt_vec(remarks.clone()))
                .and_links(to_opt_vec(links.clone()))
                .and_events(to_opt_vec(events.clone()))
                .status(statuses.clone())
                .and_entities(to_opt_vec(entities.clone()))
                .and_redacted(redacted.clone())
                .build(),
            digests: if !digests.is_empty() {
                Some(digests)
            } else {
                None
            },
            serial_number,
            issuer,
            signature_algorithm,
            subject,
            subject_public_key_info,
            subject_key_identifier,
            not_valid_before,
            not_valid_after,
            publication_uri,
            notification_uri,
            rpki_type,
            ips: if !ips.is_empty() { Some(ips) } else { None },
            autnums: if !autnums.is_empty() {
                Some(autnums.into_iter().map(Numberish::from).collect())
            } else {
                None
            },
        }
    }

    /// Builds an X.509 Resource Certificate object for a response.
    #[builder(entry = "response_obj", visibility = "pub")]
    #[allow(clippy::too_many_arguments)]
    fn new_response_obj(
        handle: Option<String>,
        digests: Vec<Rpk1Digest>,
        serial_number: Option<String>,
        issuer: Option<String>,
        signature_algorithm: Option<String>,
        subject: Option<String>,
        subject_public_key_info: Option<Rpk1SubjectPublicKeyInfo>,
        subject_key_identifier: Option<String>,
        ips: Vec<String>,
        autnums: Vec<u32>,
        not_valid_before: Option<String>,
        not_valid_after: Option<String>,
        publication_uri: Option<String>,
        notification_uri: Option<String>,
        entities: Vec<Entity>,
        rpki_type: Option<Rpk1RpkiType>,
        remarks: Vec<Remark>,
        links: Vec<Link>,
        events: Vec<Event>,
        statuses: Vec<String>,
        notices: Vec<Notice>,
        extensions: Vec<Extension>,
        redacted: Option<Vec<crate::response::redacted::Redacted>>,
    ) -> Self {
        let mut rpki_exts = vec![ExtensionId::Rpki1.to_extension()];
        rpki_exts.extend(extensions);
        let common = Common::level0()
            .extensions(rpki_exts)
            .and_notices(to_opt_vec(notices))
            .build();
        let mut cert = Rpk1X509ResourceCert::builder()
            .and_handle(handle)
            .digests(digests)
            .and_serial_number(serial_number)
            .and_issuer(issuer)
            .and_signature_algorithm(signature_algorithm)
            .and_subject(subject)
            .and_subject_public_key_info(subject_public_key_info)
            .and_subject_key_identifier(subject_key_identifier)
            .ips(ips)
            .autnums(autnums)
            .and_not_valid_before(not_valid_before)
            .and_not_valid_after(not_valid_after)
            .and_publication_uri(publication_uri)
            .and_notification_uri(notification_uri)
            .entities(entities)
            .and_rpki_type(rpki_type)
            .remarks(remarks)
            .links(links)
            .events(events)
            .statuses(statuses)
            .and_redacted(redacted)
            .build();
        cert.common = common;
        cert
    }

    #[builder(entry = "illegal", visibility = "pub(crate)")]
    #[allow(dead_code)]
    fn new_illegal(
        handle: Option<String>,
        digests: Option<Vec<Rpk1Digest>>,
        serial_number: Option<String>,
        issuer: Option<String>,
        signature_algorithm: Option<String>,
        subject: Option<String>,
        subject_public_key_info: Option<Rpk1SubjectPublicKeyInfo>,
        subject_key_identifier: Option<String>,
        ips: Option<Vec<String>>,
        autnums: Option<Vec<u32>>,
        not_valid_before: Option<String>,
        not_valid_after: Option<String>,
        publication_uri: Option<String>,
        notification_uri: Option<String>,
        _entities: Option<Vec<Entity>>,
        rpki_type: Option<Rpk1RpkiType>,
    ) -> Self {
        Self {
            common: Common::level0()
                .extension(ExtensionId::Rpki1.to_extension())
                .build(),
            object_common: ObjectCommon {
                object_class_name: "rpki1_x509ResourceCert".to_string(),
                handle: handle.map(|s| s.into()),
                remarks: None,
                links: None,
                events: None,
                status: None,
                port_43: None,
                entities: _entities,
                redacted: None,
            },
            digests,
            serial_number,
            issuer,
            signature_algorithm,
            subject,
            subject_public_key_info,
            subject_key_identifier,
            not_valid_before,
            not_valid_after,
            publication_uri,
            notification_uri,
            rpki_type,
            ips,
            autnums: autnums.map(|a| a.into_iter().map(Numberish::from).collect()),
        }
    }

    pub fn subject_public_key_info(&self) -> Option<&Rpk1SubjectPublicKeyInfo> {
        self.subject_public_key_info.as_ref()
    }

    pub fn subject_key_identifier(&self) -> Option<&str> {
        self.subject_key_identifier.as_deref()
    }

    pub fn ips(&self) -> &[String] {
        self.ips.as_deref().unwrap_or_default()
    }

    pub fn autnums(&self) -> Vec<u32> {
        self.autnums
            .as_ref()
            .map(|a| a.iter().filter_map(|n| n.as_u32()).collect())
            .unwrap_or_default()
    }
}

impl ToResponse for Rpk1X509ResourceCert {
    fn to_response(self) -> super::RdapResponse {
        super::RdapResponse::Rpki1X509ResourceCert(Box::new(self))
    }
}

impl GetSelfLink for Rpk1X509ResourceCert {
    fn self_link(&self) -> Option<&Link> {
        self.object_common.self_link()
    }
}

impl SelfLink for Rpk1X509ResourceCert {
    fn with_self_link(mut self, link: Link) -> Self {
        self.object_common = self.object_common.with_self_link(link);
        self
    }
}

impl ToChild for Rpk1X509ResourceCert {
    fn to_child(mut self) -> Self {
        self.common = Common {
            rdap_conformance: None,
            notices: None,
        };
        self
    }
}

impl CommonFields for Rpk1X509ResourceCert {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ObjectCommonFields for Rpk1X509ResourceCert {
    fn object_common(&self) -> &ObjectCommon {
        &self.object_common
    }
}

impl ContentExtensions for Rpk1X509ResourceCert {
    fn content_extensions(&self) -> HashSet<ExtensionId> {
        let mut exts = HashSet::new();
        exts.insert(ExtensionId::Rpki1);
        exts.extend(self.common().content_extensions());
        exts.extend(self.object_common().content_extensions());
        exts
    }
}

// Search Results (Sections 4.3.1, 5.3.1, 6.3.1)

/// ROA search results.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Eq)]
pub struct Rpk1RoaSearchResults {
    #[serde(flatten)]
    pub common: Common,

    #[serde(rename = "rpki1_roaSearchResults")]
    pub results: Vec<Rpk1Roa>,
}

#[buildstructor::buildstructor]
impl Rpk1RoaSearchResults {
    #[builder(entry = "response_obj", visibility = "pub")]
    fn new_response_obj(results: Vec<Rpk1Roa>, extensions: Vec<Extension>) -> Self {
        Self {
            common: Common::level0().extensions(extensions).build(),
            results,
        }
    }

    pub fn results(&self) -> &[Rpk1Roa] {
        &self.results
    }
}

impl CommonFields for Rpk1RoaSearchResults {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ToResponse for Rpk1RoaSearchResults {
    fn to_response(self) -> super::RdapResponse {
        super::RdapResponse::Rpki1RoaSearchResults(Box::new(self))
    }
}

impl ContentExtensions for Rpk1RoaSearchResults {
    fn content_extensions(&self) -> HashSet<ExtensionId> {
        let mut exts = HashSet::new();
        exts.insert(ExtensionId::Rpki1);
        self.results()
            .iter()
            .for_each(|r| exts.extend(r.content_extensions()));
        exts.extend(self.common().content_extensions());
        exts
    }
}

/// ASPA search results.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Eq)]
pub struct Rpk1AspaSearchResults {
    #[serde(flatten)]
    pub common: Common,

    #[serde(rename = "rpki1_aspaSearchResults")]
    pub results: Vec<Rpk1Aspa>,
}

#[buildstructor::buildstructor]
impl Rpk1AspaSearchResults {
    #[builder(entry = "response_obj", visibility = "pub")]
    fn new_response_obj(results: Vec<Rpk1Aspa>, extensions: Vec<Extension>) -> Self {
        Self {
            common: Common::level0().extensions(extensions).build(),
            results,
        }
    }

    pub fn results(&self) -> &[Rpk1Aspa] {
        &self.results
    }
}

impl CommonFields for Rpk1AspaSearchResults {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ToResponse for Rpk1AspaSearchResults {
    fn to_response(self) -> super::RdapResponse {
        super::RdapResponse::Rpki1AspaSearchResults(Box::new(self))
    }
}

impl ContentExtensions for Rpk1AspaSearchResults {
    fn content_extensions(&self) -> HashSet<ExtensionId> {
        let mut exts = HashSet::new();
        exts.insert(ExtensionId::Rpki1);
        self.results()
            .iter()
            .for_each(|r| exts.extend(r.content_extensions()));
        exts.extend(self.common().content_extensions());
        exts
    }
}

/// X.509 Resource Certificate search results.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Eq)]
pub struct Rpk1X509ResourceCertSearchResults {
    #[serde(flatten)]
    pub common: Common,

    #[serde(rename = "rpki1_x509ResourceCertSearchResults")]
    pub results: Vec<Rpk1X509ResourceCert>,
}

#[buildstructor::buildstructor]
impl Rpk1X509ResourceCertSearchResults {
    #[builder(entry = "response_obj", visibility = "pub")]
    fn new_response_obj(results: Vec<Rpk1X509ResourceCert>, extensions: Vec<Extension>) -> Self {
        Self {
            common: Common::level0().extensions(extensions).build(),
            results,
        }
    }

    pub fn results(&self) -> &[Rpk1X509ResourceCert] {
        &self.results
    }
}

impl CommonFields for Rpk1X509ResourceCertSearchResults {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ToResponse for Rpk1X509ResourceCertSearchResults {
    fn to_response(self) -> super::RdapResponse {
        super::RdapResponse::Rpki1X509ResourceCertSearchResults(Box::new(self))
    }
}

impl ContentExtensions for Rpk1X509ResourceCertSearchResults {
    fn content_extensions(&self) -> HashSet<ExtensionId> {
        let mut exts = HashSet::new();
        exts.insert(ExtensionId::Rpki1);
        self.results()
            .iter()
            .for_each(|r| exts.extend(r.content_extensions()));
        exts.extend(self.common().content_extensions());
        exts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::RdapResponse;

    #[test]
    fn test_roa_serialize() {
        let roa = Rpk1Roa::illegal()
            .handle("ROA-1")
            .roa_ips(vec![Rpk1RoaIp::new("2001:db8::/48".to_string(), 64)])
            .origin_autnum(65536)
            .build();
        let json = serde_json::to_string(&roa).unwrap();
        assert!(json.contains("rpki1_roa"));
        assert!(json.contains("roaIps"));
        assert!(json.contains("originAutnum"));
    }

    #[test]
    fn test_aspa_serialize() {
        let aspa = Rpk1Aspa::illegal()
            .handle("ASPA-1")
            .customer_autnum(65536)
            .provider_autnums(vec![65542])
            .build();
        let json = serde_json::to_string(&aspa).unwrap();
        assert!(json.contains("rpki1_aspa"));
        assert!(json.contains("customerAutnum"));
        assert!(json.contains("providerAutnums"));
    }

    #[test]
    fn test_x509_cert_serialize() {
        let cert = Rpk1X509ResourceCert::illegal()
            .handle("CERT-1")
            .serial_number("1234")
            .issuer("CN=RIR-CA")
            .subject("CN=ISP-CA")
            .ips(vec!["192.0.2.0/24".to_string()])
            .autnums(vec![65536])
            .build();
        let json = serde_json::to_string(&cert).unwrap();
        assert!(json.contains("rpki1_x509ResourceCert"));
        assert!(json.contains("serialNumber"));
        assert!(json.contains("issuer"));
        assert!(json.contains("subject"));
    }

    #[test]
    fn test_roa_to_response() {
        let roa = Rpk1Roa::illegal().handle("ROA-1").build();
        let response = roa.to_response();
        assert!(matches!(response, RdapResponse::Rpki1Roa(_)));
    }

    #[test]
    fn test_aspa_to_response() {
        let aspa = Rpk1Aspa::illegal().handle("ASPA-1").build();
        let response = aspa.to_response();
        assert!(matches!(response, RdapResponse::Rpki1Aspa(_)));
    }

    #[test]
    fn test_x509_to_response() {
        let cert = Rpk1X509ResourceCert::illegal().handle("CERT-1").build();
        let response = cert.to_response();
        assert!(matches!(response, RdapResponse::Rpki1X509ResourceCert(_)));
    }

    #[test]
    fn test_roa_content_extensions() {
        let roa = Rpk1Roa::illegal().handle("ROA-1").build();
        let exts = roa.content_extensions();
        assert!(exts.contains(&ExtensionId::Rpki1));
    }

    #[test]
    fn test_aspa_content_extensions() {
        let aspa = Rpk1Aspa::illegal().handle("ASPA-1").build();
        let exts = aspa.content_extensions();
        assert!(exts.contains(&ExtensionId::Rpki1));
    }

    #[test]
    fn test_x509_content_extensions() {
        let cert = Rpk1X509ResourceCert::illegal().handle("CERT-1").build();
        let exts = cert.content_extensions();
        assert!(exts.contains(&ExtensionId::Rpki1));
    }

    #[test]
    fn test_rpki_type_serialize() {
        let json = serde_json::to_string(&Rpk1RpkiType::Hosted).unwrap();
        assert_eq!(json, "\"hosted\"");
        let json = serde_json::to_string(&Rpk1RpkiType::Delegated).unwrap();
        assert_eq!(json, "\"delegated\"");
        let json = serde_json::to_string(&Rpk1RpkiType::Hybrid).unwrap();
        assert_eq!(json, "\"hybrid\"");
    }

    #[test]
    fn test_rpki_type_deserialize() {
        let hosted: Rpk1RpkiType = serde_json::from_str("\"hosted\"").unwrap();
        assert_eq!(hosted, Rpk1RpkiType::Hosted);
        let delegated: Rpk1RpkiType = serde_json::from_str("\"delegated\"").unwrap();
        assert_eq!(delegated, Rpk1RpkiType::Delegated);
        let hybrid: Rpk1RpkiType = serde_json::from_str("\"hybrid\"").unwrap();
        assert_eq!(hybrid, Rpk1RpkiType::Hybrid);
    }

    #[test]
    fn test_digest_serialize() {
        let digest = Rpk1Digest::new(
            "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069".to_string(),
            "SHA-256".to_string(),
        );
        let json = serde_json::to_string(&digest).unwrap();
        assert!(json.contains("digest"));
        assert!(json.contains("digestAlgorithm"));
        assert!(json.contains("SHA-256"));
    }

    #[test]
    fn test_roa_ip_serialize() {
        let roa_ip = Rpk1RoaIp::new("2001:db8::/48".to_string(), 64);
        let json = serde_json::to_string(&roa_ip).unwrap();
        assert!(json.contains("ip"));
        assert!(json.contains("maxLength"));
        assert!(json.contains("64"));
    }

    #[test]
    fn test_subject_public_key_info_serialize() {
        let spki = Rpk1SubjectPublicKeyInfo::new("id-ecPublicKey".to_string(), "04...".to_string());
        let json = serde_json::to_string(&spki).unwrap();
        assert!(json.contains("publicKeyAlgorithm"));
        assert!(json.contains("publicKey"));
    }
}
