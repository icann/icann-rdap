//! Common data structures, etc...
use serde::{Deserialize, Serialize};
use strum_macros::{AsRefStr, Display, EnumString};

use super::lenient::VectorStringish;

/// Represents an RDAP extension identifier.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Extension(pub String);

impl From<&str> for Extension {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl std::ops::Deref for Extension {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The RDAP conformance array.
///
/// This is a vec of [Extension] specifically to be able to handle one or more
/// unknown extension ids. Known extension identifiers are enumerated by [ExtensionId].
pub type RdapConformance = Vec<Extension>;

/// Extension Identifiers
///
/// This enum uses [EnumString] and [AsRefStr] to allow serialization
/// and deserialization of the variant to the matching name in the IANA registry.
///
/// To get the variant from a string:
///
/// ```rust
/// use std::str::FromStr;
/// use icann_rdap_common::prelude::*;
///
/// let cidr0 = ExtensionId::from_str("cidr0").unwrap();
/// assert_eq!(cidr0, ExtensionId::Cidr0);
/// println!("{}", cidr0.to_string());
/// ```
///
/// To get the variants as a string:
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let s = ExtensionId::Cidr0.to_string();
/// ```
///
/// To get the variants as a &str:
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let s = ExtensionId::Cidr0.as_ref();
/// ```
#[derive(Serialize, Deserialize, EnumString, Display, Debug, PartialEq, Eq, AsRefStr)]
pub enum ExtensionId {
    #[strum(serialize = "rdap_level_0")]
    RdapLevel0,
    #[strum(serialize = "arin_originas0")]
    ArinOriginAs0,
    #[strum(serialize = "artRecord")]
    ArtRecord,
    #[strum(serialize = "cidr0")]
    Cidr0,
    #[strum(serialize = "farv1")]
    Farv1,
    #[strum(serialize = "fred")]
    Fred,
    #[strum(serialize = "icann_rdap_response_profile_0")]
    IcannRdapResponseProfile0,
    #[strum(serialize = "icann_rdap_response_profile_1")]
    IcannRdapResponseProfile1,
    #[strum(serialize = "icann_rdap_technical_implementation_guide_0")]
    IcannRdapTechnicalImplementationGuide0,
    #[strum(serialize = "icann_rdap_technical_implementation_guide_1")]
    IcannRdapTechnicalImplementationGuide1,
    #[strum(serialize = "nro_rdap_profile_0")]
    NroRdapProfile0,
    #[strum(serialize = "nro_rdap_profile_asn_flat_0")]
    NroRdapProfileAsnFlat0,
    #[strum(serialize = "nro_rdap_profile_asn_hierarchical_0")]
    NroRdapProfileAsnHierarchical0,
    #[strum(serialize = "paging")]
    Paging,
    #[strum(serialize = "platformNS")]
    PlatformNs,
    #[strum(serialize = "rdap_objectTag")]
    RdapObjectTag,
    #[strum(serialize = "redacted")]
    Redacted,
    #[strum(serialize = "redirect_with_content")]
    RedirectWithContent,
    #[strum(serialize = "regType")]
    RegType,
    #[strum(serialize = "reverse_search")]
    ReverseSearch,
    #[strum(serialize = "sorting")]
    Sorting,
    #[strum(serialize = "subsetting")]
    Subsetting,
}

impl ExtensionId {
    /// Gets an [Extension] from an Extension ID.
    pub fn to_extension(&self) -> Extension {
        Extension(self.to_string())
    }
}

/// HrefLang, either a string or an array of strings.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum HrefLang {
    Langs(Vec<String>),
    Lang(String),
}

/// An array of RDAP link structures.
pub type Links = Vec<Link>;

/// Represents and RDAP link structure.
///
/// This structure allows `value`, `rel`, and `href` to be
/// optional to be tolerant of misbehaving servers,
/// but those are fields required by RFC 9083.
///
/// To create an RFC valid structure, use the builder
/// which will not allow omision of required fields.
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let link = Link::builder()
///   .value("https://example.com/domains?domain=foo.*")
///   .rel("related")
///   .href("https://example.com/domain/foo.example")
///   .hreflang("ch")
///   .title("Related Object")
///   .media("print")
///   .media_type("application/rdap+json")
///   .build();
/// ```
///
/// Note also that this structure allows for `hreflang` to
/// be either a single string or an array of strings. However,
/// the builder will always construct an array of strings.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Link {
    /// Represents the value part of a link in an RDAP response.
    /// According to RFC 9083, this field is required
    /// but many servers do not return it as it was
    /// optional in RFC 7483.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,

    /// Represents the relationship of a link in an RDAP response.
    /// According to RFC 9083, this field is required
    /// but many servers do not return it as it was
    /// optional in RFC 7483.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rel: Option<String>,

    /// This is required by RDAP, both RFC 7043 and 9083,
    /// but is optional because some servers do the wrong thing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,

    /// This can either be a string or an array of strings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hreflang: Option<HrefLang>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub media: Option<String>,

    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

#[buildstructor::buildstructor]
impl Link {
    /// True if the link `rel` property is equal to the given value.
    pub fn is_relation(&self, rel: &str) -> bool {
        let Some(link_rel) = &self.rel else {
            return false;
        };
        link_rel == rel
    }

    /// Builds an RDAP link.
    #[builder(visibility = "pub")]
    fn new(
        value: String,
        href: String,
        rel: String,
        hreflang: Option<String>,
        title: Option<String>,
        media: Option<String>,
        media_type: Option<String>,
    ) -> Self {
        let hreflang = hreflang.map(HrefLang::Lang);
        Self {
            value: Some(value),
            rel: Some(rel),
            href: Some(href),
            hreflang,
            title,
            media,
            media_type,
        }
    }

    /// Builds a potentially illegal RDAP link.
    #[builder(entry = "illegal", visibility = "pub(crate)")]
    #[allow(dead_code)]
    fn new_illegal(
        value: Option<String>,
        href: Option<String>,
        rel: Option<String>,
        hreflang: Option<String>,
        title: Option<String>,
        media: Option<String>,
        media_type: Option<String>,
    ) -> Self {
        let hreflang = hreflang.map(HrefLang::Lang);
        Link {
            value,
            rel,
            href,
            hreflang,
            title,
            media,
            media_type,
        }
    }

    /// Returns the value of the link.
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// Returns the relationship of the link.
    pub fn rel(&self) -> Option<&str> {
        self.rel.as_deref()
    }

    /// Returns the target URL of the link.
    pub fn href(&self) -> Option<&str> {
        self.href.as_deref()
    }

    /// Returns the language(s) of the linked resource.
    pub fn hreflang(&self) -> Option<&HrefLang> {
        self.hreflang.as_ref()
    }

    /// Returns the title of the link.
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// Returns the media type for which the link is designed.
    pub fn media(&self) -> Option<&str> {
        self.media.as_deref()
    }

    /// Returns the media type of the linked resource.
    pub fn media_type(&self) -> Option<&str> {
        self.media_type.as_deref()
    }
}

/// An array of notices.
pub type Notices = Vec<Notice>;

/// Represents an RDAP Notice.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Notice(pub NoticeOrRemark);

impl std::ops::Deref for Notice {
    type Target = NoticeOrRemark;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// An array of remarks.
pub type Remarks = Vec<Remark>;

/// Represents an RDAP Remark.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Remark(pub NoticeOrRemark);

impl std::ops::Deref for Remark {
    type Target = NoticeOrRemark;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Represents an RDAP Notice or Remark (they are the same thing in RDAP).
///
/// RFC 9083 requires that `description` be required, but some servers
/// do not follow this rule. Therefore, this structure allows `description`
/// to be optional. It is recommended to use builder to construct an RFC valid
/// structure.
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let link = Link::builder()
///   .value("https://example.com/domains/foo.example")
///   .rel("about")
///   .href("https://example.com/tou.html")
///   .hreflang("en")
///   .title("ToU Link")
///   .media_type("text/html")
///   .build();
///
/// let nr = NoticeOrRemark::builder()
///   .title("Terms of Use")
///   .description_entry("Please read our terms of use.")
///   .description_entry("TOS can be found in the link.")
///   .links(vec![link])
///   .build();
/// ```
///
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct NoticeOrRemark {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<VectorStringish>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,

    /// Description `type` as is found in the IANA registry.
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nr_type: Option<String>,
}

#[buildstructor::buildstructor]
impl NoticeOrRemark {
    /// Builds an RDAP notice/remark.
    #[builder(visibility = "pub")]
    fn new(
        title: Option<String>,
        description: Vec<String>,
        links: Vec<Link>,
        nr_type: Option<String>,
    ) -> Self {
        NoticeOrRemark {
            title,
            description: Some(VectorStringish::from(description)),
            links: (!links.is_empty()).then_some(links),
            nr_type,
        }
    }

    /// Builds an illegal RDAP notice/remark.
    #[builder(entry = "illegal", visibility = "pub(crate)")]
    #[allow(dead_code)]
    fn new_illegal(
        title: Option<String>,
        description: Option<Vec<String>>,
        links: Option<Vec<Link>>,
        nr_type: Option<String>,
    ) -> Self {
        let d = description
            .is_some()
            .then_some(VectorStringish::from(description.unwrap()));
        NoticeOrRemark {
            title,
            description: d,
            links,
            nr_type,
        }
    }

    /// Converts to a [Notice].
    pub fn notice(self) -> Notice {
        Notice(self)
    }

    /// Converts to a [Remark].
    pub fn remark(self) -> Remark {
        Remark(self)
    }

    /// Returns the title of the notice/remark.
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// Returns the description of the notice/remark.
    pub fn description(&self) -> Option<&VectorStringish> {
        self.description.as_ref()
    }

    /// Returns the links associated with the notice/remark.
    pub fn links(&self) -> Option<&Links> {
        self.links.as_ref()
    }

    /// Returns the `type` of the notice or remark.
    ///
    /// These values are suppose to come from the IANA RDAP registry.
    pub fn nr_type(&self) -> Option<&str> {
        self.nr_type.as_deref()
    }
}

/// Conversion for collection of notices.
pub trait ToNotices {
    /// Convert to a collection of notices.
    fn to_notices(self) -> Vec<Notice>;
    /// Convert to a collection if some, otherwise none.
    fn to_opt_notices(self) -> Option<Vec<Notice>>;
}

impl ToNotices for &[NoticeOrRemark] {
    fn to_notices(self) -> Vec<Notice> {
        self.iter().map(|n| Notice(n.clone())).collect::<Notices>()
    }

    fn to_opt_notices(self) -> Option<Vec<Notice>> {
        let notices = self.to_notices();
        (!notices.is_empty()).then_some(notices)
    }
}

impl ToNotices for Vec<NoticeOrRemark> {
    fn to_notices(self) -> Vec<Notice> {
        self.into_iter().map(Notice).collect::<Notices>()
    }

    fn to_opt_notices(self) -> Option<Vec<Notice>> {
        let notices = self.to_notices();
        (!notices.is_empty()).then_some(notices)
    }
}

/// Conversion for collection of remarks.
pub trait ToRemarks {
    /// Convert to a collection of remarks.
    fn to_remarks(self) -> Vec<Remark>;
    /// Convert to a collection if some, otherwise none.
    fn to_opt_remarks(self) -> Option<Vec<Remark>>;
}

impl ToRemarks for &[NoticeOrRemark] {
    fn to_remarks(self) -> Vec<Remark> {
        self.iter().map(|n| Remark(n.clone())).collect::<Remarks>()
    }

    fn to_opt_remarks(self) -> Option<Vec<Remark>> {
        let remarks = self.to_remarks();
        (!remarks.is_empty()).then_some(remarks)
    }
}

impl ToRemarks for Vec<NoticeOrRemark> {
    fn to_remarks(self) -> Vec<Remark> {
        self.into_iter().map(Remark).collect::<Remarks>()
    }

    fn to_opt_remarks(self) -> Option<Vec<Remark>> {
        let remarks = self.to_remarks();
        (!remarks.is_empty()).then_some(remarks)
    }
}

/// An array of events.
pub type Events = Vec<Event>;

/// Represents an RDAP event.
///
/// RFC 9083 requires `eventAction` (event_action) and `eventDate` (event_date), but
/// this structure allows those to be optional to be able to parse responses from
/// servers that do not strictly obey the RFC.
///
/// Use of the builder to contruct an RFC valid structure is recommended.
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let link = Link::builder()
///   .value("https://example.com/domains/foo.example")
///   .rel("about")
///   .href("https://example.com/registration-duration.html")
///   .hreflang("en")
///   .title("Domain Validity Period")
///   .media_type("text/html")
///   .build();
///
/// let nr = Event::builder()
///   .event_action("expiration")
///   .event_date("1990-12-31T23:59:59Z")
///   .links(vec![link])
///   .build();
/// ```
///
/// NOTE: `event_date` is to be an RFC 3339 valid date and time.
/// The builder does not enforce RFC 3339 validity.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// This value is required by RFC 9083 (and 7483),
    /// however some servers don't include it. Therefore
    /// it is optional here to be compatible with these
    /// types of non-compliant servers.
    #[serde(rename = "eventAction")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_action: Option<String>,

    #[serde(rename = "eventActor")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_actor: Option<String>,

    /// This value is required by RFC 9083 (and 7483),
    /// however some servers don't include it. Therefore
    /// it is optional here to be compatible with these
    /// types of non-compliant servers.
    #[serde(rename = "eventDate")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_date: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,
}

#[buildstructor::buildstructor]
impl Event {
    /// Builds an Event.
    #[builder(visibility = "pub")]
    fn new(
        event_action: String,
        event_date: String,
        event_actor: Option<String>,
        links: Option<Links>,
    ) -> Self {
        Self {
            event_action: Some(event_action),
            event_actor,
            event_date: Some(event_date),
            links,
        }
    }

    #[builder(entry = "illegal", visibility = "pub(crate)")]
    #[allow(dead_code)]
    fn new_illegal(
        event_action: Option<String>,
        event_date: Option<String>,
        event_actor: Option<String>,
        links: Option<Links>,
    ) -> Self {
        Event {
            event_action,
            event_actor,
            event_date,
            links,
        }
    }

    /// Returns the action associated with the event.
    pub fn event_action(&self) -> Option<&str> {
        self.event_action.as_deref()
    }

    /// Returns the actor associated with the event.
    pub fn event_actor(&self) -> Option<&str> {
        self.event_actor.as_deref()
    }

    /// Returns the date and time of the event.
    pub fn event_date(&self) -> Option<&str> {
        self.event_date.as_deref()
    }

    /// Returns the links associated with the event.
    pub fn links(&self) -> Option<&Links> {
        self.links.as_ref()
    }
}

/// An RDAP port53 type.
pub type Port43 = String;

/// An array of RDAP public IDs.
pub type PublicIds = Vec<PublicId>;

/// An RDAP Public ID.
///
/// RFC 9083 requires `type` (id_type) and `identifier`, but
/// this structure allows those to be optional to be able to parse responses from
/// servers that do not strictly obey the RFC.
///
/// Use of the builder to contruct an RFC valid structure is recommended.
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let public_id = PublicId::builder()
///   .id_type("IANA Registrar ID")
///   .identifier("1990")
///   .build();
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicId {
    /// This are manditory per RFC 9083.
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_type: Option<String>,

    /// This are manditory per RFC 9083.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
}

#[buildstructor::buildstructor]
impl PublicId {
    /// Builds a public ID.
    #[builder(visibility = "pub")]
    fn new(id_type: String, identifier: String) -> Self {
        PublicId {
            id_type: Some(id_type),
            identifier: Some(identifier),
        }
    }

    /// Builds an illegal public ID.
    #[builder(entry = "illegal", visibility = "pub(crate)")]
    #[allow(dead_code)]
    fn new_illegal(id_type: Option<String>, identifier: Option<String>) -> Self {
        PublicId {
            id_type,
            identifier,
        }
    }

    /// Returns the type of the public ID.
    pub fn id_type(&self) -> Option<&str> {
        self.id_type.as_deref()
    }

    /// Returns the identifier of the public ID.
    pub fn identifier(&self) -> Option<&str> {
        self.identifier.as_deref()
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use crate::{
        prelude::ObjectCommon,
        response::types::{Extension, Notice, Notices, RdapConformance, Remark, Remarks},
    };

    use super::{Event, Link, Links, NoticeOrRemark, PublicId};

    #[test]
    fn GIVEN_rdap_conformance_WHEN_serialize_THEN_array_of_strings() {
        // GIVEN
        let rdap_conformance: RdapConformance =
            vec![Extension("foo".to_string()), Extension("bar".to_string())];

        // WHEN
        let actual = serde_json::to_string(&rdap_conformance).unwrap();

        // THEN
        let expected = r#"["foo","bar"]"#;
        assert_eq!(actual, expected);
    }

    #[test]
    fn GIVEN_an_array_of_links_WHEN_deserialize_THEN_success() {
        // GIVEN
        let expected = r#"
        [
            {
                "value" : "https://1.example.com/context_uri",
                "rel" : "self",
                "href" : "https://1.example.com/target_uri",
                "hreflang" : [ "en", "ch" ],
                "title" : "title1",
                "media" : "screen",
                "type" : "application/json"
            },
            {
                "value" : "https://2.example.com/context_uri",
                "rel" : "self",
                "href" : "https://2.example.com/target_uri",
                "hreflang" : [ "en", "ch" ],
                "title" : "title2",
                "media" : "screen",
                "type" : "application/json"
            }
        ]   
        "#;

        // WHEN
        let links = serde_json::from_str::<Links>(expected);

        // THEN
        let actual = links.unwrap();
        assert_eq!(actual.len(), 2);
        let actual_1 = actual.first().unwrap();
        let actual_2 = actual.last().unwrap();
        assert_eq!(
            actual_1.value.as_ref().unwrap(),
            "https://1.example.com/context_uri"
        );
        assert_eq!(
            actual_2.value.as_ref().unwrap(),
            "https://2.example.com/context_uri"
        );
        assert_eq!(
            actual_1.href.as_ref().unwrap(),
            "https://1.example.com/target_uri"
        );
        assert_eq!(
            actual_2.href.as_ref().unwrap(),
            "https://2.example.com/target_uri"
        );
        assert_eq!(actual_1.title.as_ref().unwrap(), "title1");
        assert_eq!(actual_2.title.as_ref().unwrap(), "title2");
        assert_eq!(actual_1.media_type.as_ref().unwrap(), "application/json");
        assert_eq!(actual_2.media_type.as_ref().unwrap(), "application/json");
    }

    #[test]
    fn GIVEN_an_array_of_links_with_one_lang_WHEN_deserialize_THEN_success() {
        // GIVEN
        let expected = r#"
        [
            {
                "value" : "https://1.example.com/context_uri",
                "rel" : "self",
                "href" : "https://1.example.com/target_uri",
                "hreflang" : "en",
                "title" : "title1",
                "media" : "screen",
                "type" : "application/json"
            },
            {
                "value" : "https://2.example.com/context_uri",
                "rel" : "self",
                "href" : "https://2.example.com/target_uri",
                "hreflang" : "ch",
                "title" : "title2",
                "media" : "screen",
                "type" : "application/json"
            }
        ]   
        "#;

        // WHEN
        let links = serde_json::from_str::<Links>(expected);

        // THEN
        let actual = links.unwrap();
        assert_eq!(actual.len(), 2);
        let actual_1 = actual.first().unwrap();
        let actual_2 = actual.last().unwrap();
        assert_eq!(
            actual_1.value.as_ref().unwrap(),
            "https://1.example.com/context_uri"
        );
        assert_eq!(
            actual_2.value.as_ref().unwrap(),
            "https://2.example.com/context_uri"
        );
        assert_eq!(
            actual_1.href.as_ref().unwrap(),
            "https://1.example.com/target_uri"
        );
        assert_eq!(
            actual_2.href.as_ref().unwrap(),
            "https://2.example.com/target_uri"
        );
        assert_eq!(actual_1.title.as_ref().unwrap(), "title1");
        assert_eq!(actual_2.title.as_ref().unwrap(), "title2");
        assert_eq!(actual_1.media_type.as_ref().unwrap(), "application/json");
        assert_eq!(actual_2.media_type.as_ref().unwrap(), "application/json");
    }

    #[test]
    fn GIVEN_a_notice_or_remark_WHEN_deserialize_THEN_success() {
        // GIVEN
        let expected = r#"
        {
            "title" : "Terms of Use",
            "description" :
            [
                "Service subject to The Registry of the Moon's TOS.",
                "Copyright (c) 2020 LunarNIC"
            ],
            "links" :
            [
                {
                    "value" : "https://example.net/entity/XXXX",
                    "rel" : "alternate",
                    "type" : "text/html",
                    "href" : "https://www.example.com/terms_of_use.html"
                }
            ]
        }
        "#;

        // WHEN
        let actual = serde_json::from_str::<NoticeOrRemark>(expected);

        // THEN
        let actual = actual.unwrap();
        actual.title.as_ref().unwrap();
        let description: Vec<String> = actual.description.expect("must have description").into();
        assert_eq!(description.len(), 2);
        actual.links.unwrap();
    }

    #[test]
    fn GIVEN_notices_WHEN_serialize_THEN_array_of_notice_structs() {
        // GIVEN
        let notices: Notices = vec![
            Notice(
                NoticeOrRemark::builder()
                    .description(vec!["foo".to_string()])
                    .build(),
            ),
            Notice(
                NoticeOrRemark::builder()
                    .description(vec!["bar".to_string()])
                    .build(),
            ),
        ];

        // WHEN
        let actual = serde_json::to_string(&notices).unwrap();

        // THEN
        let expected = r#"[{"description":["foo"]},{"description":["bar"]}]"#;
        assert_eq!(actual, expected);
    }

    #[test]
    fn GIVEN_remarks_WHEN_serialize_THEN_array_of_remark_structs() {
        // GIVEN
        let remarks: Remarks = vec![
            Remark(
                NoticeOrRemark::builder()
                    .description(vec!["foo".to_string()])
                    .build(),
            ),
            Remark(
                NoticeOrRemark::builder()
                    .description(vec!["bar".to_string()])
                    .build(),
            ),
        ];

        // WHEN
        let actual = serde_json::to_string(&remarks).unwrap();

        // THEN
        let expected = r#"[{"description":["foo"]},{"description":["bar"]}]"#;
        assert_eq!(actual, expected);
    }

    #[test]
    fn GIVEN_an_event_WHEN_deserialize_THEN_success() {
        // GIVEN
        let expected = r#"
        {
            "eventAction" : "last changed",
            "eventActor" : "OTHERID-LUNARNIC",
            "eventDate" : "1991-12-31T23:59:59Z"
        }
        "#;

        // WHEN
        let actual = serde_json::from_str::<Event>(expected);

        // THEN
        let actual = actual.unwrap();
        actual.event_actor.as_ref().unwrap();
    }

    #[test]
    fn GIVEN_a_public_id_WHEN_deserialize_THEN_success() {
        // GIVEN
        let expected = r#"
        {
            "type":"IANA Registrar ID",
            "identifier":"1"
        }
        "#;

        // WHEN
        let actual = serde_json::from_str::<PublicId>(expected);

        // THEN
        let _actual = actual.unwrap();
    }

    #[test]
    fn GIVEN_no_self_links_WHEN_set_self_link_THEN_link_is_only_one() {
        // GIVEN
        let mut oc = ObjectCommon::domain()
            .links(vec![Link::builder()
                .href("http://bar.example")
                .value("http://bar.example")
                .rel("unknown")
                .build()])
            .build();

        // WHEN
        oc = oc.set_self_link(
            Link::builder()
                .href("http://foo.example")
                .value("http://foo.example")
                .rel("unknown")
                .build(),
        );

        // THEN
        assert_eq!(
            oc.links
                .expect("links are empty")
                .iter()
                .filter(|link| link.is_relation("self"))
                .count(),
            1
        );
    }

    #[test]
    fn GIVEN_no_links_WHEN_set_self_link_THEN_link_is_only_one() {
        // GIVEN
        let mut oc = ObjectCommon::domain().build();

        // WHEN
        oc = oc.set_self_link(
            Link::builder()
                .href("http://foo.example")
                .value("http://foo.example")
                .rel("unknown")
                .build(),
        );

        // THEN
        assert_eq!(
            oc.links
                .expect("links are empty")
                .iter()
                .filter(|link| link.is_relation("self"))
                .count(),
            1
        );
    }

    #[test]
    fn GIVEN_one_self_link_WHEN_set_self_link_THEN_link_is_only_one() {
        // GIVEN
        let mut oc = ObjectCommon::domain()
            .links(vec![Link::builder()
                .href("http://bar.example")
                .value("http://bar.example")
                .rel("self")
                .build()])
            .build();

        // WHEN
        oc = oc.set_self_link(
            Link::builder()
                .href("http://foo.example")
                .value("http://foo.example")
                .rel("unknown")
                .build(),
        );

        // THEN
        // new link is in
        assert_eq!(
            oc.links
                .as_ref()
                .expect("links are empty")
                .iter()
                .filter(|link| link.is_relation("self")
                    && link.href.as_ref().unwrap() == "http://foo.example")
                .count(),
            1
        );
        // all self links count == 1
        assert_eq!(
            oc.links
                .as_ref()
                .expect("links are empty")
                .iter()
                .filter(|link| link.is_relation("self"))
                .count(),
            1
        );
    }
}
