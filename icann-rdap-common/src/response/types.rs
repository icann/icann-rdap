use buildstructor::Builder;
use serde::{Deserialize, Serialize};
use strum_macros::{AsRefStr, Display, EnumString};

use super::{entity::Entity, redacted::Redacted};

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
/// use icann_rdap_common::response::types::ExtensionId;
///
/// let cidr0 = ExtensionId::from_str("cidr0").unwrap();
/// assert_eq!(cidr0, ExtensionId::Cidr0);
/// println!("{}", cidr0.to_string());
/// ```
///
/// To get the variants as a string:
///
/// ```rust
/// use icann_rdap_common::response::types::ExtensionId;
///
/// let s = ExtensionId::Cidr0.to_string();
/// ```
///
/// To get the variants as a &str:
///
/// ```rust
/// use icann_rdap_common::response::types::ExtensionId;
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
/// use icann_rdap_common::response::types::Link;
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
    pub fn is_relation(&self, rel: &str) -> bool {
        let Some(link_rel) = &self.rel else {
            return false;
        };
        link_rel == rel
    }

    #[builder]
    pub fn new(
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
/// to be optional. It is recommended to use builder to construct an RFC valie
/// structure.
///
/// ```rust
/// use icann_rdap_common::response::types::NoticeOrRemark;
/// use icann_rdap_common::response::types::Link;
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
///   .links(vec![link])
///   .build();
/// ```
///
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct NoticeOrRemark {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<StringOrStringArray>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,
}

#[buildstructor::buildstructor]
impl NoticeOrRemark {
    #[builder]
    pub fn new(title: Option<String>, description: Vec<String>, links: Option<Links>) -> Self {
        Self {
            title,
            description: Some(StringOrStringArray::Many(description)),
            links,
        }
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
/// use icann_rdap_common::response::types::Event;
/// use icann_rdap_common::response::types::Link;
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
    #[builder]
    pub fn new(
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
}

/// Represents an item in an RDAP status array.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StatusValue(pub String);

impl std::ops::Deref for StatusValue {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// An array of status values.
pub type Status = Vec<StatusValue>;

pub fn to_option_status(values: Vec<String>) -> Option<Status> {
    if !values.is_empty() {
        Some(values.into_iter().map(StatusValue).collect::<Status>())
    } else {
        None
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
/// use icann_rdap_common::response::types::PublicId;
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
    #[builder]
    pub fn new(id_type: String, identifier: String) -> Self {
        Self {
            id_type: Some(id_type),
            identifier: Some(identifier),
        }
    }
}

/// Holds those types that are common in all responses.
#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
pub struct Common {
    #[serde(rename = "rdapConformance")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdap_conformance: Option<RdapConformance>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub notices: Option<Notices>,
}

#[buildstructor::buildstructor]
impl Common {
    #[builder(entry = "level0")]
    pub fn new_level0(extensions: Vec<Extension>, notices: Vec<Notice>) -> Self {
        let notices = (!notices.is_empty()).then_some(notices);
        Self::new_level0_with_options(extensions, notices)
    }

    #[builder(entry = "level0_with_options")]
    pub fn new_level0_with_options(
        mut extensions: Vec<Extension>,
        notices: Option<Vec<Notice>>,
    ) -> Self {
        let mut standard_extensions = vec![ExtensionId::RdapLevel0.to_extension()];
        extensions.append(&mut standard_extensions);
        Self {
            rdap_conformance: Some(extensions),
            notices,
        }
    }
}

/// Holds those types that are common in all object classes.
#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
pub struct ObjectCommon {
    #[serde(rename = "objectClassName")]
    pub object_class_name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,

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

    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted: Option<Vec<Redacted>>,
}

#[buildstructor::buildstructor]
impl ObjectCommon {
    #[builder(entry = "domain")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_domain(
        handle: Option<String>,
        remarks: Option<Remarks>,
        links: Option<Links>,
        events: Option<Events>,
        status: Option<Status>,
        port_43: Option<Port43>,
        entities: Option<Vec<Entity>>,
        redacted: Option<Vec<Redacted>>,
    ) -> Self {
        Self {
            object_class_name: "domain".to_string(),
            handle,
            remarks,
            links,
            events,
            status,
            port_43,
            entities,
            redacted,
        }
    }

    #[builder(entry = "ip_network")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_ip_network(
        handle: Option<String>,
        remarks: Option<Remarks>,
        links: Option<Links>,
        events: Option<Events>,
        status: Option<Status>,
        port_43: Option<Port43>,
        entities: Option<Vec<Entity>>,
        redacted: Option<Vec<Redacted>>,
    ) -> Self {
        Self {
            object_class_name: "ip network".to_string(),
            handle,
            remarks,
            links,
            events,
            status,
            port_43,
            entities,
            redacted,
        }
    }

    #[builder(entry = "autnum")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_autnum(
        handle: Option<String>,
        remarks: Option<Remarks>,
        links: Option<Links>,
        events: Option<Events>,
        status: Option<Status>,
        port_43: Option<Port43>,
        entities: Option<Vec<Entity>>,
        redacted: Option<Vec<Redacted>>,
    ) -> Self {
        Self {
            object_class_name: "autnum".to_string(),
            handle,
            remarks,
            links,
            events,
            status,
            port_43,
            entities,
            redacted,
        }
    }

    #[builder(entry = "nameserver")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_nameserver(
        handle: Option<String>,
        remarks: Option<Remarks>,
        links: Option<Links>,
        events: Option<Events>,
        status: Option<Status>,
        port_43: Option<Port43>,
        entities: Option<Vec<Entity>>,
        redacted: Option<Vec<Redacted>>,
    ) -> Self {
        Self {
            object_class_name: "nameserver".to_string(),
            handle,
            remarks,
            links,
            events,
            status,
            port_43,
            entities,
            redacted,
        }
    }

    #[builder(entry = "entity")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_entity(
        handle: Option<String>,
        remarks: Option<Remarks>,
        links: Option<Links>,
        events: Option<Events>,
        status: Option<Status>,
        port_43: Option<Port43>,
        entities: Option<Vec<Entity>>,
        redacted: Option<Vec<Redacted>>,
    ) -> Self {
        Self {
            object_class_name: "entity".to_string(),
            handle,
            remarks,
            links,
            events,
            status,
            port_43,
            entities,
            redacted,
        }
    }

    /// This will remove all other self links and place the provided link
    /// into the Links. This method will also set the "rel" attribute
    /// to "self" on the provided link.
    pub fn set_self_link(mut self, mut link: Link) -> Self {
        link.rel = Some("self".to_string());
        self.links = Some(if let Some(links) = self.links {
            let mut new_links = links
                .into_iter()
                .filter(|link| !link.is_relation("self"))
                .collect::<Vec<Link>>();
            new_links.push(link);
            new_links
        } else {
            vec![link]
        });
        self
    }

    pub fn get_self_link(&self) -> Option<&Link> {
        self.links
            .as_ref()
            .and_then(|links| links.iter().find(|link| link.is_relation("self")))
    }
}

/// Provides a choice between a string or an array of strings.
///
/// This is provided to be lenient with misbehaving RDAP servers that
/// serve a string when they are suppose to be serving an array of
/// strings. Usage of a string where an array of strings is an error.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum StringOrStringArray {
    Many(Vec<String>),
    One(String),
}

impl StringOrStringArray {
    pub fn many(&self) -> Vec<String> {
        match self {
            Self::Many(many) => many.clone(),
            Self::One(one) => vec![one.to_owned()],
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use crate::response::types::{
        Extension, Notice, Notices, RdapConformance, Remark, Remarks, Status, StatusValue,
        StringOrStringArray,
    };

    use super::{Event, Link, Links, NoticeOrRemark, ObjectCommon, PublicId};

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
        let StringOrStringArray::Many(description) =
            actual.description.expect("must have description")
        else {
            panic!();
        };
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
    fn GIVEN_status_array_WHEN_serialize_THEN_array_of_strings() {
        // GIVEN
        let status: Status = vec![
            StatusValue("foo".to_string()),
            StatusValue("bar".to_string()),
        ];

        // WHEN
        let actual = serde_json::to_string(&status).unwrap();

        // THEN
        let expected = r#"["foo","bar"]"#;
        assert_eq!(actual, expected);
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
