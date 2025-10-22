//! Common data structures, etc...
use serde::{Deserialize, Serialize};

use super::lenient::{Stringish, VectorStringish};

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
/// unknown extension ids. Known extension identifiers are enumerated by [crate::prelude::ExtensionId].
pub type RdapConformance = Vec<Extension>;

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
///
/// Use the getter functions to get the data.
/// ```rust
/// # use icann_rdap_common::prelude::*;
/// # let link = Link::builder()
/// #  .value("https://example.com/domains?domain=foo.*")
/// #  .rel("related")
/// #  .href("https://example.com/domain/foo.example")
/// #  .hreflang("ch")
/// #  .title("Related Object")
/// #  .media("print")
/// #  .media_type("application/rdap+json")
/// #  .build();
/// let href = link.href();
/// ```
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
    ///
    /// To create an RFC valid structure, use the builder
    /// which will not allow omision of required fields.
    ///
    /// ```rust
    /// use icann_rdap_common::prelude::*;
    ///
    /// let link = Link::builder()
    ///   .value("https://example.com/domains?domain=foo.*") //required
    ///   .rel("related")                                    //required
    ///   .href("https://example.com/domain/foo.example")    //required
    ///   .hreflang("ch")
    ///   .title("Related Object")
    ///   .media("print")
    ///   .media_type("application/rdap+json")
    ///   .build();
    /// ```
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
        Self {
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
///
/// It is recommended to use builder to construct an RFC valid
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
/// let notice = Notice::builder()
///   .title("Terms of Use")
///   .description_entry("Please read our terms of use.")
///   .description_entry("TOS can be found in the link.")
///   .link(link)
///   .build();
/// ```
///
/// Use the getter functions to get the data.
/// ```rust
/// # use icann_rdap_common::prelude::*;
/// # let notice = Notice::builder()
/// #  .title("Terms of Use")
/// #  .description_entry("Please read our terms of use.")
/// #  .description_entry("TOS can be found in the link.")
/// #  .build();
/// let title = notice.title();
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Notice(pub NoticeOrRemark);

#[buildstructor::buildstructor]
impl Notice {
    /// Builds an RDAP notice.
    #[builder(visibility = "pub")]
    fn new(
        title: Option<String>,
        description: Vec<String>,
        links: Vec<Link>,
        nr_type: Option<String>,
    ) -> Self {
        let nr = NoticeOrRemark::builder()
            .description(description)
            .and_title(title)
            .links(links)
            .and_nr_type(nr_type)
            .build();
        Self(nr)
    }
}

impl std::ops::Deref for Notice {
    type Target = NoticeOrRemark;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// An array of remarks.
pub type Remarks = Vec<Remark>;

/// Represents an RDAP Remark.
///
/// It is recommended to use builder to construct an RFC valid
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
/// let remark = Remark::builder()
///   .title("Terms of Use")
///   .description_entry("Please read our terms of use.")
///   .description_entry("TOS can be found in the link.")
///   .link(link)
///   .build();
/// ```
///
/// Use the getter functions to get the data.
/// ```rust
/// # use icann_rdap_common::prelude::*;
/// # let remark = Remark::builder()
/// #  .title("Terms of Use")
/// #  .description_entry("Please read our terms of use.")
/// #  .description_entry("TOS can be found in the link.")
/// #  .build();
/// let title = remark.title();
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Remark(pub NoticeOrRemark);

#[buildstructor::buildstructor]
impl Remark {
    /// Builds an RDAP notice.
    #[builder(visibility = "pub")]
    fn new(
        title: Option<String>,
        description: Vec<String>,
        links: Vec<Link>,
        nr_type: Option<String>,
    ) -> Self {
        let nr = NoticeOrRemark::builder()
            .description(description)
            .and_title(title)
            .links(links)
            .and_nr_type(nr_type)
            .build();
        Self(nr)
    }
}

impl std::ops::Deref for Remark {
    type Target = NoticeOrRemark;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Represents an RDAP Notice or Remark (they are the same thing in RDAP).
///
/// It is probably easier to use [Notice] or [Remark] directly.
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
/// Use the getter functions to get the data.
/// ```rust
/// # use icann_rdap_common::prelude::*;
/// # let nr = NoticeOrRemark::builder()
/// #  .title("Terms of Use")
/// #  .description_entry("Please read our terms of use.")
/// #  .description_entry("TOS can be found in the link.")
/// #  .build();
/// let title = nr.title();
/// ```
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
        Self {
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
        Self {
            title,
            description: d,
            links,
            nr_type,
        }
    }

    /// Returns the title of the notice/remark.
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// Returns the description of the notice/remark.
    pub fn description(&self) -> &[String] {
        self.description
            .as_ref()
            .map(|v| v.vec().as_ref())
            .unwrap_or_default()
    }

    /// Returns the description where lines that are
    /// not sentences are consolidated into paragraphs.
    pub fn description_as_pgs(&self) -> Vec<String> {
        let mut pgs = vec![];
        let mut acc_line = String::new();
        for line in self.description() {
            acc_line.push_str(line.trim());
            if acc_line.ends_with('.') || acc_line.to_ascii_uppercase().eq(&acc_line) {
                pgs.push(acc_line);
                acc_line = String::new();
            } else {
                acc_line.push(' ');
            }
        }
        if !acc_line.is_empty() {
            pgs.push(acc_line);
        }
        pgs
    }

    /// Returns the links associated with the notice/remark.
    pub fn links(&self) -> &[Link] {
        self.links.as_deref().unwrap_or_default()
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
/// let event = Event::builder()
///   .event_action("expiration")
///   .event_date("1990-12-31T23:59:59Z")
///   .links(vec![link])
///   .build();
/// ```
///
/// NOTE: `event_date` is to be an RFC 3339 valid date and time.
/// The builder does not enforce RFC 3339 validity.
///
/// Use the getter functions to get the data.
/// ```rust
/// # use icann_rdap_common::prelude::*;
/// # let event = Event::builder()
/// #   .event_action("expiration")
/// #  .event_date("1990-12-31T23:59:59Z")
/// #  .build();
/// let event_date = event.event_date();
/// ```
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
    ///
    /// Use of the builder to contruct an RFC valid structure is recommended.
    ///
    /// ```rust
    /// use icann_rdap_common::prelude::*;
    ///
    /// let event = Event::builder()
    ///   .event_action("expiration")         //required
    ///   .event_date("1990-12-31T23:59:59Z") //required
    ///   .event_actor("FOO")
    ///   .build();
    /// ```
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
        Self {
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
    pub fn links(&self) -> &[Link] {
        self.links.as_deref().unwrap_or_default()
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
///
/// Use the getter functions to get the data.
/// ```rust
/// # use icann_rdap_common::prelude::*;
/// # let public_id = PublicId::builder()
/// #   .id_type("IANA Registrar ID")
/// #   .identifier("1990")
/// #   .build();
/// let id_type = public_id.id_type();
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicId {
    /// This are manditory per RFC 9083.
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_type: Option<Stringish>,

    /// This are manditory per RFC 9083.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<Stringish>,
}

#[buildstructor::buildstructor]
impl PublicId {
    /// Builds a public ID.
    #[builder(visibility = "pub")]
    fn new(id_type: String, identifier: String) -> Self {
        Self {
            id_type: Some(id_type.into()),
            identifier: Some(identifier.into()),
        }
    }

    /// Builds an illegal public ID.
    #[builder(entry = "illegal", visibility = "pub(crate)")]
    #[allow(dead_code)]
    fn new_illegal(id_type: Option<String>, identifier: Option<String>) -> Self {
        Self {
            id_type: id_type.map(|s| s.into()),
            identifier: identifier.map(|s| s.into()),
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
mod tests {
    use crate::{
        prelude::ObjectCommon,
        response::types::{Extension, Notice, Notices, RdapConformance, Remark, Remarks},
    };

    use super::{Event, Link, Links, NoticeOrRemark, PublicId};

    #[test]
    fn test_rdap_conformance_serialize() {
        // GIVEN rdap conformaance
        let rdap_conformance: RdapConformance =
            vec![Extension("foo".to_string()), Extension("bar".to_string())];

        // WHEN serialized
        let actual = serde_json::to_string(&rdap_conformance).unwrap();

        // THEN expect array of strings
        let expected = r#"["foo","bar"]"#;
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_an_array_of_links_deserialize() {
        // GIVEN array of links
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

        // WHEN deserialize
        let links = serde_json::from_str::<Links>(expected);

        // THEN data is correct
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
    fn test_an_array_of_links_with_one_lang() {
        // GIVEN array of links with one lang
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

        // WHEN deserialize
        let links = serde_json::from_str::<Links>(expected);

        // THEN data is accurate
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
    fn test_a_notice_or_remark_deserialize() {
        // GIVEN notice or remark
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

        // WHEN deserialize
        let actual = serde_json::from_str::<NoticeOrRemark>(expected);

        // THEN data is accurate
        let actual = actual.unwrap();
        actual.title.as_ref().unwrap();
        let description: Vec<String> = actual.description.expect("must have description").into();
        assert_eq!(description.len(), 2);
        actual.links.unwrap();
    }

    #[test]
    fn test_notices_serialize() {
        // GIVEN notices
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

        // WHEN deserialize
        let actual = serde_json::to_string(&notices).unwrap();

        // THEN then array of notices
        let expected = r#"[{"description":["foo"]},{"description":["bar"]}]"#;
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_remarks_serialize() {
        // GIVEN remarks
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

        // WHEN serialize
        let actual = serde_json::to_string(&remarks).unwrap();

        // THEN array of remarks
        let expected = r#"[{"description":["foo"]},{"description":["bar"]}]"#;
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_an_event_deserialize() {
        // GIVEN an event
        let expected = r#"
        {
            "eventAction" : "last changed",
            "eventActor" : "OTHERID-LUNARNIC",
            "eventDate" : "1991-12-31T23:59:59Z"
        }
        "#;

        // WHEN deserialize
        let actual = serde_json::from_str::<Event>(expected);

        // THEN success
        let actual = actual.unwrap();
        actual.event_actor.as_ref().unwrap();
    }

    #[test]
    fn test_a_public_id_deserialize() {
        // GIVEN public id
        let expected = r#"
        {
            "type":"IANA Registrar ID",
            "identifier":"1"
        }
        "#;

        // WHEN deserialize
        let actual = serde_json::from_str::<PublicId>(expected);

        // THEN
        let _actual = actual.unwrap();
    }

    #[test]
    fn test_set_self_link() {
        // GIVEN no self links
        let mut oc = ObjectCommon::domain()
            .links(vec![Link::builder()
                .href("http://bar.example")
                .value("http://bar.example")
                .rel("unknown")
                .build()])
            .build();

        // WHEN set self link
        oc = oc.set_self_link(
            Link::builder()
                .href("http://foo.example")
                .value("http://foo.example")
                .rel("unknown")
                .build(),
        );

        // THEN it is the only one
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
    fn test_set_self_link_on_no_links() {
        // GIVEN no links
        let mut oc = ObjectCommon::domain().build();

        // WHEN set self link
        oc = oc.set_self_link(
            Link::builder()
                .href("http://foo.example")
                .value("http://foo.example")
                .rel("unknown")
                .build(),
        );

        // THEN then it is the only one
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
    fn test_set_self_link_when_one_exists() {
        // GIVEN one self link
        let mut oc = ObjectCommon::domain()
            .links(vec![Link::builder()
                .href("http://bar.example")
                .value("http://bar.example")
                .rel("self")
                .build()])
            .build();

        // WHEN set self link
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

    #[test]
    fn test_description_as_pgs() {
        // GIVEN notice
        let notice = Notice::builder()
            .description_entry("This is a test")
            .description_entry("that should be consolidated.")
            .description_entry("SEPARATE LINE")
            .description_entry("Another line.")
            .build();

        // WHEN converted to pgs
        let actual = notice.description_as_pgs();

        // THEN
        assert_eq!(
            actual.first().unwrap(),
            "This is a test that should be consolidated."
        );
        assert_eq!(actual.get(1).unwrap(), "SEPARATE LINE");
        assert_eq!(actual.get(2).unwrap(), "Another line.");
    }
}
