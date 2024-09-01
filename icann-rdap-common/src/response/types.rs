use buildstructor::Builder;
use serde::{Deserialize, Serialize};

use super::{entity::Entity, redacted::Redacted};

/// Represents an RDAP extension identifier.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Extension(pub String);

impl From<&str> for Extension {
    fn from(value: &str) -> Self {
        Extension(value.to_string())
    }
}

impl std::ops::Deref for Extension {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The RDAP conformance array.
pub type RdapConformance = Vec<Extension>;

/// An array of RDAP link structures.
pub type Links = Vec<Link>;

/// Represents and RDAP link structure.
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

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hreflang: Option<Vec<String>>,

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
        hreflang: Option<Vec<String>>,
        title: Option<String>,
        media: Option<String>,
        media_type: Option<String>,
    ) -> Self {
        Link {
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
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct NoticeOrRemark {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,
}

#[buildstructor::buildstructor]
impl NoticeOrRemark {
    #[builder]
    pub fn new(title: Option<String>, description: Vec<String>, links: Option<Links>) -> Self {
        NoticeOrRemark {
            title,
            description: Some(description),
            links,
        }
    }
}

/// An array of events.
pub type Events = Vec<Event>;

/// Represents an RDAP event.
#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
pub struct Event {
    #[serde(rename = "eventAction")]
    pub event_action: String,

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
#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
pub struct PublicId {
    #[serde(rename = "type")]
    pub id_type: String,

    pub identifier: String,
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
        Common::new_level0_with_options(extensions, notices)
    }

    #[builder(entry = "level0_with_options")]
    pub fn new_level0_with_options(
        mut extensions: Vec<Extension>,
        notices: Option<Vec<Notice>>,
    ) -> Self {
        let mut standard_extensions = vec![Extension("rdap_level_0".to_string())];
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
        if let Some(links) = self.links {
            let mut new_links = links
                .into_iter()
                .filter(|link| !link.is_relation("self"))
                .collect::<Vec<Link>>();
            new_links.push(link);
            self.links = Some(new_links);
        } else {
            self.links = Some(vec![link]);
        }
        self
    }

    pub fn get_self_link(&self) -> Option<&Link> {
        if let Some(links) = &self.links {
            links.iter().find(|link| link.is_relation("self"))
        } else {
            None
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use crate::response::types::{
        Extension, Notice, Notices, RdapConformance, Remark, Remarks, Status, StatusValue,
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
        assert_eq!(actual.description.expect("must have description").len(), 2);
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
