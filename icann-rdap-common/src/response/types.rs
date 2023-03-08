use buildstructor::Builder;
use serde::{Deserialize, Serialize};

/// The RDAP conformance array.
pub type RdapConformance = Vec<String>;

/// An array of RDAP link structures.
pub type Links = Vec<Link>;

/// Represents and RDAP link structure.
#[derive(Serialize, Deserialize, Builder)]
pub struct Link {
    /// Represents the value part of an RDAP response.
    /// According to RFC 9083, this field is required
    /// but many servers do not return it.
    // TODO add this to a validation mode in the future.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,

    pub rel: String,

    pub href: String,

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

/// An array of notices.
pub type Notices = Vec<NoticeOrRemark>;

/// An array of remarks.
pub type Remarks = Vec<NoticeOrRemark>;

/// Represents an RDAP Notice or Remark (they are the same thing in RDAP).
#[derive(Serialize, Deserialize, Builder)]
pub struct NoticeOrRemark {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    pub description: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,
}

/// An array of events.
pub type Events = Vec<Event>;

/// Represents an RDAP event.
#[derive(Serialize, Deserialize, Builder)]
pub struct Event {
    #[serde(rename = "eventAction")]
    pub event_action: String,

    #[serde(rename = "eventActor")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_actor: Option<String>,

    #[serde(rename = "eventDate")]
    pub event_date: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,
}

/// An array of status values.
pub type Status = Vec<String>;

/// An RDAP port53 type.
pub type Port43 = String;

/// An array of RDAP public IDs.
pub type PublicIds = Vec<PublicId>;

/// An RDAP Public ID.
#[derive(Serialize, Deserialize, Builder)]
pub struct PublicId {
    #[serde(rename = "type")]
    pub id_type: String,

    pub identifier: String,
}

/// Holds those types that are common in all responses.
#[derive(Serialize, Deserialize, Builder)]
pub struct Common {
    #[serde(rename = "rdapConformance")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdap_conformance: Option<RdapConformance>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub notices: Option<Notices>,
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::{Event, Links, NoticeOrRemark, PublicId};

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
        assert_eq!(actual_1.href, "https://1.example.com/target_uri");
        assert_eq!(actual_2.href, "https://2.example.com/target_uri");
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
        assert_eq!(actual.description.len(), 2);
        actual.links.unwrap();
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
}
