//! JSContact for Contact
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct JsContactCard {
    #[serde(rename = "@type")]
    pub card_type: String,

    pub version: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub organizations: Option<Organizations>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Name>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Addresses>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub phones: Option<Phones>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub emails: Option<Emails>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Organizations {
    pub org: Org,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Org {
    pub name: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Name {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<KindValue>>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct KindValue {
    pub kind: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Addresses {
    pub addr: Option<PostalAddress>,
    pub address_one: Option<PostalAddress>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct PostalAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<Name>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "countryCode")]
    pub country_code: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Features {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voice: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fax: Option<bool>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Phone {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Features>,

    pub number: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Phones {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voice: Option<Phone>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fax: Option<Phone>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Emails {
    pub email: Email,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Email {
    pub address: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Url {
    pub uri: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct ContactUri {
    pub kind: String,

    pub uri: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Links {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<Url>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "contact-uri")]
    pub contact_uri: Option<ContactUri>,
}

#[cfg(test)]
mod test {
    use indoc::indoc;

    use crate::contact::jscontact::{
        Addresses, ContactUri, Email, Emails, Features, JsContactCard, KindValue, Links, Name, Org,
        Organizations, Phone, Phones, PostalAddress, Url,
    };

    const DRAFT_EXAMPLE: &str = indoc! {r#"
      {
          "@type": "Card",
          "version": "2.0",
          "name": {
            "full": "Joe User",
            "components": [
              { "kind": "surname", "value": "User" },
              { "kind": "given", "value": "Joe" }
            ]
          },
          "organizations": {
            "org": {
              "name": "Org Example"
            }
          },
           "addresses": {
             "addr": {
               "components": [
                 { "kind": "name", "value": "Main Street 1" },
                 { "kind": "locality", "value": "Ludwigshafen am Rhein" },
                 { "kind": "region", "value": "Rhineland-Palatinate" },
                 { "kind": "postcode", "value": "67067" },
                 { "kind": "country", "value": "Germany" }
               ],
               "countryCode": "DE"
             },
             "addresses-1": {
               "full": "Somewhere Street 1 Mutterstadt 67112 Germany"
             }
           },
          "phones": {
            "voice": {
              "features": { "voice": true },
              "number": "tel:+49-1522-3433333"
            },
            "fax": {
              "features": { "fax": true },
              "number": "tel:+49-30-901820"
            }
          },
          "emails": {
            "email": {
              "address": "joe.user@example.com"
            }
          },
          "links": {
            "url": {
              "uri": "https://www.example.com"
            },
            "contact-uri": {
              "kind": "contact",
              "uri": "mailto:contact@example.com"
            }
          }
      }"#};

    fn test_jscontact_card() -> JsContactCard {
        JsContactCard {
            card_type: "Card".to_string(),
            version: "2.0".to_string(),
            language: Some("en".to_string()),
            organizations: Some(Organizations {
                org: Org {
                    name: "Acme Ltd".to_string(),
                },
            }),
            name: Some(Name {
                full: Some("Bob Smurd".to_string()),
                components: Some(vec![
                    KindValue {
                        kind: "surname".to_string(),
                        value: "Smurd".to_string(),
                    },
                    KindValue {
                        kind: "given".to_string(),
                        value: "Bob".to_string(),
                    },
                ]),
            }),
            addresses: Some(Addresses {
                addr: Some(PostalAddress {
                    components: Some(vec![Name {
                        full: Some("123 Glendale Blvd".to_string()),
                        components: Some(vec![
                            KindValue {
                                kind: "locality".to_string(),
                                value: "Glenburnie".to_string(),
                            },
                            KindValue {
                                kind: "region".to_string(),
                                value: "Maryland".to_string(),
                            },
                        ]),
                    }]),
                    country_code: Some("US".to_string()),
                }),
                address_one: Some(PostalAddress {
                    components: Some(vec![Name {
                        full: Some("123 Glendale Blvd".to_string()),
                        components: Some(vec![
                            KindValue {
                                kind: "locality".to_string(),
                                value: "Glenburnie".to_string(),
                            },
                            KindValue {
                                kind: "region".to_string(),
                                value: "Maryland".to_string(),
                            },
                        ]),
                    }]),
                    country_code: Some("US".to_string()),
                }),
            }),
            phones: Some(Phones {
                voice: Some(Phone {
                    features: Some(Features {
                        voice: Some(true),
                        fax: None,
                    }),
                    number: "555-1212".to_string(),
                }),
                fax: Some(Phone {
                    features: Some(Features {
                        voice: None,
                        fax: Some(true),
                    }),
                    number: "555-2121".to_string(),
                }),
            }),
            emails: Some(Emails {
                email: Email {
                    address: "mailto:foo@example.com".to_string(),
                },
            }),
            links: Some(Links {
                url: Some(Url {
                    uri: "https://example.com".to_string(),
                }),
                contact_uri: Some(ContactUri {
                    kind: "contact-uri".to_owned(),
                    uri: "https://example.org".to_owned(),
                }),
            }),
        }
    }

    #[test]
    fn test_deserialize_example_from_draft() {
        // GIVEN
        let expected = DRAFT_EXAMPLE;

        // WHEN
        let actual = serde_json::from_str::<JsContactCard>(expected);

        // THEN
        actual.unwrap();
    }

    #[test]
    fn test_serialize() {
        // GIVEN
        let expected = test_jscontact_card();

        // WHEN
        let actual = serde_json::to_string_pretty(&expected);

        // THEN
        eprintln!("\n{}\n", actual.unwrap());
    }
}
