//! JSContact for Contact
use serde::{Deserialize, Serialize};

use crate::contact::{Contact, PostalAddress};

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
    pub org: Option<Org>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Org {
    pub name: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<Address>,

    #[serde(rename = "addresses-1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_one: Option<Address>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Address {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub name: Option<Name>,

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

impl Contact {
    pub fn to_jscontact(&self) -> JsContactCard {
        JsContactCard {
            card_type: "Card".to_string(),
            version: "2.0".to_string(),
            language: self.lang().map(|l| l.tag().to_string()),
            organizations: Some(Organizations {
                org: Some(Org {
                    name: self.organization_name().map(|s| s.to_owned()),
                }),
            }),
            name: Some(Name {
                full: self.full_name().map(|s| s.to_owned()),
                components: self.name_parts().map(|np| {
                    let mut components = vec![];
                    if let Some(prefix) = np.prefix() {
                        components.push(KindValue {
                            kind: "title".to_string(),
                            value: prefix.to_owned(),
                        })
                    };
                    if let Some(given_name) = np.given_name() {
                        components.push(KindValue {
                            kind: "given".to_string(),
                            value: given_name.to_owned(),
                        })
                    };
                    if let Some(middle_name) = np.middle_name() {
                        components.push(KindValue {
                            kind: "given2".to_string(),
                            value: middle_name.to_owned(),
                        })
                    };
                    if let Some(surname) = np.surname() {
                        components.push(KindValue {
                            kind: "surname".to_string(),
                            value: surname.to_owned(),
                        })
                    };
                    if let Some(surname) = np.surnames().get(1) {
                        components.push(KindValue {
                            kind: "surname2".to_string(),
                            value: surname.to_owned(),
                        })
                    };
                    if let Some(suffix) = np.suffix() {
                        components.push(KindValue {
                            kind: "credential".to_string(),
                            value: suffix.to_owned(),
                        })
                    };
                    if let Some(generation) = np.generation() {
                        components.push(KindValue {
                            kind: "generation".to_string(),
                            value: generation.to_owned(),
                        })
                    };
                    components
                }),
            }),
            addresses: self.postal_addresses.as_ref().map(|pas| {
                let addresses = Addresses {
                    addr: pas.first().map(postal_address_to_address),
                    address_one: pas.get(1).map(postal_address_to_address),
                };
                addresses
            }),
            phones: Some(Phones {
                voice: self.prefer_voice_phone().map(phone_to_phone),
                fax: self.fax_phone().map(phone_to_phone),
            }),
            emails: self.emails().first().map(|email| Emails {
                email: Email {
                    address: email.email().to_owned(),
                },
            }),
            links: links(self),
        }
    }
}

fn postal_address_to_address(addr: &PostalAddress) -> Address {
    let mut components = vec![];
    for part in addr.street_parts() {
        components.push(KindValue {
            kind: "name".to_string(),
            value: part.to_owned(),
        })
    }
    if let Some(locality) = addr.locality() {
        components.push(KindValue {
            kind: "locality".to_string(),
            value: locality.to_owned(),
        })
    }
    if let Some(region) = addr.region_name() {
        components.push(KindValue {
            kind: "region".to_string(),
            value: region.to_owned(),
        })
    }
    if let Some(country) = addr.country_name() {
        components.push(KindValue {
            kind: "country".to_string(),
            value: country.to_owned(),
        })
    }
    if let Some(postal) = addr.postal_code() {
        components.push(KindValue {
            kind: "postalcode".to_string(),
            value: postal.to_owned(),
        })
    }
    let name = Name {
        full: addr.full_address().map(|s| s.to_owned()),
        components: Some(components),
    };
    Address {
        country_code: addr.country_code().map(|s| s.to_owned()),
        name: Some(name),
    }
}

fn phone_to_phone(phone: &super::Phone) -> Phone {
    let voice = phone.features().contains(&"voice".to_string());
    let fax = phone.features().contains(&"fax".to_string());
    let features = if voice || fax {
        Some(Features {
            voice: voice.then_some(true),
            fax: fax.then_some(true),
        })
    } else {
        None
    };
    Phone {
        features,
        number: phone.phone().to_owned(),
    }
}

fn links(contact: &Contact) -> Option<Links> {
    if contact.urls().is_empty() || contact.contact_uris().is_empty() {
        return None;
    }
    //else
    Some(Links {
        url: contact.url().map(|u| Url { uri: u.to_owned() }),
        contact_uri: contact.contact_uri().map(|u| ContactUri {
            kind: "contact".to_string(),
            uri: u.to_owned(),
        }),
    })
}

#[cfg(test)]
mod test {
    use indoc::indoc;

    use crate::contact::jscontact::{
        Address, Addresses, ContactUri, Email, Emails, Features, JsContactCard, KindValue, Links,
        Name, Org, Organizations, Phone, Phones, Url,
    };

    const DRAFT_EXAMPLE1: &str = indoc! {r#"
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
                org: Some(Org {
                    name: Some("Acme Ltd".to_string()),
                }),
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
                addr: Some(Address {
                    name: Some(Name {
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
                    }),
                    country_code: Some("US".to_string()),
                }),
                address_one: Some(Address {
                    name: Some(Name {
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
                    }),
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
        let expected = DRAFT_EXAMPLE1;

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

    #[test]
    fn test_roundtrip_example1() {
        // GIVEN
        let expected = serde_json::from_str::<JsContactCard>(DRAFT_EXAMPLE1).expect("valid json");
        dbg!(&expected);

        // WHEN
        let de_ser = serde_json::from_str::<JsContactCard>(DRAFT_EXAMPLE1).expect("valid json");
        let ser = serde_json::to_string_pretty(&de_ser).expect("serialize json");
        let actual = serde_json::from_str::<JsContactCard>(&ser).expect("valid json");
        dbg!(&actual);

        // THEN
        assert_eq!(expected, actual);
    }
}
