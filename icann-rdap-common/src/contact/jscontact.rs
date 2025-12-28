//! JSContact for Contact
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::contact::{Contact, Localizable, NameParts, PostalAddress};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
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

    #[serde(skip_serializing_if = "Option::is_none")]
    pub localizations: Option<HashMap<String, Localization>>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Localization {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organizations: Option<Organizations>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Name>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Addresses>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Organizations {
    pub org: Option<Org>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Org {
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Name {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<KindValue>>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct KindValue {
    pub kind: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Addresses {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<Address>,

    #[serde(rename = "addresses-1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_one: Option<Address>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Address {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub name: Option<Name>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "countryCode")]
    pub country_code: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Features {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voice: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fax: Option<bool>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Phone {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Features>,

    pub number: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Phones {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voice: Option<Phone>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fax: Option<Phone>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Emails {
    pub email: Email,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Email {
    pub address: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Url {
    pub uri: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct ContactUri {
    pub kind: String,

    pub uri: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
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
            organizations: org_to_jscontact(self.organization_name()),
            name: name_to_jscontact(self.full_name(), self.name_parts()),
            addresses: addresses_to_jscontact(self.postal_addresses()),
            phones: phones_to_jscontact(self.prefer_voice_phone(), self.fax_phone()),
            emails: emails_to_jscontact(self.emails()),
            links: links_to_jscontact(self),
            localizations: if self.localizations_is_empty() {
                None
            } else {
                let mut hm = HashMap::new();
                for (tag, local) in self.localizations_iter() {
                    hm.insert(tag.to_owned(), local.to_localization());
                }
                Some(hm)
            },
        }
    }

    pub fn from_jscontact(jscontact: &JsContactCard) -> Contact {
        let mut builder = Contact::builder();
        if let Some(lang) = &jscontact.language {
            builder = builder.lang(super::Lang {
                preference: None,
                tag: lang.to_owned(),
            });
        };
        if let Some(phones) = &jscontact.phones {
            if let Some(voice) = &phones.voice {
                builder = builder.phone(
                    super::Phone::builder()
                        .phone(voice.number.clone())
                        .feature("voice".to_string())
                        .build(),
                )
            }
            if let Some(fax) = &phones.fax {
                builder = builder.phone(
                    super::Phone::builder()
                        .phone(fax.number.clone())
                        .feature("fax".to_string())
                        .build(),
                )
            }
        };
        if let Some(emails) = &jscontact.emails {
            builder = builder.email(
                super::Email::builder()
                    .email(emails.email.address.to_owned())
                    .build(),
            )
        };
        if let Some(links) = &jscontact.links {
            if let Some(url) = &links.url {
                builder = builder.url(url.uri.to_owned())
            }
            if let Some(contact_uri) = &links.contact_uri {
                builder = builder.url(contact_uri.uri.to_owned())
            }
        }
        let builder = builder
            .organization_names(jscontact_to_org_names(&jscontact.organizations))
            .and_name_parts(jscontact_to_nameparts(&jscontact.name))
            .postal_addresses(jscontact_to_postaladdresses(&jscontact.addresses))
            .and_full_name(jscontact_to_fullname(&jscontact.name));
        let mut contact = builder.build();
        if let Some(localizations) = &jscontact.localizations {
            for (tag, local) in localizations {
                contact =
                    contact.set_localization(tag.to_owned(), Localizable::from_jscontact(local));
            }
        }
        contact
    }
}

impl Localizable {
    pub fn to_localization(&self) -> Localization {
        Localization {
            organizations: org_to_jscontact(self.organization_name()),
            name: name_to_jscontact(self.full_name(), self.name_parts()),
            addresses: addresses_to_jscontact(self.postal_addresses()),
        }
    }

    pub fn from_jscontact(localization: &Localization) -> Self {
        Localizable::builder()
            .organization_names(jscontact_to_org_names(&localization.organizations))
            .and_name_parts(jscontact_to_nameparts(&localization.name))
            .postal_addresses(jscontact_to_postaladdresses(&localization.addresses))
            .and_full_name(jscontact_to_fullname(&localization.name))
            .build()
    }
}

fn jscontact_to_postaladdresses(addresses: &Option<Addresses>) -> Vec<PostalAddress> {
    let mut postal_addresses = vec![];
    if let Some(addresses) = addresses {
        if let Some(addr) = &addresses.addr {
            postal_addresses.push(address_to_postaladdress(addr));
        }
        if let Some(addr) = &addresses.address_one {
            postal_addresses.push(address_to_postaladdress(addr));
        }
    }
    postal_addresses
}

fn address_to_postaladdress(addr: &Address) -> PostalAddress {
    let mut street_parts = vec![];
    let mut locality = None;
    let mut region = None;
    let mut country = None;
    let mut postal_code = None;
    if let Some(Name {
        components: Some(components),
        ..
    }) = &addr.name
    {
        for component in components {
            if component.kind.eq_ignore_ascii_case("name") {
                street_parts.push(component.value.to_owned());
            }
            if component.kind.eq_ignore_ascii_case("locality") {
                locality = Some(component.value.to_owned());
            }
            if component.kind.eq_ignore_ascii_case("region") {
                region = Some(component.value.to_owned());
            }
            if component.kind.eq_ignore_ascii_case("country") {
                country = Some(component.value.to_owned());
            }
            if component.kind.eq_ignore_ascii_case("postalcode") {
                postal_code = Some(component.value.to_owned());
            }
        }
    }
    let builder = PostalAddress::builder()
        .and_full_address(addr.name.as_ref().and_then(|n| n.full.to_owned()))
        .street_parts(street_parts)
        .and_locality(locality)
        .and_region_name(region)
        .and_country_name(country)
        .and_postal_code(postal_code)
        .and_country_code(addr.country_code.to_owned());
    builder.build()
}

fn jscontact_to_nameparts(name: &Option<Name>) -> Option<NameParts> {
    if let Some(Name {
        components: Some(components),
        ..
    }) = name
    {
        let mut np = NameParts::builder();
        for component in components {
            if component.kind.eq_ignore_ascii_case("title") {
                np = np.prefix(component.value.to_owned())
            }
            if component.kind.eq_ignore_ascii_case("given")
                || component.kind.eq_ignore_ascii_case("given2")
            {
                np = np.given_name(component.value.to_owned())
            }
            if component.kind.eq_ignore_ascii_case("surname")
                || component.kind.eq_ignore_ascii_case("surname2")
            {
                np = np.surname(component.value.to_owned())
            }
            if component.kind.eq_ignore_ascii_case("credentials") {
                np = np.suffix(component.value.to_owned())
            }
            if component.kind.eq_ignore_ascii_case("generation") {
                np = np.generation(component.value.to_owned())
            }
        }
        Some(np.build())
    } else {
        None
    }
}

fn jscontact_to_fullname(name: &Option<Name>) -> Option<String> {
    name.as_ref().and_then(|n| n.full.to_owned())
}

fn jscontact_to_org_names(organizations: &Option<Organizations>) -> Vec<String> {
    organizations
        .as_ref()
        .and_then(|o| o.org.as_ref())
        .and_then(|o| o.name.as_ref())
        .map(|n| vec![n.to_owned()])
        .unwrap_or_default()
}

fn org_to_jscontact(organization_name: Option<&str>) -> Option<Organizations> {
    Some(Organizations {
        org: Some(Org {
            name: organization_name.map(|s| s.to_owned()),
        }),
    })
}

fn name_to_jscontact(full_name: Option<&str>, name_parts: Option<&NameParts>) -> Option<Name> {
    Some(Name {
        full: full_name.map(|s| s.to_owned()),
        components: name_parts.map(|np| {
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
    })
}

fn emails_to_jscontact(emails: &[super::Email]) -> Option<Emails> {
    emails.first().map(|email| Emails {
        email: Email {
            address: email.email().to_owned(),
        },
    })
}

fn addresses_to_jscontact(addresses: &[PostalAddress]) -> Option<Addresses> {
    if addresses.is_empty() {
        None
    } else {
        let addresses = Addresses {
            addr: addresses.first().map(postal_address_to_jscontact),
            address_one: addresses.get(1).map(postal_address_to_jscontact),
        };
        Some(addresses)
    }
}

fn postal_address_to_jscontact(addr: &PostalAddress) -> Address {
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

fn phones_to_jscontact(voice: Option<&super::Phone>, fax: Option<&super::Phone>) -> Option<Phones> {
    Some(Phones {
        voice: voice.map(phone_to_jscontact),
        fax: fax.map(phone_to_jscontact),
    })
}

fn phone_to_jscontact(phone: &super::Phone) -> Phone {
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

fn links_to_jscontact(contact: &Contact) -> Option<Links> {
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

    const DRAFT_EXAMPLE2: &str = indoc! {r#"
            {
              "@type": "Card",
              "version": "2.0",
              "language": "en",
              "name": {
                "full": "Vasya Pupkin"
              },
              "organizations": {
                "org": {
                  "name": "My Company"
                }
              },
              "addresses": {
                "addr": {
                  "components": [
                    { "kind": "name", "value": "1 Street" },
                    { "kind": "postOfficeBox", "value": "01001" },
                    { "kind": "locality", "value": "Kyiv" }
                  ],
                  "countryCode": "UA"
                }
              },
              "localizations": {
                "ua": {
                  "addresses": {
                    "addr": {
                      "components": [
                       { "kind": "name", "value": "1, Улица" },
                       { "kind": "postOfficeBox", "value": "01001" },
                       { "kind": "locality", "value": "Киев" }
                      ],
                      "countryCode": "UA"
                    }
                  },
                  "name": {
                    "full": "Вася Пупкин"
                  },
                  "organizations": {
                    "org": {
                      "name": "Моя Компания"
                    }
                  }
                }
              }
            }
        "#};

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
            localizations: None,
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

    #[test]
    fn test_roundtrip_example2() {
        // GIVEN
        let expected = serde_json::from_str::<JsContactCard>(DRAFT_EXAMPLE2).expect("valid json");
        dbg!(&expected);

        // WHEN
        let de_ser = serde_json::from_str::<JsContactCard>(DRAFT_EXAMPLE2).expect("valid json");
        let ser = serde_json::to_string_pretty(&de_ser).expect("serialize json");
        let actual = serde_json::from_str::<JsContactCard>(&ser).expect("valid json");
        dbg!(&actual);

        // THEN
        assert_eq!(expected, actual);
    }
}
