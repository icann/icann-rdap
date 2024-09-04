//! Convert jCard/vCard to Contact.
use serde_json::Value;

use super::{Contact, Email, Lang, NameParts, Phone, PostalAddress};

impl Contact {
    /// Creates a Contact from an array of [`Value`]s.
    ///
    /// ```rust
    /// use icann_rdap_common::contact::Contact;
    /// use serde::Deserialize;
    /// use serde_json::Value;
    ///
    /// let json = r#"
    /// [
    ///   "vcard",
    ///   [
    ///     ["version", {}, "text", "4.0"],
    ///     ["fn", {}, "text", "Joe User"],
    ///     ["kind", {}, "text", "individual"],
    ///     ["org", {
    ///       "type":"work"
    ///     }, "text", "Example"],
    ///     ["title", {}, "text", "Research Scientist"],
    ///     ["role", {}, "text", "Project Lead"],
    ///     ["adr",
    ///       { "type":"work" },
    ///       "text",
    ///       [
    ///         "",
    ///         "Suite 1234",
    ///         "4321 Rue Somewhere",
    ///         "Quebec",
    ///         "QC",
    ///         "G1V 2M2",
    ///         "Canada"
    ///       ]
    ///     ],
    ///     ["tel",
    ///       { "type":["work", "voice"], "pref":"1" },
    ///       "uri", "tel:+1-555-555-1234;ext=102"
    ///     ],
    ///     ["email",
    ///       { "type":"work" },
    ///       "text", "joe.user@example.com"
    ///     ]
    ///   ]
    /// ]"#;
    ///
    /// let data: Vec<Value> = serde_json::from_str(json).unwrap();
    /// let contact = Contact::from_vcard(&data);
    /// ```
    pub fn from_vcard(vcard_array: &[Value]) -> Option<Contact> {
        // value should be "vcard" followed by array
        let value = vcard_array.first()?;
        let vcard_literal = value.as_str()?;
        if !vcard_literal.eq_ignore_ascii_case("vcard") {
            return None;
        };
        let vcard = vcard_array.get(1)?;
        let vcard = vcard.as_array()?;

        let contact = Contact::builder()
            .and_full_name(vcard.find_property("fn").get_text())
            .and_kind(vcard.find_property("kind").get_text())
            .and_titles(vcard.find_properties("title").get_texts())
            .and_roles(vcard.find_properties("role").get_texts())
            .and_nick_names(vcard.find_properties("nickname").get_texts())
            .and_organization_names(vcard.find_properties("org").get_texts())
            .and_langs(vcard.find_properties("lang").get_langs())
            .and_emails(vcard.find_properties("email").get_emails())
            .and_phones(vcard.find_properties("tel").get_phones())
            .and_postal_addresses(vcard.find_properties("adr").get_postal_addresses())
            .and_name_parts(vcard.find_property("n").get_name_parts())
            .build();

        contact.is_non_empty().then_some(contact)
    }
}

trait FindProperty<'a> {
    fn find_property(self, name: &'a str) -> Option<&'a Vec<Value>>;
}

impl<'a> FindProperty<'a> for &'a [Value] {
    fn find_property(self, name: &'a str) -> Option<&'a Vec<Value>> {
        self.iter()
            .filter_map(|prop_array| prop_array.as_array())
            .find(|prop_array| {
                if let Some(prop_name) = prop_array.first() {
                    if let Some(prop_name) = prop_name.as_str() {
                        prop_name.eq_ignore_ascii_case(name)
                    } else {
                        false
                    }
                } else {
                    false
                }
            })
    }
}

trait FindProperties<'a> {
    fn find_properties(self, name: &'a str) -> Vec<&'a Vec<Value>>;
}

impl<'a> FindProperties<'a> for &'a [Value] {
    fn find_properties(self, name: &'a str) -> Vec<&'a Vec<Value>> {
        self.iter()
            .filter_map(|prop_array| prop_array.as_array())
            .filter(|prop_array| {
                if let Some(prop_name) = prop_array.first() {
                    if let Some(prop_name) = prop_name.as_str() {
                        prop_name.eq_ignore_ascii_case(name)
                    } else {
                        false
                    }
                } else {
                    false
                }
            })
            .collect()
    }
}

trait GetText<'a> {
    fn get_text(self) -> Option<String>;
}

impl<'a> GetText<'a> for Option<&'a Vec<Value>> {
    fn get_text(self) -> Option<String> {
        let values = self?;
        let fourth = values.get(3)?;
        fourth.as_str().map(|s| s.to_owned())
    }
}

impl<'a> GetText<'a> for &'a Vec<Value> {
    fn get_text(self) -> Option<String> {
        let fourth = self.get(3)?;
        fourth.as_str().map(|s| s.to_owned())
    }
}

trait GetTexts<'a> {
    fn get_texts(self) -> Option<Vec<String>>;
}

impl<'a> GetTexts<'a> for &'a [&'a Vec<Value>] {
    fn get_texts(self) -> Option<Vec<String>> {
        let texts = self
            .iter()
            .filter_map(|prop| (*prop).get_text())
            .collect::<Vec<String>>();
        (!texts.is_empty()).then_some(texts)
    }
}

trait GetPreference<'a> {
    fn get_preference(self) -> Option<u64>;
}

impl<'a> GetPreference<'a> for &'a Vec<Value> {
    fn get_preference(self) -> Option<u64> {
        let second = self.get(1)?;
        let second = second.as_object()?;
        let preference = second.get("pref")?;
        preference.as_str().and_then(|s| s.parse().ok())
    }
}

trait GetLabel<'a> {
    fn get_label(self) -> Option<String>;
}

impl<'a> GetLabel<'a> for &'a Vec<Value> {
    fn get_label(self) -> Option<String> {
        let second = self.get(1)?;
        let second = second.as_object()?;
        let label = second.get("label")?;
        label.as_str().map(|s| s.to_owned())
    }
}

const CONTEXTS: [&str; 6] = ["home", "work", "office", "private", "mobile", "cell"];

trait GetContexts<'a> {
    fn get_contexts(self) -> Option<Vec<String>>;
}

impl<'a> GetContexts<'a> for &'a Vec<Value> {
    fn get_contexts(self) -> Option<Vec<String>> {
        let second = self.get(1)?;
        let second = second.as_object()?;
        let contexts = second.get("type")?;
        if let Some(context) = contexts.as_str() {
            let context = context.to_lowercase();
            if CONTEXTS.contains(&context.as_str()) {
                return Some(vec![context]);
            } else {
                return None;
            }
        };
        let contexts = contexts.as_array()?;
        let contexts = contexts
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_lowercase())
            .filter(|s| CONTEXTS.contains(&s.as_str()))
            .collect::<Vec<String>>();
        (!contexts.is_empty()).then_some(contexts)
    }
}

trait GetFeatures<'a> {
    fn get_features(self) -> Option<Vec<String>>;
}

impl<'a> GetFeatures<'a> for &'a Vec<Value> {
    fn get_features(self) -> Option<Vec<String>> {
        let second = self.get(1)?;
        let second = second.as_object()?;
        let features = second.get("type")?;
        if let Some(feature) = features.as_str() {
            let feature = feature.to_lowercase();
            if !CONTEXTS.contains(&feature.as_str()) {
                return Some(vec![feature]);
            } else {
                return None;
            }
        };
        let features = features.as_array()?;
        let features = features
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_lowercase())
            .filter(|s| !CONTEXTS.contains(&s.as_str()))
            .collect::<Vec<String>>();
        (!features.is_empty()).then_some(features)
    }
}

trait GetLangs<'a> {
    fn get_langs(self) -> Option<Vec<Lang>>;
}

impl<'a> GetLangs<'a> for &'a [&'a Vec<Value>] {
    fn get_langs(self) -> Option<Vec<Lang>> {
        let langs = self
            .iter()
            .filter_map(|prop| {
                let tag = (*prop).get_text()?;
                let lang = Lang::builder()
                    .tag(tag)
                    .and_preference((*prop).get_preference())
                    .build();
                Some(lang)
            })
            .collect::<Vec<Lang>>();
        (!langs.is_empty()).then_some(langs)
    }
}

trait GetEmails<'a> {
    fn get_emails(self) -> Option<Vec<Email>>;
}

impl<'a> GetEmails<'a> for &'a [&'a Vec<Value>] {
    fn get_emails(self) -> Option<Vec<Email>> {
        let emails = self
            .iter()
            .filter_map(|prop| {
                let addr = (*prop).get_text()?;
                let email = Email::builder()
                    .email(addr)
                    .and_contexts((*prop).get_contexts())
                    .and_preference((*prop).get_preference())
                    .build();
                Some(email)
            })
            .collect::<Vec<Email>>();
        (!emails.is_empty()).then_some(emails)
    }
}

trait GetPhones<'a> {
    fn get_phones(self) -> Option<Vec<Phone>>;
}

impl<'a> GetPhones<'a> for &'a [&'a Vec<Value>] {
    fn get_phones(self) -> Option<Vec<Phone>> {
        let phones = self
            .iter()
            .filter_map(|prop| {
                let number = (*prop).get_text()?;
                let phone = Phone::builder()
                    .phone(number)
                    .and_features((*prop).get_features())
                    .and_contexts((*prop).get_contexts())
                    .and_preference((*prop).get_preference())
                    .build();
                Some(phone)
            })
            .collect::<Vec<Phone>>();
        (!phones.is_empty()).then_some(phones)
    }
}

trait GetPostalAddresses<'a> {
    fn get_postal_addresses(self) -> Option<Vec<PostalAddress>>;
}

impl<'a> GetPostalAddresses<'a> for &'a [&'a Vec<Value>] {
    fn get_postal_addresses(self) -> Option<Vec<PostalAddress>> {
        let addrs = self
            .iter()
            .map(|prop| {
                let mut postal_code: Option<String> = None;
                let mut country_code: Option<String> = None;
                let mut country_name: Option<String> = None;
                let mut region_code: Option<String> = None;
                let mut region_name: Option<String> = None;
                let mut locality: Option<String> = None;
                let mut street_parts: Vec<String> = Vec::new();
                if let Some(fourth) = prop.get(3) {
                    if let Some(addr) = fourth.as_array() {
                        let mut iter = addr
                            .iter()
                            .rev()
                            .filter_map(|i| i.as_str())
                            .filter(|i| !i.is_empty());
                        if let Some(e) = iter.next() {
                            if e.len() == 2 && e.to_uppercase() == e {
                                country_code = Some(e.to_string())
                            } else {
                                country_name = Some(e.to_string())
                            }
                        };
                        if let Some(e) = iter.next() {
                            postal_code = Some(e.to_string());
                        };
                        if let Some(e) = iter.next() {
                            if e.len() == 2 && e.to_uppercase() == e {
                                region_code = Some(e.to_string())
                            } else {
                                region_name = Some(e.to_string())
                            }
                        };
                        if let Some(e) = iter.next() {
                            locality = Some(e.to_string());
                        };
                        for e in iter {
                            street_parts.insert(0, e.to_string());
                        }
                    }
                };
                let street_parts = (!street_parts.is_empty()).then_some(street_parts);
                PostalAddress::builder()
                    .and_full_address((*prop).get_label())
                    .and_contexts((*prop).get_contexts())
                    .and_preference((*prop).get_preference())
                    .and_country_code(country_code)
                    .and_country_name(country_name)
                    .and_postal_code(postal_code)
                    .and_region_name(region_name)
                    .and_region_code(region_code)
                    .and_locality(locality)
                    .and_street_parts(street_parts)
                    .build()
            })
            .collect::<Vec<PostalAddress>>();
        (!addrs.is_empty()).then_some(addrs)
    }
}

trait GetNameParts<'a> {
    fn get_name_parts(self) -> Option<NameParts>;
}

impl<'a> GetNameParts<'a> for Option<&'a Vec<Value>> {
    fn get_name_parts(self) -> Option<NameParts> {
        let values = self?;
        let fourth = values.get(3)?;
        let parts = fourth.as_array()?;
        let mut iter = parts.iter().filter(|p| p.is_string() || p.is_array());
        let mut prefixes: Option<Vec<String>> = None;
        let mut surnames: Option<Vec<String>> = None;
        let mut given_names: Option<Vec<String>> = None;
        let mut middle_names: Option<Vec<String>> = None;
        let mut suffixes: Option<Vec<String>> = None;
        if let Some(e) = iter.next() {
            surnames = get_string_or_vec(e);
        };
        if let Some(e) = iter.next() {
            given_names = get_string_or_vec(e);
        };
        if let Some(e) = iter.next() {
            middle_names = get_string_or_vec(e);
        };
        if let Some(e) = iter.next() {
            prefixes = get_string_or_vec(e);
        };
        if let Some(e) = iter.next() {
            suffixes = get_string_or_vec(e);
        };
        let name_parts = NameParts::builder()
            .and_surnames(surnames)
            .and_prefixes(prefixes)
            .and_given_names(given_names)
            .and_middle_names(middle_names)
            .and_suffixes(suffixes)
            .build();
        if name_parts.surnames.is_none()
            && name_parts.given_names.is_none()
            && name_parts.middle_names.is_none()
            && name_parts.suffixes.is_none()
            && name_parts.prefixes.is_none()
        {
            None
        } else {
            Some(name_parts)
        }
    }
}

fn get_string_or_vec(value: &Value) -> Option<Vec<String>> {
    if let Some(e) = value.as_str() {
        if e.is_empty() {
            return None;
        } else {
            return Some(vec![e.to_string()]);
        };
    };
    if let Some(e) = value.as_array() {
        let strings = e
            .iter()
            .filter_map(|e| e.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect::<Vec<String>>();
        return (!strings.is_empty()).then_some(strings);
    };
    None
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use serde_json::Value;

    use crate::contact::{Contact, NameParts};

    #[test]
    fn GIVEN_vcard_WHEN_from_vcard_THEN_properties_are_correct() {
        // GIVEN
        let vcard = r#"
          [
            "vcard",
            [
              ["version", {}, "text", "4.0"],
              ["fn", {}, "text", "Joe User"],
              ["n", {}, "text",
                ["User", "Joe", "", "", ["ing. jr", "M.Sc."]]
              ],
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
              ["adr",
                {
                  "type":"home",
                  "label":"123 Maple Ave\nSuite 90001\nVancouver\nBC\n1239\n"
                },
                "text",
                [
                  "", "", "", "", "", "", ""
                ]
              ],
              ["tel",
                {
                  "type":["work", "voice"],
                  "pref":"1"
                },
                "uri",
                "tel:+1-555-555-1234;ext=102"
              ],
              ["tel",
                { "type":["work", "cell", "voice", "video", "text"] },
                "uri",
                "tel:+1-555-555-4321"
              ],
              ["email",
                { "type":"work" },
                "text",
                "joe.user@example.com"
              ],
              ["geo", {
                "type":"work"
              }, "uri", "geo:46.772673,-71.282945"],
              ["key",
                { "type":"work" },
                "uri",
                "https://www.example.com/joe.user/joe.asc"
              ],
              ["tz", {},
                "utc-offset", "-05:00"],
              ["url", { "type":"home" },
                "uri", "https://example.org"]
            ]
          ]
        "#;

        // WHEN
        let actual = serde_json::from_str::<Vec<Value>>(vcard);

        // THEN
        let actual = actual.expect("parsing vcard");
        let actual = Contact::from_vcard(&actual).expect("vcard not found");

        // full name
        assert_eq!(actual.full_name.expect("full_name not found"), "Joe User");

        // kind
        assert_eq!(actual.kind.expect("kind not found"), "individual");

        // titles
        assert_eq!(
            actual
                .titles
                .expect("no titles")
                .first()
                .expect("titles empty"),
            "Research Scientist"
        );

        // roles
        assert_eq!(
            actual
                .roles
                .expect("no roles")
                .first()
                .expect("roles empty"),
            "Project Lead"
        );

        // organization names
        assert_eq!(
            actual
                .organization_names
                .expect("no organization_names")
                .first()
                .expect("organization_names empty"),
            "Example"
        );

        // nick names
        assert!(actual.nick_names.is_none());

        // langs
        let Some(langs) = actual.langs else {
            panic!("langs not found")
        };
        assert_eq!(langs.len(), 2);
        assert_eq!(langs.first().expect("first lang").tag, "fr");
        assert_eq!(langs.first().expect("first lang").preference, Some(1));
        assert_eq!(langs.get(1).expect("second lang").tag, "en");
        assert_eq!(langs.get(1).expect("second lang").preference, Some(2));

        // emails
        let Some(emails) = actual.emails else {
            panic!("emails not found")
        };
        let Some(email) = emails.first() else {
            panic!("no email found")
        };
        assert_eq!(email.email, "joe.user@example.com");
        assert!(email
            .contexts
            .as_ref()
            .expect("contexts not found")
            .contains(&"work".to_string()));

        // phones
        let Some(phones) = actual.phones else {
            panic!("no phones found")
        };
        let Some(phone) = phones.first() else {
            panic!("no first phone")
        };
        assert_eq!(phone.phone, "tel:+1-555-555-1234;ext=102");
        assert!(phone
            .contexts
            .as_ref()
            .expect("no contexts")
            .contains(&"work".to_string()));
        assert!(phone
            .features
            .as_ref()
            .expect("no features")
            .contains(&"voice".to_string()));
        let Some(phone) = phones.last() else {
            panic!("no last phone")
        };
        assert_eq!(phone.phone, "tel:+1-555-555-4321");
        assert!(phone
            .contexts
            .as_ref()
            .expect("no contexts")
            .contains(&"cell".to_string()));
        assert!(phone
            .features
            .as_ref()
            .expect("no features")
            .contains(&"video".to_string()));

        // postal addresses
        let Some(addresses) = actual.postal_addresses else {
            panic!("no postal addresses")
        };
        let Some(addr) = addresses.first() else {
            panic!("first address not found")
        };
        assert!(addr
            .contexts
            .as_ref()
            .expect("no contexts")
            .contains(&"work".to_string()));
        let Some(street_parts) = &addr.street_parts else {
            panic!("no street parts")
        };
        assert_eq!(street_parts.first().expect("street part 0"), "Suite 1234");
        assert_eq!(
            street_parts.get(1).expect("street part 1"),
            "4321 Rue Somewhere"
        );
        assert_eq!(addr.country_name.as_ref().expect("country name"), "Canada");
        assert!(addr.country_code.is_none());
        assert_eq!(addr.region_code.as_ref().expect("region code"), "QC");
        assert!(addr.region_name.is_none());
        assert_eq!(addr.postal_code.as_ref().expect("postal code"), "G1V 2M2");
        let Some(addr) = addresses.last() else {
            panic!("last address not found")
        };
        assert!(addr
            .contexts
            .as_ref()
            .expect("no contexts")
            .contains(&"home".to_string()));
        assert_eq!(
            addr.full_address.as_ref().expect("full address not foudn"),
            "123 Maple Ave\nSuite 90001\nVancouver\nBC\n1239\n"
        );

        // name parts
        let Some(name_parts) = actual.name_parts else {
            panic!("no name parts")
        };
        let expected = NameParts::builder()
            .surnames(vec!["User".to_string()])
            .given_names(vec!["Joe".to_string()])
            .suffixes(vec!["ing. jr".to_string(), "M.Sc.".to_string()])
            .build();
        assert_eq!(name_parts, expected);
    }
}
