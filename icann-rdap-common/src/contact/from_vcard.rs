use serde_json::Value;

use super::{Contact, Email, Lang};

impl Contact {
    pub fn from_vcard(vcard_array: &[Value]) -> Option<Contact> {
        // value should be "vcard" followed by array
        let Some(value) = vcard_array.first() else {return None};
        let Some(vcard_literal) = value.as_str() else {return None};
        if !vcard_literal.eq_ignore_ascii_case("vcard") {
            return None;
        };
        let Some(vcard) = vcard_array.get(1) else {return None};
        let Some(vcard) = vcard.as_array() else {return None};

        let contact = Contact::builder()
            .and_full_name(vcard.find_property("fn").get_text())
            .and_kind(vcard.find_property("kind").get_text())
            .and_titles(vcard.find_properties("title").get_texts())
            .and_nick_names(vcard.find_properties("nickname").get_texts())
            .and_organization_names(vcard.find_properties("org").get_texts())
            .and_langs(vcard.find_properties("lang").get_langs())
            .and_emails(vcard.find_properties("email").get_emails())
            .build();

        Some(contact)
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
        let Some(values) = self else {return None};
        let Some(fourth) = values.get(3) else {return None};
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
            .filter_map(|prop| Some(*prop).get_text())
            .collect::<Vec<String>>();
        (!texts.is_empty()).then_some(texts)
    }
}

trait GetPreference<'a> {
    fn get_preference(self) -> Option<u64>;
}

impl<'a> GetPreference<'a> for &'a Vec<Value> {
    fn get_preference(self) -> Option<u64> {
        let Some(second) = self.get(1) else {return None};
        let Some(second) = second.as_object() else {return None};
        let Some(preference) = second.get("pref") else {return None};
        preference.as_str().and_then(|s| s.parse().ok())
    }
}

const CONTEXTS: [&str; 5] = ["home", "work", "office", "private", "mobile"];

trait GetContexts<'a> {
    fn get_contexts(self) -> Option<Vec<String>>;
}

impl<'a> GetContexts<'a> for &'a Vec<Value> {
    fn get_contexts(self) -> Option<Vec<String>> {
        let Some(second) = self.get(1) else {return None};
        let Some(second) = second.as_object() else {return None};
        let Some(contexts) = second.get("type") else {return None};
        if let Some(context) = contexts.as_str() {
            let context = context.to_lowercase();
            if CONTEXTS.contains(&context.as_str()) {
                return Some(vec![context]);
            } else {
                return None;
            }
        };
        let Some(contexts) = contexts.as_array() else {return None};
        let contexts = contexts
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_lowercase())
            .filter(|s| CONTEXTS.contains(&s.as_str()))
            .collect::<Vec<String>>();
        (!contexts.is_empty()).then_some(contexts)
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
                let Some(tag) = Some(*prop).get_text() else {return None};
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
                let Some(addr) = Some(*prop).get_text() else {return None};
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

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use serde_json::Value;

    use crate::contact::Contact;

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
        assert_eq!(actual.full_name.expect("full_name not found"), "Joe User");
        assert_eq!(actual.kind.expect("kind not found"), "individual");
        assert_eq!(
            actual
                .titles
                .expect("no titles")
                .first()
                .expect("titles empty"),
            "Research Scientist"
        );
        assert_eq!(
            actual
                .organization_names
                .expect("no organization_names")
                .first()
                .expect("organization_names empty"),
            "Example"
        );
        assert!(actual.nick_names.is_none());
        let Some(langs) = actual.langs else {panic!("langs not found")};
        assert_eq!(langs.len(), 2);
        assert_eq!(langs.get(0).expect("first lang").tag, "fr");
        assert_eq!(langs.get(0).expect("first lang").preference, Some(1));
        assert_eq!(langs.get(1).expect("second lang").tag, "en");
        assert_eq!(langs.get(1).expect("second lang").preference, Some(2));
        let Some(emails) = actual.emails else {panic!("emails not found")};
        let Some(email) = emails.first() else {panic!("no email found")};
        assert_eq!(email.email, "joe.user@example.com");
        assert!(email
            .contexts
            .as_ref()
            .expect("contexts not found")
            .contains(&"work".to_string()));
    }
}