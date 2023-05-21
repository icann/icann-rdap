use serde_json::Value;

use super::Contact;

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
    }
}
