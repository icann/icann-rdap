use buildstructor::Builder;
use serde::{Deserialize, Serialize};
use std::any::TypeId;
use std::fmt;

use crate::check::Checks;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Name {
    #[serde(rename = "description")]
    pub description: Option<String>,

    #[serde(rename = "type")]
    pub type_field: Option<String>,
}

impl Name {
    pub fn description(&self) -> Option<&String> {
        self.description.as_ref()
    }

    pub fn type_field(&self) -> Option<&String> {
        self.type_field.as_ref()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Reason {
    #[serde(rename = "description")]
    pub description: Option<String>,

    #[serde(rename = "type")]
    pub type_field: Option<String>,
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let output = self.description.clone().unwrap_or_default();
        write!(f, "{}", output)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Method {
    Removal,
    EmptyValue,
    PartialValue,
    ReplacementValue,
}

#[derive(Builder, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Redacted {
    #[serde[rename = "name"]]
    pub name: Name,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "reason")]
    pub reason: Option<Reason>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "prePath")]
    pub pre_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "postPath")]
    pub post_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "pathLang")]
    pub path_lang: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "replacementPath")]
    pub replacement_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "method")]
    pub method: Option<Method>,
}

impl Default for Name {
    fn default() -> Self {
        Self {
            description: Some(String::default()),
            type_field: None,
        }
    }
}

impl Default for Method {
    fn default() -> Self {
        Self::Removal // according to IETF draft this is the default
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Method::Removal => write!(f, "Removal"),
            Method::EmptyValue => write!(f, "EmptyValue"),
            Method::PartialValue => write!(f, "PartialValue"),
            Method::ReplacementValue => write!(f, "ReplacementValue"),
        }
    }
}

impl Redacted {
    pub fn get_checks(
        &self,
        _check_params: crate::check::CheckParams<'_>,
    ) -> crate::check::Checks<'_> {
        Checks {
            struct_name: "RDAP Conformance",
            items: Vec::new(),
            sub_checks: Vec::new(),
        }
    }

    pub fn get_type(&self) -> std::any::TypeId {
        TypeId::of::<Redacted>()
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn GIVEN_redaction_WHEN_set_THEN_success() {
        // GIVEN
        let name = Name {
            description: Some("Registry Domain ID".to_string()),
            type_field: None,
        };

        // WHEN
        let redacted = Redacted::builder()
            .name(name)
            .reason(Reason::default())
            .pre_path("$.handle".to_string())
            .post_path("$.entities[?(@.roles[0]=='registrant'".to_string())
            .path_lang("jsonpath".to_string())
            .replacement_path(
                "$.entities[?(@.roles[0]=='registrant')].vcardArray[1][?(@[0]=='contact-uri')]"
                    .to_string(),
            )
            .method(Method::Removal)
            .build();

        // THEN
        assert_eq!(
            redacted.name.description,
            Some("Registry Domain ID".to_string())
        );
        assert_eq!(redacted.pre_path, Some("$.handle".to_string()));
        assert_eq!(
            redacted.post_path,
            Some("$.entities[?(@.roles[0]=='registrant'".to_string())
        );
        assert_eq!(redacted.path_lang, Some("jsonpath".to_string()));
        assert_eq!(
            redacted.replacement_path,
            Some(
                "$.entities[?(@.roles[0]=='registrant')].vcardArray[1][?(@[0]=='contact-uri')]"
                    .to_string()
            )
        );
        assert_eq!(redacted.method, Some(Method::Removal));
    }

    #[test]
    fn GIVEN_redaction_WHEN_deserialize_THEN_success() {
        // GIVEN
        let expected = r#"
        {
          "name": {
            "type": "Registry Domain ID"
          },
          "prePath": "$.handle",
          "pathLang": "jsonpath",
          "postPath": "$.entities[?(@.roles[0]=='registrant'",
          "replacementPath": "$.entities[?(@.roles[0]=='registrant')].vcardArray[1][?(@[0]=='contact-uri')]",
          "method": "removal",
          "reason": {
            "description": "Server policy"
          }
        }
        "#;

        // in this one we swap the two fields
        let name = Name {
            type_field: Some("Registry Domain ID".to_string()),
            description: None,
        };

        let reason: Reason = Reason {
            description: Some("Server policy".to_string()),
            type_field: None,
        };

        // WHEN
        // use the builder for most of the fields but not all
        let mut sample_redact: Redacted = Redacted::builder()
            .name(name)
            .pre_path("$.handle".to_string())
            .path_lang("jsonpath".to_string())
            .post_path("$.entities[?(@.roles[0]=='registrant'".to_string())
            .replacement_path(
                "$.entities[?(@.roles[0]=='registrant')].vcardArray[1][?(@[0]=='contact-uri')]"
                    .to_string(),
            )
            .build();

        // also make sure we can set the rest
        sample_redact.method = Some(Method::Removal);
        sample_redact.reason = Some(reason);

        let actual: Result<Redacted, serde_json::Error> =
            serde_json::from_str::<Redacted>(expected);

        // THEN
        let actual: Redacted = actual.unwrap();
        assert_eq!(actual, sample_redact); // sanity check
        assert_eq!(
            actual.name.type_field,
            Some("Registry Domain ID".to_string())
        );
        assert_eq!(actual.pre_path, Some("$.handle".to_string()));
        assert_eq!(
            actual.post_path,
            Some("$.entities[?(@.roles[0]=='registrant'".to_string())
        );
        assert_eq!(actual.path_lang, Some("jsonpath".to_string()));
        assert_eq!(
            actual.replacement_path,
            Some(
                "$.entities[?(@.roles[0]=='registrant')].vcardArray[1][?(@[0]=='contact-uri')]"
                    .to_string()
            )
        );
        assert_eq!(actual.method, Some(Method::Removal));
    }
}
