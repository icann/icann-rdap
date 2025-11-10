//! RFC 9537.
//!
//! Using the builders to create redactions is recommended.
//! The following is an example:
//!
//! ```rust
//! use icann_rdap_common::prelude::*;
//! use icann_rdap_common::response::redacted::*;
//!
//! let r_name = Name::builder().type_field("Tech Email").build();
//! let redacted = Redacted::builder()
//!   .name(r_name)
//!   .build();
//!
//! let domain = Domain::builder()
//!   .ldh_name("foo.example.com")
//!   .redacted(vec![redacted])
//!   .build();
//! ```
//!
//! To get the data out of redactions, using the getters is recommended.
//!
//! ```rust
//! use icann_rdap_common::response::redacted::*;
//!
//! let r_name = Name::builder().type_field("Tech Email").build();
//! let redacted = Redacted::builder()
//!   .name(r_name)
//!   .build();
//!
//! // get the data from the redaction.
//! let name_type = redacted.name().type_field();
//! ```
//!
use {
    buildstructor::Builder,
    serde::{Deserialize, Serialize},
    std::{any::TypeId, fmt},
};

use crate::check::Checks;

/// Redacted registered name.
#[derive(Builder, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Name {
    #[serde(rename = "description")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_field: Option<String>,
}

impl Name {
    /// Get the description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Get the redaction type.
    pub fn type_field(&self) -> Option<&str> {
        self.type_field.as_deref()
    }
}

/// Redaction reason.
#[derive(Builder, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Reason {
    #[serde(rename = "description")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_field: Option<String>,
}

impl Reason {
    /// Get the description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Get the redaction type.
    pub fn type_field(&self) -> Option<&str> {
        self.type_field.as_deref()
    }
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

/// RFC 9537 redaction structure.
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
            Self::Removal => write!(f, "Removal"),
            Self::EmptyValue => write!(f, "EmptyValue"),
            Self::PartialValue => write!(f, "PartialValue"),
            Self::ReplacementValue => write!(f, "ReplacementValue"),
        }
    }
}

impl Redacted {
    /// Get the name.
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Get the reason.
    pub fn reason(&self) -> Option<&Reason> {
        self.reason.as_ref()
    }

    /// Get the prePath.
    pub fn pre_path(&self) -> Option<&str> {
        self.pre_path.as_deref()
    }

    /// Get the postPath.
    pub fn post_path(&self) -> Option<&str> {
        self.post_path.as_deref()
    }

    /// Get the replacementPath.
    pub fn replacement_path(&self) -> Option<&str> {
        self.replacement_path.as_deref()
    }

    /// Get the pathLang.
    pub fn path_lang(&self) -> Option<&str> {
        self.path_lang.as_deref()
    }

    /// Get the method.
    pub fn method(&self) -> Option<&Method> {
        self.method.as_ref()
    }

    /// Get the checks from Redactions.
    pub fn get_checks(&self, _check_params: crate::check::CheckParams<'_>) -> crate::check::Checks {
        Checks {
            rdap_struct: crate::check::RdapStructure::Redacted,
            index: None,
            items: vec![],
            sub_checks: vec![],
        }
    }

    /// Get the type.
    pub fn get_type(&self) -> std::any::TypeId {
        TypeId::of::<Self>()
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
