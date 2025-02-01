//! Types for more lenient processing of invalid RDAP

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
enum VectorStringishInner {
    /// Valid RDAP.
    Many(Vec<String>),

    /// Invalide RDAP.
    One(String),
}

/// A type that is suppose to be a vector of strings.
///
/// Provides a choice between a string or a vector of strings for deserialization.
///
/// This type is provided to be lenient with misbehaving RDAP servers that
/// serve a string when they are suppose to be serving an array of
/// strings. Usage of a string where an array of strings is an error.
///
/// Use one of the From methods for construction.
/// ```rust
/// use icann_rdap_common::response::lenient::VectorStringish;
///
/// let v = VectorStringish::from(vec!["one".to_string(), "two".to_string()]);
///
/// // or
///
/// let v = VectorStringish::from("one".to_string());
/// ````
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(transparent)]
pub struct VectorStringish {
    inner: VectorStringishInner,
}

impl From<String> for VectorStringish {
    fn from(value: String) -> Self {
        VectorStringish {
            inner: VectorStringishInner::Many(vec![value]),
        }
    }
}

impl From<Vec<String>> for VectorStringish {
    fn from(value: Vec<String>) -> Self {
        VectorStringish {
            inner: VectorStringishInner::Many(value),
        }
    }
}

impl From<VectorStringish> for Vec<String> {
    fn from(value: VectorStringish) -> Self {
        match value.inner {
            VectorStringishInner::Many(many) => many,
            VectorStringishInner::One(one) => vec![one],
        }
    }
}

impl From<&VectorStringish> for Vec<String> {
    fn from(value: &VectorStringish) -> Self {
        match &value.inner {
            VectorStringishInner::Many(many) => many.to_owned(),
            VectorStringishInner::One(one) => vec![one.to_owned()],
        }
    }
}

impl VectorStringish {
    /// Consumes and converts it to a `Vec<String>`.
    pub fn into_vec_string(self) -> Vec<String> {
        match self.inner {
            VectorStringishInner::Many(many) => many,
            VectorStringishInner::One(one) => vec![one],
        }
    }

    /// Converts it a `Vec<String>` by cloning().
    pub fn into_vec_string_owned(&self) -> Vec<String> {
        match &self.inner {
            VectorStringishInner::Many(many) => many.clone(),
            VectorStringishInner::One(one) => vec![one.to_owned()],
        }
    }

    /// Returns true if the deserialization was as a string.
    pub fn is_string(&self) -> bool {
        match self.inner {
            VectorStringishInner::Many(_) => false,
            VectorStringishInner::One(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_str, to_string};

    #[test]
    fn test_stringorstringarray_serialize_many() {
        // GIVEN
        let many = VectorStringish::from(vec!["one".to_string(), "two".to_string()]);

        // WHEN
        let serialized = to_string(&many).unwrap();

        // THEN
        assert_eq!(serialized, r#"["one","two"]"#);
    }

    #[test]
    fn test_stringorstringarray_serialize_one() {
        // GIVEN
        let one = VectorStringish::from("one".to_string());

        // WHEN
        let serialized = to_string(&one).unwrap();

        // THEN
        assert_eq!(serialized, r#"["one"]"#);
    }

    #[test]
    fn test_stringorstringarray_deserialize_many() {
        // GIVEN
        let json_str = r#"["one","two"]"#;

        // WHEN
        let deserialized: VectorStringish = from_str(json_str).unwrap();

        // THEN
        assert_eq!(
            deserialized.into_vec_string_owned(),
            vec!["one".to_string(), "two".to_string()]
        );

        // and THEN is not string
        assert!(!deserialized.is_string())
    }

    #[test]
    fn test_stringorstringarray_deserialize_one() {
        // GIVEN
        let json_str = r#""one""#;

        // WHEN
        let deserialized: VectorStringish = from_str(json_str).unwrap();

        // THEN
        assert_eq!(
            deserialized.into_vec_string_owned(),
            vec!["one".to_string()]
        );

        // and THEN is string
        assert!(deserialized.is_string())
    }
}
