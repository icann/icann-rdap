//! Extension Identifiers
//!
//! This enum uses [EnumString] and [AsRefStr] to allow serialization
//! and deserialization of the variant to the matching name in the IANA registry.
//!
//! To get the variant from a string:
//!
//! ```rust
//! use std::str::FromStr;
//! use icann_rdap_common::prelude::*;
//!
//! let cidr0 = ExtensionId::from_str("cidr0").unwrap();
//! assert_eq!(cidr0, ExtensionId::Cidr0);
//! println!("{}", cidr0.to_string());
//! ```
//!
//! To get the enum variants as a string:
//!
//! ```rust
//! use icann_rdap_common::prelude::*;
//!
//! let s = ExtensionId::Cidr0.to_string();
//! ```
//!
//! To get the enum variants as a &str:
//!
//! ```rust
//! use icann_rdap_common::prelude::*;
//!
//! let s = ExtensionId::Cidr0.as_ref();
//! ```

use {
    crate::response::Extension,
    serde::{Deserialize, Serialize},
    strum::{AsRefStr, EnumIter, EnumString},
};

use strum::Display as EnumDisplay;

/// IANA RDAP Extension Identifiers.
#[derive(
    Serialize,
    Deserialize,
    EnumString,
    EnumDisplay,
    Debug,
    PartialEq,
    Eq,
    AsRefStr,
    Hash,
    Clone,
    EnumIter,
)]
pub enum ExtensionId {
    #[strum(serialize = "rdap_level_0")]
    RdapLevel0,
    #[strum(serialize = "arin_originas0")]
    ArinOriginAs0,
    #[strum(serialize = "autnums")]
    Autnums,
    #[strum(serialize = "autnumSearchResults")]
    AutnumSearchResults,
    #[strum(serialize = "artRecord")]
    ArtRecord,
    #[strum(serialize = "cidr0")]
    Cidr0,
    #[strum(serialize = "exts")]
    Exts,
    #[strum(serialize = "farv1")]
    Farv1,
    #[strum(serialize = "fred")]
    Fred,
    #[strum(serialize = "geofeed1")]
    Geofeed1,
    #[strum(serialize = "icann_rdap_response_profile_0")]
    IcannRdapResponseProfile0,
    #[strum(serialize = "icann_rdap_response_profile_1")]
    IcannRdapResponseProfile1,
    #[strum(serialize = "icann_rdap_technical_implementation_guide_0")]
    IcannRdapTechnicalImplementationGuide0,
    #[strum(serialize = "icann_rdap_technical_implementation_guide_1")]
    IcannRdapTechnicalImplementationGuide1,
    #[strum(serialize = "ips")]
    Ips,
    #[strum(serialize = "ipSearchResults")]
    IpSearchResults,
    #[strum(serialize = "jscontact")]
    JsContact,
    #[strum(serialize = "nask")]
    Nask,
    #[strum(serialize = "nro_rdap_profile_0")]
    NroRdapProfile0,
    #[strum(serialize = "nro_rdap_profile_asn_flat_0")]
    NroRdapProfileAsnFlat0,
    #[strum(serialize = "nro_rdap_profile_asn_hierarchical_0")]
    NroRdapProfileAsnHierarchical0,
    #[strum(serialize = "paging")]
    Paging,
    #[strum(serialize = "platformNS")]
    PlatformNs,
    #[strum(serialize = "rdap_objectTag")]
    RdapObjectTag,
    #[strum(serialize = "redacted")]
    Redacted,
    #[strum(serialize = "redirect_with_content")]
    RedirectWithContent,
    #[strum(serialize = "regType")]
    RegType,
    #[strum(serialize = "reverse_search")]
    ReverseSearch,
    #[strum(serialize = "rirSearch1")]
    RirSearch1,
    #[strum(serialize = "simpleRedaction")]
    SimpleRedaction,
    #[strum(serialize = "sorting")]
    Sorting,
    #[strum(serialize = "subsetting")]
    Subsetting,
    #[strum(serialize = "ttl0")]
    Ttl0,
}

impl ExtensionId {
    /// Gets an [Extension] from an Extension ID.
    pub fn to_extension(&self) -> Extension {
        Extension(self.to_string())
    }
}

#[cfg(all(test, feature = "iana_registry_tests"))]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    const IANA_REGISTRY_URL: &str =
        "https://www.iana.org/assignments/rdap-extensions/rdap-extensions.xml";

    #[test]
    fn iana_extension_ids_match_enum() {
        let client = reqwest::blocking::Client::builder()
            .user_agent("icann-rdap-iana-test")
            .build()
            .expect("failed to build reqwest client");
        let resp = client
            .get(IANA_REGISTRY_URL)
            .header("Accept", "application/xml")
            .send()
            .expect("failed to fetch IANA RDAP extensions registry");
        let body = resp.text().expect("failed to read IANA registry body");

        let mut iana_values: std::collections::HashSet<String> = std::collections::HashSet::new();
        let records: Vec<&str> = body.split("<record").skip(1).collect();
        for record in records {
            let value_start = match record.find("<value>") {
                Some(pos) => pos + 7,
                None => continue,
            };
            let value_end = match record[value_start..].find("</value>") {
                Some(len) => len,
                None => continue,
            };
            let mut value = record[value_start..value_start + value_end]
                .trim()
                .to_string();
            if let Some(obl) = value.find(" (OBSOLETED)") {
                value.truncate(obl);
            }
            iana_values.insert(value);
        }

        let mut enum_values: std::collections::HashSet<String> = std::collections::HashSet::new();
        for variant in ExtensionId::iter() {
            enum_values.insert(variant.to_string());
        }

        let mut missing = Vec::new();
        for value in &iana_values {
            if !enum_values.contains(value) {
                missing.push(value.clone());
            }
        }

        missing.sort();

        if !missing.is_empty() {
            let mut msg = String::from("ExtensionId enum does not match IANA registry:\n");
            msg.push_str("Missing from enum:\n");
            for v in &missing {
                msg.push_str(&format!("  - {v}\n"));
            }
            panic!("{msg}");
        }
    }
}
