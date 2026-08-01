//! IANA registered roles for entities.

use super::EnumDisplay;
use strum::{EnumIter, EnumString};

/// Entity Roles registered with IANA.
#[derive(PartialEq, Eq, Debug, Clone, Copy, EnumString, EnumDisplay, EnumIter)]
#[strum(serialize_all = "lowercase")]
pub enum EntityRole {
    Registrant,
    Technical,
    Administrative,
    Abuse,
    Billing,
    Registrar,
    Reseller,
    Sponsor,
    Proxy,
    Notifications,
    Noc,
}

#[cfg(all(test, feature = "iana_registry_tests"))]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    const IANA_REGISTRY_URL: &str =
        "https://www.iana.org/assignments/rdap-json-values/rdap-json-values.xml";

    #[test]
    fn iana_entity_roles_match_enum() {
        let client = reqwest::blocking::Client::builder()
            .user_agent("icann-rdap-iana-test")
            .build()
            .expect("failed to build reqwest client");
        let resp = client
            .get(IANA_REGISTRY_URL)
            .header("Accept", "application/xml")
            .send()
            .expect("failed to fetch IANA RDAP JSON values registry");
        let body = resp.text().expect("failed to read IANA registry body");

        let mut iana_values: std::collections::HashSet<String> = std::collections::HashSet::new();
        let records: Vec<&str> = body.split("<record").skip(1).collect();
        for record in records {
            let type_start = match record.find("<type>") {
                Some(pos) => pos + 6,
                None => continue,
            };
            let type_end = match record[type_start..].find("</type>") {
                Some(len) => len,
                None => continue,
            };
            let type_val = record[type_start..type_start + type_end].trim().to_string();
            if type_val != "role" {
                continue;
            }
            let value_start = match record.find("<value>") {
                Some(pos) => pos + 7,
                None => continue,
            };
            let value_end = match record[value_start..].find("</value>") {
                Some(len) => len,
                None => continue,
            };
            let value = record[value_start..value_start + value_end]
                .trim()
                .to_string();
            iana_values.insert(value);
        }

        let mut enum_values: std::collections::HashSet<String> = std::collections::HashSet::new();
        for variant in EntityRole::iter() {
            enum_values.insert(variant.to_string());
        }

        let mut missing = Vec::new();
        for value in &iana_values {
            if !enum_values.contains(value) {
                missing.push(value.clone());
            }
        }

        let mut extra = Vec::new();
        for value in &enum_values {
            if !iana_values.contains(value) {
                extra.push(value.clone());
            }
        }

        missing.sort();
        extra.sort();

        if !missing.is_empty() || !extra.is_empty() {
            let mut msg = String::from("EntityRole enum does not match IANA registry:\n");
            if !missing.is_empty() {
                msg.push_str("Missing from enum:\n");
                for v in &missing {
                    msg.push_str(&format!("  - {v}\n"));
                }
            }
            if !extra.is_empty() {
                msg.push_str("Not in IANA registry:\n");
                for v in &extra {
                    msg.push_str(&format!("  - {v}\n"));
                }
            }
            panic!("{msg}");
        }
    }
}
