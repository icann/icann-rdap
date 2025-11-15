//! Changes RFC 9537 redactions to simple redactions

use crate::rdap::redacted::simplify_ids::simplify_registry_domain_id;
use crate::rdap::redacted::simplify_ids::simplify_registry_registrant_id;
use crate::rdap::redacted::simplify_ids::simplify_registry_tech_id;
use crate::rdap::redacted::simplify_names::simplify_registrant_name;
use crate::rdap::redacted::simplify_names::simplify_tech_name;
use std::str::FromStr;

use icann_rdap_common::prelude::{redacted::Redacted, Domain, RdapResponse, Remark, ToResponse};

use crate::rdap::redacted::RedactedName;

/// Takes in an RDAP response and creates Simple Redactions
/// from the RFC 9537 redactions.
///
/// # Arguments
///
/// * `rdap` is the [RdapResponse] which is altered.
/// * `only_pre_path` only create Simple Redactions when no path expression is given or the prePath expression is present.
pub fn simplify_redactions(rdap: RdapResponse, only_pre_path: bool) -> RdapResponse {
    match rdap {
        RdapResponse::Entity(entity) => {
            // no registered redactions are on plain entities. They must all
            // have roles.
            entity.to_response()
        }
        RdapResponse::Domain(domain) => simplify_domain_redactions(domain, only_pre_path),
        RdapResponse::Nameserver(nameserver) => {
            // no registered redactions on nameservers.
            nameserver.to_response()
        }
        RdapResponse::Autnum(autnum) => {
            // no registered redactions on autnums.
            autnum.to_response()
        }
        RdapResponse::Network(network) => {
            // no registered redactons on networks
            network.to_response()
        }
        _ => {
            // do nothing as RFC 9537 does not explain how or if its redacted
            // directives work against search results or other, non-object class responses.
            rdap
        }
    }
}

fn simplify_domain_redactions(mut domain: Box<Domain>, only_pre_path: bool) -> RdapResponse {
    let binding = domain.object_common.redacted.clone();
    let redactions = binding.as_deref().unwrap_or_default();
    for redaction in redactions {
        if !is_only_pre_path(only_pre_path, redaction) {
            continue;
        }
        if let Some(r_type) = redaction.name().type_field() {
            let r_name = RedactedName::from_str(r_type);
            if let Ok(registered_redaction) = r_name {
                domain = match registered_redaction {
                    RedactedName::RegistryDomainId => simplify_registry_domain_id(domain),
                    RedactedName::RegistryRegistrantId => simplify_registry_registrant_id(domain),
                    RedactedName::RegistrantName => simplify_registrant_name(domain),
                    RedactedName::RegistrantOrganization => todo!(),
                    RedactedName::RegistrantStreet => todo!(),
                    RedactedName::RegistrantCity => todo!(),
                    RedactedName::RegistrantPostalCode => todo!(),
                    RedactedName::RegistrantPhone => todo!(),
                    RedactedName::RegistrantPhoneExt => todo!(),
                    RedactedName::RegistrantFax => todo!(),
                    RedactedName::RegistrantFaxExt => todo!(),
                    RedactedName::RegistrantEmail => todo!(),
                    RedactedName::RegistryTechId => simplify_registry_tech_id(domain),
                    RedactedName::TechName => simplify_tech_name(domain),
                    RedactedName::TechPhone => todo!(),
                    RedactedName::TechPhoneExt => todo!(),
                    RedactedName::TechEmail => todo!(),
                };
            }
        }
    }
    domain.to_response()
}

fn is_only_pre_path(only_pre_path: bool, redaction: &Redacted) -> bool {
    if only_pre_path
        && (redaction.pre_path().is_some()
            || (redaction.post_path().is_none() && redaction.replacement_path().is_none()))
    {
        return true;
    }
    false
}

pub(crate) fn add_remark(
    key: &str,
    desc: &str,
    remarks: Option<Vec<Remark>>,
) -> Option<Vec<Remark>> {
    let mut remarks = remarks.unwrap_or_default();
    if !remarks.iter().any(|r| {
        r.simple_redaction_key
            .as_deref()
            .unwrap_or_default()
            .eq(key)
    }) {
        let remark = Remark::builder()
            .simple_redaction_key(key)
            .description_entry(desc)
            .build();
        remarks.push(remark);
    }
    Some(remarks)
}

#[cfg(test)]
mod tests {
    use super::{add_remark, is_only_pre_path};

    use icann_rdap_common::response::redacted::{Name, Redacted};

    #[test]
    fn test_is_only_pre_path_returns_true_when_only_pre_path_and_pre_path_exists() {
        // GIVEN a redaction with only_pre_path=true and a pre_path
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .pre_path("$.test".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(true, &redaction);

        // THEN it should return true
        assert!(result);
    }

    #[test]
    fn test_is_only_pre_path_returns_true_when_minimal_redaction() {
        // GIVEN a minimal redaction with only_pre_path=true (no paths at all)
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(true, &redaction);

        // THEN it should return true (since post_path and replacement_path are both None)
        assert!(result);
    }

    #[test]
    fn test_is_only_pre_path_returns_false_when_only_pre_path_and_post_path_only() {
        // GIVEN a redaction with only_pre_path=true and post_path but no pre_path
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .post_path("$.post".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(true, &redaction);

        // THEN it should return false
        assert!(!result);
    }

    #[test]
    fn test_is_only_pre_path_returns_false_when_only_pre_path_and_replacement_path_only() {
        // GIVEN a redaction with only_pre_path=true and replacement_path but no pre_path
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .replacement_path("$.replacement".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(true, &redaction);

        // THEN it should return false
        assert!(!result);
    }

    #[test]
    fn test_is_only_pre_path_returns_false_when_only_pre_path_and_post_replacement_paths_no_pre() {
        // GIVEN a redaction with only_pre_path=true, post_path and replacement_path but no pre_path
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .post_path("$.post".to_string())
            .replacement_path("$.replacement".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(true, &redaction);

        // THEN it should return false
        assert!(!result);
    }

    #[test]
    fn test_is_only_pre_path_returns_false_when_only_pre_path_false_with_pre_path() {
        // GIVEN a redaction with only_pre_path=false and pre_path
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .pre_path("$.test".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(false, &redaction);

        // THEN it should return false
        assert!(!result);
    }

    #[test]
    fn test_is_only_pre_path_returns_false_when_only_pre_path_false_with_post_path() {
        // GIVEN a redaction with only_pre_path=false and post_path
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .post_path("$.post".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(false, &redaction);

        // THEN it should return false
        assert!(!result);
    }

    #[test]
    fn test_is_only_pre_path_returns_true_when_only_pre_path_false_with_post_path() {
        // GIVEN a redaction with only_pre_path=true and post_path
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .post_path("$.post".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(true, &redaction);

        // THEN it should return false
        assert!(!result);
    }

    #[test]
    fn test_is_only_pre_path_returns_true_when_only_pre_path_false_with_replacement_path() {
        // GIVEN a redaction with only_pre_path=true and replacement
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .replacement_path("$.post".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(true, &redaction);

        // THEN it should return false
        assert!(!result);
    }

    #[test]
    fn test_is_only_pre_path_returns_false_when_only_pre_path_false_minimal() {
        // GIVEN a minimal redaction with only_pre_path=false
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(false, &redaction);

        // THEN it should return false
        assert!(!result);
    }

    #[test]
    fn test_is_only_pre_path_returns_true_when_only_pre_path_and_all_paths_present() {
        // GIVEN a redaction with only_pre_path=true and all path types
        let redaction = Redacted::builder()
            .name(Name::builder().type_field("Test").build())
            .pre_path("$.pre".to_string())
            .post_path("$.post".to_string())
            .replacement_path("$.replacement".to_string())
            .build();

        // WHEN calling is_only_pre_path
        let result = is_only_pre_path(true, &redaction);

        // THEN it should return true (because pre_path exists)
        assert!(result);
    }

    #[test]
    fn test_add_remark_with_none_remarks() {
        // GIVEN no existing remarks
        let key = "test_key";
        let desc = "test description";
        let remarks = None;

        // WHEN calling add_remark
        let result = add_remark(key, desc, remarks);

        // THEN it should return a vector with one remark
        assert!(result.is_some());
        let result_vec = result.unwrap();
        assert_eq!(result_vec.len(), 1);
        assert_eq!(result_vec[0].simple_redaction_key.as_deref(), Some(key));
        assert_eq!(
            result_vec[0].description.as_ref().unwrap().vec().first(),
            Some(&desc.to_string())
        );
    }

    #[test]
    fn test_add_remark_with_empty_remarks() {
        // GIVEN an empty remarks vector
        let key = "test_key";
        let desc = "test description";
        let remarks = Some(vec![]);

        // WHEN calling add_remark
        let result = add_remark(key, desc, remarks);

        // THEN it should return a vector with one remark
        assert!(result.is_some());
        let result_vec = result.unwrap();
        assert_eq!(result_vec.len(), 1);
        assert_eq!(result_vec[0].simple_redaction_key.as_deref(), Some(key));
        assert_eq!(
            result_vec[0].description.as_ref().unwrap().vec().first(),
            Some(&desc.to_string())
        );
    }

    #[test]
    fn test_add_remark_with_existing_different_key() {
        // GIVEN existing remarks with different keys
        let key = "new_key";
        let desc = "new description";
        let existing_remark = icann_rdap_common::prelude::Remark::builder()
            .simple_redaction_key("existing_key")
            .description_entry("existing description")
            .build();
        let remarks = Some(vec![existing_remark]);

        // WHEN calling add_remark
        let result = add_remark(key, desc, remarks);

        // THEN it should return a vector with two remarks
        assert!(result.is_some());
        let result_vec = result.unwrap();
        assert_eq!(result_vec.len(), 2);
        assert_eq!(
            result_vec[0].simple_redaction_key.as_deref(),
            Some("existing_key")
        );
        assert_eq!(result_vec[1].simple_redaction_key.as_deref(), Some(key));
        assert_eq!(
            result_vec[1].description.as_ref().unwrap().vec().first(),
            Some(&desc.to_string())
        );
    }

    #[test]
    fn test_add_remark_with_existing_same_key() {
        // GIVEN existing remarks with the same key
        let key = "test_key";
        let desc = "new description";
        let existing_remark = icann_rdap_common::prelude::Remark::builder()
            .simple_redaction_key(key)
            .description_entry("existing description")
            .build();
        let remarks = Some(vec![existing_remark]);

        // WHEN calling add_remark
        let result = add_remark(key, desc, remarks);

        // THEN it should return the original vector unchanged (no duplicate key)
        assert!(result.is_some());
        let result_vec = result.unwrap();
        assert_eq!(result_vec.len(), 1);
        assert_eq!(result_vec[0].simple_redaction_key.as_deref(), Some(key));
        assert_eq!(
            result_vec[0].description.as_ref().unwrap().vec().first(),
            Some(&"existing description".to_string())
        );
    }

    #[test]
    fn test_add_remark_with_multiple_existing_remarks_no_duplicate() {
        // GIVEN multiple existing remarks with different keys
        let key = "new_key";
        let desc = "new description";
        let remark1 = icann_rdap_common::prelude::Remark::builder()
            .simple_redaction_key("key1")
            .description_entry("description1")
            .build();
        let remark2 = icann_rdap_common::prelude::Remark::builder()
            .simple_redaction_key("key2")
            .description_entry("description2")
            .build();
        let remarks = Some(vec![remark1, remark2]);

        // WHEN calling add_remark
        let result = add_remark(key, desc, remarks);

        // THEN it should return a vector with three remarks
        assert!(result.is_some());
        let result_vec = result.unwrap();
        assert_eq!(result_vec.len(), 3);
        assert_eq!(result_vec[0].simple_redaction_key.as_deref(), Some("key1"));
        assert_eq!(result_vec[1].simple_redaction_key.as_deref(), Some("key2"));
        assert_eq!(result_vec[2].simple_redaction_key.as_deref(), Some(key));
        assert_eq!(
            result_vec[2].description.as_ref().unwrap().vec().first(),
            Some(&desc.to_string())
        );
    }

    #[test]
    fn test_add_remark_with_multiple_existing_remarks_with_duplicate() {
        // GIVEN multiple existing remarks including one with the same key
        let key = "key2";
        let desc = "new description";
        let remark1 = icann_rdap_common::prelude::Remark::builder()
            .simple_redaction_key("key1")
            .description_entry("description1")
            .build();
        let remark2 = icann_rdap_common::prelude::Remark::builder()
            .simple_redaction_key(key)
            .description_entry("existing description")
            .build();
        let remarks = Some(vec![remark1, remark2]);

        // WHEN calling add_remark
        let result = add_remark(key, desc, remarks);

        // THEN it should return the original vector unchanged (no duplicate key)
        assert!(result.is_some());
        let result_vec = result.unwrap();
        assert_eq!(result_vec.len(), 2);
        assert_eq!(result_vec[0].simple_redaction_key.as_deref(), Some("key1"));
        assert_eq!(result_vec[1].simple_redaction_key.as_deref(), Some(key));
        assert_eq!(
            result_vec[1].description.as_ref().unwrap().vec().first(),
            Some(&"existing description".to_string())
        );
    }

    #[test]
    fn test_add_remark_with_existing_remark_no_simple_redaction_key() {
        // GIVEN existing remarks without simple_redaction_key
        let key = "test_key";
        let desc = "test description";
        let existing_remark = icann_rdap_common::prelude::Remark::builder()
            .description_entry("existing description")
            .build();
        let remarks = Some(vec![existing_remark]);

        // WHEN calling add_remark
        let result = add_remark(key, desc, remarks);

        // THEN it should add the new remark since no existing remark has the same key
        assert!(result.is_some());
        let result_vec = result.unwrap();
        assert_eq!(result_vec.len(), 2);
        assert_eq!(result_vec[0].simple_redaction_key.as_deref(), None);
        assert_eq!(result_vec[1].simple_redaction_key.as_deref(), Some(key));
        assert_eq!(
            result_vec[1].description.as_ref().unwrap().vec().first(),
            Some(&desc.to_string())
        );
    }

    #[test]
    fn test_add_remark_with_empty_key_and_description() {
        // GIVEN empty key and description
        let key = "";
        let desc = "";
        let remarks = None;

        // WHEN calling add_remark
        let result = add_remark(key, desc, remarks);

        // THEN it should still create a remark with empty strings
        assert!(result.is_some());
        let result_vec = result.unwrap();
        assert_eq!(result_vec.len(), 1);
        assert_eq!(result_vec[0].simple_redaction_key.as_deref(), Some(key));
        assert_eq!(
            result_vec[0].description.as_ref().unwrap().vec().first(),
            Some(&desc.to_string())
        );
    }
}
