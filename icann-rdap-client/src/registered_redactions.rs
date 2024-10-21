//! Determines of an RFC 9537 registered redaction is present.

use icann_rdap_common::response::{entity::Entity, RdapResponse};
use strum_macros::EnumString;

/// Redacted types in the IANA registry
#[derive(Debug, PartialEq, Eq, EnumString)]
pub enum Iana {
    #[strum(serialize = "Registry Domain ID")]
    RegistryDomainId,
    #[strum(serialize = "Registry Registrant ID")]
    RegistryRegistrantId,
    #[strum(serialize = "Registrant Name")]
    RegistrantName,
    #[strum(serialize = "Registrant Organization")]
    RegistrantOrganization,
    #[strum(serialize = "Registrant Street")]
    RegistrantStreet,
    #[strum(serialize = "Registrant City")]
    RegistrantCity,
    #[strum(serialize = "Registrant Postal Code")]
    RegistrantPostalCode,
    #[strum(serialize = "Registrant Phone")]
    RegistrantPhone,
    #[strum(serialize = "Registrant Phone Ext")]
    RegistrantPhoneExt,
    #[strum(serialize = "Registrant Fax")]
    RegistrantFax,
    #[strum(serialize = "Registrant Fax Ext")]
    RegistrantFaxExt,
    #[strum(serialize = "Registrant Email")]
    RegistrantEmail,
    #[strum(serialize = "Registry Tech ID")]
    RegistryTechId,
    #[strum(serialize = "Tech Name")]
    TechName,
    #[strum(serialize = "Tech Phone")]
    TechPhone,
    #[strum(serialize = "Tech Phone Ext")]
    TechPhoneExt,
    #[strum(serialize = "Tech Phone Email")]
    TechEmail,
}

/// This function looks at the RDAP response to see if a
/// redaction is present where the type of redaction is registered
/// with the IANA.
///
/// * rdap_response - a reference to the RDAP response.
/// * redaction_type - a reference to the string registered in the IANA.
pub fn is_redaction_registered(rdap_response: &RdapResponse, redaction_type: &str) -> bool {
    let object_common = match rdap_response {
        RdapResponse::Entity(e) => Some(&e.object_common.redacted),
        RdapResponse::Domain(d) => Some(&d.object_common.redacted),
        RdapResponse::Nameserver(s) => Some(&s.object_common.redacted),
        RdapResponse::Autnum(a) => Some(&a.object_common.redacted),
        RdapResponse::Network(n) => Some(&n.object_common.redacted),
        _ => None,
    };
    if let Some(Some(redacted_vec)) = object_common {
        redacted_vec.iter().any(|r| {
            if let Some(r_type) = &r.name.type_field {
                r_type.eq_ignore_ascii_case(redaction_type)
            } else {
                false
            }
        })
    } else {
        false
    }
}

/// This function checks that an entity has a certain role, and if so then
/// checks of the redaction is registered for IANA.
///
/// * rdap_response - a reference to the RDAP response.
/// * redaction_type - a reference to the string registered in the IANA.
/// * entity - a reference to the entity to check
/// * role - the role of the entity
pub fn is_redaction_registered_for_role(
    rdap_response: &RdapResponse,
    redaction_type: &str,
    entity: &Entity,
    role: &str,
) -> bool {
    if let Some(roles) = &entity.roles {
        if roles.iter().any(|r| r.eq_ignore_ascii_case(role)) {
            return is_redaction_registered(rdap_response, redaction_type);
        }
    }
    false
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use icann_rdap_common::response::{
        domain::Domain,
        redacted::{Name, Redacted},
    };

    use super::*;

    #[test]
    fn GIVEN_redaction_type_WHEN_search_for_type_THEN_true() {
        // GIVEN
        let r_type = "tech_email".to_string();
        let domain = Domain::basic()
            .ldh_name("example.com")
            .redacted(vec![Redacted {
                name: Name {
                    description: None,
                    type_field: Some(r_type.clone()),
                },
                reason: None,
                pre_path: None,
                post_path: None,
                path_lang: None,
                replacement_path: None,
                method: None,
            }])
            .build();
        let rdap = RdapResponse::Domain(domain);

        // WHEN
        let actual = is_redaction_registered(&rdap, &r_type);

        // THEN
        assert!(actual);
    }

    #[test]
    fn GIVEN_multiple_redaction_type_WHEN_search_for_one_of_the_types_THEN_true() {
        // GIVEN
        let r_type = "tech_email".to_string();
        let domain = Domain::basic()
            .ldh_name("example.com")
            .redacted(vec![
                Redacted {
                    name: Name {
                        description: None,
                        type_field: Some(r_type.clone()),
                    },
                    reason: None,
                    pre_path: None,
                    post_path: None,
                    path_lang: None,
                    replacement_path: None,
                    method: None,
                },
                Redacted {
                    name: Name {
                        description: None,
                        type_field: Some("some_other_type".to_string()),
                    },
                    reason: None,
                    pre_path: None,
                    post_path: None,
                    path_lang: None,
                    replacement_path: None,
                    method: None,
                },
            ])
            .build();
        let rdap = RdapResponse::Domain(domain);

        // WHEN
        let actual = is_redaction_registered(&rdap, &r_type);

        // THEN
        assert!(actual);
    }

    #[test]
    fn GIVEN_no_redactions_WHEN_search_for_type_THEN_false() {
        // GIVEN
        let r_type = "tech_email".to_string();
        let domain = Domain::basic().ldh_name("example.com").build();
        let rdap = RdapResponse::Domain(domain);

        // WHEN
        let actual = is_redaction_registered(&rdap, &r_type);

        // THEN
        assert!(!actual);
    }

    #[test]
    fn GIVEN_redaction_type_WHEN_search_for_wrong_type_THEN_false() {
        // GIVEN
        let r_type = "tech_email".to_string();
        let domain = Domain::basic()
            .ldh_name("example.com")
            .redacted(vec![Redacted {
                name: Name {
                    description: None,
                    type_field: Some("some_other_type".to_string()),
                },
                reason: None,
                pre_path: None,
                post_path: None,
                path_lang: None,
                replacement_path: None,
                method: None,
            }])
            .build();
        let rdap = RdapResponse::Domain(domain);

        // WHEN
        let actual = is_redaction_registered(&rdap, &r_type);

        // THEN
        assert!(!actual);
    }

    #[test]
    fn GIVEN_entity_and_redaction_type_WHEN_search_for_type_on_entity_with_role_THEN_true() {
        // GIVEN
        let r_type = "tech_email".to_string();
        let domain = Domain::basic()
            .ldh_name("example.com")
            .redacted(vec![Redacted {
                name: Name {
                    description: None,
                    type_field: Some(r_type.clone()),
                },
                reason: None,
                pre_path: None,
                post_path: None,
                path_lang: None,
                replacement_path: None,
                method: None,
            }])
            .build();
        let rdap = RdapResponse::Domain(domain);
        let role = "technical".to_string();
        let entity = Entity::basic().handle("foo_bar").role(role.clone()).build();

        // WHEN
        let actual = is_redaction_registered_for_role(&rdap, &r_type, &entity, &role);

        // THEN
        assert!(actual);
    }
}
