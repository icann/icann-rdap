//! Determines of an RFC 9537 registered redaction is present.

use icann_rdap_common::response::{
    RdapResponse, {Entity, EntityRole},
};
use strum_macros::{Display, EnumString};

/// Redacted types in the IANA registry
#[derive(Debug, PartialEq, Eq, EnumString, Display)]
pub enum RedactedName {
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
    #[strum(serialize = "Tech Email")]
    TechEmail,
}

/// This function looks at the RDAP response to see if a
/// redaction is present where the type of redaction is registered
/// with the IANA.
///
/// * rdap_response - a reference to the RDAP response.
/// * redaction_type - a reference to the string registered in the IANA.
pub fn is_redaction_registered(
    rdap_response: &RdapResponse,
    redaction_type: &RedactedName,
) -> bool {
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
                r_type.eq_ignore_ascii_case(&redaction_type.to_string())
            } else {
                false
            }
        })
    } else {
        false
    }
}

/// This function takes a set of [RedactedName]s instead of just one,
/// and runs them through [is_redaction_registered].
pub fn are_redactions_registered(
    rdap_response: &RdapResponse,
    redaction_types: &[&RedactedName],
) -> bool {
    redaction_types
        .iter()
        .any(|rn| is_redaction_registered(rdap_response, rn))
}

/// This function substitutes redaction_text if [is_redaction_registered] returns true.
pub fn text_or_registered_redaction(
    rdap_response: &RdapResponse,
    redaction_type: &RedactedName,
    text: &Option<String>,
    redaction_text: &str,
) -> Option<String> {
    if is_redaction_registered(rdap_response, redaction_type) {
        Some(redaction_text.to_string())
    } else {
        text.clone()
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
    redaction_type: &RedactedName,
    entity: &Entity,
    entity_role: &EntityRole,
) -> bool {
    let roles = entity.roles();
    if roles
        .iter()
        .any(|r| r.eq_ignore_ascii_case(&entity_role.to_string()))
    {
        return is_redaction_registered(rdap_response, redaction_type);
    }
    false
}

/// Same as [is_redaction_registered_for_role] but takes an array of [EntityRole] references.
pub fn are_redactions_registered_for_roles(
    rdap_response: &RdapResponse,
    redaction_type: &[&RedactedName],
    entity: &Entity,
    entity_roles: &[&EntityRole],
) -> bool {
    let roles = entity.roles();
    if roles.iter().any(|r| {
        entity_roles
            .iter()
            .any(|er| r.eq_ignore_ascii_case(&er.to_string()))
    }) {
        return are_redactions_registered(rdap_response, redaction_type);
    }
    false
}

/// This function substitutes redaction_text if [is_redaction_registered_for_role] return true.
pub fn text_or_registered_redaction_for_role(
    rdap_response: &RdapResponse,
    redaction_type: &RedactedName,
    entity: &Entity,
    entity_role: &EntityRole,
    text: &Option<String>,
    redaction_text: &str,
) -> Option<String> {
    if is_redaction_registered_for_role(rdap_response, redaction_type, entity, entity_role) {
        Some(redaction_text.to_string())
    } else {
        text.clone()
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use icann_rdap_common::{
        prelude::ToResponse,
        response::{
            redacted::{Name, Redacted},
            Domain,
        },
    };

    use super::*;

    #[test]
    fn GIVEN_redaction_type_WHEN_search_for_type_THEN_true() {
        // GIVEN
        let domain = Domain::builder()
            .ldh_name("example.com")
            .redacted(vec![Redacted {
                name: Name {
                    description: None,
                    type_field: Some(RedactedName::TechEmail.to_string()),
                },
                reason: None,
                pre_path: None,
                post_path: None,
                path_lang: None,
                replacement_path: None,
                method: None,
            }])
            .build();
        let rdap = domain.to_response();

        // WHEN
        let actual = is_redaction_registered(&rdap, &RedactedName::TechEmail);

        // THEN
        assert!(actual);
    }

    #[test]
    fn GIVEN_redaction_type_WHEN_get_text_for_type_THEN_redacted_text_returned() {
        // GIVEN
        let domain = Domain::builder()
            .ldh_name("example.com")
            .redacted(vec![Redacted {
                name: Name {
                    description: None,
                    type_field: Some(RedactedName::TechEmail.to_string()),
                },
                reason: None,
                pre_path: None,
                post_path: None,
                path_lang: None,
                replacement_path: None,
                method: None,
            }])
            .build();
        let rdap = domain.to_response();

        // WHEN
        let actual = text_or_registered_redaction(
            &rdap,
            &RedactedName::TechEmail,
            &Some("not_redacted".to_string()),
            "redacted",
        );

        // THEN
        assert_eq!(actual, Some("redacted".to_string()));
    }

    #[test]
    fn GIVEN_multiple_redaction_type_WHEN_search_for_one_of_the_types_THEN_true() {
        // GIVEN
        let domain = Domain::builder()
            .ldh_name("example.com")
            .redacted(vec![
                Redacted {
                    name: Name {
                        description: None,
                        type_field: Some(RedactedName::TechEmail.to_string()),
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
                        type_field: Some(RedactedName::RegistryRegistrantId.to_string()),
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
        let rdap = domain.to_response();

        // WHEN
        let actual = is_redaction_registered(&rdap, &RedactedName::TechEmail);

        // THEN
        assert!(actual);
    }

    #[test]
    fn GIVEN_multiple_redaction_type_WHEN_search_for_multiple_that_some_exist_THEN_true() {
        // GIVEN
        let domain = Domain::builder()
            .ldh_name("example.com")
            .redacted(vec![
                Redacted {
                    name: Name {
                        description: None,
                        type_field: Some(RedactedName::TechEmail.to_string()),
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
                        type_field: Some(RedactedName::RegistryRegistrantId.to_string()),
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
        let rdap = domain.to_response();

        // WHEN
        let actual = are_redactions_registered(
            &rdap,
            &[&RedactedName::TechEmail, &RedactedName::RegistrantName],
        );

        // THEN
        assert!(actual);
    }

    #[test]
    fn GIVEN_multiple_redaction_type_WHEN_search_for_multiple_that_not_exist_THEN_false() {
        // GIVEN
        let domain = Domain::builder()
            .ldh_name("example.com")
            .redacted(vec![
                Redacted {
                    name: Name {
                        description: None,
                        type_field: Some(RedactedName::TechEmail.to_string()),
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
                        type_field: Some(RedactedName::RegistryRegistrantId.to_string()),
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
        let rdap = domain.to_response();

        // WHEN
        let actual = are_redactions_registered(
            &rdap,
            &[
                &RedactedName::RegistrantPhone,
                &RedactedName::RegistrantName,
            ],
        );

        // THEN
        assert!(!actual);
    }

    #[test]
    fn GIVEN_no_redactions_WHEN_search_for_type_THEN_false() {
        // GIVEN
        let domain = Domain::builder().ldh_name("example.com").build();
        let rdap = domain.to_response();

        // WHEN
        let actual = is_redaction_registered(&rdap, &RedactedName::TechEmail);

        // THEN
        assert!(!actual);
    }

    #[test]
    fn GIVEN_redaction_type_WHEN_search_for_wrong_type_THEN_false() {
        // GIVEN
        let domain = Domain::builder()
            .ldh_name("example.com")
            .redacted(vec![Redacted {
                name: Name {
                    description: None,
                    type_field: Some(RedactedName::RegistryRegistrantId.to_string()),
                },
                reason: None,
                pre_path: None,
                post_path: None,
                path_lang: None,
                replacement_path: None,
                method: None,
            }])
            .build();
        let rdap = domain.to_response();

        // WHEN
        let actual = is_redaction_registered(&rdap, &RedactedName::TechEmail);

        // THEN
        assert!(!actual);
    }

    #[test]
    fn GIVEN_entity_and_redaction_type_WHEN_search_for_type_on_entity_with_role_THEN_true() {
        // GIVEN
        let domain = Domain::builder()
            .ldh_name("example.com")
            .redacted(vec![Redacted {
                name: Name {
                    description: None,
                    type_field: Some(RedactedName::TechEmail.to_string()),
                },
                reason: None,
                pre_path: None,
                post_path: None,
                path_lang: None,
                replacement_path: None,
                method: None,
            }])
            .build();
        let rdap = domain.to_response();
        let role = EntityRole::Technical.to_string();
        let entity = Entity::builder()
            .handle("foo_bar")
            .role(role.clone())
            .build();

        // WHEN
        let actual = is_redaction_registered_for_role(
            &rdap,
            &RedactedName::TechEmail,
            &entity,
            &EntityRole::Technical,
        );

        // THEN
        assert!(actual);
    }

    #[test]
    fn GIVEN_entity_and_multiple_redaction_WHEN_search_for_multipe_type_on_entity_with_roles_THEN_true(
    ) {
        // GIVEN
        let domain = Domain::builder()
            .ldh_name("example.com")
            .redacted(vec![
                Redacted {
                    name: Name {
                        description: None,
                        type_field: Some(RedactedName::TechEmail.to_string()),
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
                        type_field: Some(RedactedName::RegistryRegistrantId.to_string()),
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
        let rdap = domain.to_response();
        let role = EntityRole::Technical.to_string();
        let entity = Entity::builder()
            .handle("foo_bar")
            .role(role.clone())
            .build();

        // WHEN
        let actual = are_redactions_registered_for_roles(
            &rdap,
            &[&RedactedName::TechEmail, &RedactedName::TechPhoneExt],
            &entity,
            &[&EntityRole::Technical, &EntityRole::Abuse],
        );

        // THEN
        assert!(actual);
    }

    #[test]
    fn GIVEN_entity_and_multiple_redaction_WHEN_search_for_not_exist_type_on_entity_with_roles_THEN_false(
    ) {
        // GIVEN
        let domain = Domain::builder()
            .ldh_name("example.com")
            .redacted(vec![
                Redacted {
                    name: Name {
                        description: None,
                        type_field: Some(RedactedName::TechEmail.to_string()),
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
                        type_field: Some(RedactedName::RegistryRegistrantId.to_string()),
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
        let rdap = domain.to_response();
        let role = EntityRole::Technical.to_string();
        let entity = Entity::builder()
            .handle("foo_bar")
            .role(role.clone())
            .build();

        // WHEN
        let actual = are_redactions_registered_for_roles(
            &rdap,
            &[&RedactedName::TechPhone, &RedactedName::TechPhoneExt],
            &entity,
            &[&EntityRole::Technical, &EntityRole::Abuse],
        );

        // THEN
        assert!(!actual);
    }

    #[test]
    fn GIVEN_entity_and_multiple_redaction_WHEN_search_for_type_on_entity_with_other_rolesroles_THEN_false(
    ) {
        // GIVEN
        let domain = Domain::builder()
            .ldh_name("example.com")
            .redacted(vec![
                Redacted {
                    name: Name {
                        description: None,
                        type_field: Some(RedactedName::TechEmail.to_string()),
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
                        type_field: Some(RedactedName::RegistryRegistrantId.to_string()),
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
        let rdap = domain.to_response();
        let role = EntityRole::Technical.to_string();
        let entity = Entity::builder()
            .handle("foo_bar")
            .role(role.clone())
            .build();

        // WHEN
        let actual = are_redactions_registered_for_roles(
            &rdap,
            &[&RedactedName::TechEmail, &RedactedName::TechPhoneExt],
            &entity,
            &[&EntityRole::Billing, &EntityRole::Abuse],
        );

        // THEN
        assert!(!actual);
    }

    #[test]
    fn GIVEN_entity_and_redaction_type_WHEN_get_text_for_type_on_entity_with_role_THEN_redaction_text_returned(
    ) {
        // GIVEN
        let domain = Domain::builder()
            .ldh_name("example.com")
            .redacted(vec![Redacted {
                name: Name {
                    description: None,
                    type_field: Some(RedactedName::TechEmail.to_string()),
                },
                reason: None,
                pre_path: None,
                post_path: None,
                path_lang: None,
                replacement_path: None,
                method: None,
            }])
            .build();
        let rdap = domain.to_response();
        let role = EntityRole::Technical.to_string();
        let entity = Entity::builder()
            .handle("foo_bar")
            .role(role.clone())
            .build();

        // WHEN
        let actual = text_or_registered_redaction_for_role(
            &rdap,
            &RedactedName::TechEmail,
            &entity,
            &EntityRole::Technical,
            &Some("not_redacted".to_string()),
            "redacted",
        );

        // THEN
        assert_eq!(actual, Some("redacted".to_string()));
    }
}
