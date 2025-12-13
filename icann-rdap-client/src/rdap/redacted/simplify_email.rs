//! Simplify redaction of names

use icann_rdap_common::prelude::{Domain, EntityRole};

use crate::rdap::redacted::add_remark;

static REDACTED_EMAIL: &str = "redacted_email@redacted.invalid";
static REDACTED_EMAIL_DESC: &str = "Email redacted.";

pub(crate) fn simplify_registrant_email(mut domain: Box<Domain>) -> Box<Domain> {
    simplify_email(domain, &EntityRole::Registrant)
}

pub(crate) fn simplify_tech_email(domain: Box<Domain>) -> Box<Domain> {
    simplify_email(domain, &EntityRole::Technical)
}

fn simplify_email(mut domain: Box<Domain>, role: &EntityRole) -> Box<Domain> {
    if let Some(entities) = &mut domain.object_common.entities {
        for entity in entities.iter_mut() {
            if entity.is_entity_role(&role.to_string()) {
                let contact = entity.contact();
                if let Some(mut contact) = contact {
                    if let Some(mut emails) = contact.emails {
                        for email in emails.iter_mut() {
                            email.email = REDACTED_EMAIL.to_string();
                        }
                        contact.emails = Some(emails);
                    }
                    entity.vcard_array = Some(contact.to_vcard());
                    entity.object_common.remarks = add_remark(
                        REDACTED_EMAIL,
                        REDACTED_EMAIL_DESC,
                        entity.object_common.remarks.clone(),
                    );
                    break; // Only modify first entity
                }
            }
        }
    }
    domain
}

#[cfg(test)]
mod tests {
    use icann_rdap_common::prelude::Remark;
    use icann_rdap_common::prelude::{Contact, Entity};
    use icann_rdap_common::response::ObjectCommonFields;
    use serde_json::Value;

    use super::*;
}
