use std::any::TypeId;

use crate::{contact::Contact, response::entity::Entity};

use super::{
    string::{StringCheck, StringListCheck},
    CheckItem, CheckParams, Checks, GetChecks, GetSubChecks,
};

impl GetChecks for Entity {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks = if params.do_subchecks {
            let mut sub_checks: Vec<Checks> = self
                .common
                .get_sub_checks(params.from_parent(TypeId::of::<Entity>()));
            sub_checks.append(
                &mut self
                    .object_common
                    .get_sub_checks(params.from_parent(TypeId::of::<Entity>())),
            );
            sub_checks
        } else {
            Vec::new()
        };

        let mut items = Vec::new();

        if let Some(roles) = &self.roles {
            if roles.as_slice().is_empty_or_any_empty_or_whitespace() {
                items.push(CheckItem::roles_are_empty());
            }
        }

        if let Some(vcard) = &self.vcard_array {
            if let Some(contact) = Contact::from_vcard(vcard) {
                if let Some(full_name) = contact.full_name {
                    if full_name.is_whitespace_or_empty() {
                        items.push(CheckItem::vcard_fn_is_empty())
                    }
                } else {
                    items.push(CheckItem::vcard_has_no_fn())
                }
            } else {
                items.push(CheckItem::vcard_array_is_empty())
            }
        }

        Checks {
            struct_name: "Entity",
            items,
            sub_checks,
        }
    }
}
