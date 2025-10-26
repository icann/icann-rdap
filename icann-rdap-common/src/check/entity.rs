use std::{any::TypeId, str::FromStr};

use crate::{contact::Contact, prelude::EntityRole, response::entity::Entity};

use super::{
    string::{StringCheck, StringListCheck},
    Check, CheckParams, Checks, GetChecks, GetGroupChecks, RdapStructure,
};

impl GetChecks for Entity {
    fn get_checks(&self, index: Option<usize>, params: CheckParams) -> super::Checks {
        let sub_checks = {
            let mut sub_checks: Vec<Checks> = vec![];
            sub_checks.append(&mut GetGroupChecks::get_group_checks(
                &self.common,
                params.from_parent(TypeId::of::<Self>()),
            ));
            sub_checks.append(
                &mut self
                    .object_common
                    .get_group_checks(params.from_parent(TypeId::of::<Self>())),
            );
            if let Some(public_ids) = &self.public_ids {
                sub_checks.push(public_ids.get_checks(None, params));
            }

            // nets
            for (i, net) in self.networks().iter().enumerate() {
                sub_checks.push(net.get_checks(Some(i), params));
            }

            // autnums
            for (i, asn) in self.autnums().iter().enumerate() {
                sub_checks.push(asn.get_checks(Some(i), params));
            }

            sub_checks
        };

        let mut items = vec![];

        if let Some(roles) = &self.roles {
            if roles.is_string() {
                items.push(Check::RoleIsString.check_item());
            }
            let roles = roles.vec();
            if roles.is_empty_or_any_empty_or_whitespace() {
                items.push(Check::RoleIsEmpty.check_item());
            } else {
                for role in roles {
                    let r = EntityRole::from_str(role);
                    if r.is_err() {
                        items.push(Check::UnknownRole.check_item());
                    }
                }
            }
        }

        if let Some(vcard) = &self.vcard_array {
            if let Some(contact) = Contact::from_vcard(vcard) {
                if let Some(full_name) = contact.full_name {
                    if full_name.is_whitespace_or_empty() {
                        items.push(Check::VcardFnIsEmpty.check_item())
                    }
                } else {
                    items.push(Check::VcardHasNoFn.check_item())
                }
            } else {
                items.push(Check::VcardArrayIsEmpty.check_item())
            }
        }

        Checks {
            rdap_struct: RdapStructure::Entity,
            index,
            items,
            sub_checks,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        check::{contains_check, Check, CheckParams, GetChecks},
        prelude::{Autnum, Entity, Network, ToResponse},
    };

    #[test]
    fn test_entity_with_entity_empty_handle() {
        // GIVEN
        let entity = Entity::builder()
            .handle("foo")
            .entity(Entity::builder().handle("").build())
            .build()
            .to_response();

        // WHEN
        let checks = entity.get_checks(None, CheckParams::for_rdap(&entity));

        // THEN
        assert!(contains_check(Check::HandleIsEmpty, &checks));
    }

    #[test]
    fn test_entity_with_net_empty_handle() {
        // GIVEN
        let entity = Entity::builder()
            .handle("foo")
            .network(
                Network::builder()
                    .cidr("10.0.0.0/8")
                    .handle("")
                    .build()
                    .unwrap(),
            )
            .build()
            .to_response();

        // WHEN
        let checks = entity.get_checks(None, CheckParams::for_rdap(&entity));

        // THEN
        assert!(contains_check(Check::HandleIsEmpty, &checks));
    }

    #[test]
    fn test_entity_with_autnum_empty_handle() {
        // GIVEN
        let entity = Entity::builder()
            .handle("foo")
            .autnum(Autnum::builder().autnum_range(701..703).handle("").build())
            .build()
            .to_response();

        // WHEN
        let checks = entity.get_checks(None, CheckParams::for_rdap(&entity));

        // THEN
        assert!(contains_check(Check::HandleIsEmpty, &checks));
    }
}
