use std::any::TypeId;

use crate::response::domain::Domain;

use super::{Check, CheckItem, CheckParams, Checks, GetChecks, GetSubChecks};

impl GetChecks for Domain {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks = if params.do_subchecks {
            let mut sub_checks: Vec<Checks> = self
                .common
                .get_sub_checks(params.from_parent(TypeId::of::<Domain>()));
            sub_checks.append(
                &mut self
                    .object_common
                    .get_sub_checks(params.from_parent(TypeId::of::<Domain>())),
            );
            sub_checks
        } else {
            Vec::new()
        };

        let mut items = Vec::new();
        if let Some(variants) = &self.variants {
            let empty_count = variants
                .iter()
                .filter(|v| {
                    v.relation.is_none() && v.idn_table.is_none() && v.variant_names.is_none()
                })
                .count();
            if empty_count != 0 {
                items.push(CheckItem {
                    check_class: super::CheckClass::SpecificationWarning,
                    check: Check::EmptyDomainVariant,
                });
            };
        };

        Checks {
            struct_name: "Domain",
            items,
            sub_checks,
        }
    }
}
