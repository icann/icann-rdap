use std::any::TypeId;

use icann_rdap_common::response::domain::Domain;

use super::{CheckParams, Checks, GetChecks};

impl GetChecks for Domain {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks = if params.do_subchecks {
            let mut sub_checks: Vec<Checks> = vec![self
                .common
                .get_checks(params.from_parent(TypeId::of::<Domain>()))];
            sub_checks.push(
                self.object_common
                    .get_checks(params.from_parent(TypeId::of::<Domain>())),
            );
            sub_checks
        } else {
            Vec::new()
        };
        Checks {
            struct_name: "Domain",
            items: Vec::new(),
            sub_checks,
        }
    }
}
