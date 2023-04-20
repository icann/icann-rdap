use std::any::TypeId;

use icann_rdap_common::response::autnum::Autnum;

use super::{CheckParams, Checks, GetChecks};

impl GetChecks for Autnum {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks = if params.do_subchecks {
            let mut sub_checks: Vec<Checks> = vec![self
                .common
                .get_checks(params.from_parent(TypeId::of::<Autnum>()))];
            sub_checks.push(
                self.object_common
                    .get_checks(params.from_parent(TypeId::of::<Autnum>())),
            );
            sub_checks
        } else {
            Vec::new()
        };
        Checks {
            struct_name: "Autnum",
            items: Vec::new(),
            sub_checks,
        }
    }
}
