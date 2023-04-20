use std::any::TypeId;

use icann_rdap_common::response::help::Help;

use super::{CheckParams, Checks, GetChecks};

impl GetChecks for Help {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks = if params.do_subchecks {
            let sub_checks: Vec<Checks> = vec![self
                .common
                .get_checks(params.from_parent(TypeId::of::<Help>()))];
            sub_checks
        } else {
            Vec::new()
        };
        Checks {
            struct_name: "Help",
            items: Vec::new(),
            sub_checks,
        }
    }
}
