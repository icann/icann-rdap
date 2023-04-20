use std::any::TypeId;

use icann_rdap_common::response::nameserver::Nameserver;

use super::{CheckParams, Checks, GetChecks};

impl GetChecks for Nameserver {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks = if params.do_subchecks {
            let mut sub_checks: Vec<Checks> = vec![self
                .common
                .get_checks(params.from_parent(TypeId::of::<Nameserver>()))];
            sub_checks.push(
                self.object_common
                    .get_checks(params.from_parent(TypeId::of::<Nameserver>())),
            );
            sub_checks
        } else {
            Vec::new()
        };
        Checks {
            struct_name: "Nameserver",
            items: Vec::new(),
            sub_checks,
        }
    }
}
