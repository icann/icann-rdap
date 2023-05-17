use std::any::TypeId;

use crate::response::network::Network;

use super::{CheckParams, Checks, GetChecks, GetSubChecks};

impl GetChecks for Network {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks = if params.do_subchecks {
            let mut sub_checks: Vec<Checks> = self
                .common
                .get_sub_checks(params.from_parent(TypeId::of::<Network>()));
            sub_checks.append(
                &mut self
                    .object_common
                    .get_sub_checks(params.from_parent(TypeId::of::<Network>())),
            );
            sub_checks
        } else {
            Vec::new()
        };
        Checks {
            struct_name: "Network",
            items: Vec::new(),
            sub_checks,
        }
    }
}
