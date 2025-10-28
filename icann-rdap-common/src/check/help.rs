use std::any::TypeId;

use crate::response::help::Help;

use super::{CheckParams, Checks, GetChecks, GetGroupChecks};

impl GetChecks for Help {
    fn get_checks(&self, index: Option<usize>, params: CheckParams) -> super::Checks {
        let sub_checks = {
            let sub_checks = self
                .common
                .get_group_checks(params.from_parent(TypeId::of::<Self>()));
            sub_checks
        };
        Checks {
            rdap_struct: super::RdapStructure::Help,
            index,
            items: vec![],
            sub_checks,
        }
    }
}
