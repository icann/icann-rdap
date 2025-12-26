use std::any::TypeId;

use crate::response::error::Rfc9083Error;

use super::{CheckParams, Checks, GetChecks, GetGroupChecks};

impl GetChecks for Rfc9083Error {
    fn get_checks(&self, index: Option<usize>, params: CheckParams) -> super::Checks {
        let sub_checks = {
            let sub_checks = self
                .common
                .get_group_checks(params.from_parent(TypeId::of::<Self>()));
            sub_checks
        };
        Checks {
            rdap_struct: super::RdapStructure::Error,
            index,
            items: vec![],
            sub_checks,
        }
    }
}
