use std::any::TypeId;

use crate::response::error::Rfc9083Error;

use super::{CheckParams, Checks, GetChecks, GetSubChecks};

impl GetChecks for Rfc9083Error {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks = if params.do_subchecks {
            let sub_checks: Vec<Checks> = self
                .common
                .get_sub_checks(params.from_parent(TypeId::of::<Self>()));
            sub_checks
        } else {
            vec![]
        };
        Checks {
            rdap_struct: super::RdapStructure::Error,
            items: vec![],
            sub_checks,
        }
    }
}
