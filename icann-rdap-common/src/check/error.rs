use std::any::TypeId;

use crate::response::error::Error;

use super::{CheckParams, Checks, GetChecks, GetSubChecks};

impl GetChecks for Error {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks = if params.do_subchecks {
            let sub_checks: Vec<Checks> = self
                .common
                .get_sub_checks(params.from_parent(TypeId::of::<Error>()));
            sub_checks
        } else {
            Vec::new()
        };
        Checks {
            rdap_struct: super::RdapStructure::Error,
            items: Vec::new(),
            sub_checks,
        }
    }
}
