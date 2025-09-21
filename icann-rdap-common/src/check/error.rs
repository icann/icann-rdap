use crate::response::error::Rfc9083Error;

use super::{CheckParams, Checks, GetChecks};

impl GetChecks for Rfc9083Error {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks = if params.do_subchecks {
            let mut sub_checks: Vec<Checks> = vec![];
            if let Some(rdap_conformance) = &self.rdap_conformance {
                sub_checks.push(rdap_conformance.get_checks(params))
            };
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
