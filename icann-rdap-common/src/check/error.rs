use crate::response::error::Rfc9083Error;

use super::{CheckParams, Checks, GetChecks};

impl GetChecks for Rfc9083Error {
    fn get_checks(&self, index: Option<usize>, params: CheckParams) -> super::Checks {
        let sub_checks = {
            let mut sub_checks: Vec<Checks> = vec![];
            if let Some(rdap_conformance) = &self.rdap_conformance {
                sub_checks.push(rdap_conformance.get_checks(None, params))
            };
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
