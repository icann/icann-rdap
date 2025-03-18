use std::any::TypeId;

use crate::response::search::{DomainSearchResults, EntitySearchResults, NameserverSearchResults};

use super::{CheckParams, Checks, GetChecks, GetSubChecks};

impl GetChecks for DomainSearchResults {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks: Vec<Checks> = if params.do_subchecks {
            let mut sub_checks = self
                .common
                .get_sub_checks(params.from_parent(TypeId::of::<Self>()));
            self.results.iter().for_each(|result| {
                sub_checks.push(
                    result.get_checks(params.from_parent(TypeId::of::<Self>())),
                )
            });
            sub_checks
        } else {
            vec![]
        };
        Checks {
            rdap_struct: super::RdapStructure::DomainSearchResults,
            items: vec![],
            sub_checks,
        }
    }
}

impl GetChecks for NameserverSearchResults {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks: Vec<Checks> = if params.do_subchecks {
            let mut sub_checks: Vec<Checks> = self
                .common
                .get_sub_checks(params.from_parent(TypeId::of::<Self>()));
            self.results.iter().for_each(|result| {
                sub_checks.push(
                    result.get_checks(params.from_parent(TypeId::of::<Self>())),
                )
            });
            sub_checks
        } else {
            vec![]
        };
        Checks {
            rdap_struct: super::RdapStructure::NameserverSearchResults,
            items: vec![],
            sub_checks,
        }
    }
}

impl GetChecks for EntitySearchResults {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks: Vec<Checks> = if params.do_subchecks {
            let mut sub_checks: Vec<Checks> = self
                .common
                .get_sub_checks(params.from_parent(TypeId::of::<Self>()));
            self.results.iter().for_each(|result| {
                sub_checks.push(
                    result.get_checks(params.from_parent(TypeId::of::<Self>())),
                )
            });
            sub_checks
        } else {
            vec![]
        };
        Checks {
            rdap_struct: super::RdapStructure::EntitySearchResults,
            items: vec![],
            sub_checks,
        }
    }
}
