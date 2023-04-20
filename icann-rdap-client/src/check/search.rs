use std::any::TypeId;

use icann_rdap_common::response::search::{
    DomainSearchResults, EntitySearchResults, NameserverSearchResults,
};

use super::{CheckParams, Checks, GetChecks};

impl GetChecks for DomainSearchResults {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks: Vec<Checks> = if params.do_subchecks {
            let mut sub_checks = vec![self
                .common
                .get_checks(params.from_parent(TypeId::of::<DomainSearchResults>()))];
            self.results.iter().for_each(|result| {
                sub_checks.push(
                    result.get_checks(params.from_parent(TypeId::of::<DomainSearchResults>())),
                )
            });
            sub_checks
        } else {
            Vec::new()
        };
        Checks {
            struct_name: "Domain Search Results",
            items: Vec::new(),
            sub_checks,
        }
    }
}

impl GetChecks for NameserverSearchResults {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks: Vec<Checks> = if params.do_subchecks {
            let mut sub_checks: Vec<Checks> = vec![self
                .common
                .get_checks(params.from_parent(TypeId::of::<NameserverSearchResults>()))];
            self.results.iter().for_each(|result| {
                sub_checks.push(
                    result.get_checks(params.from_parent(TypeId::of::<NameserverSearchResults>())),
                )
            });
            sub_checks
        } else {
            Vec::new()
        };
        Checks {
            struct_name: "Nameserver Search Results",
            items: Vec::new(),
            sub_checks,
        }
    }
}

impl GetChecks for EntitySearchResults {
    fn get_checks(&self, params: CheckParams) -> super::Checks {
        let sub_checks: Vec<Checks> = if params.do_subchecks {
            let mut sub_checks: Vec<Checks> = vec![self
                .common
                .get_checks(params.from_parent(TypeId::of::<EntitySearchResults>()))];
            self.results.iter().for_each(|result| {
                sub_checks.push(
                    result.get_checks(params.from_parent(TypeId::of::<EntitySearchResults>())),
                )
            });
            sub_checks
        } else {
            Vec::new()
        };
        Checks {
            struct_name: "Entity Search Results",
            items: Vec::new(),
            sub_checks,
        }
    }
}
