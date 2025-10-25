use std::any::TypeId;

use crate::response::search::{DomainSearchResults, EntitySearchResults, NameserverSearchResults};

use super::{CheckParams, Checks, GetChecks, GetGroupChecks};

impl GetChecks for DomainSearchResults {
    fn get_checks(&self, index: Option<usize>, params: CheckParams) -> super::Checks {
        let sub_checks: Vec<Checks> = {
            let mut sub_checks = self
                .common
                .get_group_checks(params.from_parent(TypeId::of::<Self>()));
            self.results.iter().enumerate().for_each(|(i, result)| {
                sub_checks
                    .push(result.get_checks(Some(i), params.from_parent(TypeId::of::<Self>())))
            });
            sub_checks
        };
        Checks {
            rdap_struct: super::RdapStructure::DomainSearchResults,
            index,
            items: vec![],
            sub_checks,
        }
    }
}

impl GetChecks for NameserverSearchResults {
    fn get_checks(&self, index: Option<usize>, params: CheckParams) -> super::Checks {
        let sub_checks: Vec<Checks> = {
            let mut sub_checks: Vec<Checks> = self
                .common
                .get_group_checks(params.from_parent(TypeId::of::<Self>()));
            self.results.iter().enumerate().for_each(|(i, result)| {
                sub_checks
                    .push(result.get_checks(Some(i), params.from_parent(TypeId::of::<Self>())))
            });
            sub_checks
        };
        Checks {
            rdap_struct: super::RdapStructure::NameserverSearchResults,
            index,
            items: vec![],
            sub_checks,
        }
    }
}

impl GetChecks for EntitySearchResults {
    fn get_checks(&self, index: Option<usize>, params: CheckParams) -> super::Checks {
        let sub_checks: Vec<Checks> = {
            let mut sub_checks: Vec<Checks> = self
                .common
                .get_group_checks(params.from_parent(TypeId::of::<Self>()));
            self.results.iter().enumerate().for_each(|(i, result)| {
                sub_checks
                    .push(result.get_checks(Some(i), params.from_parent(TypeId::of::<Self>())))
            });
            sub_checks
        };
        Checks {
            rdap_struct: super::RdapStructure::EntitySearchResults,
            index,
            items: vec![],
            sub_checks,
        }
    }
}
