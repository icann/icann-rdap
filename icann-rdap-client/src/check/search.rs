use icann_rdap_common::response::search::{
    DomainSearchResults, EntitySearchResults, NameserverSearchResults,
};

use super::{Checks, GetChecks};

impl GetChecks for DomainSearchResults {
    fn get_checks(&self) -> super::Checks {
        let mut sub_checks: Vec<Checks> = vec![self.common.get_checks()];
        self.results
            .iter()
            .for_each(|result| sub_checks.push(result.get_checks()));
        Checks {
            struct_name: "Domain Search Results",
            items: Vec::new(),
            sub_checks,
        }
    }
}

impl GetChecks for NameserverSearchResults {
    fn get_checks(&self) -> super::Checks {
        let mut sub_checks: Vec<Checks> = vec![self.common.get_checks()];
        self.results
            .iter()
            .for_each(|result| sub_checks.push(result.get_checks()));
        Checks {
            struct_name: "Nameserver Search Results",
            items: Vec::new(),
            sub_checks,
        }
    }
}

impl GetChecks for EntitySearchResults {
    fn get_checks(&self) -> super::Checks {
        let mut sub_checks: Vec<Checks> = vec![self.common.get_checks()];
        self.results
            .iter()
            .for_each(|result| sub_checks.push(result.get_checks()));
        Checks {
            struct_name: "Entity Search Results",
            items: Vec::new(),
            sub_checks,
        }
    }
}
