use icann_rdap_common::response::domain::Domain;

use super::{Checks, GetChecks};

impl GetChecks for Domain {
    fn get_checks(&self) -> super::Checks {
        let mut sub_checks: Vec<Checks> = vec![self.common.get_checks()];
        sub_checks.push(self.object_common.get_checks());
        Checks {
            struct_name: "Domain",
            items: Vec::new(),
            sub_checks,
        }
    }
}