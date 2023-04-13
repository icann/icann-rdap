use icann_rdap_common::response::autnum::Autnum;

use super::{Checks, GetChecks};

impl GetChecks for Autnum {
    fn get_checks(&self) -> super::Checks {
        let mut sub_checks: Vec<Checks> = vec![self.common.get_checks()];
        sub_checks.push(self.object_common.get_checks());
        Checks {
            struct_name: "Autnum",
            items: Vec::new(),
            sub_checks,
        }
    }
}
