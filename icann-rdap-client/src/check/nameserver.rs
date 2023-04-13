use icann_rdap_common::response::nameserver::Nameserver;

use super::{Checks, GetChecks};

impl GetChecks for Nameserver {
    fn get_checks(&self) -> super::Checks {
        let mut sub_checks: Vec<Checks> = vec![self.common.get_checks()];
        sub_checks.push(self.object_common.get_checks());
        Checks {
            struct_name: "Nameserver",
            items: Vec::new(),
            sub_checks,
        }
    }
}
