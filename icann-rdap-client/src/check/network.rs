use icann_rdap_common::response::network::Network;

use super::{Checks, GetChecks};

impl GetChecks for Network {
    fn get_checks(&self) -> super::Checks {
        let mut sub_checks: Vec<Checks> = vec![self.common.get_checks()];
        sub_checks.push(self.object_common.get_checks());
        Checks {
            struct_name: "Network",
            items: Vec::new(),
            sub_checks,
        }
    }
}
