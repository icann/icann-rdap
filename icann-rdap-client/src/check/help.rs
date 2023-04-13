use icann_rdap_common::response::help::Help;

use super::{Checks, GetChecks};

impl GetChecks for Help {
    fn get_checks(&self) -> super::Checks {
        let sub_checks: Vec<Checks> = vec![self.common.get_checks()];
        Checks {
            struct_name: "Help",
            items: Vec::new(),
            sub_checks,
        }
    }
}
