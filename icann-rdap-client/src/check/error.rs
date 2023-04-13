use icann_rdap_common::response::error::Error;

use super::{Checks, GetChecks};

impl GetChecks for Error {
    fn get_checks(&self) -> super::Checks {
        let sub_checks: Vec<Checks> = vec![self.common.get_checks()];
        Checks {
            struct_name: "Error",
            items: Vec::new(),
            sub_checks,
        }
    }
}
