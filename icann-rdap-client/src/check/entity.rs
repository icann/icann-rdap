use icann_rdap_common::response::entity::Entity;

use super::{Checks, GetChecks};

impl GetChecks for Entity {
    fn get_checks(&self) -> super::Checks {
        let mut sub_checks: Vec<Checks> = vec![self.common.get_checks()];
        sub_checks.push(self.object_common.get_checks());
        Checks {
            struct_name: "Entity",
            items: Vec::new(),
            sub_checks,
        }
    }
}
