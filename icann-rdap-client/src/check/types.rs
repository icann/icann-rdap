use icann_rdap_common::response::types::{
    Common, Link, Links, NoticeOrRemark, Notices, ObjectCommon, RdapConformance, Remarks,
};

use super::{CheckItem, CheckType, Checks, GetChecks};

impl GetChecks for RdapConformance {
    fn get_checks(&self) -> Checks {
        Checks {
            struct_name: "RDAP Conformance",
            items: Vec::new(),
            sub_checks: Vec::new(),
        }
    }
}

impl GetChecks for Links {
    fn get_checks(&self) -> Checks {
        let mut sub_checks: Vec<Checks> = Vec::new();
        self.iter()
            .for_each(|link| sub_checks.push(link.get_checks()));
        Checks {
            struct_name: "Links",
            items: Vec::new(),
            sub_checks,
        }
    }
}

impl GetChecks for Link {
    fn get_checks(&self) -> Checks {
        let mut items: Vec<CheckItem> = Vec::new();
        if self.value.is_none() {
            items.push(CheckItem {
                check_type: CheckType::SpecificationCompliance,
                message: "'value' property not found in Link structure as required by RFC 7083"
                    .to_string(),
            })
        };
        if self.rel.is_none() {
            items.push(CheckItem {
                check_type: CheckType::SpecificationCompliance,
                message: "'rel' property not found in Link structure as required by RFC 7083"
                    .to_string(),
            })
        };
        Checks {
            struct_name: "Link",
            items,
            sub_checks: Vec::new(),
        }
    }
}

impl GetChecks for Notices {
    fn get_checks(&self) -> Checks {
        let mut sub_checks: Vec<Checks> = Vec::new();
        self.iter()
            .for_each(|note| sub_checks.push(note.0.get_checks()));
        Checks {
            struct_name: "Notices",
            items: Vec::new(),
            sub_checks,
        }
    }
}

impl GetChecks for Remarks {
    fn get_checks(&self) -> Checks {
        let mut sub_checks: Vec<Checks> = Vec::new();
        self.iter()
            .for_each(|remark| sub_checks.push(remark.0.get_checks()));
        Checks {
            struct_name: "Remarks",
            items: Vec::new(),
            sub_checks,
        }
    }
}

impl GetChecks for NoticeOrRemark {
    fn get_checks(&self) -> Checks {
        let mut sub_checks: Vec<Checks> = Vec::new();
        if let Some(links) = &self.links {
            links
                .iter()
                .for_each(|link| sub_checks.push(link.get_checks()));
        };
        Checks {
            struct_name: "Notice/Remark",
            items: Vec::new(),
            sub_checks,
        }
    }
}

impl GetChecks for Common {
    fn get_checks(&self) -> Checks {
        let mut sub_checks: Vec<Checks> = Vec::new();
        if let Some(rdap_conformance) = &self.rdap_conformance {
            sub_checks.push(rdap_conformance.get_checks())
        };
        if let Some(notices) = &self.notices {
            sub_checks.push(notices.get_checks())
        };
        Checks {
            struct_name: "Common RDAP Response Structures",
            items: Vec::new(),
            sub_checks,
        }
    }
}

impl GetChecks for ObjectCommon {
    fn get_checks(&self) -> Checks {
        let mut sub_checks: Vec<Checks> = Vec::new();
        if let Some(entities) = &self.entities {
            entities
                .iter()
                .for_each(|e| sub_checks.push(e.get_checks()))
        };
        if let Some(links) = &self.links {
            sub_checks.push(links.get_checks());
        };
        if let Some(remarks) = &self.remarks {
            sub_checks.push(remarks.get_checks())
        };
        // TODO get handle
        // TODO get object_class_name
        // TODO get events
        // TODO get status
        // TODO get port43
        Checks {
            struct_name: "Common RDAP ObjectClass Structures",
            items: Vec::new(),
            sub_checks,
        }
    }
}
