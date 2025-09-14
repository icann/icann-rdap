use icann_rdap_common::prelude::{
    CommonFields, DomainSearchResults, EntitySearchResults, NameserverSearchResults,
};

use crate::rpsl::{RpslParams, ToRpsl};

use super::push_notices;

impl ToRpsl for DomainSearchResults {
    fn to_rpsl(&self, params: RpslParams) -> String {
        let mut rpsl = String::new();

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        for domain in self.results() {
            rpsl.push_str(&domain.to_rpsl(params));
        }

        //end
        rpsl.push('\n');

        rpsl
    }
}

impl ToRpsl for NameserverSearchResults {
    fn to_rpsl(&self, params: RpslParams) -> String {
        let mut rpsl = String::new();

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        for ns in self.results() {
            rpsl.push_str(&ns.to_rpsl(params));
        }

        //end
        rpsl.push('\n');

        rpsl
    }
}

impl ToRpsl for EntitySearchResults {
    fn to_rpsl(&self, params: RpslParams) -> String {
        let mut rpsl = String::new();

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        for entity in self.results() {
            rpsl.push_str(&entity.to_rpsl(params));
        }

        //end
        rpsl.push('\n');

        rpsl
    }
}
