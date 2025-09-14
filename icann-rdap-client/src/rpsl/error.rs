use icann_rdap_common::prelude::{CommonFields, Rfc9083Error};

use crate::rpsl::{RpslParams, ToRpsl};

use super::{push_manditory_attribute, push_notices};

impl ToRpsl for Rfc9083Error {
    fn to_rpsl(&self, _params: RpslParams) -> String {
        let mut rpsl = String::new();

        // error code
        rpsl = push_manditory_attribute(
            rpsl,
            super::AttrName::ErrorCode,
            &self.error_code().to_string(),
        );

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        //end
        rpsl.push('\n');

        rpsl
    }
}
