use icann_rdap_common::prelude::Rfc9083Error;

use crate::rpsl::{RpslParams, ToRpsl};

use super::push_manditory_attribute;

impl ToRpsl for Rfc9083Error {
    fn to_rpsl(&self, _params: RpslParams) -> String {
        let mut rpsl = String::new();

        // error code
        rpsl = push_manditory_attribute(
            rpsl,
            super::AttrName::ErrorCode,
            &self.error_code().to_string(),
        );

        if let Some(title) = self.title() {
            rpsl.push_str(&format!("# {title}\n"));
        }
        for line in self.description() {
            rpsl.push_str(&format!("# {line}\n"));
        }

        //end
        rpsl.push('\n');

        rpsl
    }
}
