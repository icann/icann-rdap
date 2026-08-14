use icann_rdap_common::prelude::{CommonFields, Help};

use crate::rpsl::{RpslParams, ToRpsl};

use super::{push_extensions, push_notices};

impl ToRpsl for Help {
    fn to_rpsl(&self, _params: RpslParams) -> String {
        let mut rpsl = String::new();

        // extensions are comments before the objects
        rpsl = push_extensions(rpsl, self.extensions());

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        //end
        rpsl.push('\n');

        rpsl
    }
}
