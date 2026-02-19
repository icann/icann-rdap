use icann_rdap_common::prelude::{CommonFields, Rfc9083Error};

use crate::rpsl::{RpslParams, ToRpsl};

use super::{push_mandatory_attribute, push_notices};

impl ToRpsl for Rfc9083Error {
    fn to_rpsl(&self, _params: RpslParams) -> String {
        let mut rpsl = String::new();

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        // error code
        rpsl = push_mandatory_attribute(
            rpsl,
            super::AttrName::ErrorCode,
            &self.error_code().to_string(),
        );

        if let Some(title) = self.title() {
            rpsl = push_mandatory_attribute(rpsl, super::AttrName::ErrorTitle, title);
        }

        for line in self.description() {
            rpsl = push_mandatory_attribute(rpsl, super::AttrName::ErrorDescription, line);
        }

        //end
        rpsl.push('\n');

        rpsl
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use goldenfile::Mint;
    use icann_rdap_common::{httpdata::HttpData, prelude::Rfc9083Error};

    use crate::rpsl::{RpslParams, ToRpsl};

    static MINT_PATH: &str = "src/test_files/rpsl/error";

    #[test]
    fn test_rpsl_error_with_description() {
        // GIVEN
        let error = Rfc9083Error::response_obj()
            .error_code(404)
            .description_entry("Resource not found.")
            .build();

        // WHEN
        let http_data = HttpData::example().build();
        let params = RpslParams {
            http_data: &http_data,
        };
        let actual = error.to_rpsl(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_404_and_description.txt").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }
}
