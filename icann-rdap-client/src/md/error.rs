use icann_rdap_common::{check::StringCheck, response::Rfc9083Error};

use crate::md::string::StringUtil;

use super::{MdHeaderText, MdParams, MdUtil, ToMd};

impl ToMd for Rfc9083Error {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent()));
        md.push('\n');
        md.push_str(&format!("Error Code: {}", self.error_code).to_em(params.options));
        md.push('\n');
        if let Some(title) = &self.title {
            md.push_str(&format!("{}\n", title.to_bold(params.options)));
        };
        for line in self.description() {
            if !line.is_whitespace_or_empty() {
                md.push_str(&format!("> {}\n\n", line.replace_md_chars()))
            }
        }
        md.push('\n');
        md
    }
}

impl MdUtil for Rfc9083Error {
    fn get_header_text(&self) -> MdHeaderText {
        MdHeaderText::builder().header_text("RDAP Error").build()
    }
}

#[cfg(test)]
mod test {
    use std::io::Write;

    use goldenfile::Mint;
    use icann_rdap_common::{
        httpdata::HttpData,
        prelude::{RdapResponse, Rfc9083Error},
    };

    use crate::{
        md::{MdOptions, MdParams, ToMd},
        rdap::RequestData,
    };

    static MINT_PATH: &str = "src/test_files/md/error";
    #[test]
    fn test_md_error() {
        // GIVEN error
        let error = Rfc9083Error::response_obj()
            .error_code(404)
            .description_entry("Resource not found.")
            .build();

        // WHEN
        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
        };
        let params = MdParams {
            heading_level: 1,
            root: &RdapResponse::ErrorResponse(Box::new(error.clone())),
            http_data: &http_data,
            options: &MdOptions::default(),
            req_data: &req_data,
            show_rfc9537_redactions: false,
            highlight_simple_redactions: false,
        };
        let actual = error.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("404_with_description.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }
}
