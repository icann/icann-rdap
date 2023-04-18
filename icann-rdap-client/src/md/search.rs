use icann_rdap_common::response::search::{
    DomainSearchResults, EntitySearchResults, NameserverSearchResults,
};

use super::{MdParams, ToMd};

impl ToMd for DomainSearchResults {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params));
        self.results.iter().for_each(|result| {
            md.push_str(&result.to_md(MdParams {
                heading_level: params.heading_level + 1,
                ..params
            }))
        });
        md.push('\n');
        md
    }
}

impl ToMd for NameserverSearchResults {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params));
        self.results.iter().for_each(|result| {
            md.push_str(&result.to_md(MdParams {
                heading_level: params.heading_level + 1,
                ..params
            }))
        });
        md.push('\n');
        md
    }
}

impl ToMd for EntitySearchResults {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params));
        self.results.iter().for_each(|result| {
            md.push_str(&result.to_md(MdParams {
                heading_level: params.heading_level + 1,
                ..params
            }))
        });
        md.push('\n');
        md
    }
}
