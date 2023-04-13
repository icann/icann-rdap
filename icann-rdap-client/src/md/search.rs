use icann_rdap_common::response::search::{
    DomainSearchResults, EntitySearchResults, NameserverSearchResults,
};

use super::ToMd;

impl ToMd for DomainSearchResults {
    fn to_md(
        &self,
        heading_level: usize,
        check_types: &[crate::check::CheckType],
        options: &super::MdOptions,
    ) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(heading_level, check_types, options));
        self.results
            .iter()
            .for_each(|result| md.push_str(&result.to_md(heading_level + 1, check_types, options)));
        md.push('\n');
        md
    }
}

impl ToMd for NameserverSearchResults {
    fn to_md(
        &self,
        heading_level: usize,
        check_types: &[crate::check::CheckType],
        options: &super::MdOptions,
    ) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(heading_level, check_types, options));
        self.results
            .iter()
            .for_each(|result| md.push_str(&result.to_md(heading_level + 1, check_types, options)));
        md.push('\n');
        md
    }
}

impl ToMd for EntitySearchResults {
    fn to_md(
        &self,
        heading_level: usize,
        check_types: &[crate::check::CheckType],
        options: &super::MdOptions,
    ) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(heading_level, check_types, options));
        self.results
            .iter()
            .for_each(|result| md.push_str(&result.to_md(heading_level + 1, check_types, options)));
        md.push('\n');
        md
    }
}
