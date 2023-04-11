use icann_rdap_common::response::types::{Common, Link, Links, Notices, Remarks};
use icann_rdap_common::response::types::{NoticeOrRemark, RdapConformance};

use crate::check::CheckType;
use crate::check::GetChecks;

use super::{to_bold, to_header, CODE_INDENT};
use super::{to_em, ToMd};

impl ToMd for RdapConformance {
    fn to_md(&self, _heading_level: usize, check_types: &[CheckType]) -> String {
        let mut md = String::from("RDAP Server Conformance:\n");
        self.iter()
            .for_each(|s| md.push_str(&format!("* {}\n", s.0)));
        self.get_checks()
            .items
            .iter()
            .filter(|item| check_types.contains(&item.check_type))
            .for_each(|item| md.push_str(&format!("* _{}_: {}\n", item.check_type, item.message)));
        md.push('\n');
        md
    }
}

impl ToMd for Links {
    fn to_md(&self, heading_level: usize, check_types: &[CheckType]) -> String {
        let mut md = String::new();
        self.iter()
            .for_each(|link| md.push_str(&link.to_md(heading_level, check_types)));
        md
    }
}

impl ToMd for Link {
    fn to_md(&self, _heading_level: usize, check_types: &[CheckType]) -> String {
        let mut md = String::new();
        let key_width = 8;
        if let Some(title) = &self.title {
            md.push_str(&format!("{CODE_INDENT}Link: {title}\n"));
        } else {
            md.push_str(&format!("{CODE_INDENT}Link:\n"))
        };
        md.push_str(&format!(
            "{CODE_INDENT}{:>key_width$}: {}\n",
            "href", self.href
        ));
        if let Some(rel) = &self.rel {
            md.push_str(&format!("{CODE_INDENT}{:>key_width$}: {}\n", "rel", rel));
        };
        if let Some(value) = &self.value {
            md.push_str(&format!(
                "{CODE_INDENT}{:>key_width$}: {}\n",
                "value", value
            ));
        };
        if let Some(hreflang) = &self.hreflang {
            md.push_str(&format!(
                "{CODE_INDENT}{:>key_width$}: {}\n",
                "hreflang",
                hreflang.join(", ")
            ));
        };
        if let Some(media) = &self.media {
            md.push_str(&format!(
                "{CODE_INDENT}{:>key_width$}: {}\n",
                "media", media
            ));
        };
        if let Some(media_type) = &self.media_type {
            md.push_str(&format!(
                "{CODE_INDENT}{:>key_width$}: {}\n",
                "type", media_type
            ));
        };
        let checks = self.get_checks();
        checks
            .items
            .iter()
            .filter(|item| check_types.contains(&item.check_type))
            .for_each(|item| {
                md.push_str(&format!(
                    "{CODE_INDENT}{:>key_width$}: {}\n",
                    to_em(&item.check_type.to_string()),
                    item.message
                ))
            });
        md.push('\n');
        md
    }
}

impl ToMd for Notices {
    fn to_md(&self, heading_level: usize, check_types: &[CheckType]) -> String {
        let mut md = String::new();
        self.iter()
            .for_each(|notice| md.push_str(&notice.0.to_md(heading_level, check_types)));
        md
    }
}

impl ToMd for Remarks {
    fn to_md(&self, heading_level: usize, check_types: &[CheckType]) -> String {
        let mut md = String::new();
        self.iter()
            .for_each(|remark| md.push_str(&remark.0.to_md(heading_level, check_types)));
        md
    }
}

impl ToMd for NoticeOrRemark {
    fn to_md(&self, heading_level: usize, check_types: &[CheckType]) -> String {
        let mut md = String::new();
        if let Some(title) = &self.title {
            md.push_str(&format!("{}\n", to_bold(title)));
        };
        self.description
            .iter()
            .for_each(|s| md.push_str(&format!("> {s}\n")));
        self.get_checks()
            .items
            .iter()
            .filter(|item| check_types.contains(&item.check_type))
            .for_each(|item| {
                md.push_str(&format!(
                    "* {}: {}\n",
                    to_em(&item.check_type.to_string()),
                    item.message
                ))
            });
        if let Some(links) = &self.links {
            links
                .iter()
                .for_each(|link| md.push_str(&link.to_md(heading_level, check_types)));
        }
        md.push('\n');
        md
    }
}

impl ToMd for Common {
    fn to_md(&self, heading_level: usize, check_types: &[CheckType]) -> String {
        let mut md = String::new();
        md.push_str("\n---\n");
        if let Some(rdap_conformance) = &self.rdap_conformance {
            md.push_str(&rdap_conformance.to_md(heading_level, check_types));
        };
        if let Some(notices) = &self.notices {
            md.push_str(&to_header("Server Notices\n\n", heading_level));
            md.push_str(&notices.to_md(heading_level, check_types));
        }
        md.push_str("---\n");
        md
    }
}
