use icann_rdap_common::response::types::{Common, Link, Links, Notices, ObjectCommon, Remarks};
use icann_rdap_common::response::types::{NoticeOrRemark, RdapConformance};

use crate::check::GetChecks;

use super::{to_bold, to_header, to_right, to_right_em, MdParams, HR};
use super::{to_em, ToMd};

impl ToMd for RdapConformance {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::from("RDAP Server Conformance:\n");
        self.iter()
            .for_each(|s| md.push_str(&format!("* {}\n", s.0)));
        self.get_checks()
            .items
            .iter()
            .filter(|item| params.check_types.contains(&item.check_type))
            .for_each(|item| md.push_str(&format!("* _{}_: {}\n", item.check_type, item.message)));
        md.push('\n');
        md
    }
}

impl ToMd for Links {
    fn to_md(&self, mdparams: MdParams) -> String {
        let mut md = String::new();
        self.iter()
            .for_each(|link| md.push_str(&link.to_md(mdparams)));
        md
    }
}

impl ToMd for Link {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        let key_width = 8;
        if let Some(title) = &self.title {
            md.push_str(&format!("Link: {title}\n"));
        } else {
            md.push_str("Link:\n")
        };
        md.push_str(&format!(
            "* {}: {}\n",
            to_right("href", key_width, params.options),
            self.href
        ));
        if let Some(rel) = &self.rel {
            md.push_str(&format!(
                "* {}: {}\n",
                to_right("rel", key_width, params.options),
                rel
            ));
        };
        if let Some(value) = &self.value {
            md.push_str(&format!(
                "* {}: {}\n",
                to_right("value", key_width, params.options),
                value
            ));
        };
        if let Some(hreflang) = &self.hreflang {
            md.push_str(&format!(
                "* {}: {}\n",
                to_right("hreflang", key_width, params.options),
                hreflang.join(", ")
            ));
        };
        if let Some(media) = &self.media {
            md.push_str(&format!(
                "* {}: {}\n",
                to_right("media", key_width, params.options),
                media
            ));
        };
        if let Some(media_type) = &self.media_type {
            md.push_str(&format!(
                "* {}: {}\n",
                to_right("type", key_width, params.options),
                media_type
            ));
        };
        let checks = self.get_checks();
        checks
            .items
            .iter()
            .filter(|item| params.check_types.contains(&item.check_type))
            .for_each(|item| {
                md.push_str(&format!(
                    "* {}: {}\n",
                    to_right_em(&item.check_type.to_string(), key_width, params.options),
                    item.message
                ))
            });
        md.push('\n');
        md
    }
}

impl ToMd for Notices {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        self.iter()
            .for_each(|notice| md.push_str(&notice.0.to_md(params)));
        md
    }
}

impl ToMd for Remarks {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        self.iter()
            .for_each(|remark| md.push_str(&remark.0.to_md(params)));
        md
    }
}

impl ToMd for NoticeOrRemark {
    fn to_md(
        &self,
        MdParams {
            heading_level,
            check_types,
            options,
        }: MdParams,
    ) -> String {
        let mut md = String::new();
        if let Some(title) = &self.title {
            md.push_str(&format!("{}\n", to_bold(title, options)));
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
                    to_em(&item.check_type.to_string(), options),
                    item.message
                ))
            });
        if let Some(links) = &self.links {
            links.iter().for_each(|link| {
                md.push_str(&link.to_md(MdParams {
                    heading_level,
                    check_types,
                    options,
                }))
            });
        }
        md.push('\n');
        md
    }
}

impl ToMd for Common {
    fn to_md(
        &self,
        MdParams {
            heading_level,
            check_types,
            options,
        }: MdParams,
    ) -> String {
        let mut md = String::new();
        let not_empty = self.rdap_conformance.is_some() || self.notices.is_some();
        if not_empty {
            md.push('\n');
            md.push_str(HR);
        };
        if let Some(rdap_conformance) = &self.rdap_conformance {
            md.push_str(&rdap_conformance.to_md(MdParams {
                heading_level,
                check_types,
                options,
            }));
        };
        if let Some(notices) = &self.notices {
            md.push_str(&to_header("Server Notices", heading_level, options));
            md.push_str(&notices.to_md(MdParams {
                heading_level,
                check_types,
                options,
            }));
        }
        if not_empty {
            md.push_str(HR);
        };
        md
    }
}

impl ToMd for ObjectCommon {
    fn to_md(
        &self,
        MdParams {
            heading_level,
            check_types,
            options,
        }: MdParams,
    ) -> String {
        let mut md = String::new();
        if let Some(remarks) = &self.remarks {
            md.push_str(&remarks.to_md(MdParams {
                heading_level: heading_level + 1,
                check_types,
                options,
            }));
        };
        if let Some(links) = &self.links {
            md.push_str(&links.to_md(MdParams {
                heading_level: heading_level + 1,
                check_types,
                options,
            }));
        };
        if let Some(entities) = &self.entities {
            entities.iter().for_each(|entity| {
                md.push_str(&entity.to_md(MdParams {
                    heading_level: heading_level + 1,
                    check_types,
                    options,
                }))
            });
        }
        md
    }
}
