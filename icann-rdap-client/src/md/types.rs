use std::any::TypeId;
use std::cmp::max;

use icann_rdap_common::response::types::{Common, Link, Links, Notices, ObjectCommon, Remarks};
use icann_rdap_common::response::types::{NoticeOrRemark, RdapConformance};
use strum::EnumMessage;

use crate::check::{CheckParams, GetChecks, GetSubChecks, CHECK_CLASS_LEN};

use super::{to_bold, to_header, to_right, to_right_em, MdParams, SimpleTable, HR};
use super::{to_em, ToMd};

impl ToMd for RdapConformance {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&to_header(
            &format!("{} Capabilities", params.req_data.source_host),
            params.heading_level + 1,
            params.options,
        ));
        self.iter()
            .for_each(|s| md.push_str(&format!("* {}\n", s.0)));
        self.get_checks(CheckParams::from_md_no_parent(params))
            .items
            .iter()
            .filter(|item| params.check_types.contains(&item.check_class))
            .for_each(|item| {
                md.push_str(&format!(
                    "* {}: {}\n", // TODO fix!
                    to_em(&item.check_class.to_string(), params.options),
                    item.check
                        .get_message()
                        .expect("Check has no message. Coding error.")
                ))
            });
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
        // the max of the values in RDAP link is 'hreflang' which 8
        let key_width = max(8, *CHECK_CLASS_LEN);
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
        let checks = self.get_checks(CheckParams::from_md(params, TypeId::of::<Link>()));
        checks
            .items
            .iter()
            .filter(|item| params.check_types.contains(&item.check_class))
            .for_each(|item| {
                md.push_str(&format!(
                    "* {}: {}\n",
                    to_right_em(&item.check_class.to_string(), key_width, params.options),
                    item.check
                        .get_message()
                        .expect("Check has no message. Coding error.")
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
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        if let Some(title) = &self.title {
            md.push_str(&format!("{}\n", to_bold(title, params.options)));
        };
        self.description
            .iter()
            .for_each(|s| md.push_str(&format!("{s}\n")));
        self.get_checks(CheckParams::from_md(params, TypeId::of::<NoticeOrRemark>()))
            .items
            .iter()
            .filter(|item| params.check_types.contains(&item.check_class))
            .for_each(|item| {
                md.push_str(&format!(
                    "* {}: {}\n",
                    to_em(&item.check_class.to_string(), params.options),
                    item.check
                        .get_message()
                        .expect("Check has no message. Coding error.")
                ))
            });
        if let Some(links) = &self.links {
            links
                .iter()
                .for_each(|link| md.push_str(&link.to_md(params)));
        }
        md.push('\n');
        md
    }
}

impl ToMd for Common {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        let not_empty = self.rdap_conformance.is_some() || self.notices.is_some();
        if not_empty {
            md.push('\n');
            md.push_str(HR);
            let header_text = format!(
                "Response from {} at {}",
                params.req_data.source_type, params.req_data.source_host
            );
            md.push_str(&to_header(
                &header_text,
                params.heading_level,
                params.options,
            ));
        };
        if let Some(rdap_conformance) = &self.rdap_conformance {
            md.push_str(&rdap_conformance.to_md(params));
        };
        if let Some(notices) = &self.notices {
            md.push_str(&to_header(
                "Server Notices",
                params.heading_level + 1,
                params.options,
            ));
            md.push_str(&notices.to_md(params));
        }
        if not_empty {
            md.push_str(HR);
        };
        md
    }
}

impl ToMd for ObjectCommon {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();

        // events
        if let Some(events) = &self.events {
            let mut table = SimpleTable::new("Events");
            for event in events {
                let mut ul: Vec<&String> = vec![&event.event_date];
                if let Some(event_actor) = &event.event_actor {
                    ul.push(event_actor);
                }
                table = table.row_ul(&event.event_action, ul);
            }
            md.push_str(&table.to_md(params));
        }

        // remarks
        if let Some(remarks) = &self.remarks {
            md.push_str(&remarks.to_md(MdParams {
                heading_level: params.heading_level + 1,
                ..params
            }));
        };

        // links
        if let Some(links) = &self.links {
            md.push_str(&links.to_md(MdParams {
                heading_level: params.heading_level + 1,
                ..params
            }));
        } else {
            let link_checks = self.get_sub_checks(CheckParams::from_md_no_parent(params));
            if !link_checks.is_empty() {
                md.push('\n');
                link_checks.iter().for_each(|check| {
                    check
                        .items
                        .iter()
                        .filter(|item| params.check_types.contains(&item.check_class))
                        .for_each(|item| {
                            md.push_str(&format!(
                                "* {}: {}\n",
                                to_right_em(
                                    &item.check_class.to_string(),
                                    *CHECK_CLASS_LEN,
                                    params.options
                                ),
                                item.check
                                    .get_message()
                                    .expect("Check has no message. Coding error.")
                            ))
                        })
                });
                md.push('\n');
            }
        };

        // entities
        if let Some(entities) = &self.entities {
            entities.iter().for_each(|entity| {
                md.push_str(&entity.to_md(MdParams {
                    heading_level: params.heading_level + 1,
                    ..params
                }))
            });
        }
        md
    }
}
