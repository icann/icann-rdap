use icann_rdap_common::prelude::ObjectCommon;
use std::any::TypeId;

use lazy_static::lazy_static;

use icann_rdap_common::check::StringCheck;
use icann_rdap_common::httpdata::HttpData;
use icann_rdap_common::response::{Common, Event, Link, Links, Notices, PublicId, Remarks};
use icann_rdap_common::response::{NoticeOrRemark, RdapConformance};
use reqwest::header::{
    ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_LENGTH, EXPIRES, HOST,
    STRICT_TRANSPORT_SECURITY,
};
use strum::EnumMessage;

use icann_rdap_common::check::{
    CheckClass, CheckItem, CheckParams, Checks, GetChecks, CHECK_CLASS_LEN,
};

use super::string::{StringListUtil, StringUtil};
use super::table::{MultiPartTable, ToMpTable};
use super::{checks_ul, MdParams, HR};
use super::{FromMd, ToMd};

impl ToMd for RdapConformance {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(
            &format!(
                "{} Conformance Claims",
                params.req_data.source_host.to_title_case()
            )
            .to_header(5, params.options),
        );
        self.iter().for_each(|s| {
            md.push_str(&format!(
                "* {}\n",
                s.0.replace('_', " ")
                    .to_cap_acronyms()
                    .to_words_title_case()
            ))
        });
        self.get_checks(CheckParams::from_md_no_parent(params))
            .items
            .iter()
            .filter(|item| params.check_types.contains(&item.check_class))
            .for_each(|item| {
                md.push_str(&format!(
                    "* {}: {}\n",
                    item.check_class.to_string().to_em(params.options),
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
        if let Some(title) = &self.title {
            md.push_str(&format!("* {}:\n", title.replace_ws()));
        } else {
            md.push_str("* Link:\n")
        };
        if let Some(href) = &self.href {
            md.push_str(&format!(
                "* {}\n",
                href.to_owned().to_inline(params.options)
            ));
        };
        if let Some(rel) = &self.rel {
            md.push_str(&format!("* Relation:  {}\n", rel.replace_ws()));
        };
        if let Some(media_type) = &self.media_type {
            md.push_str(&format!("* Type:      {}\n", media_type.replace_ws()));
        };
        if let Some(media) = &self.media {
            md.push_str(&format!("* Media:     {}\n", media.replace_ws()));
        };
        if let Some(value) = &self.value {
            md.push_str(&format!("* Value:     {}\n", value.replace_ws()));
        };
        if let Some(hreflang) = &self.hreflang {
            match hreflang {
                icann_rdap_common::response::HrefLang::Lang(lang) => {
                    md.push_str(&format!("* Language:  {}\n", lang.replace_ws()));
                }
                icann_rdap_common::response::HrefLang::Langs(langs) => {
                    md.push_str(&format!("* Languages: {}", langs.join(", ").replace_ws()));
                }
            }
        };
        let checks = self.get_checks(CheckParams::from_md(params, TypeId::of::<Link>()));
        md.push_str(&checks_ul(&checks, params));
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

impl ToMd for Option<Remarks> {
    fn to_md(&self, params: MdParams) -> String {
        if let Some(remarks) = &self {
            remarks.to_md(params)
        } else {
            String::new()
        }
    }
}

impl ToMd for NoticeOrRemark {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        if let Some(title) = &self.title {
            md.push_str(&format!("{}\n", title.to_bold(params.options)));
        };
        if let Some(nr_type) = &self.nr_type {
            md.push_str(&format!("Type: {}\n", nr_type.to_words_title_case()));
        };
        if let Some(description) = &self.description {
            description.vec().iter().for_each(|s| {
                if !s.is_whitespace_or_empty() {
                    md.push_str(&format!("> {}\n\n", s.trim().replace_ws()))
                }
            });
        }
        self.get_checks(CheckParams::from_md(params, TypeId::of::<NoticeOrRemark>()))
            .items
            .iter()
            .filter(|item| params.check_types.contains(&item.check_class))
            .for_each(|item| {
                md.push_str(&format!(
                    "* {}: {}\n",
                    &item.check_class.to_string().to_em(params.options),
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
                params.req_data.source_type,
                params.req_data.source_host.to_title_case()
            );
            md.push_str(&header_text.to_header(params.heading_level, params.options));
        };
        if let Some(rdap_conformance) = &self.rdap_conformance {
            md.push_str(&rdap_conformance.to_md(params));
        };
        if let Some(notices) = &self.notices {
            md.push_str(&"Server Notices".to_header(5, params.options));
            md.push_str(&notices.to_md(params));
        }
        if not_empty {
            md.push_str(HR);
        };
        md
    }
}

const RECEIVED: &str = "Received";
const REQUEST_URI: &str = "Request URI";

lazy_static! {
    pub static ref NAMES: [String; 7] = [
        HOST.to_string(),
        reqwest::header::EXPIRES.to_string(),
        reqwest::header::CACHE_CONTROL.to_string(),
        reqwest::header::STRICT_TRANSPORT_SECURITY.to_string(),
        reqwest::header::ACCESS_CONTROL_ALLOW_ORIGIN.to_string(),
        RECEIVED.to_string(),
        REQUEST_URI.to_string()
    ];
    pub static ref NAME_LEN: usize = NAMES
        .iter()
        .max_by_key(|x| x.to_string().len())
        .map_or(8, |x| x.to_string().len());
}

impl ToMd for HttpData {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = HR.to_string();
        md.push_str(&format!(" * {:<NAME_LEN$}: {}\n", HOST, &self.host));
        if let Some(request_uri) = &self.request_uri {
            md.push_str(&format!(" * {:<NAME_LEN$}: {}\n", REQUEST_URI, request_uri));
        }
        if let Some(content_length) = &self.content_length {
            md.push_str(&format!(
                " * {:<NAME_LEN$}: {}\n",
                CONTENT_LENGTH, content_length
            ));
        }
        if let Some(expires) = &self.expires {
            md.push_str(&format!(" * {:<NAME_LEN$}: {}\n", EXPIRES, expires));
        }
        if let Some(cache_control) = &self.cache_control {
            md.push_str(&format!(
                " * {:<NAME_LEN$}: {}\n",
                CACHE_CONTROL, cache_control
            ));
        }
        if let Some(strict_transport_security) = &self.strict_transport_security {
            md.push_str(&format!(
                " * {:<NAME_LEN$}: {}\n",
                STRICT_TRANSPORT_SECURITY, strict_transport_security
            ));
        }
        if let Some(access_control_allow_origin) = &self.access_control_allow_origin {
            md.push_str(&format!(
                " * {:<NAME_LEN$}: {}\n",
                ACCESS_CONTROL_ALLOW_ORIGIN, access_control_allow_origin
            ));
        }
        md.push_str(&format!(" * {RECEIVED:<NAME_LEN$}: {}\n", &self.received));
        self.get_checks(CheckParams::from_md(params, TypeId::of::<NoticeOrRemark>()))
            .items
            .iter()
            .filter(|item| params.check_types.contains(&item.check_class))
            .for_each(|item| {
                md.push_str(&format!(
                    "* {}: {}\n",
                    &item.check_class.to_string().to_em(params.options),
                    item.check
                        .get_message()
                        .expect("Check has no message. Coding error.")
                ))
            });
        md
    }
}

impl ToMpTable for ObjectCommon {
    fn add_to_mptable(&self, mut table: MultiPartTable, params: MdParams) -> MultiPartTable {
        if self.status.is_some() || self.port_43.is_some() {
            table = table.header_ref(&"Information");

            // Status
            if let Some(status) = &self.status {
                let values = status.vec();
                table = table.nv_ul(&"Status", values.make_list_all_title_case());
            }

            // Port 43
            table = table.and_nv_ref(&"Whois", &self.port_43);
        }

        // Events
        if let Some(events) = &self.events {
            table = events_to_table(events, table, "Events", params);
        }

        // Links
        if let Some(links) = &self.links {
            table = links_to_table(links, table, "Links");
        }

        // TODO Checks
        table
    }
}

pub(crate) fn public_ids_to_table(
    publid_ids: &[PublicId],
    mut table: MultiPartTable,
) -> MultiPartTable {
    for pid in publid_ids {
        table = table.nv_ref(
            pid.id_type.as_ref().unwrap_or(&"(not given)".to_string()),
            pid.identifier
                .as_ref()
                .unwrap_or(&"(not given)".to_string()),
        );
    }
    table
}

pub(crate) fn events_to_table(
    events: &[Event],
    mut table: MultiPartTable,
    header_name: &str,
    params: MdParams,
) -> MultiPartTable {
    table = table.header_ref(&header_name.to_string());
    for event in events {
        let event_date = &event
            .event_date
            .to_owned()
            .unwrap_or("????".to_string())
            .format_date_time(params)
            .unwrap_or_default();
        let mut ul: Vec<&String> = vec![event_date];
        if let Some(event_actor) = &event.event_actor {
            ul.push(event_actor);
        }
        table = table.nv_ul_ref(
            &event
                .event_action
                .as_ref()
                .unwrap_or(&"action not given".to_string())
                .to_owned()
                .to_words_title_case(),
            ul,
        );
    }
    table
}

pub(crate) fn links_to_table(
    links: &[Link],
    mut table: MultiPartTable,
    header_name: &str,
) -> MultiPartTable {
    table = table.header_ref(&header_name.to_string());
    for link in links {
        if let Some(title) = &link.title {
            table = table.nv_ref(&"Title", &title.trim());
        };
        let rel = link
            .rel
            .as_ref()
            .unwrap_or(&"Link".to_string())
            .to_title_case();
        let mut ul: Vec<&String> = vec![];
        if let Some(href) = &link.href {
            ul.push(href)
        }
        if let Some(media_type) = &link.media_type {
            ul.push(media_type)
        };
        if let Some(media) = &link.media {
            ul.push(media)
        };
        if let Some(value) = &link.value {
            ul.push(value)
        };
        let hreflang_s;
        if let Some(hreflang) = &link.hreflang {
            hreflang_s = match hreflang {
                icann_rdap_common::response::HrefLang::Lang(lang) => lang.to_owned(),
                icann_rdap_common::response::HrefLang::Langs(langs) => langs.join(", "),
            };
            ul.push(&hreflang_s)
        };
        table = table.nv_ul_ref(&rel, ul);
    }
    table
}

pub(crate) fn checks_to_table(
    checks: Vec<Checks>,
    mut table: MultiPartTable,
    params: MdParams,
) -> MultiPartTable {
    let mut filtered_checks: Vec<CheckItem> = checks
        .into_iter()
        .flat_map(|checks| checks.items)
        .filter(|item| params.check_types.contains(&item.check_class))
        .collect();

    if !filtered_checks.is_empty() {
        filtered_checks.sort();
        filtered_checks.dedup();
        table = table.header_ref(&"Checks");

        // Informational
        let class = CheckClass::Informational;
        let ul: Vec<String> = filtered_checks
            .iter()
            .filter(|item| item.check_class == class)
            .map(|item| item.check.get_message().unwrap_or_default().to_owned())
            .collect();
        table = table.nv_ul_ref(
            &&class
                .to_string()
                .to_right_em(*CHECK_CLASS_LEN, params.options),
            ul.iter().collect(),
        );

        // Specification Warning
        let class = CheckClass::StdWarning;
        let ul: Vec<String> = filtered_checks
            .iter()
            .filter(|item| item.check_class == class)
            .map(|item| item.check.get_message().unwrap_or_default().to_owned())
            .collect();
        table = table.nv_ul_ref(
            &class
                .to_string()
                .to_right_em(*CHECK_CLASS_LEN, params.options),
            ul.iter().collect(),
        );

        // Specification Error
        let class = CheckClass::StdError;
        let ul: Vec<String> = filtered_checks
            .iter()
            .filter(|item| item.check_class == class)
            .map(|item| item.check.get_message().unwrap_or_default().to_owned())
            .collect();
        table = table.nv_ul_ref(
            &&class
                .to_string()
                .to_right_em(*CHECK_CLASS_LEN, params.options),
            ul.iter().collect(),
        );
    }

    table
}
