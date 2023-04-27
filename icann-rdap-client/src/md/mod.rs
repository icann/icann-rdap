use std::{any::TypeId, char};

use icann_rdap_common::response::RdapResponse;
use strum::EnumMessage;

use crate::{
    check::{CheckClass, Checks, CHECK_CLASS_LEN},
    request::RequestData,
};

use self::string::StringUtil;

pub mod autnum;
pub mod domain;
pub mod entity;
pub mod error;
pub mod help;
pub mod nameserver;
pub mod network;
pub mod search;
pub mod string;
pub mod table;
pub mod types;

pub(crate) const _CODE_INDENT: &str = "    ";

pub(crate) const HR: &str = "----------------------------------------\n";

/// Specifies options for generating markdown.
pub struct MdOptions {
    /// If true, do not use Unicode characters.
    pub no_unicode_chars: bool,

    /// The character used for text styling of bold and italics.
    pub text_style_char: char,

    /// If true, headers use the hash marks or under lines.
    pub hash_headers: bool,

    /// If true, the text_style_char will appear in a justified text.
    pub style_in_justify: bool,
}

impl Default for MdOptions {
    fn default() -> Self {
        MdOptions {
            no_unicode_chars: false,
            text_style_char: '*',
            hash_headers: true,
            style_in_justify: false,
        }
    }
}

impl MdOptions {
    /// Defaults for markdown that looks more like plain text.
    pub fn plain_text() -> Self {
        MdOptions {
            no_unicode_chars: true,
            text_style_char: '_',
            hash_headers: false,
            style_in_justify: true,
        }
    }
}

#[derive(Clone, Copy)]
pub struct MdParams<'a> {
    pub heading_level: usize,
    pub root: &'a RdapResponse,
    pub parent_type: TypeId,
    pub check_types: &'a [CheckClass],
    pub options: &'a MdOptions,
    pub req_data: &'a RequestData<'a>,
}

impl<'a> MdParams<'a> {
    pub fn from_parent(&self, parent_type: TypeId) -> Self {
        MdParams {
            parent_type,
            heading_level: self.heading_level,
            root: self.root,
            check_types: self.check_types,
            options: self.options,
            req_data: self.req_data,
        }
    }

    pub fn next_level(&self) -> Self {
        MdParams {
            heading_level: self.heading_level + 1,
            ..*self
        }
    }
}

pub trait ToMd {
    fn to_md(&self, params: MdParams) -> String;
}

impl ToMd for RdapResponse {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        let variant_md = match &self {
            RdapResponse::Entity(entity) => entity.to_md(params),
            RdapResponse::Domain(domain) => domain.to_md(params),
            RdapResponse::Nameserver(nameserver) => nameserver.to_md(params),
            RdapResponse::Autnum(autnum) => autnum.to_md(params),
            RdapResponse::Network(network) => network.to_md(params),
            RdapResponse::DomainSearchResults(results) => results.to_md(params),
            RdapResponse::EntitySearchResults(results) => results.to_md(params),
            RdapResponse::NameserverSearchResults(results) => results.to_md(params),
            RdapResponse::ErrorResponse(error) => error.to_md(params),
            RdapResponse::Help(help) => help.to_md(params),
        };
        md.push_str(&variant_md);
        md.push_str(HR);
        md
    }
}

pub(crate) fn checks_ul(checks: &Checks, params: MdParams) -> String {
    let mut md = String::new();
    checks
        .items
        .iter()
        .filter(|item| params.check_types.contains(&item.check_class))
        .for_each(|item| {
            md.push_str(&format!(
                "* {}: {}\n",
                &item
                    .check_class
                    .to_string()
                    .to_right_em(*CHECK_CLASS_LEN, params.options),
                item.check
                    .get_message()
                    .expect("Check has no message. Coding error.")
            ))
        });
    md
}
