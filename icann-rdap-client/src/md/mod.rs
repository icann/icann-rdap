use std::char;

use icann_rdap_common::response::RdapResponse;

use crate::check::CheckType;

pub mod domain;
pub mod entity;
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

pub trait ToMd {
    fn to_md(&self, heading_level: usize, check_types: &[CheckType], options: &MdOptions)
        -> String;
}

impl ToMd for RdapResponse {
    fn to_md(
        &self,
        heading_level: usize,
        check_types: &[CheckType],
        options: &MdOptions,
    ) -> String {
        match &self {
            RdapResponse::Entity(_) => todo!(),
            RdapResponse::Domain(domain) => domain.to_md(heading_level, check_types, options),
            RdapResponse::Nameserver(_) => todo!(),
            RdapResponse::Autnum(_) => todo!(),
            RdapResponse::Network(_) => todo!(),
            RdapResponse::DomainSearchResults(_) => todo!(),
            RdapResponse::EntitySearchResults(_) => todo!(),
            RdapResponse::NameserverSearchResults(_) => todo!(),
            RdapResponse::ErrorResponse(_) => todo!(),
            RdapResponse::Help(_) => todo!(),
        }
    }
}

pub(crate) fn to_em(str: &str, options: &MdOptions) -> String {
    format!(
        "{}{str}{}",
        options.text_style_char, options.text_style_char
    )
}

pub(crate) fn to_bold(str: &str, options: &MdOptions) -> String {
    format!(
        "{}{}{str}{}{}",
        options.text_style_char,
        options.text_style_char,
        options.text_style_char,
        options.text_style_char
    )
}

pub(crate) fn to_header(str: &str, level: usize, options: &MdOptions) -> String {
    if options.hash_headers {
        format!("{} {str}\n\n", "#".repeat(level))
    } else {
        let line = if level == 1 {
            "=".repeat(str.len())
        } else {
            "-".repeat(str.len())
        };
        format!("{str}\n{line}\n\n")
    }
}

pub(crate) fn to_right(str: &str, width: usize, options: &MdOptions) -> String {
    if options.no_unicode_chars {
        format!("{:>width$}", str)
    } else {
        format!("{:\u{2003}>width$}", str)
    }
}

pub(crate) fn to_right_em(str: &str, width: usize, options: &MdOptions) -> String {
    if options.style_in_justify {
        to_right(&to_em(str, options), width, options)
    } else {
        to_em(&to_right(str, width, options), options)
    }
}

#[allow(dead_code)]
pub(crate) fn to_right_bold(str: &str, width: usize, options: &MdOptions) -> String {
    if options.style_in_justify {
        to_right(&to_bold(str, options), width, options)
    } else {
        to_bold(&to_right(str, width, options), options)
    }
}

pub(crate) fn to_left(str: &str, width: usize, options: &MdOptions) -> String {
    if options.no_unicode_chars {
        format!("{:<width$}", str)
    } else {
        format!("{:\u{2003}<width$}", str)
    }
}

#[allow(dead_code)]
pub(crate) fn to_left_em(str: &str, width: usize, options: &MdOptions) -> String {
    if options.style_in_justify {
        to_left(&to_em(str, options), width, options)
    } else {
        to_em(&to_left(str, width, options), options)
    }
}

#[allow(dead_code)]
pub(crate) fn to_left_bold(str: &str, width: usize, options: &MdOptions) -> String {
    if options.style_in_justify {
        to_left(&to_bold(str, options), width, options)
    } else {
        to_bold(&to_left(str, width, options), options)
    }
}

#[allow(dead_code)]
pub(crate) fn to_center(str: &str, width: usize, options: &MdOptions) -> String {
    if options.no_unicode_chars {
        format!("{:^width$}", str)
    } else {
        format!("{:\u{2003}^width$}", str)
    }
}

#[allow(dead_code)]
pub(crate) fn to_center_em(str: &str, width: usize, options: &MdOptions) -> String {
    if options.style_in_justify {
        to_center(&to_em(str, options), width, options)
    } else {
        to_em(&to_center(str, width, options), options)
    }
}

#[allow(dead_code)]
pub(crate) fn to_center_bold(str: &str, width: usize, options: &MdOptions) -> String {
    if options.style_in_justify {
        to_center(&to_bold(str, options), width, options)
    } else {
        to_bold(&to_center(str, width, options), options)
    }
}
