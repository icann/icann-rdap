use std::{any::TypeId, char, cmp::max};

use icann_rdap_common::response::RdapResponse;
use strum::EnumMessage;

use crate::{
    check::{CheckClass, Checks, CHECK_CLASS_LEN},
    request::RequestData,
};

pub mod autnum;
pub mod domain;
pub mod entity;
pub mod error;
pub mod help;
pub mod nameserver;
pub mod network;
pub mod search;
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
        format!("{str:>width$}")
    } else {
        format!("{str:\u{2003}>width$}")
    }
}

pub(crate) fn to_right_em(str: &str, width: usize, options: &MdOptions) -> String {
    if options.style_in_justify {
        to_right(&to_em(str, options), width, options)
    } else {
        to_em(&to_right(str, width, options), options)
    }
}

pub(crate) fn to_right_bold(str: &str, width: usize, options: &MdOptions) -> String {
    if options.style_in_justify {
        to_right(&to_bold(str, options), width, options)
    } else {
        to_bold(&to_right(str, width, options), options)
    }
}

pub(crate) fn to_left(str: &str, width: usize, options: &MdOptions) -> String {
    if options.no_unicode_chars {
        format!("{str:<width$}")
    } else {
        format!("{str:\u{2003}<width$}")
    }
}

pub(crate) fn to_left_em(str: &str, width: usize, options: &MdOptions) -> String {
    if options.style_in_justify {
        to_left(&to_em(str, options), width, options)
    } else {
        to_em(&to_left(str, width, options), options)
    }
}

pub(crate) fn to_left_bold(str: &str, width: usize, options: &MdOptions) -> String {
    if options.style_in_justify {
        to_left(&to_bold(str, options), width, options)
    } else {
        to_bold(&to_left(str, width, options), options)
    }
}

pub(crate) fn to_center(str: &str, width: usize, options: &MdOptions) -> String {
    if options.no_unicode_chars {
        format!("{str:^width$}")
    } else {
        format!("{str:\u{2003}^width$}")
    }
}

pub(crate) fn to_center_em(str: &str, width: usize, options: &MdOptions) -> String {
    if options.style_in_justify {
        to_center(&to_em(str, options), width, options)
    } else {
        to_em(&to_center(str, width, options), options)
    }
}

pub(crate) fn to_center_bold(str: &str, width: usize, options: &MdOptions) -> String {
    if options.style_in_justify {
        to_center(&to_bold(str, options), width, options)
    } else {
        to_bold(&to_center(str, width, options), options)
    }
}

pub(crate) struct SimpleTable {
    pub name: Option<String>,
    pub rows: Vec<(String, String)>,
}

impl SimpleTable {
    pub(crate) fn new(name: impl ToString) -> Self {
        SimpleTable {
            name: Some(name.to_string()),
            rows: Vec::new(),
        }
    }

    pub(crate) fn noname() -> Self {
        SimpleTable {
            name: None,
            rows: Vec::new(),
        }
    }

    pub(crate) fn row(mut self, name: &impl ToString, value: &impl ToString) -> Self {
        self.rows.push((name.to_string(), value.to_string()));
        self
    }

    pub(crate) fn row_ul(mut self, name: &impl ToString, value: Vec<&impl ToString>) -> Self {
        value.iter().enumerate().for_each(|(i, v)| {
            if i == 0 {
                self.rows
                    .push((name.to_string(), format!("* {}", v.to_string())))
            } else {
                self.rows
                    .push((String::default(), format!("* {}", v.to_string())))
            }
        });
        self
    }

    pub(crate) fn and_row(mut self, name: &impl ToString, value: &Option<String>) -> Self {
        self.rows.push((
            name.to_string(),
            value.as_deref().unwrap_or_default().to_string(),
        ));
        self
    }

    pub(crate) fn and_row_ul(
        self,
        name: &impl ToString,
        value: Option<Vec<&impl ToString>>,
    ) -> Self {
        if let Some(value) = value {
            self.row_ul(name, value)
        } else {
            self.row(name, &String::default())
        }
    }
}

impl ToMd for SimpleTable {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();

        let mut col_type_width = max(self.name.as_deref().unwrap_or_default().len(), 1);
        col_type_width = max(
            self.rows.iter().map(|row| row.0.len()).sum(),
            col_type_width,
        );

        // table name
        if let Some(name) = &self.name {
            md.push_str(&format!(
                "|:-:|\n|{}|\n",
                to_right_bold(name, col_type_width, params.options)
            ));
        };

        md.push_str("|-:|:-|\n");

        self.rows.iter().for_each(|row| {
            md.push_str(&format!(
                "|{}|{}\n",
                to_right(&row.0, col_type_width, params.options),
                row.1
            ))
        });

        md.push_str("|\n\n");

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
                to_right_em(
                    &item.check_class.to_string(),
                    *CHECK_CLASS_LEN,
                    params.options
                ),
                item.check
                    .get_message()
                    .expect("Check has no message. Coding error.")
            ))
        });
    md
}

pub(crate) fn make_title_case(s: impl ToString) -> String {
    s.to_string()
        .char_indices()
        .map(|(i, mut c)| {
            if i == 0 {
                c.make_ascii_uppercase();
                c
            } else {
                c.make_ascii_lowercase();
                c
            }
        })
        .collect::<String>()
}

pub(crate) fn make_all_title_case(s: impl ToString) -> String {
    s.to_string()
        .split_whitespace()
        .map(make_title_case)
        .collect::<Vec<String>>()
        .join(" ")
}

pub(crate) fn make_list_all_title_case(list: &[impl ToString]) -> Vec<String> {
    list.iter()
        .map(|s| make_all_title_case(s.to_string()))
        .collect::<Vec<String>>()
}

pub(crate) fn make_title_case_list(list: &[impl ToString]) -> String {
    make_list_all_title_case(list).join(", ")
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use rstest::rstest;

    use crate::md::make_title_case_list;

    use super::make_all_title_case;
    use super::make_list_all_title_case;
    use super::make_title_case;

    #[rstest]
    #[case("foo", "Foo")]
    #[case("FOO", "Foo")]
    fn GIVEN_word_WHEN_make_title_case_THEN_only_first_char_is_upper(
        #[case] word: &str,
        #[case] expected: &str,
    ) {
        // GIVEN in arguments

        // WHEN
        let actual = make_title_case(word);

        // THEN
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case("foo bar", "Foo Bar")]
    #[case("foo  bar", "Foo Bar")]
    #[case("foO  baR", "Foo Bar")]
    fn GIVEN_sentence_WHEN_make_all_title_case_THEN_only_first_chars_is_upper(
        #[case] sentence: &str,
        #[case] expected: &str,
    ) {
        // GIVEN in arguments

        // WHEN
        let actual = make_all_title_case(sentence);

        // THEN
        assert_eq!(actual, expected);
    }

    #[test]
    fn GIVEN_list_of_sentences_WHEN_make_list_all_title_case_THEN_each_sentence_all_title_cased() {
        // GIVEN
        let v = vec!["foo bar", "foO baR"];

        // WHEN
        let actual = make_list_all_title_case(&v);

        // THEN
        assert_eq!(actual, vec!["Foo Bar".to_string(), "Foo Bar".to_string()])
    }

    #[test]
    fn GIVEN_list_WHEN_make_title_case_list_THEN_comma_separated_title_cased() {
        // GIVEN
        let list = vec!["foo bar", "bizz buzz"];

        // WHEN
        let actual = make_title_case_list(&list);

        // THEN
        assert_eq!(actual, "Foo Bar, Bizz Buzz");
    }
}
