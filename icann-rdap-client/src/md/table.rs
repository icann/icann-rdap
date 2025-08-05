use std::cmp::max;

use super::{string::StringUtil, MdHeaderText, MdOptions, MdParams, ToMd};

pub(crate) trait ToMpTable {
    fn add_to_mptable(&self, table: MultiPartTable, params: MdParams) -> MultiPartTable;
}

/// A datastructue to hold various row types for a markdown table.
///
/// This datastructure has the following types of rows:
/// * header - just the left most column which is centered and bolded text
/// * name/value - first column is the name and the second column is data.
///
/// For name/value rows, the name is right justified. Name/value rows may also
/// have unordered (bulleted) lists. In markdown, there is no such thing as a
/// multiline row, so this creates multiple rows where the name is left blank.
pub struct MultiPartTable {
    rows: Vec<Row>,
}

enum Row {
    Header(String),
    NameValue((String, String)),
    MultiValue(Vec<String>),
}

impl Default for MultiPartTable {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiPartTable {
    pub fn new() -> Self {
        Self { rows: vec![] }
    }

    /// Add a header row.
    pub fn header_ref(mut self, name: &impl ToString) -> Self {
        self.rows.push(Row::Header(name.to_string()));
        self
    }

    /// Add a name/value row.
    pub fn nv_ref(mut self, name: &impl ToString, value: &impl ToString) -> Self {
        self.rows.push(Row::NameValue((
            name.to_string(),
            value.to_string().replace_md_chars(),
        )));
        self
    }

    /// Add a name/value row.
    pub fn nv(mut self, name: &impl ToString, value: impl ToString) -> Self {
        self.rows.push(Row::NameValue((
            name.to_string(),
            value.to_string().replace_md_chars(),
        )));
        self
    }

    /// Add a name/value row without processing whitespace or markdown charaters.
    pub fn nv_raw(mut self, name: &impl ToString, value: impl ToString) -> Self {
        self.rows
            .push(Row::NameValue((name.to_string(), value.to_string())));
        self
    }

    /// Add a name/value row with unordered list.
    pub fn nv_ul_ref(mut self, name: &impl ToString, value: Vec<&impl ToString>) -> Self {
        value.iter().enumerate().for_each(|(i, v)| {
            if i == 0 {
                self.rows.push(Row::NameValue((
                    name.to_string(),
                    format!("* {}", v.to_string().replace_md_chars()),
                )))
            } else {
                self.rows.push(Row::NameValue((
                    String::default(),
                    format!("* {}", v.to_string().replace_md_chars()),
                )))
            }
        });
        self
    }

    /// Add a name/value row with unordered list.
    pub fn nv_ul(mut self, name: &impl ToString, value: Vec<impl ToString>) -> Self {
        value.iter().enumerate().for_each(|(i, v)| {
            if i == 0 {
                self.rows.push(Row::NameValue((
                    name.to_string(),
                    format!("* {}", v.to_string().replace_md_chars()),
                )))
            } else {
                self.rows.push(Row::NameValue((
                    String::default(),
                    format!("* {}", v.to_string().replace_md_chars()),
                )))
            }
        });
        self
    }

    /// Add a name/value row.
    pub fn and_nv_ref<T: ToString>(mut self, name: &impl ToString, value: &Option<T>) -> Self {
        self.rows.push(Row::NameValue((
            name.to_string(),
            value
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_default()
                .replace_md_chars(),
        )));
        self
    }

    /// Add a name/value row.
    pub fn and_nv_ref_maybe<T: ToString>(self, name: &impl ToString, value: &Option<T>) -> Self {
        if let Some(value) = value {
            self.nv_ref(name, &value.to_string())
        } else {
            self
        }
    }

    /// Add a name/value row with unordered list.
    pub fn and_nv_ul_ref(self, name: &impl ToString, value: Option<Vec<&impl ToString>>) -> Self {
        if let Some(value) = value {
            self.nv_ul_ref(name, value)
        } else {
            self
        }
    }

    /// Add a name/value row with unordered list.
    pub fn and_nv_ul(self, name: &impl ToString, value: Option<Vec<impl ToString>>) -> Self {
        if let Some(value) = value {
            self.nv_ul(name, value)
        } else {
            self
        }
    }

    /// A summary row is a special type of name/value row that has an unordered (bulleted) list
    /// that is output in a tree structure (max 3 levels).
    pub fn summary(mut self, header_text: MdHeaderText) -> Self {
        self.rows.push(Row::NameValue((
            "Summary".to_string(),
            header_text.to_string().replace_md_chars().to_string(),
        )));
        // note that termimad has limits on list depth, so we can't go too crazy.
        // however, this seems perfectly reasonable for must RDAP use cases.
        for level1 in header_text.children {
            self.rows.push(Row::NameValue((
                "".to_string(),
                format!("* {}", level1.to_string().replace_md_chars()),
            )));
            for level2 in level1.children {
                self.rows.push(Row::NameValue((
                    "".to_string(),
                    format!("  * {}", level2.to_string().replace_md_chars()),
                )));
            }
        }
        self
    }

    /// Adds a multivalue row.
    pub fn multi(mut self, values: Vec<String>) -> Self {
        self.rows.push(Row::MultiValue(
            values.iter().map(|s| s.replace_md_chars()).collect(),
        ));
        self
    }

    /// Adds a multivalue row.
    pub fn multi_ref(mut self, values: &[&str]) -> Self {
        self.rows.push(Row::MultiValue(
            values.iter().map(|s| s.replace_md_chars()).collect(),
        ));
        self
    }

    /// Adds a multivalue row without processing whitespace or markdown characters.
    pub fn multi_raw(mut self, values: Vec<String>) -> Self {
        self.rows.push(Row::MultiValue(
            values.iter().map(|s| s.to_owned()).collect(),
        ));
        self
    }

    /// Adds a multivalue row without processing whitespace or markdown characters.
    pub fn multi_raw_ref(mut self, values: &[&str]) -> Self {
        self.rows.push(Row::MultiValue(
            values.iter().map(|s| s.to_string()).collect(),
        ));
        self
    }

    pub fn to_md_table(&self, options: &MdOptions) -> String {
        let mut md = String::new();

        let col_type_width = max(
            self.rows
                .iter()
                .map(|row| match row {
                    Row::Header(header) => header.len(),
                    Row::NameValue((name, _value)) => name.len(),
                    Row::MultiValue(_) => 1,
                })
                .max()
                .unwrap_or(1),
            1,
        );

        self.rows
            .iter()
            .scan(true, |state, x| {
                let new_state = match x {
                    Row::Header(name) => {
                        md.push_str(&format!(
                            "|:-:|\n|{}|\n",
                            name.to_center_bold(col_type_width, options)
                        ));
                        true
                    }
                    Row::NameValue((name, value)) => {
                        if *state {
                            md.push_str("|-:|:-|\n");
                        };
                        md.push_str(&format!(
                            "|{}|{}|\n",
                            name.to_right(col_type_width, options),
                            value
                        ));
                        false
                    }
                    Row::MultiValue(values) => {
                        // column formatting
                        md.push('|');
                        for _col in values {
                            md.push_str(":--:|");
                        }
                        md.push('\n');

                        // the actual data
                        md.push('|');
                        for col in values {
                            md.push_str(&format!("{col}|"));
                        }
                        md.push('\n');
                        true
                    }
                };
                *state = new_state;
                Some(new_state)
            })
            .last();

        md.push_str("|\n\n");
        md
    }
}

impl ToMd for MultiPartTable {
    fn to_md(&self, params: super::MdParams) -> String {
        self.to_md_table(params.options)
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use icann_rdap_common::{httpdata::HttpData, prelude::ToResponse, response::Rfc9083Error};

    use crate::{
        md::ToMd,
        rdap::rr::{RequestData, SourceType},
    };

    use super::MultiPartTable;

    #[test]
    fn GIVEN_header_WHEN_to_md_THEN_header_format_and_header() {
        // GIVEN
        let table = MultiPartTable::new().header_ref(&"foo");

        // WHEN
        let req_data = RequestData {
            req_number: 0,
            source_host: "",
            source_type: SourceType::UncategorizedRegistry,
        };
        let rdap_response = Rfc9083Error::builder()
            .error_code(500)
            .build()
            .to_response();
        let actual = table.to_md(crate::md::MdParams {
            heading_level: 0,
            root: &rdap_response,
            http_data: &HttpData::example().build(),
            parent_type: std::any::TypeId::of::<crate::md::MdParams>(),
            check_types: &[],
            options: &crate::md::MdOptions::plain_text(),
            req_data: &req_data,
        });

        assert_eq!(actual, "|:-:|\n|__foo__|\n|\n\n")
    }

    #[test]
    fn GIVEN_header_and_data_ref_WHEN_to_md_THEN_header_format_and_header() {
        // GIVEN
        let table = MultiPartTable::new()
            .header_ref(&"foo")
            .nv_ref(&"bizz", &"buzz");

        // WHEN
        let req_data = RequestData {
            req_number: 0,
            source_host: "",
            source_type: SourceType::UncategorizedRegistry,
        };
        let rdap_response = Rfc9083Error::builder()
            .error_code(500)
            .build()
            .to_response();
        let actual = table.to_md(crate::md::MdParams {
            heading_level: 0,
            root: &rdap_response,
            http_data: &HttpData::example().build(),
            parent_type: std::any::TypeId::of::<crate::md::MdParams>(),
            check_types: &[],
            options: &crate::md::MdOptions::plain_text(),
            req_data: &req_data,
        });

        assert_eq!(actual, "|:-:|\n|__foo__|\n|-:|:-|\n|bizz|buzz|\n|\n\n")
    }

    #[test]
    fn GIVEN_header_and_2_data_ref_WHEN_to_md_THEN_header_format_and_header() {
        // GIVEN
        let table = MultiPartTable::new()
            .header_ref(&"foo")
            .nv_ref(&"bizz", &"buzz")
            .nv_ref(&"bar", &"baz");

        // WHEN
        let req_data = RequestData {
            req_number: 0,
            source_host: "",
            source_type: SourceType::UncategorizedRegistry,
        };
        let rdap_response = Rfc9083Error::builder()
            .error_code(500)
            .build()
            .to_response();
        let actual = table.to_md(crate::md::MdParams {
            heading_level: 0,
            root: &rdap_response,
            http_data: &HttpData::example().build(),
            parent_type: std::any::TypeId::of::<crate::md::MdParams>(),
            check_types: &[],
            options: &crate::md::MdOptions::plain_text(),
            req_data: &req_data,
        });

        assert_eq!(
            actual,
            "|:-:|\n|__foo__|\n|-:|:-|\n|bizz|buzz|\n| bar|baz|\n|\n\n"
        )
    }

    #[test]
    fn GIVEN_header_and_data_WHEN_to_md_THEN_header_format_and_header() {
        // GIVEN
        let table = MultiPartTable::new()
            .header_ref(&"foo")
            .nv(&"bizz", "buzz".to_string());

        // WHEN
        let req_data = RequestData {
            req_number: 0,
            source_host: "",
            source_type: SourceType::UncategorizedRegistry,
        };
        let rdap_response = Rfc9083Error::builder()
            .error_code(500)
            .build()
            .to_response();
        let actual = table.to_md(crate::md::MdParams {
            heading_level: 0,
            root: &rdap_response,
            http_data: &HttpData::example().build(),
            parent_type: std::any::TypeId::of::<crate::md::MdParams>(),
            check_types: &[],
            options: &crate::md::MdOptions::plain_text(),
            req_data: &req_data,
        });

        assert_eq!(actual, "|:-:|\n|__foo__|\n|-:|:-|\n|bizz|buzz|\n|\n\n")
    }

    #[test]
    fn GIVEN_header_and_2_data_WHEN_to_md_THEN_header_format_and_header() {
        // GIVEN
        let table = MultiPartTable::new()
            .header_ref(&"foo")
            .nv(&"bizz", "buzz")
            .nv(&"bar", "baz");

        // WHEN
        let req_data = RequestData {
            req_number: 0,
            source_host: "",
            source_type: SourceType::UncategorizedRegistry,
        };
        let rdap_response = Rfc9083Error::builder()
            .error_code(500)
            .build()
            .to_response();
        let actual = table.to_md(crate::md::MdParams {
            heading_level: 0,
            root: &rdap_response,
            http_data: &HttpData::example().build(),
            parent_type: std::any::TypeId::of::<crate::md::MdParams>(),
            check_types: &[],
            options: &crate::md::MdOptions::plain_text(),
            req_data: &req_data,
        });

        assert_eq!(
            actual,
            "|:-:|\n|__foo__|\n|-:|:-|\n|bizz|buzz|\n| bar|baz|\n|\n\n"
        )
    }

    #[test]
    fn GIVEN_header_and_2_data_ref_twice_WHEN_to_md_THEN_header_format_and_header() {
        // GIVEN
        let table = MultiPartTable::new()
            .header_ref(&"foo")
            .nv_ref(&"bizz", &"buzz")
            .nv_ref(&"bar", &"baz")
            .header_ref(&"foo")
            .nv_ref(&"bizz", &"buzz")
            .nv_ref(&"bar", &"baz");

        // WHEN
        let req_data = RequestData {
            req_number: 0,
            source_host: "",
            source_type: SourceType::UncategorizedRegistry,
        };
        let rdap_response = Rfc9083Error::builder()
            .error_code(500)
            .build()
            .to_response();
        let actual = table.to_md(crate::md::MdParams {
            heading_level: 0,
            root: &rdap_response,
            http_data: &HttpData::example().build(),
            parent_type: std::any::TypeId::of::<crate::md::MdParams>(),
            check_types: &[],
            options: &crate::md::MdOptions::plain_text(),
            req_data: &req_data,
        });

        assert_eq!(
            actual,
            "|:-:|\n|__foo__|\n|-:|:-|\n|bizz|buzz|\n| bar|baz|\n|:-:|\n|__foo__|\n|-:|:-|\n|bizz|buzz|\n| bar|baz|\n|\n\n"
        )
    }
}
