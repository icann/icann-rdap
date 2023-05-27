use std::cmp::max;

use super::{string::StringUtil, MdParams, ToMd};

pub(crate) trait ToMpTable {
    fn add_to_mptable(&self, table: MultiPartTable, params: MdParams) -> MultiPartTable;
}

pub(crate) struct MultiPartTable {
    rows: Vec<Row>,
}

enum Row {
    Header(String),
    Data((String, String)),
}

impl MultiPartTable {
    pub(crate) fn new() -> Self {
        Self { rows: Vec::new() }
    }

    pub(crate) fn header_ref(mut self, name: &impl ToString) -> Self {
        self.rows.push(Row::Header(name.to_string()));
        self
    }

    pub(crate) fn data_ref(mut self, name: &impl ToString, value: &impl ToString) -> Self {
        self.rows
            .push(Row::Data((name.to_string(), value.to_string())));
        self
    }

    pub(crate) fn data(mut self, name: &impl ToString, value: impl ToString) -> Self {
        self.rows
            .push(Row::Data((name.to_string(), value.to_string())));
        self
    }

    pub(crate) fn data_ul_ref(mut self, name: &impl ToString, value: Vec<&impl ToString>) -> Self {
        value.iter().enumerate().for_each(|(i, v)| {
            if i == 0 {
                self.rows.push(Row::Data((
                    name.to_string(),
                    format!("* {}", v.to_string()),
                )))
            } else {
                self.rows.push(Row::Data((
                    String::default(),
                    format!("* {}", v.to_string()),
                )))
            }
        });
        self
    }

    pub(crate) fn data_ul(mut self, name: &impl ToString, value: Vec<impl ToString>) -> Self {
        value.iter().enumerate().for_each(|(i, v)| {
            if i == 0 {
                self.rows.push(Row::Data((
                    name.to_string(),
                    format!("* {}", v.to_string()),
                )))
            } else {
                self.rows.push(Row::Data((
                    String::default(),
                    format!("* {}", v.to_string()),
                )))
            }
        });
        self
    }

    pub(crate) fn and_data_ref(mut self, name: &impl ToString, value: &Option<String>) -> Self {
        self.rows.push(Row::Data((
            name.to_string(),
            value.as_deref().unwrap_or_default().to_string(),
        )));
        self
    }

    pub(crate) fn and_data_ref_maybe(self, name: &impl ToString, value: &Option<String>) -> Self {
        if let Some(value) = value {
            self.data_ref(name, value)
        } else {
            self
        }
    }

    pub(crate) fn and_data_ul_ref(
        self,
        name: &impl ToString,
        value: Option<Vec<&impl ToString>>,
    ) -> Self {
        if let Some(value) = value {
            self.data_ul_ref(name, value)
        } else {
            self
        }
    }

    pub(crate) fn and_data_ul(
        self,
        name: &impl ToString,
        value: Option<Vec<impl ToString>>,
    ) -> Self {
        if let Some(value) = value {
            self.data_ul(name, value)
        } else {
            self
        }
    }
}

impl ToMd for MultiPartTable {
    fn to_md(&self, params: super::MdParams) -> String {
        let mut md = String::new();

        let col_type_width = max(
            self.rows
                .iter()
                .map(|row| match row {
                    Row::Header(header) => header.len(),
                    Row::Data((name, _value)) => name.len(),
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
                            name.to_center_bold(col_type_width, params.options)
                        ));
                        true
                    }
                    Row::Data((name, value)) => {
                        if *state {
                            md.push_str("|-:|:-|\n");
                        };
                        md.push_str(&format!(
                            "|{}|{}|\n",
                            name.to_right(col_type_width, params.options),
                            value
                        ));
                        false
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

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use icann_rdap_common::response::{types::Common, RdapResponse};

    use crate::{md::ToMd, request::RequestData};

    use super::MultiPartTable;

    #[test]
    fn GIVEN_header_WHEN_to_md_THEN_header_format_and_header() {
        // GIVEN
        let table = MultiPartTable::new().header_ref(&"foo");

        // WHEN
        let req_data = RequestData {
            req_number: 0,
            source_host: "",
            source_type: crate::request::SourceType::UncategorizedRegistry,
        };
        let rdap_response = RdapResponse::ErrorResponse(
            icann_rdap_common::response::error::Error::builder()
                .common(Common::builder().build())
                .error_code(500)
                .build(),
        );
        let actual = table.to_md(crate::md::MdParams {
            heading_level: 0,
            root: &rdap_response,
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
            .data_ref(&"bizz", &"buzz");

        // WHEN
        let req_data = RequestData {
            req_number: 0,
            source_host: "",
            source_type: crate::request::SourceType::UncategorizedRegistry,
        };
        let rdap_response = RdapResponse::ErrorResponse(
            icann_rdap_common::response::error::Error::builder()
                .common(Common::builder().build())
                .error_code(500)
                .build(),
        );
        let actual = table.to_md(crate::md::MdParams {
            heading_level: 0,
            root: &rdap_response,
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
            .data_ref(&"bizz", &"buzz")
            .data_ref(&"bar", &"baz");

        // WHEN
        let req_data = RequestData {
            req_number: 0,
            source_host: "",
            source_type: crate::request::SourceType::UncategorizedRegistry,
        };
        let rdap_response = RdapResponse::ErrorResponse(
            icann_rdap_common::response::error::Error::builder()
                .common(Common::builder().build())
                .error_code(500)
                .build(),
        );
        let actual = table.to_md(crate::md::MdParams {
            heading_level: 0,
            root: &rdap_response,
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
            .data(&"bizz", "buzz".to_string());

        // WHEN
        let req_data = RequestData {
            req_number: 0,
            source_host: "",
            source_type: crate::request::SourceType::UncategorizedRegistry,
        };
        let rdap_response = RdapResponse::ErrorResponse(
            icann_rdap_common::response::error::Error::builder()
                .common(Common::builder().build())
                .error_code(500)
                .build(),
        );
        let actual = table.to_md(crate::md::MdParams {
            heading_level: 0,
            root: &rdap_response,
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
            .data(&"bizz", "buzz")
            .data(&"bar", "baz");

        // WHEN
        let req_data = RequestData {
            req_number: 0,
            source_host: "",
            source_type: crate::request::SourceType::UncategorizedRegistry,
        };
        let rdap_response = RdapResponse::ErrorResponse(
            icann_rdap_common::response::error::Error::builder()
                .common(Common::builder().build())
                .error_code(500)
                .build(),
        );
        let actual = table.to_md(crate::md::MdParams {
            heading_level: 0,
            root: &rdap_response,
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
            .data_ref(&"bizz", &"buzz")
            .data_ref(&"bar", &"baz")
            .header_ref(&"foo")
            .data_ref(&"bizz", &"buzz")
            .data_ref(&"bar", &"baz");

        // WHEN
        let req_data = RequestData {
            req_number: 0,
            source_host: "",
            source_type: crate::request::SourceType::UncategorizedRegistry,
        };
        let rdap_response = RdapResponse::ErrorResponse(
            icann_rdap_common::response::error::Error::builder()
                .common(Common::builder().build())
                .error_code(500)
                .build(),
        );
        let actual = table.to_md(crate::md::MdParams {
            heading_level: 0,
            root: &rdap_response,
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
