use chrono::DateTime;

use super::{MdOptions, MdParams};

pub trait StringUtil {
    fn replace_ws(self) -> String;
    fn to_em(self, options: &MdOptions) -> String;
    fn to_bold(self, options: &MdOptions) -> String;
    fn to_inline(self, options: &MdOptions) -> String;
    fn to_header(self, level: usize, options: &MdOptions) -> String;
    fn to_right(self, width: usize, options: &MdOptions) -> String;
    fn to_right_em(self, width: usize, options: &MdOptions) -> String;
    fn to_right_bold(self, width: usize, options: &MdOptions) -> String;
    fn to_left(self, width: usize, options: &MdOptions) -> String;
    fn to_left_em(self, width: usize, options: &MdOptions) -> String;
    fn to_left_bold(self, width: usize, options: &MdOptions) -> String;
    fn to_center(self, width: usize, options: &MdOptions) -> String;
    fn to_center_em(self, width: usize, options: &MdOptions) -> String;
    fn to_center_bold(self, width: usize, options: &MdOptions) -> String;
    fn to_title_case(self) -> String;
    fn to_words_title_case(self) -> String;
    fn to_cap_acronyms(self) -> String;
    fn format_date_time(self, params: MdParams) -> Option<String>;
}

impl<T: ToString> StringUtil for T {
    fn replace_ws(self) -> String {
        self.to_string().replace(|c: char| c.is_whitespace(), " ")
    }

    fn to_em(self, options: &MdOptions) -> String {
        format!(
            "{}{}{}",
            options.text_style_char,
            self.to_string().replace_ws(),
            options.text_style_char
        )
    }

    fn to_bold(self, options: &MdOptions) -> String {
        format!(
            "{}{}{}{}{}",
            options.text_style_char,
            options.text_style_char,
            self.to_string().replace_ws(),
            options.text_style_char,
            options.text_style_char
        )
    }

    fn to_inline(self, _options: &MdOptions) -> String {
        format!("`{}`", self.to_string().replace_ws(),)
    }

    fn to_header(self, level: usize, options: &MdOptions) -> String {
        let s = self.to_string().replace_ws();
        if options.hash_headers {
            format!("{} {s}\n\n", "#".repeat(level))
        } else {
            let line = if level == 1 {
                "=".repeat(s.len())
            } else {
                "-".repeat(s.len())
            };
            format!("{s}\n{line}\n\n")
        }
    }

    fn to_right(self, width: usize, options: &MdOptions) -> String {
        let str = self.to_string().replace_ws();
        if options.no_unicode_chars {
            format!("{str:>width$}")
        } else {
            format!("{str:\u{2003}>width$}")
        }
    }

    fn to_right_em(self, width: usize, options: &MdOptions) -> String {
        if options.style_in_justify {
            self.to_em(options).to_right(width, options)
        } else {
            self.to_right(width, options).to_em(options)
        }
    }

    fn to_right_bold(self, width: usize, options: &MdOptions) -> String {
        if options.style_in_justify {
            self.to_bold(options).to_right(width, options)
        } else {
            self.to_right(width, options).to_bold(options)
        }
    }

    fn to_left(self, width: usize, options: &MdOptions) -> String {
        let str = self.to_string().replace_ws();
        if options.no_unicode_chars {
            format!("{str:<width$}")
        } else {
            format!("{str:\u{2003}<width$}")
        }
    }

    fn to_left_em(self, width: usize, options: &MdOptions) -> String {
        if options.style_in_justify {
            self.to_em(options).to_left(width, options)
        } else {
            self.to_left(width, options).to_em(options)
        }
    }

    fn to_left_bold(self, width: usize, options: &MdOptions) -> String {
        if options.style_in_justify {
            self.to_bold(options).to_left(width, options)
        } else {
            self.to_left(width, options).to_bold(options)
        }
    }

    fn to_center(self, width: usize, options: &MdOptions) -> String {
        let str = self.to_string().replace_ws();
        if options.no_unicode_chars {
            format!("{str:^width$}")
        } else {
            format!("{str:\u{2003}^width$}")
        }
    }

    fn to_center_em(self, width: usize, options: &MdOptions) -> String {
        if options.style_in_justify {
            self.to_em(options).to_center(width, options)
        } else {
            self.to_center(width, options).to_bold(options)
        }
    }

    fn to_center_bold(self, width: usize, options: &MdOptions) -> String {
        if options.style_in_justify {
            self.to_bold(options).to_center(width, options)
        } else {
            self.to_center(width, options).to_bold(options)
        }
    }

    fn to_title_case(self) -> String {
        self.to_string()
            .replace_ws()
            .char_indices()
            .map(|(i, mut c)| {
                if i == 0 {
                    c.make_ascii_uppercase();
                    c
                } else {
                    c
                }
            })
            .collect::<String>()
    }

    fn to_words_title_case(self) -> String {
        self.to_string()
            .replace_ws()
            .split_whitespace()
            .map(|s| s.to_title_case())
            .collect::<Vec<String>>()
            .join(" ")
    }

    fn format_date_time(self, _params: MdParams) -> Option<String> {
        let date = DateTime::parse_from_rfc3339(&self.to_string()).ok()?;
        Some(date.format("%a, %v %X %Z").to_string())
    }

    fn to_cap_acronyms(self) -> String {
        self.to_string()
            .replace_ws()
            .replace("rdap", "RDAP")
            .replace("icann", "ICANN")
            .replace("arin", "ARIN")
            .replace("ripe", "RIPE")
            .replace("apnic", "APNIC")
            .replace("lacnic", "LACNIC")
            .replace("afrinic", "AFRINIC")
            .replace("nro", "NRO")
            .replace("ietf", "IETF")
    }
}

pub(crate) trait StringListUtil {
    fn make_list_all_title_case(self) -> Vec<String>;
    fn make_title_case_list(self) -> String;
}

impl<T: ToString> StringListUtil for &[T] {
    fn make_list_all_title_case(self) -> Vec<String> {
        self.iter()
            .map(|s| s.to_string().to_words_title_case())
            .collect::<Vec<String>>()
    }

    fn make_title_case_list(self) -> String {
        self.make_list_all_title_case().join(", ")
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use rstest::rstest;

    use super::{StringListUtil, StringUtil};

    #[rstest]
    #[case("foo", "Foo")]
    #[case("FOO", "FOO")]
    fn GIVEN_word_WHEN_make_title_case_THEN_first_char_is_upper(
        #[case] word: &str,
        #[case] expected: &str,
    ) {
        // GIVEN in arguments

        // WHEN
        let actual = word.to_title_case();

        // THEN
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case("foo bar", "Foo Bar")]
    #[case("foo  bar", "Foo Bar")]
    #[case("foO  baR", "FoO BaR")]
    fn GIVEN_sentence_WHEN_make_all_title_case_THEN_first_chars_is_upper(
        #[case] sentence: &str,
        #[case] expected: &str,
    ) {
        // GIVEN in arguments

        // WHEN
        let actual = sentence.to_words_title_case();

        // THEN
        assert_eq!(actual, expected);
    }

    #[test]
    fn GIVEN_list_of_sentences_WHEN_make_list_all_title_case_THEN_each_sentence_all_title_cased() {
        // GIVEN
        let v = ["foo bar", "foO baR"];

        // WHEN
        let actual = v.make_list_all_title_case();

        // THEN
        assert_eq!(actual, vec!["Foo Bar".to_string(), "FoO BaR".to_string()])
    }

    #[test]
    fn GIVEN_list_WHEN_make_title_case_list_THEN_comma_separated_title_cased() {
        // GIVEN
        let list = ["foo bar", "bizz buzz"];

        // WHEN
        let actual = list.make_title_case_list();

        // THEN
        assert_eq!(actual, "Foo Bar, Bizz Buzz");
    }
}
