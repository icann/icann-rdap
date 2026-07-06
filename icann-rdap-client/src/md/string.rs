use chrono::DateTime;

use super::{MdOptions, MdParams};

pub trait StringUtil {
    /// Replaces and filters markdown characters.
    fn replace_md_chars(self) -> String;
    fn to_em(self, options: &MdOptions) -> String;
    fn to_bold(self, options: &MdOptions) -> String;
    fn to_strikethrough(self, options: &MdOptions) -> String;
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
    fn to_unordered_item(self, indent_level: usize, options: &MdOptions) -> String;
}

impl<T: ToString> StringUtil for T {
    fn replace_md_chars(self) -> String {
        self.to_string()
            .replace(|c: char| c.is_whitespace(), " ")
            .replace("*** ", " ")
            .replace("** ", " ")
            .replace("* ", " ")
            .chars()
            .map(|c| match c {
                '*' | '|' => format!("\\{c}"),
                '#' => format!("`{}`", c),
                _ => c.to_string(),
            })
            .collect()
    }

    fn to_em(self, options: &MdOptions) -> String {
        format!(
            "{}{}{}",
            options.text_style_char,
            self.to_string(),
            options.text_style_char
        )
    }

    fn to_bold(self, options: &MdOptions) -> String {
        format!(
            "{}{}{}{}{}",
            options.text_style_char,
            options.text_style_char,
            self.to_string(),
            options.text_style_char,
            options.text_style_char
        )
    }

    fn to_strikethrough(self, _options: &MdOptions) -> String {
        format!("~~{}~~", self.to_string(),)
    }

    fn to_inline(self, _options: &MdOptions) -> String {
        format!("`{}`", self.to_string(),)
    }

    fn to_header(self, level: usize, options: &MdOptions) -> String {
        let s = self.to_string();
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
        let str = self.to_string();
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
        let str = self.to_string();
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
        let str = self.to_string();
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
            .replace_md_chars()
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

    fn to_unordered_item(self, indent_level: usize, options: &MdOptions) -> String {
        let mut s = self.to_string();
        let trimmed = s.trim_start();
        let leading = &s[..s.len() - trimmed.len()];
        if let Some(first) = trimmed.chars().next()
            && first == '>'
        {
            s = format!("{}`{}`{}", leading, first, &trimmed[1..]);
        }
        if options.indent_simulate_bullet {
            let bullet = format!("{} ", options.bullet_char);
            let prefix = bullet.repeat(indent_level.saturating_sub(1));
            format!("{prefix}{} {}", options.bullet_char, s)
        } else {
            let indent = "  ".repeat(indent_level);
            format!("{}{} {}", indent, options.bullet_char, s)
        }
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
mod tests {
    use rstest::rstest;

    use super::{StringListUtil, StringUtil};

    #[rstest]
    #[case("foo", "Foo")]
    #[case("FOO", "FOO")]
    fn test_words(#[case] word: &str, #[case] expected: &str) {
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
    fn test_sentences(#[case] sentence: &str, #[case] expected: &str) {
        // GIVEN in arguments

        // WHEN
        let actual = sentence.to_words_title_case();

        // THEN
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_list_of_sentences() {
        // GIVEN
        let v = ["foo bar", "foO baR"];

        // WHEN
        let actual = v.make_list_all_title_case();

        // THEN
        assert_eq!(actual, vec!["Foo Bar".to_string(), "FoO BaR".to_string()])
    }

    #[test]
    fn test_list() {
        // GIVEN
        let list = ["foo bar", "bizz buzz"];

        // WHEN
        let actual = list.make_title_case_list();

        // THEN
        assert_eq!(actual, "Foo Bar, Bizz Buzz");
    }

    #[test]
    fn test_replace_md_chars() {
        // GIVEN
        let s = "The *brown* | fox # \tjumped*** over** the* fence.";

        // WHEN
        let actual = s.replace_md_chars();

        // THEN
        assert_eq!(r#"The \*brown \| fox `#`  jumped over the fence."#, &actual);
    }

    #[rstest]
    #[case("normal item", 0, "- normal item")]
    #[case("> quoted text", 0, "- `>` quoted text")]
    #[case("+ plus sign", 0, "- + plus sign")]
    #[case("- dash item", 0, "- - dash item")]
    #[case("  > indented quoted", 0, "-   `>` indented quoted")]
    #[case("nested item", 1, "  - nested item")]
    #[case("hash text", 0, "- hash text")]
    fn test_to_unordered_item(#[case] input: &str, #[case] indent: usize, #[case] expected: &str) {
        let options = crate::md::MdOptions::default();
        let actual = input.to_unordered_item(indent, &options);
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case("normal item", 0, "* normal item")]
    #[case("> quoted text", 0, "* `>` quoted text")]
    #[case("+ plus sign", 0, "* + plus sign")]
    #[case("- dash item", 0, "* - dash item")]
    #[case("  > indented quoted", 0, "*   `>` indented quoted")]
    #[case("nested item", 1, "  * nested item")]
    #[case("hash text", 0, "* hash text")]
    fn test_to_unordered_item_plain_text(
        #[case] input: &str,
        #[case] indent: usize,
        #[case] expected: &str,
    ) {
        let options = crate::md::MdOptions::plain_text();
        let actual = input.to_unordered_item(indent, &options);
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case("nested item", 1, "- nested item")]
    #[case("nested item", 2, "- - nested item")]
    #[case("nested item", 3, "- - - nested item")]
    fn test_to_unordered_item_indent_simulate_bullet(
        #[case] input: &str,
        #[case] indent: usize,
        #[case] expected: &str,
    ) {
        let mut options = crate::md::MdOptions::default();
        options.indent_simulate_bullet = true;
        let actual = input.to_unordered_item(indent, &options);
        assert_eq!(actual, expected);
    }
}
