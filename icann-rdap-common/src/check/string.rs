/// Functions for types that can be turned into strings.
///
/// Example:
/// ```rust
/// use icann_rdap_common::check::*;
///
/// let s = "  ";
/// assert!(s.is_whitespace_or_empty());
/// ```
pub trait StringCheck {
    /// Tests if the string is empty, including for if the string only has whitespace.
    fn is_whitespace_or_empty(&self) -> bool;

    /// Tests if the string contains only letters, digits, or hyphens and is not empty.
    fn is_ldh_string(&self) -> bool;

    /// Tests if a string is an LDH domain name. This is not to be confused with [StringCheck::is_ldh_string],
    /// which checks individual domain labels.
    fn is_ldh_domain_name(&self) -> bool;

    /// Tests if a string is a Unicode domain name.
    fn is_unicode_domain_name(&self) -> bool;

    /// Tests if a string begins with a period and only has one label.
    fn is_tld(&self) -> bool;

    /// Tests if a string is an ldh host name (i.e., at least to labels)
    fn is_ldh_hostname(&self) -> bool;
}

impl<T: ToString> StringCheck for T {
    fn is_whitespace_or_empty(&self) -> bool {
        let s = self.to_string();
        s.is_empty() || s.chars().all(char::is_whitespace)
    }

    fn is_ldh_string(&self) -> bool {
        let s = self.to_string();
        !s.is_empty() && s.chars().all(char::is_ldh)
    }

    fn is_ldh_domain_name(&self) -> bool {
        let s = self.to_string();
        s == "." || (!s.is_empty() && s.split_terminator('.').all(|s| s.is_ldh_string()))
    }

    fn is_unicode_domain_name(&self) -> bool {
        let s = self.to_string();
        s == "."
            || (!s.is_empty()
                && s.split_terminator('.').all(|s| {
                    s.chars()
                        .all(|c| c == '-' || (!c.is_ascii_punctuation() && !c.is_whitespace()))
                }))
    }

    fn is_tld(&self) -> bool {
        let s = self.to_string();
        s.starts_with('.')
            && s.len() > 2
            && s.matches('.').count() == 1
            && s.split_terminator('.').all(|s| {
                s.chars()
                    .all(|c| !c.is_ascii_punctuation() && !c.is_whitespace())
            })
    }

    fn is_ldh_hostname(&self) -> bool {
        let s = self.to_string();
        let count = s.split_terminator('.').try_fold(0, |acc, s| {
            if s.is_ldh_string() {
                Ok(acc + 1)
            } else {
                Err(acc)
            }
        });
        match count {
            Ok(count) => count > 1,
            Err(_) => false,
        }
    }
}

/// Functions for types that can be turned into arrays of strings.
///
/// Example:
/// ```rust
/// use icann_rdap_common::check::*;
///
/// let a: &[&str] = &["foo",""];
/// assert!(a.is_empty_or_any_empty_or_whitespace());
/// ```
pub trait StringListCheck {
    /// Tests if a list of strings is empty, or if any of the
    /// elements of the list are empty or whitespace.
    fn is_empty_or_any_empty_or_whitespace(&self) -> bool;

    /// Tests if a list of strings are LDH strings. See [CharCheck::is_ldh].
    fn is_ldh_string_list(&self) -> bool;
}

impl<T: ToString> StringListCheck for &[T] {
    fn is_empty_or_any_empty_or_whitespace(&self) -> bool {
        self.is_empty() || self.iter().any(|s| s.to_string().is_whitespace_or_empty())
    }

    fn is_ldh_string_list(&self) -> bool {
        !self.is_empty() && self.iter().all(|s| s.to_string().is_ldh_string())
    }
}

impl<T: ToString> StringListCheck for Vec<T> {
    fn is_empty_or_any_empty_or_whitespace(&self) -> bool {
        self.is_empty() || self.iter().any(|s| s.to_string().is_whitespace_or_empty())
    }

    fn is_ldh_string_list(&self) -> bool {
        !self.is_empty() && self.iter().all(|s| s.to_string().is_ldh_string())
    }
}

/// Functions for chars.
///
/// Example:
/// ```rust
/// use icann_rdap_common::check::*;
///
/// let c = 'a';
/// assert!(c.is_ldh());
/// ```
pub trait CharCheck {
    /// Checks if the character is a letter, digit or a hyphen
    #[allow(clippy::wrong_self_convention)]
    fn is_ldh(self) -> bool;
}

impl CharCheck for char {
    fn is_ldh(self) -> bool {
        matches!(self, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-')
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::check::string::{CharCheck, StringListCheck};

    use super::StringCheck;

    #[rstest]
    #[case("foo", false)]
    #[case("", true)]
    #[case(" ", true)]
    #[case("foo bar", false)]
    fn test_is_whitespace_or_empty(#[case] test_string: &str, #[case] expected: bool) {
        // GIVEN in parameters

        // WHEN
        let actual = test_string.is_whitespace_or_empty();

        // THEN
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case(&[], true)]
    #[case(&["foo"], false)]
    #[case(&["foo",""], true)]
    #[case(&["foo","bar"], false)]
    #[case(&["foo","bar baz"], false)]
    #[case(&[""], true)]
    #[case(&[" "], true)]
    fn test_is_whitespace_or_any_empty_or_whitespace(
        #[case] test_list: &[&str],
        #[case] expected: bool,
    ) {
        // GIVEN in parameters

        // WHEN
        let actual = test_list.is_empty_or_any_empty_or_whitespace();

        // THEN
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case('a', true)]
    #[case('l', true)]
    #[case('z', true)]
    #[case('A', true)]
    #[case('L', true)]
    #[case('Z', true)]
    #[case('0', true)]
    #[case('3', true)]
    #[case('9', true)]
    #[case('-', true)]
    #[case('_', false)]
    #[case('.', false)]
    fn test_is_ldh(#[case] test_char: char, #[case] expected: bool) {
        // GIVEN in parameters

        // WHEN
        let actual = test_char.is_ldh();

        // THEN
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case("foo", true)]
    #[case("", false)]
    #[case("foo-bar", true)]
    #[case("foo bar", false)]
    fn test_is_ldh_string(#[case] test_string: &str, #[case] expected: bool) {
        // GIVEN in parameters

        // WHEN
        let actual = test_string.is_ldh_string();

        // THEN
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case("foo", false)]
    #[case("", false)]
    #[case("foo-bar", false)]
    #[case("foo bar", false)]
    #[case(".", false)]
    #[case(".foo.bar", false)]
    #[case(".foo", true)]
    fn test_is_tld(#[case] test_string: &str, #[case] expected: bool) {
        // GIVEN in parameters

        // WHEN
        let actual = test_string.is_tld();

        // THEN
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case(&[], false)]
    #[case(&["foo"], true)]
    #[case(&["foo",""], false)]
    #[case(&["foo","bar"], true)]
    #[case(&["foo","bar baz"], false)]
    #[case(&[""], false)]
    #[case(&[" "], false)]
    fn test_is_ldh_string_list(#[case] test_list: &[&str], #[case] expected: bool) {
        // GIVEN in parameters

        // WHEN
        let actual = test_list.is_ldh_string_list();

        // THEN
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case("foo", true)]
    #[case("", false)]
    #[case(".", true)]
    #[case("foo.bar", true)]
    #[case("foo.bar.", true)]
    fn test_is_ldh_domain_name(#[case] test_string: &str, #[case] expected: bool) {
        // GIVEN in parameters

        // WHEN
        let actual = test_string.is_ldh_domain_name();

        // THEN
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case("foo", true)]
    #[case("", false)]
    #[case(".", true)]
    #[case("foo.bar", true)]
    #[case("foè.bar", true)]
    #[case("foo.bar.", true)]
    #[case("fo_o.bar.", false)]
    #[case("fo o.bar.", false)]
    fn test_is_unicode_domain_name(#[case] test_string: &str, #[case] expected: bool) {
        // GIVEN in parameters

        // WHEN
        let actual = test_string.is_unicode_domain_name();

        // THEN
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case("foo", false)]
    #[case("", false)]
    #[case(".", false)]
    #[case("foo.bar", true)]
    #[case("foè.bar", false)]
    #[case("foo.bar.", true)]
    #[case("fo_o.bar.", false)]
    #[case("fo o.bar.", false)]
    #[case("bar.foo.bar", true)]
    #[case("https://foo.bar", false)]
    #[case("http://foo.bar", false)]
    fn test_is_ldh_hostname(#[case] test_string: &str, #[case] expected: bool) {
        // GIVEN in parameters

        // WHEN
        let actual = test_string.is_ldh_hostname();

        // THEN
        assert_eq!(actual, expected);
    }
}
