pub trait StringCheck {
    /// Tests if the string is empty, including for if the string only has whitespace.
    fn is_whitespace_or_empty(&self) -> bool;

    /// Tests if the string contains only letters, digits, or hyphens and is not empty.
    fn is_ldh_string(&self) -> bool;

    /// Tests if a string is an LDH doamin name. This is not to be confused with [is_ldh_string],
    /// which checks individual domain labels.
    fn is_ldh_domain_name(&self) -> bool;
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
}

pub trait StringListCheck {
    /// Tests if a list of strings is empty, or if any of the
    /// elemeents of the list are empty or whitespace.
    fn is_empty_or_any_empty_or_whitespace(&self) -> bool;

    /// Tests if a list of strings ard LDH strings. See [CharCheck::is_ldh].
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
#[allow(non_snake_case)]
mod tests {
    use rstest::rstest;

    use crate::check::string::CharCheck;
    use crate::check::string::StringListCheck;

    use super::StringCheck;

    #[rstest]
    #[case("foo", false)]
    #[case("", true)]
    #[case(" ", true)]
    #[case("foo bar", false)]
    fn GIVEN_string_WHEN_is_whitespace_or_empty_THEN_correct_result(
        #[case] test_string: &str,
        #[case] expected: bool,
    ) {
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
    fn GIVEN_string_list_WHEN_is_whitespace_or_empty_THEN_correct_result(
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
    fn GIVEN_char_WHEN_is_ldh_THEN_correct_result(#[case] test_char: char, #[case] expected: bool) {
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
    fn GIVEN_string_WHEN_is_ldh_string_THEN_correct_result(
        #[case] test_string: &str,
        #[case] expected: bool,
    ) {
        // GIVEN in parameters

        // WHEN
        let actual = test_string.is_ldh_string();

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
    fn GIVEN_string_list_WHEN_is_ldh_string_list_THEN_correct_result(
        #[case] test_list: &[&str],
        #[case] expected: bool,
    ) {
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
    fn GIVEN_string_WHEN_is_ldh_domain_name_THEN_correct_result(
        #[case] test_string: &str,
        #[case] expected: bool,
    ) {
        // GIVEN in parameters

        // WHEN
        let actual = test_string.is_ldh_domain_name();

        // THEN
        assert_eq!(actual, expected);
    }
}
