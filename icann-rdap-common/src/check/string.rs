pub trait StringCheck {
    /// Tests if the string is empty, including for if the string only has whitespace.
    fn is_whitespace_or_empty(&self) -> bool;
}

impl<T: ToString> StringCheck for T {
    fn is_whitespace_or_empty(&self) -> bool {
        let s = self.to_string();
        s.is_empty() || s.chars().all(char::is_whitespace)
    }
}

pub trait StringListCheck {
    /// Tests if a list of strings is empty, or if any of the
    /// elemeents of the list are empty or whitespace.
    fn is_empty_or_any_empty_or_whitespace(&self) -> bool;
}

impl<T: ToString> StringListCheck for &[T] {
    fn is_empty_or_any_empty_or_whitespace(&self) -> bool {
        self.is_empty() || self.iter().any(|s| s.to_string().is_whitespace_or_empty())
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use rstest::rstest;

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
}
