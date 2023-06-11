pub trait StringCheck {
    /// Tests if the string is empty, including for if the string only has whitespace.
    fn is_whitespace_or_empty(&self) -> bool;
}

impl<T: ToString> StringCheck for T {
    fn is_whitespace_or_empty(&self) -> bool {
        let s = self.to_string();
        s.is_empty() || s.contains(char::is_whitespace)
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use rstest::rstest;

    use super::StringCheck;

    #[rstest]
    #[case("foo", false)]
    #[case("", true)]
    #[case(" ", true)]
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
}
