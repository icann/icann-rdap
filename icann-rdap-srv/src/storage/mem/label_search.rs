use std::collections::HashMap;

use {ab_radix_trie::Trie, buildstructor::Builder};

use crate::error::RdapServerError;

/// A structure for searching DNS labels as specified in RFC 9082.
/// For RDAP, type T is likely RdapResponse or Arc<RdapResponse>.
#[derive(Builder)]
pub struct SearchLabels<T: Clone> {
    label_suffixes: HashMap<String, Trie<T>>,
}

impl<T: Clone> SearchLabels<T> {
    /// Insert a value based on a domain name.
    pub(crate) fn insert(&mut self, text: &str, value: T) {
        // char_indices gets the UTF8 indices as well as the character
        for (i, char) in text.char_indices() {
            if char == '.' && i != 0 {
                let prefix = &text[..i];
                // find the next UTF8 character index
                let mut next_i = i + 1;
                while !text.is_char_boundary(next_i) {
                    next_i += 1;
                }
                let suffix = &text[next_i..];
                self.label_suffixes
                    .entry(suffix.to_owned())
                    .or_insert(Trie::new())
                    .insert(prefix, Some(value.clone()));
            }
        }
        // the root
        self.label_suffixes
            .entry(String::default())
            .or_insert(Trie::new())
            .insert(text, Some(value.clone()));
    }

    /// Search values based on a label search
    pub(crate) fn search(&self, search: &str) -> Result<Vec<T>, RdapServerError> {
        // search string is invalid if it doesn't have only one asterisk ('*')
        if search.chars().filter(|c| *c == '*').count() != 1 {
            return Err(RdapServerError::InvalidArg(
                "Search string must contain one and only one asterisk ('*')".to_string(),
            ));
        }
        // asterisk must not be followed by a character other than dot ('.')
        let star = search
            .find('*')
            .expect("internal error. previous check should have caught this");
        if star != search.chars().count() - 1
            && search
                .chars()
                .nth(star + 1)
                .expect("should have been short circuited")
                != '.'
        {
            return Err(RdapServerError::InvalidArg(
                "Search string asterisk ('*') must terminate domain label".to_string(),
            ));
        }

        let parts = search
            .split_once('*')
            .expect("internal error. previous check should insure there is an asterisk");

        // this is a limitation of the trie in that it requires a prefix
        if parts.0.is_empty() {
            return Err(RdapServerError::InvalidArg(
                "Search string must have a prefix".to_string(),
            ));
        }

        if let Some(trie) = self.label_suffixes.get(parts.1.trim_start_matches('.')) {
            if let Some(entries) = trie.get_suffixes_values(parts.0) {
                if !entries.is_empty() {
                    let values = entries
                        .iter()
                        .filter_map(|e| e.val.clone())
                        .collect::<Vec<T>>();
                    return Ok(values);
                }
            }
        }

        Ok(vec![])
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {

    use ab_radix_trie::{Entry, Trie};

    use super::SearchLabels;

    #[test]
    fn GIVEN_domain_names_WHEN_inserting_THEN_search_labels_is_correct() {
        // GIVEN
        let mut search = SearchLabels::builder().build();

        // WHEN
        search.insert("foo.example.com", "foo.example.com".to_owned());
        search.insert("bar.example.com", "bar.example.com".to_owned());
        search.insert("foo.example.net", "foo.example.net".to_owned());
        search.insert("bar.example.net", "bar.example.net".to_owned());

        // THEN
        dbg!(&search.label_suffixes);
        assert_eq!(search.label_suffixes.len(), 5);
        // root
        let root = search.label_suffixes.get("").expect("no root");
        assert_trie(
            root,
            "foo.example.",
            &["foo.example.com", "foo.example.net"],
            &["bar.example.com", "bar.example.net"],
        );
        assert_trie(
            root,
            "bar.example.",
            &["bar.example.com", "bar.example.net"],
            &["foo.example.com", "foo.example.net"],
        );
        // com
        let com = search.label_suffixes.get("com").expect("no trie");
        assert_trie(
            com,
            "foo.example",
            &["foo.example.com"],
            &["bar.example.com", "bar.example.net", "foo.example.net"],
        );
        assert_trie(
            com,
            "bar.example",
            &["bar.example.com"],
            &["foo.example.com", "foo.example.net", "bar.example.net"],
        );
        // net
        let net = search.label_suffixes.get("net").expect("no trie");
        assert_trie(
            net,
            "foo.example",
            &["foo.example.net"],
            &["bar.example.net", "bar.example.com", "foo.example.com"],
        );
        assert_trie(
            net,
            "bar.example",
            &["bar.example.net"],
            &["foo.example.com", "foo.example.net", "bar.example.com"],
        );
        // example.com
        let example_com = search.label_suffixes.get("example.com").expect("no trie");
        assert_trie(
            example_com,
            "foo",
            &["foo.example.com"],
            &["bar.example.com", "bar.example.net", "foo.example.net"],
        );
        assert_trie(
            example_com,
            "bar",
            &["bar.example.com"],
            &["foo.example.com", "foo.example.net", "bar.example.net"],
        );
        // example.net
        let example_net = search.label_suffixes.get("example.net").expect("no trie");
        assert_trie(
            example_net,
            "foo",
            &["foo.example.net"],
            &["bar.example.net", "bar.example.com", "foo.example.com"],
        );
        assert_trie(
            example_net,
            "bar",
            &["bar.example.net"],
            &["foo.example.com", "foo.example.net", "bar.example.com"],
        );
    }

    fn assert_trie(trie: &Trie<String>, suffix: &str, must_have: &[&str], must_not_have: &[&str]) {
        let entries = trie
            .get_suffixes_values(suffix)
            .expect("no values in entries");
        for s in must_have {
            assert!(
                trie_contains(&entries, s),
                "suffix = {suffix} did not find {s}"
            );
        }
        for s in must_not_have {
            assert!(!trie_contains(&entries, s), "suffix = {suffix} found {s}");
        }
    }

    fn trie_contains(entries: &[Entry<'_, String>], value: &str) -> bool {
        entries
            .iter()
            .any(|e| e.val.as_ref().expect("no entry value") == value)
    }

    #[test]
    fn GIVEN_search_string_with_two_asterisks_WHEN_search_THEN_error() {
        // GIVEN
        let labels: SearchLabels<String> = SearchLabels::builder().build();
        let search = "foo.*.*";

        // WHEN
        let actual = labels.search(search);

        // THEN
        assert!(actual.is_err());
    }

    #[test]
    fn GIVEN_search_string_with_asterisk_suffix_WHEN_search_THEN_error() {
        // GIVEN
        let labels: SearchLabels<String> = SearchLabels::builder().build();
        let search = "foo.*example.net";

        // WHEN
        let actual = labels.search(search);

        // THEN
        assert!(actual.is_err());
    }

    #[test]
    fn GIVEN_search_string_with_no_asterisk_WHEN_search_THEN_error() {
        // GIVEN
        let labels: SearchLabels<String> = SearchLabels::builder().build();
        let search = "foo.example.net";

        // WHEN
        let actual = labels.search(search);

        // THEN
        assert!(actual.is_err());
    }

    #[test]
    fn GIVEN_empty_search_string_WHEN_search_THEN_error() {
        // GIVEN
        let labels: SearchLabels<String> = SearchLabels::builder().build();
        let search = "";

        // WHEN
        let actual = labels.search(search);

        // THEN
        assert!(actual.is_err());
    }

    #[test]
    fn GIVEN_root_search_WHEN_search_THEN_correct_values_found() {
        // GIVEN
        let mut labels = SearchLabels::builder().build();
        labels.insert("foo.example.com", "foo.example.com".to_owned());
        labels.insert("bar.example.com", "bar.example.com".to_owned());
        labels.insert("foo.example.net", "foo.example.net".to_owned());
        labels.insert("bar.example.net", "bar.example.net".to_owned());

        // WHEN
        let actual = labels.search("foo.example.*").expect("search is invalid");

        // THEN
        dbg!(&actual);
        assert_eq!(actual.len(), 2);
        assert!(actual.contains(&"foo.example.com".to_string()));
        assert!(actual.contains(&"foo.example.net".to_string()));
    }

    #[test]
    fn GIVEN_root_search_WHEN_search_with_prefix_THEN_correct_values_found() {
        // GIVEN
        let mut labels = SearchLabels::builder().build();
        labels.insert("foo.example.com", "foo.example.com".to_owned());
        labels.insert("bar.example.com", "bar.example.com".to_owned());
        labels.insert("foo.example.net", "foo.example.net".to_owned());
        labels.insert("bar.example.net", "bar.example.net".to_owned());

        // WHEN
        let actual = labels.search("foo.example.n*").expect("search is invalid");

        // THEN
        dbg!(&actual);
        assert_eq!(actual.len(), 1);
        assert!(actual.contains(&"foo.example.net".to_string()));
    }

    #[test]
    fn GIVEN_labels_WHEN_sld_search_with_prefix_THEN_correct_values_found() {
        // GIVEN
        let mut labels = SearchLabels::builder().build();
        labels.insert("foo.example.com", "foo.example.com".to_owned());
        labels.insert("bar.example.com", "bar.example.com".to_owned());
        labels.insert("foo.example.net", "foo.example.net".to_owned());
        labels.insert("bar.example.net", "bar.example.net".to_owned());

        // WHEN
        let actual = labels.search("foo.ex*.com").expect("search is invalid");

        // THEN
        dbg!(&actual);
        assert_eq!(actual.len(), 1);
        assert!(actual.contains(&"foo.example.com".to_string()));
    }

    #[test]
    fn GIVEN_labels_WHEN_3ld_search_with_prefix_THEN_correct_values_found() {
        // GIVEN
        let mut labels = SearchLabels::builder().build();
        labels.insert("foo.example.com", "foo.example.com".to_owned());
        labels.insert("bar.example.com", "bar.example.com".to_owned());
        labels.insert("foo.example.net", "foo.example.net".to_owned());
        labels.insert("bar.example.net", "bar.example.net".to_owned());

        // WHEN
        let actual = labels.search("fo*.example.com").expect("search is invalid");

        // THEN
        dbg!(&actual);
        assert_eq!(actual.len(), 1);
        assert!(actual.contains(&"foo.example.com".to_string()));
    }

    #[test]
    fn GIVEN_labels_WHEN_sld_search_THEN_correct_values_found() {
        // GIVEN
        let mut labels = SearchLabels::builder().build();
        labels.insert("foo.example.com", "foo.example.com".to_owned());
        labels.insert("bar.example.com", "bar.example.com".to_owned());
        labels.insert("foo.example.net", "foo.example.net".to_owned());
        labels.insert("bar.example.net", "bar.example.net".to_owned());

        // WHEN
        let actual = labels.search("foo.*.com").expect("search is invalid");

        // THEN
        dbg!(&actual);
        assert_eq!(actual.len(), 1);
        assert!(actual.contains(&"foo.example.com".to_string()));
    }

    #[test]
    fn GIVEN_labels_WHEN_3ld_search_THEN_error() {
        // GIVEN
        let mut labels = SearchLabels::builder().build();
        labels.insert("foo.example.com", "foo.example.com".to_owned());
        labels.insert("bar.example.com", "bar.example.com".to_owned());
        labels.insert("foo.example.net", "foo.example.net".to_owned());
        labels.insert("bar.example.net", "bar.example.net".to_owned());

        // WHEN
        let actual = labels.search("*.example.com");

        // THEN
        dbg!(&actual);
        assert!(actual.is_err());
    }
}
