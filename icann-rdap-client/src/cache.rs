use buildstructor::Builder;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::RdapClientError;

#[derive(Serialize, Deserialize, Debug, Builder, PartialEq, Eq)]
pub struct CacheData {
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    pub host: String,
    pub expires: Option<String>,
    pub cache_control: Option<String>,
    pub received: DateTime<Utc>,
}

#[buildstructor::buildstructor]
impl CacheData {
    #[builder(entry = "now")]
    pub fn new_now(
        content_length: Option<u64>,
        content_type: Option<String>,
        host: String,
        expires: Option<String>,
        cache_control: Option<String>,
    ) -> Self {
        Self {
            content_length,
            content_type,
            host,
            expires,
            cache_control,
            received: Utc::now(),
        }
    }

    pub fn is_expired(&self, max_age: i64) -> bool {
        let now = Utc::now();
        if now > self.received + Duration::seconds(max_age) {
            return true;
        }
        if let Some(cache_control) = &self.cache_control {
            let cc_max_age = cache_control
                .split(',')
                .map(|s| s.trim())
                .find(|s| s.starts_with("max-age="));
            if let Some(cc_max_age) = cc_max_age {
                let cc_max_age = cc_max_age.trim_start_matches("max-age=").parse::<i64>();
                if let Ok(cc_max_age) = cc_max_age {
                    return now > self.received + Duration::seconds(cc_max_age);
                }
            }
        }
        if let Some(expires) = &self.expires {
            let expire_time = DateTime::parse_from_rfc2822(expires);
            if let Ok(expire_time) = expire_time {
                return now > expire_time;
            } else {
                return false;
            }
        }
        false
    }

    pub fn should_cache(&self) -> bool {
        if let Some(cache_control) = &self.cache_control {
            return !cache_control
                .split(',')
                .map(|s| s.trim())
                .any(|s| s.eq("no-store") || s.eq("no-cache"));
        }
        true
    }

    pub fn from_lines(lines: &[String]) -> Result<(Self, &[String]), RdapClientError> {
        let count = lines.iter().take_while(|s| !s.starts_with("---")).count();
        let cache_data = lines
            .iter()
            .take(count)
            .cloned()
            .collect::<Vec<String>>()
            .join("");
        let cache_data = serde_json::from_str(&cache_data)?;
        Ok((cache_data, &lines[count + 1..]))
    }

    pub fn to_lines(&self, data: &str) -> Result<String, RdapClientError> {
        let mut lines = serde_json::to_string(self)?;
        lines.push_str("\n---\n");
        lines.push_str(data);
        Ok(lines)
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::CacheData;
    use chrono::Duration;
    use chrono::Utc;
    use rstest::rstest;

    #[rstest]
    #[case(CacheData::now().host("example.com").cache_control("max-age=0").build(), 100, true)]
    #[case(CacheData::now().host("example.com").cache_control("max-age=100").build(), 0, true)]
    #[case(CacheData::now().host("example.com").cache_control("max-age=100").build(), 50, false)]
    #[case(CacheData::now().host("example.com").build(), 0, true)]
    #[case(CacheData::now().host("example.com").build(), 100, false)]
    #[case(CacheData::now().host("example.com").expires(Utc::now().to_rfc2822()).build(), 100, true)]
    #[case(CacheData::now().host("example.com").expires((Utc::now() + Duration::seconds(50)).to_rfc2822()).build(), 100, false)]
    #[case(CacheData::now().host("example.com").expires((Utc::now() + Duration::seconds(100)).to_rfc2822()).build(), 50, false)]
    #[case(CacheData::now().host("example.com").cache_control("max-age=100").expires(Utc::now().to_rfc2822()).build(), 100, false)]
    #[case(CacheData::now().host("example.com").cache_control("max-age=0").expires((Utc::now() + Duration::seconds(50)).to_rfc2822()).build(), 100, true)]
    fn GIVEN_cache_data_and_max_age_WHEN_is_expired_THEN_correc(
        #[case] cache_data: CacheData,
        #[case] max_age: i64,
        #[case] expected: bool,
    ) {
        // GIVEN in parameters

        // WHEN
        let actual = cache_data.is_expired(max_age);

        // THEN
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case(CacheData::now().host("example.com").cache_control("no-cache").build(), false)]
    #[case(CacheData::now().host("example.com").cache_control("no-store").build(), false)]
    #[case(CacheData::now().host("example.com").cache_control("max-age=40").build(), true)]
    fn GIVEN_cache_control_WHEN_should_cache_THEN_correc(
        #[case] cache_data: CacheData,
        #[case] expected: bool,
    ) {
        // GIVEN in parameters

        // WHEN
        let actual = cache_data.should_cache();

        // THEN
        assert_eq!(actual, expected);
    }

    #[test]
    fn GIVEN_data_and_data_cache_WHEN_to_lines_THEN_format_correct() {
        // GIVEN
        let data = "foo";
        let cache_data = CacheData::now()
            .host("example.com")
            .content_length(14)
            .build();

        // WHEN
        let actual = cache_data.to_lines(data).unwrap();

        // THEN
        let expected = format!("{}\n---\nfoo", serde_json::to_string(&cache_data).unwrap());
        assert_eq!(actual, expected);
    }

    #[test]
    fn GIVEN_lines_WHEN_from_lines_THEN_parse_correctly() {
        // GIVEN
        let data = "foo";
        let cache_data = CacheData::now()
            .host("example.com")
            .content_length(14)
            .build();
        let lines = cache_data
            .to_lines(data)
            .unwrap()
            .split('\n')
            .map(|s| s.to_string())
            .collect::<Vec<String>>();

        // WHEN
        let actual = CacheData::from_lines(&lines).expect("parsing lines");

        // THEN
        assert_eq!(cache_data, actual.0);
        assert_eq!(vec![data], actual.1);
    }
}
