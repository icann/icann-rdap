//! Code for handling HTTP caching.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Represents the data from HTTP responses.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HttpData {
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    pub scheme: Option<String>,
    pub host: String,
    pub expires: Option<String>,
    pub cache_control: Option<String>,
    pub received: DateTime<Utc>,
    pub status_code: u16,
    pub location: Option<String>,
    pub access_control_allow_origin: Option<String>,
    pub access_control_allow_credentials: Option<String>,
    pub strict_transport_security: Option<String>,
    pub retry_after: Option<String>,
    pub request_uri: Option<String>,
}

#[buildstructor::buildstructor]
impl HttpData {
    #[builder(visibility = "pub")]
    #[allow(clippy::too_many_arguments)]
    fn new(
        content_length: Option<u64>,
        content_type: Option<String>,
        scheme: Option<String>,
        host: String,
        expires: Option<String>,
        cache_control: Option<String>,
        status_code: u16,
        location: Option<String>,
        access_control_allow_origin: Option<String>,
        access_control_allow_credentials: Option<String>,
        strict_transport_security: Option<String>,
        retry_after: Option<String>,
        received: DateTime<Utc>,
        request_uri: Option<String>,
    ) -> Self {
        Self {
            content_length,
            content_type,
            scheme,
            host,
            expires,
            cache_control,
            received,
            status_code,
            location,
            access_control_allow_origin,
            access_control_allow_credentials,
            strict_transport_security,
            retry_after,
            request_uri,
        }
    }

    #[builder(entry = "now", visibility = "pub")]
    #[allow(clippy::too_many_arguments)]
    fn new_now(
        content_length: Option<u64>,
        content_type: Option<String>,
        scheme: String,
        host: String,
        expires: Option<String>,
        cache_control: Option<String>,
        status_code: Option<u16>,
        location: Option<String>,
        access_control_allow_origin: Option<String>,
        access_control_allow_credentials: Option<String>,
        strict_transport_security: Option<String>,
        retry_after: Option<String>,
        request_uri: Option<String>,
    ) -> Self {
        Self {
            content_length,
            content_type,
            scheme: Some(scheme),
            host,
            expires,
            cache_control,
            received: Utc::now(),
            status_code: status_code.unwrap_or(200),
            location,
            access_control_allow_origin,
            access_control_allow_credentials,
            strict_transport_security,
            retry_after,
            request_uri,
        }
    }

    #[builder(entry = "example", visibility = "pub")]
    #[allow(clippy::too_many_arguments)]
    fn new_example(
        content_length: Option<u64>,
        content_type: Option<String>,
        expires: Option<String>,
        cache_control: Option<String>,
        status_code: Option<u16>,
        location: Option<String>,
        access_control_allow_origin: Option<String>,
        access_control_allow_credentials: Option<String>,
        strict_transport_security: Option<String>,
        retry_after: Option<String>,
        request_uri: Option<String>,
    ) -> Self {
        Self {
            content_length,
            content_type,
            scheme: Some("http".to_string()),
            host: "example.com".to_string(),
            expires,
            cache_control,
            received: Utc::now(),
            status_code: status_code.unwrap_or(200),
            location,
            access_control_allow_origin,
            access_control_allow_credentials,
            strict_transport_security,
            retry_after,
            request_uri,
        }
    }

    pub fn is_expired(&self, max_age: i64) -> bool {
        let now = Utc::now();
        if now >= self.received + Duration::seconds(max_age) {
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
                    return now >= self.received + Duration::seconds(cc_max_age);
                }
            }
        }
        if let Some(expires) = &self.expires {
            let expire_time = DateTime::parse_from_rfc2822(expires);
            if let Ok(expire_time) = expire_time {
                return now >= expire_time;
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

    pub fn from_lines(lines: &[String]) -> Result<(Self, &[String]), serde_json::Error> {
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

    pub fn to_lines(&self, data: &str) -> Result<String, serde_json::Error> {
        let mut lines = serde_json::to_string(self)?;
        lines.push_str("\n---\n");
        lines.push_str(data);
        Ok(lines)
    }

    pub fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    pub fn scheme(&self) -> Option<&str> {
        self.scheme.as_deref()
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn expires(&self) -> Option<&str> {
        self.expires.as_deref()
    }

    pub fn cache_control(&self) -> Option<&str> {
        self.cache_control.as_deref()
    }

    pub fn received(&self) -> &DateTime<Utc> {
        &self.received
    }

    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    pub fn location(&self) -> Option<&str> {
        self.location.as_deref()
    }

    pub fn access_control_allow_origin(&self) -> Option<&str> {
        self.access_control_allow_origin.as_deref()
    }

    pub fn access_control_allow_credentials(&self) -> Option<&str> {
        self.access_control_allow_credentials.as_deref()
    }

    pub fn strict_transport_security(&self) -> Option<&str> {
        self.strict_transport_security.as_deref()
    }

    pub fn retry_after(&self) -> Option<&str> {
        self.retry_after.as_deref()
    }

    pub fn request_uri(&self) -> Option<&str> {
        self.request_uri.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::HttpData;
    use chrono::Duration;
    use chrono::Utc;
    use rstest::rstest;

    #[rstest]
    #[case(HttpData::example().cache_control("max-age=0").build(), 100, true)]
    #[case(HttpData::example().cache_control("max-age=100").build(), 0, true)]
    #[case(HttpData::example().cache_control("max-age=100").build(), 50, false)]
    #[case(HttpData::example().build(), 0, true)]
    #[case(HttpData::example().build(), 100, false)]
    #[case(HttpData::example().expires(Utc::now().to_rfc2822()).build(), 100, true)]
    #[case(HttpData::example().expires((Utc::now() + Duration::seconds(50)).to_rfc2822()).build(), 100, false)]
    #[case(HttpData::example().expires((Utc::now() + Duration::seconds(100)).to_rfc2822()).build(), 50, false)]
    #[case(HttpData::example().cache_control("max-age=100").expires(Utc::now().to_rfc2822()).build(), 100, false)]
    #[case(HttpData::example().cache_control("max-age=0").expires((Utc::now() + Duration::seconds(50)).to_rfc2822()).build(), 100, true)]
    fn test_cache_data_and_max_age_is_expired(
        #[case] cache_data: HttpData,
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
    #[case(HttpData::example().cache_control("no-cache").build(), false)]
    #[case(HttpData::example().cache_control("no-store").build(), false)]
    #[case(HttpData::example().cache_control("max-age=40").build(), true)]
    fn test_cache_control(#[case] cache_data: HttpData, #[case] expected: bool) {
        // GIVEN in parameters

        // WHEN
        let actual = cache_data.should_cache();

        // THEN
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_data_and_data_cache_to_lines() {
        // GIVEN
        let data = "foo";
        let cache_data = HttpData::example().content_length(14).build();

        // WHEN
        let actual = cache_data.to_lines(data).unwrap();

        // THEN
        let expected = format!("{}\n---\nfoo", serde_json::to_string(&cache_data).unwrap());
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_from_lines() {
        // GIVEN
        let data = "foo";
        let cache_data = HttpData::example().content_length(14).build();
        let lines = cache_data
            .to_lines(data)
            .unwrap()
            .split('\n')
            .map(|s| s.to_string())
            .collect::<Vec<String>>();

        // WHEN
        let actual = HttpData::from_lines(&lines).expect("parsing lines");

        // THEN
        assert_eq!(cache_data, actual.0);
        assert_eq!(vec![data], actual.1);
    }
}
