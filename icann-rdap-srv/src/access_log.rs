//! Access logging middleware for the RDAP server.
//!
//! When the `RDAP_SRV_ACCESS_LOG` configuration value is enabled, every request is logged
//! at the `info` level with the request method and path, the returned HTTP status code, the
//! source IP of the TCP connection, and the raw values of the `Forwarded`,
//! `X-Forwarded-For`, and `X-Forwarded-Proto` request headers when present.
//!
//! Design notes:
//! - The `access_log` flag is read once when the router is built and captured by the
//!   middleware closure, so no per-request `CommonConfig` clone is needed.
//! - The middleware is registered outermost in the layer stack so the logged status is the
//!   final status returned to the client, including responses produced by the timeout and
//!   error-handling layers.
//! - The source IP is the peer address of the TCP connection (from the
//!   `ConnectInfo<SocketAddr>` extension installed by `into_make_service_with_connect_info`),
//!   not the `for=` value of a forwarded header, so it is trustworthy regardless of what
//!   headers the client sends.
//! - Header values are logged raw (all values of a repeated header joined with commas),
//!   mirroring the multi-value handling used by [`crate::rdap::build_request_uri`].
//!   Absent forwarded headers are logged as empty strings. Non-UTF-8 bytes are replaced
//!   lossily rather than dropped, and each logged value is truncated at
//!   [`MAX_LOGGED_HEADER_LEN`] to bound log line size against attacker-controlled headers.
//! - The log line is emitted after the response is produced. If the client disconnects and
//!   the service future is dropped before completion, no access line is written for that
//!   request.

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Request},
    middleware::Next,
    response::Response,
};
use http::HeaderMap;
use tracing::info;

/// The tracing target used for access log events, allowing them to be filtered
/// independently of other server logging.
pub(crate) const ACCESS_LOG_TARGET: &str = "access";

/// Placeholder logged when the peer address is unavailable (e.g. no `ConnectInfo` extension).
const UNKNOWN_SRC: &str = "unknown";

/// Maximum length of a logged header value; longer values are truncated with a trailing
/// ellipsis to bound log line size against attacker-controlled headers.
const MAX_LOGGED_HEADER_LEN: usize = 512;

/// Axum middleware that logs each request at the `info` level when `access_log` is true.
///
/// When `access_log` is false this is a pass-through with no logging.
pub(crate) async fn access_log_middleware(
    access_log: bool,
    request: Request,
    next: Next,
) -> Response {
    if !access_log {
        return next.run(request).await;
    }

    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let src_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string());
    let forwarded = header_values(request.headers(), "forwarded");
    let x_forwarded_for = header_values(request.headers(), "x-forwarded-for");
    let x_forwarded_proto = header_values(request.headers(), "x-forwarded-proto");

    let response = next.run(request).await;

    info!(
        target: ACCESS_LOG_TARGET,
        method = %method,
        path = %path,
        status = response.status().as_u16(),
        src_ip = src_ip.as_deref().unwrap_or(UNKNOWN_SRC),
        forwarded = forwarded.as_deref().unwrap_or_default(),
        x_forwarded_for = x_forwarded_for.as_deref().unwrap_or_default(),
        x_forwarded_proto = x_forwarded_proto.as_deref().unwrap_or_default(),
    );

    response
}

/// Join all values of a header with commas, returning `None` when the header is absent
/// or carries only empty values.
///
/// Values that are not valid UTF-8 (legal as obs-text in header values) are recorded with
/// lossy replacement characters rather than being silently dropped, so the audit trail
/// stays faithful. The joined value is truncated at [`MAX_LOGGED_HEADER_LEN`].
fn header_values(headers: &HeaderMap, name: &str) -> Option<String> {
    let joined = headers
        .get_all(name)
        .iter()
        .map(|v| {
            v.to_str()
                .map(str::to_owned)
                .unwrap_or_else(|_| String::from_utf8_lossy(v.as_bytes()).into_owned())
        })
        .collect::<Vec<_>>()
        .join(",");
    if joined.is_empty() {
        return None;
    }
    Some(truncate(&joined))
}

/// Truncate `s` to [`MAX_LOGGED_HEADER_LEN`] characters, appending an ellipsis when
/// truncation occurred.
fn truncate(s: &str) -> String {
    if s.chars().count() <= MAX_LOGGED_HEADER_LEN {
        return s.to_string();
    }
    let mut truncated: String = s.chars().take(MAX_LOGGED_HEADER_LEN).collect();
    truncated.push('…');
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        http::{HeaderValue, StatusCode},
        routing::get,
    };
    use tower::ServiceExt;
    use tracing::Subscriber;
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::SubscriberExt;

    use std::sync::{Arc, Mutex};

    /// A single captured event: the tracing target and its recorded fields.
    type CapturedEvent = (String, Vec<(String, String)>);

    /// A tracing layer that records the target and fields of every event it sees.
    #[derive(Clone, Default)]
    struct CapturedEvents(Arc<Mutex<Vec<CapturedEvent>>>);

    impl CapturedEvents {
        fn events(&self) -> Vec<CapturedEvent> {
            self.0.lock().unwrap().clone()
        }
    }

    impl<S: Subscriber> tracing_subscriber::Layer<S> for CapturedEvents {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = CollectFields::default();
            event.record(&mut visitor);
            self.0
                .lock()
                .unwrap()
                .push((event.metadata().target().to_string(), visitor.fields));
        }
    }

    #[derive(Default)]
    struct CollectFields {
        fields: Vec<(String, String)>,
    }

    impl Visit for CollectFields {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields
                .push((field.name().to_string(), format!("{value:?}")));
        }
    }

    fn field<'a>(fields: &'a [(String, String)], name: &str) -> &'a str {
        fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("missing field: {name}"))
    }

    fn app(access_log: bool) -> Router {
        Router::new()
            .route("/rdap/domain/{domain}", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                access_log_middleware(access_log, req, next)
            }))
    }

    fn get_request(path: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::get(format!("http://localhost{path}"))
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn access_log_enabled_logs_all_fields() {
        // GIVEN access logging enabled and a subscriber capturing events
        let captured = CapturedEvents::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(captured.clone()));

        // WHEN a request with a peer address and all forwarded headers is served
        let mut req = get_request("/rdap/domain/foo.example?x=1");
        req.extensions_mut().insert(ConnectInfo(
            "198.51.100.7:54321".parse::<SocketAddr>().unwrap(),
        ));
        req.headers_mut().insert(
            "forwarded",
            "for=1.2.3.4;proto=https;host=rdap.example.com"
                .parse()
                .unwrap(),
        );
        req.headers_mut()
            .insert("x-forwarded-for", "203.0.113.5".parse().unwrap());
        req.headers_mut()
            .insert("x-forwarded-proto", "https".parse().unwrap());
        let response = app(true).oneshot(req).await.unwrap();

        // THEN the response passes through unchanged
        assert_eq!(response.status(), StatusCode::OK);

        // AND exactly one access event was logged with all fields
        let events = captured.events();
        assert_eq!(events.len(), 1);
        let (target, fields) = &events[0];
        assert_eq!(target, ACCESS_LOG_TARGET);
        assert_eq!(field(fields, "method"), "GET");
        assert_eq!(field(fields, "path"), "/rdap/domain/foo.example");
        assert_eq!(field(fields, "status"), "200");
        assert_eq!(field(fields, "src_ip"), "198.51.100.7");
        assert_eq!(
            field(fields, "forwarded"),
            "for=1.2.3.4;proto=https;host=rdap.example.com"
        );
        assert_eq!(field(fields, "x_forwarded_for"), "203.0.113.5");
        assert_eq!(field(fields, "x_forwarded_proto"), "https");
    }

    #[tokio::test]
    async fn access_log_disabled_logs_nothing() {
        // GIVEN access logging disabled and a subscriber capturing events
        let captured = CapturedEvents::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(captured.clone()));

        // WHEN a request is served
        let response = app(false)
            .oneshot(get_request("/rdap/domain/foo.example"))
            .await
            .unwrap();

        // THEN the response still passes through and nothing was logged
        assert_eq!(response.status(), StatusCode::OK);
        assert!(captured.events().is_empty());
    }

    #[tokio::test]
    async fn access_log_without_connect_info_logs_unknown_source() {
        // GIVEN access logging enabled and a subscriber capturing events
        let captured = CapturedEvents::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(captured.clone()));

        // WHEN a request with no peer address extension and no forwarded headers is served
        let response = app(true)
            .oneshot(get_request("/rdap/domain/foo.example"))
            .await
            .unwrap();

        // THEN the source IP degrades to "unknown" and absent headers log as empty strings
        assert_eq!(response.status(), StatusCode::OK);
        let events = captured.events();
        assert_eq!(events.len(), 1);
        let fields = &events[0].1;
        assert_eq!(field(fields, "src_ip"), "unknown");
        assert_eq!(field(fields, "forwarded"), "");
        assert_eq!(field(fields, "x_forwarded_for"), "");
        assert_eq!(field(fields, "x_forwarded_proto"), "");
    }

    #[tokio::test]
    async fn access_log_joins_repeated_header_values() {
        // GIVEN access logging enabled and a subscriber capturing events
        let captured = CapturedEvents::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(captured.clone()));

        // WHEN a request carries two values of the same forwarded header
        let mut req = get_request("/rdap/domain/foo.example");
        req.extensions_mut().insert(ConnectInfo(
            "198.51.100.7:54321".parse::<SocketAddr>().unwrap(),
        ));
        req.headers_mut()
            .append("x-forwarded-for", "203.0.113.5".parse().unwrap());
        req.headers_mut()
            .append("x-forwarded-for", "203.0.113.9".parse().unwrap());
        let response = app(true).oneshot(req).await.unwrap();

        // THEN both values are logged, joined with a comma
        assert_eq!(response.status(), StatusCode::OK);
        let events = captured.events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            field(&events[0].1, "x_forwarded_for"),
            "203.0.113.5,203.0.113.9"
        );
    }

    #[tokio::test]
    async fn access_log_records_non_utf8_header_lossily() {
        // GIVEN access logging enabled and a subscriber capturing events
        let captured = CapturedEvents::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(captured.clone()));

        // WHEN a request carries a non-UTF-8 forwarded header value
        let mut req = get_request("/rdap/domain/foo.example");
        req.extensions_mut().insert(ConnectInfo(
            "198.51.100.7:54321".parse::<SocketAddr>().unwrap(),
        ));
        req.headers_mut().insert(
            "x-forwarded-for",
            HeaderValue::from_bytes(&[0xff, b'A']).unwrap(),
        );
        let response = app(true).oneshot(req).await.unwrap();

        // THEN the value is recorded with a replacement character, not dropped
        assert_eq!(response.status(), StatusCode::OK);
        let events = captured.events();
        assert_eq!(events.len(), 1);
        assert_eq!(field(&events[0].1, "x_forwarded_for"), "\u{fffd}A");
    }

    #[tokio::test]
    async fn access_log_present_but_empty_header_logs_empty() {
        // GIVEN access logging enabled and a subscriber capturing events
        let captured = CapturedEvents::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(captured.clone()));

        // WHEN a request carries a present but empty forwarded header
        let mut req = get_request("/rdap/domain/foo.example");
        req.extensions_mut().insert(ConnectInfo(
            "198.51.100.7:54321".parse::<SocketAddr>().unwrap(),
        ));
        req.headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static(""));
        let response = app(true).oneshot(req).await.unwrap();

        // THEN the empty value is logged as an empty string
        assert_eq!(response.status(), StatusCode::OK);
        let events = captured.events();
        assert_eq!(events.len(), 1);
        assert_eq!(field(&events[0].1, "x_forwarded_for"), "");
    }

    #[tokio::test]
    async fn access_log_truncates_overlong_header_values() {
        // GIVEN access logging enabled and a subscriber capturing events
        let captured = CapturedEvents::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(captured.clone()));

        // WHEN a request carries a forwarded header longer than the cap
        let long_value = "x".repeat(MAX_LOGGED_HEADER_LEN + 100);
        let mut req = get_request("/rdap/domain/foo.example");
        req.extensions_mut().insert(ConnectInfo(
            "198.51.100.7:54321".parse::<SocketAddr>().unwrap(),
        ));
        req.headers_mut()
            .insert("x-forwarded-for", long_value.parse().unwrap());
        let response = app(true).oneshot(req).await.unwrap();

        // THEN the logged value is truncated at the cap with a trailing ellipsis
        assert_eq!(response.status(), StatusCode::OK);
        let events = captured.events();
        assert_eq!(events.len(), 1);
        let logged = field(&events[0].1, "x_forwarded_for");
        assert_eq!(logged.chars().count(), MAX_LOGGED_HEADER_LEN + 1);
        assert!(logged.ends_with('…'));
    }

    #[tokio::test]
    async fn access_log_records_error_status() {
        // GIVEN access logging enabled and a subscriber capturing events
        let captured = CapturedEvents::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(captured.clone()));

        // WHEN a request for a route that does not exist is served
        let response = app(true).oneshot(get_request("/rdap/nope")).await.unwrap();

        // THEN the final 404 status is what gets logged
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let events = captured.events();
        assert_eq!(events.len(), 1);
        assert_eq!(field(&events[0].1, "status"), "404");
    }
}
