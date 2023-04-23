use axum::{response::IntoResponse, routing::get, Router};
use http::StatusCode;

use crate::server::AppState;

pub fn rdap_router() -> Router<AppState> {
    Router::new()
        .route("/domain/:domain", get(not_implemented))
        .route("/ip/:ipaddr", get(not_implemented))
        .route("/autnum/:asnumber", get(not_implemented))
        .route("/nameserver/:name", get(not_implemented))
        .route("/entity/:handle", get(not_implemented))
        .route("/domains", get(not_implemented))
        .route("/nameservers", get(not_implemented))
        .route("/entities", get(not_implemented))
        .route("/help", get(not_implemented))
}

async fn not_implemented() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        [("content-type", r#"application/rdap"#)],
        r#"{"errorCode":501,"title": "This RDAP query is not yet implemented."}"#,
    )
}
