use axum::{response::IntoResponse, routing::get, Router};

use super::{domain::domain_by_name, response::NOT_IMPLEMENTED};

pub(crate) fn rdap_router() -> Router<crate::server::DynStoreState> {
    Router::new()
        .route("/domain/:domain", get(domain_by_name))
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
    NOT_IMPLEMENTED.response()
}
