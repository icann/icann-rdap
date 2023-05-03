use axum::{response::IntoResponse, routing::get, Router};

use crate::{server::AppState, storage::StorageOperations};

use super::response::NOT_IMPLEMENTED;

pub fn rdap_router<T: StorageOperations + Clone + Send + Sync + 'static>() -> Router<AppState<T>> {
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
    NOT_IMPLEMENTED.response()
}
