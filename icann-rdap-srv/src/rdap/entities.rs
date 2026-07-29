use http::HeaderMap;
use icann_rdap_common::prelude::normalize_extensions;
use serde::Deserialize;

use axum::{
    extract::{Query, State},
    response::Response,
};

use crate::{
    error::RdapServerError,
    rdap::{jscontact_conversion, response::ResponseUtil},
    server::DynServiceState,
};

#[derive(Debug, Deserialize)]
pub(crate) struct EntitiesParams {
    handle: Option<String>,
    #[serde(rename = "fn")]
    #[allow(non_snake_case)]
    fn_: Option<String>,
}

#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn entities(
    Query(params): Query<EntitiesParams>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    Ok(if let Some(handle) = params.handle {
        let exts_list = super::parse_exts_list_from_headers(&headers);

        let storage = state.get_storage().await?;
        let results = storage.search_entities_by_handle(&handle).await?;
        let results = jscontact_conversion(
            results,
            state.get_common_config().jscontact_conversion,
            &exts_list,
        );
        let results = normalize_extensions(results);
        results.response()
    } else if let Some(full_name) = params.fn_ {
        let exts_list = super::parse_exts_list_from_headers(&headers);

        let storage = state.get_storage().await?;
        let results = storage.search_entities_by_full_name(&full_name).await?;
        let results = jscontact_conversion(
            results,
            state.get_common_config().jscontact_conversion,
            &exts_list,
        );
        let results = normalize_extensions(results);
        results.response()
    } else {
        super::response::NOT_IMPLEMENTED.response()
    })
}
