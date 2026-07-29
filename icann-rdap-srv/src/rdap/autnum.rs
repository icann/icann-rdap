use axum::{
    extract::{Path, State},
    response::Response,
};
use http::HeaderMap;
use icann_rdap_common::prelude::normalize_extensions;

use crate::{
    error::RdapServerError,
    rdap::{jscontact_conversion, response::ResponseUtil},
    server::DynServiceState,
};

use super::ToBootStrap;

/// Gets an autnum object by the number path.
#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn autnum_by_num(
    Path(as_num): Path<u32>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = super::parse_exts_list_from_headers(&headers);

    let storage = state.get_storage().await?;
    let autnum = storage.get_autnum_by_num(as_num).await?;
    Ok(if state.get_common_config().bootstrap {
        autnum.to_autnum_bootstrap(as_num).response()
    } else {
        let autnum = jscontact_conversion(
            autnum,
            state.get_common_config().jscontact_conversion,
            &exts_list,
        );
        let autnum = normalize_extensions(autnum);
        autnum.response()
    })
}
