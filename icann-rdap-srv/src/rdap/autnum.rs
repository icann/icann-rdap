use axum::{
    extract::{Path, State},
    response::Response,
};
use http::{HeaderMap, Uri};
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
    uri: Uri,
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
        let mut autnum = normalize_extensions(autnum);
        super::inject_db_last_update(&mut autnum, storage, state.get_common_config());
        super::replace_tos_link_value(
            &mut autnum,
            state.get_common_config(),
            state.get_base_origin(),
            &uri,
            &headers,
        );
        autnum.response()
    })
}
