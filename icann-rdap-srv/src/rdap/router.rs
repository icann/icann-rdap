use axum::{routing::get, Router};

use super::{
    autnum::autnum_by_num, domain::domain_by_name, domains::domains, entities::entities,
    entity::entity_by_handle, ip::network_by_netid, nameserver::nameserver_by_name,
    nameservers::nameservers, srvhelp::srvhelp,
};

pub(crate) fn rdap_router() -> Router<crate::server::DynServiceState> {
    Router::new()
        .route("/domain/:domain", get(domain_by_name))
        .route("/ip/*netid", get(network_by_netid))
        .route("/autnum/:asnumber", get(autnum_by_num))
        .route("/nameserver/:name", get(nameserver_by_name))
        .route("/entity/:handle", get(entity_by_handle))
        .route("/domains", get(domains))
        .route("/nameservers", get(nameservers))
        .route("/entities", get(entities))
        .route("/help", get(srvhelp))
}
