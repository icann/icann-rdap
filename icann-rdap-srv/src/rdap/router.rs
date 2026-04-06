use axum::{routing::get, Router};

use super::{
    autnum::autnum_by_num,
    autnums::autnum_rdap_up,
    domain::domain_by_name,
    domains::domains,
    entities::entities,
    entity::entity_by_handle,
    ip::network_by_netid,
    ips::{ip_rdap_bottom, ip_rdap_down, ip_rdap_top, ip_rdap_up},
    nameserver::nameserver_by_name,
    nameservers::nameservers,
    srvhelp::srvhelp,
};

pub(crate) fn rdap_router() -> Router<crate::server::DynServiceState> {
    Router::new()
        .route("/domain/:domain", get(domain_by_name))
        .route("/ip/*netid", get(network_by_netid))
        .route("/autnum/:asnumber", get(autnum_by_num))
        .route("/autnums/rirSearch1/rdap-up/*asNumber", get(autnum_rdap_up))
        .route("/nameserver/:name", get(nameserver_by_name))
        .route("/entity/:handle", get(entity_by_handle))
        .route("/domains", get(domains))
        .route("/nameservers", get(nameservers))
        .route("/entities", get(entities))
        .route("/help", get(srvhelp))
        .route("/ips/rirSearch1/rdap-up/*ipAddress", get(ip_rdap_up))
        .route("/ips/rirSearch1/rdap-top/*ipAddress", get(ip_rdap_top))
        .route("/ips/rirSearch1/rdap-down/*ipAddress", get(ip_rdap_down))
        .route(
            "/ips/rirSearch1/rdap-bottom/*ipAddress",
            get(ip_rdap_bottom),
        )
}
