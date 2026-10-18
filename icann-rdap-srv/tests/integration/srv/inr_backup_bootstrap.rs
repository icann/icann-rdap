//! Integration tests for the INR backup bootstrap feature.
//!
//! When `bootstrap` and `inr_backup_bootstrap` are both enabled, an INR query (IP address,
//! Autonomous System Number, or reverse DNS) that the local store cannot resolve is
//! redirected (HTTP 307) to the equivalent path on the configured backup server, rather
//! than returning a 404 (lookups, rdap-up, rdap-top) or an empty search result set
//! (rdap-down, rdap-bottom).

use icann_rdap_client::{
    http::{Client, ClientConfig, create_client},
    rdap::{QueryType, rdap_request},
};

pub(crate) const BACKUP: &str = "https://backup.example/rdap";

/// A client that does not follow redirects so the Location header can be inspected.
pub(crate) fn no_follow_client() -> Client {
    let cfg = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    create_client(&cfg).expect("creating client")
}

pub(crate) async fn query(base: &str, q: QueryType) -> icann_rdap_client::rdap::ResponseData {
    rdap_request(base, &q, &no_follow_client())
        .await
        .expect("querying server")
}

mod backup_redirects {
    use super::{BACKUP, query};
    use crate::test_jig::SrvTestJig;
    use icann_rdap_client::rdap::QueryType;
    use icann_rdap_srv::config::CommonConfig;

    #[tokio::test]
    async fn ip_rdap_up_not_found_redirects_to_backup() {
        // GIVEN a bootstrap server with INR backup enabled and rdap-up feature on, but no data
        let cfg = CommonConfig {
            bootstrap: true,
            inr_backup_bootstrap: true,
            inr_backup_bootstrap_url: BACKUP.to_string(),
            ip_rdap_up_enable: true,
            ..Default::default()
        };
        let srv = SrvTestJig::new_common_config(cfg).await;

        // WHEN querying an address that is not served locally
        let resp = query(&srv.rdap_base, QueryType::ipv4_up("192.0.2.1").unwrap()).await;

        // THEN a 307 redirect to the backup's rdap-up path
        assert_eq!(resp.http_data.status_code, 307);
        assert_eq!(
            resp.http_data.location.expect("no location header"),
            "https://backup.example/rdap/ips/rirSearch1/rdap-up/192.0.2.1"
        );
    }

    #[tokio::test]
    async fn ip_rdap_top_not_found_redirects_to_backup() {
        // GIVEN
        let cfg = CommonConfig {
            bootstrap: true,
            inr_backup_bootstrap: true,
            inr_backup_bootstrap_url: BACKUP.to_string(),
            ip_rdap_top_enable: true,
            ..Default::default()
        };
        let srv = SrvTestJig::new_common_config(cfg).await;

        // WHEN
        let resp = query(&srv.rdap_base, QueryType::ipv4_top("192.0.2.1").unwrap()).await;

        // THEN
        assert_eq!(resp.http_data.status_code, 307);
        assert_eq!(
            resp.http_data.location.expect("no location header"),
            "https://backup.example/rdap/ips/rirSearch1/rdap-top/192.0.2.1"
        );
    }

    #[tokio::test]
    async fn ip_rdap_down_empty_redirects_to_backup() {
        // GIVEN rdap-down enabled but no matching results (empty search result set)
        let cfg = CommonConfig {
            bootstrap: true,
            inr_backup_bootstrap: true,
            inr_backup_bootstrap_url: BACKUP.to_string(),
            ip_rdap_down_enable: true,
            ..Default::default()
        };
        let srv = SrvTestJig::new_common_config(cfg).await;

        // WHEN
        let resp = query(&srv.rdap_base, QueryType::ipv4_down("192.0.2.1").unwrap()).await;

        // THEN the empty result set triggers a backup redirect
        assert_eq!(resp.http_data.status_code, 307);
        assert_eq!(
            resp.http_data.location.expect("no location header"),
            "https://backup.example/rdap/ips/rirSearch1/rdap-down/192.0.2.1"
        );
    }

    #[tokio::test]
    async fn ip_rdap_bottom_empty_redirects_to_backup() {
        // GIVEN
        let cfg = CommonConfig {
            bootstrap: true,
            inr_backup_bootstrap: true,
            inr_backup_bootstrap_url: BACKUP.to_string(),
            ip_rdap_bottom_enable: true,
            ..Default::default()
        };
        let srv = SrvTestJig::new_common_config(cfg).await;

        // WHEN
        let resp = query(&srv.rdap_base, QueryType::ipv4_bottom("192.0.2.1").unwrap()).await;

        // THEN
        assert_eq!(resp.http_data.status_code, 307);
        assert_eq!(
            resp.http_data.location.expect("no location header"),
            "https://backup.example/rdap/ips/rirSearch1/rdap-bottom/192.0.2.1"
        );
    }

    #[tokio::test]
    async fn autnum_rdap_up_not_found_redirects_to_backup() {
        // GIVEN
        let cfg = CommonConfig {
            bootstrap: true,
            inr_backup_bootstrap: true,
            inr_backup_bootstrap_url: BACKUP.to_string(),
            autnum_rdap_up_enable: true,
            ..Default::default()
        };
        let srv = SrvTestJig::new_common_config(cfg).await;

        // WHEN
        let resp = query(&srv.rdap_base, QueryType::autnum_up("64496").unwrap()).await;

        // THEN
        assert_eq!(resp.http_data.status_code, 307);
        assert_eq!(
            resp.http_data.location.expect("no location header"),
            "https://backup.example/rdap/autnums/rirSearch1/rdap-up/64496"
        );
    }

    #[tokio::test]
    async fn autnum_rdap_down_empty_redirects_to_backup() {
        // GIVEN
        let cfg = CommonConfig {
            bootstrap: true,
            inr_backup_bootstrap: true,
            inr_backup_bootstrap_url: BACKUP.to_string(),
            autnum_rdap_down_enable: true,
            ..Default::default()
        };
        let srv = SrvTestJig::new_common_config(cfg).await;

        // WHEN
        let resp = query(&srv.rdap_base, QueryType::autnum_down("64496").unwrap()).await;

        // THEN
        assert_eq!(resp.http_data.status_code, 307);
        assert_eq!(
            resp.http_data.location.expect("no location header"),
            "https://backup.example/rdap/autnums/rirSearch1/rdap-down/64496"
        );
    }

    #[tokio::test]
    async fn plain_ip_not_found_redirects_to_backup() {
        // GIVEN bootstrap + backup, no feature flags needed for a plain network lookup
        let cfg = CommonConfig {
            bootstrap: true,
            inr_backup_bootstrap: true,
            inr_backup_bootstrap_url: BACKUP.to_string(),
            ..Default::default()
        };
        let srv = SrvTestJig::new_common_config(cfg).await;

        // WHEN
        let resp = query(&srv.rdap_base, QueryType::ipv4("192.0.2.1").unwrap()).await;

        // THEN redirected to the backup's plain /ip path
        assert_eq!(resp.http_data.status_code, 307);
        assert_eq!(
            resp.http_data.location.expect("no location header"),
            "https://backup.example/rdap/ip/192.0.2.1"
        );
    }

    #[tokio::test]
    async fn plain_autnum_not_found_redirects_to_backup() {
        // GIVEN
        let cfg = CommonConfig {
            bootstrap: true,
            inr_backup_bootstrap: true,
            inr_backup_bootstrap_url: BACKUP.to_string(),
            ..Default::default()
        };
        let srv = SrvTestJig::new_common_config(cfg).await;

        // WHEN
        let resp = query(&srv.rdap_base, QueryType::autnum("64496").unwrap()).await;

        // THEN
        assert_eq!(resp.http_data.status_code, 307);
        assert_eq!(
            resp.http_data.location.expect("no location header"),
            "https://backup.example/rdap/autnum/64496"
        );
    }

    #[tokio::test]
    async fn rdns_not_found_redirects_to_backup_domain() {
        // GIVEN a reverse-DNS query whose backing network is not served locally
        let cfg = CommonConfig {
            bootstrap: true,
            inr_backup_bootstrap: true,
            inr_backup_bootstrap_url: BACKUP.to_string(),
            ..Default::default()
        };
        let srv = SrvTestJig::new_common_config(cfg).await;

        // WHEN
        let resp = query(
            &srv.rdap_base,
            QueryType::rdns_ipv4("1.0.0.127.in-addr.arpa").unwrap(),
        )
        .await;

        // THEN redirected to the backup's domain path (rdns name preserved)
        assert_eq!(resp.http_data.status_code, 307);
        assert_eq!(
            resp.http_data.location.expect("no location header"),
            "https://backup.example/rdap/domain/1.0.0.127.in-addr.arpa"
        );
    }
}

mod backup_disabled {
    use super::query;
    use crate::test_jig::SrvTestJig;
    use icann_rdap_client::rdap::QueryType;
    use icann_rdap_srv::config::CommonConfig;

    #[tokio::test]
    async fn ip_rdap_up_returns_404() {
        // GIVEN bootstrap on but INR backup disabled
        let cfg = CommonConfig {
            bootstrap: true,
            inr_backup_bootstrap: false,
            ip_rdap_up_enable: true,
            ..Default::default()
        };
        let srv = SrvTestJig::new_common_config(cfg).await;

        // WHEN
        let resp = query(&srv.rdap_base, QueryType::ipv4_up("192.0.2.1").unwrap()).await;

        // THEN the original 404 is returned (no backup redirect)
        assert_eq!(resp.http_data.status_code, 404);
    }

    #[tokio::test]
    async fn ip_rdap_down_returns_empty_200() {
        // GIVEN bootstrap on but INR backup disabled
        let cfg = CommonConfig {
            bootstrap: true,
            inr_backup_bootstrap: false,
            ip_rdap_down_enable: true,
            ..Default::default()
        };
        let srv = SrvTestJig::new_common_config(cfg).await;

        // WHEN
        let resp = query(&srv.rdap_base, QueryType::ipv4_down("192.0.2.1").unwrap()).await;

        // THEN the empty search result set (200) is returned unchanged
        assert_eq!(resp.http_data.status_code, 200);
    }
}

mod url_formatting {
    use super::query;
    use crate::test_jig::SrvTestJig;
    use icann_rdap_client::rdap::QueryType;
    use icann_rdap_srv::config::CommonConfig;

    #[tokio::test]
    async fn trailing_slash_no_double_slash() {
        // GIVEN a backup base URL that ends with a slash
        let cfg = CommonConfig {
            bootstrap: true,
            inr_backup_bootstrap: true,
            inr_backup_bootstrap_url: "https://backup.example/rdap/".to_string(),
            ..Default::default()
        };
        let srv = SrvTestJig::new_common_config(cfg).await;

        // WHEN
        let resp = query(&srv.rdap_base, QueryType::ipv4("192.0.2.1").unwrap()).await;

        // THEN the joined location has exactly one slash between base and path
        assert_eq!(
            resp.http_data.location.expect("no location header"),
            "https://backup.example/rdap/ip/192.0.2.1"
        );
    }
}

mod stub_precedence {
    use super::{BACKUP, query};
    use crate::test_jig::SrvTestJig;
    use icann_rdap_client::rdap::QueryType;
    use icann_rdap_common::response::Rfc9083Error;
    use icann_rdap_srv::config::CommonConfig;
    use icann_rdap_srv::storage::{
        StoreOps,
        data::{AutnumId, NetworkId, NetworkIdType},
    };

    #[tokio::test]
    async fn ip_rdap_down_follows_stub_not_backup() {
        // GIVEN a bootstrap server with a delegation redirect stub on a more-specific block
        let cfg = CommonConfig {
            bootstrap: true,
            inr_backup_bootstrap: true,
            inr_backup_bootstrap_url: BACKUP.to_string(),
            ip_rdap_down_enable: true,
            ..Default::default()
        };
        let srv = SrvTestJig::new_common_config(cfg).await;
        let mut tx = srv.mem.new_tx().await.expect("new tx");
        tx.add_network_err(
            &NetworkId {
                network_id: NetworkIdType::Cidr(ipnet::IpNet::V4(
                    "10.0.0.0/16".parse().expect("parsing cidr"),
                )),
            },
            &Rfc9083Error::redirect()
                .url("https://auth.example/")
                .build(),
        )
        .await
        .expect("add network redirect stub");
        tx.commit().await.expect("tx commit");

        // WHEN querying rdap-down on the parent block
        let resp = query(
            &srv.rdap_base,
            QueryType::ipv4cidr_down("10.0.0.0/8").unwrap(),
        )
        .await;

        // THEN the stub is followed (not the backup), rebuilt onto the down path
        assert_eq!(resp.http_data.status_code, 307);
        let location = resp.http_data.location.expect("no location header");
        assert_eq!(
            location,
            "https://auth.example/ips/rirSearch1/rdap-down/10.0.0.0/8"
        );
        assert!(!location.contains("backup.example"));
    }

    #[tokio::test]
    async fn ip_rdap_bottom_follows_stub() {
        // GIVEN
        let cfg = CommonConfig {
            bootstrap: true,
            inr_backup_bootstrap: true,
            inr_backup_bootstrap_url: BACKUP.to_string(),
            ip_rdap_bottom_enable: true,
            ..Default::default()
        };
        let srv = SrvTestJig::new_common_config(cfg).await;
        let mut tx = srv.mem.new_tx().await.expect("new tx");
        tx.add_network_err(
            &NetworkId {
                network_id: NetworkIdType::Cidr(ipnet::IpNet::V4(
                    "10.0.0.0/16".parse().expect("parsing cidr"),
                )),
            },
            &Rfc9083Error::redirect()
                .url("https://auth.example/")
                .build(),
        )
        .await
        .expect("add network redirect stub");
        tx.commit().await.expect("tx commit");

        // WHEN
        let resp = query(
            &srv.rdap_base,
            QueryType::ipv4cidr_bottom("10.0.0.0/8").unwrap(),
        )
        .await;

        // THEN
        assert_eq!(resp.http_data.status_code, 307);
        assert_eq!(
            resp.http_data.location.expect("no location header"),
            "https://auth.example/ips/rirSearch1/rdap-bottom/10.0.0.0/8"
        );
    }

    #[tokio::test]
    async fn autnum_rdap_down_follows_stub() {
        // GIVEN an autnum redirect stub overlapping the queried number
        let cfg = CommonConfig {
            bootstrap: true,
            inr_backup_bootstrap: true,
            inr_backup_bootstrap_url: BACKUP.to_string(),
            autnum_rdap_down_enable: true,
            ..Default::default()
        };
        let srv = SrvTestJig::new_common_config(cfg).await;
        let mut tx = srv.mem.new_tx().await.expect("new tx");
        tx.add_autnum_err(
            &AutnumId {
                start_autnum: 700,
                end_autnum: 800,
            },
            &Rfc9083Error::redirect()
                .url("https://auth.example/")
                .build(),
        )
        .await
        .expect("add autnum redirect stub");
        tx.commit().await.expect("tx commit");

        // WHEN
        let resp = query(&srv.rdap_base, QueryType::autnum_down("750").unwrap()).await;

        // THEN
        assert_eq!(resp.http_data.status_code, 307);
        assert_eq!(
            resp.http_data.location.expect("no location header"),
            "https://auth.example/autnums/rirSearch1/rdap-down/750"
        );
    }
}

mod stub_suppressed_without_bootstrap {
    use super::query;
    use crate::test_jig::SrvTestJig;
    use icann_rdap_client::rdap::QueryType;
    use icann_rdap_common::response::Rfc9083Error;
    use icann_rdap_srv::config::CommonConfig;
    use icann_rdap_srv::storage::{
        StoreOps,
        data::{NetworkId, NetworkIdType},
    };

    #[tokio::test]
    async fn rdap_down_stub_dropped_empty_200() {
        // GIVEN bootstrap disabled: the store must not surface the redirect stub
        let cfg = CommonConfig {
            bootstrap: false,
            ip_rdap_down_enable: true,
            ..Default::default()
        };
        let srv = SrvTestJig::new_common_config(cfg).await;
        let mut tx = srv.mem.new_tx().await.expect("new tx");
        tx.add_network_err(
            &NetworkId {
                network_id: NetworkIdType::Cidr(ipnet::IpNet::V4(
                    "10.0.0.0/16".parse().expect("parsing cidr"),
                )),
            },
            &Rfc9083Error::redirect()
                .url("https://auth.example/")
                .build(),
        )
        .await
        .expect("add network redirect stub");
        tx.commit().await.expect("tx commit");

        // WHEN
        let resp = query(
            &srv.rdap_base,
            QueryType::ipv4cidr_down("10.0.0.0/8").unwrap(),
        )
        .await;

        // THEN the redirect is dropped and an empty search result set (200) is returned
        assert_eq!(resp.http_data.status_code, 200);
    }
}
