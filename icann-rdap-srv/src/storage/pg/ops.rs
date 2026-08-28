#![allow(clippy::diverging_sub_expression)]
use std::{net::IpAddr, str::FromStr};

use {
    async_trait::async_trait,
    icann_rdap_common::{
        prelude::ToResponse,
        response::{
            Autnum, AutnumSearchResults, Entity, EntitySearchResults, IpSearchResults, Network,
            RdapResponse,
        },
    },
    ipnet::IpNet,
    sqlx::types::Json,
    sqlx::{PgPool, query},
    tracing::{debug, info},
};

use crate::{
    error::RdapServerError,
    rdap::response::{NOT_FOUND, NOT_IMPLEMENTED},
    storage::{StoreOps, TxHandle},
};

use super::{config::PgConfig, tx::PgTx};

fn wildcard_to_pattern(input: &str) -> Result<String, RdapServerError> {
    if input.chars().filter(|c| *c == '*').count() != 1 {
        return Err(RdapServerError::InvalidArg(
            "Search string must contain one and only one asterisk ('*')".to_string(),
        ));
    }
    let star = input.find('*').expect("validated above");
    if star != input.chars().count() - 1
        && input.chars().nth(star + 1).expect("short circuited") != '.'
    {
        return Err(RdapServerError::InvalidArg(
            "Search string asterisk ('*') must terminate domain label".to_string(),
        ));
    }
    Ok(input.replace('*', "%"))
}

#[derive(Clone)]
pub struct Pg {
    pg_pool: PgPool,
}

impl Pg {
    pub async fn new(config: PgConfig) -> Result<Self, RdapServerError> {
        let pg_pool = PgPool::connect(&config.db_url).await?;
        Ok(Self { pg_pool })
    }
}

#[async_trait]
impl StoreOps for Pg {
    async fn init(&self) -> Result<(), RdapServerError> {
        debug!("Testing database connection.");
        let mut conn = self.pg_pool.acquire().await?;
        query("select 1").fetch_one(&mut *conn).await?;
        info!("Database connection test is successful.");
        Ok(())
    }

    async fn new_tx(&self) -> Result<Box<dyn TxHandle>, RdapServerError> {
        Ok(Box::new(PgTx::new(&self.pg_pool).await?))
    }

    async fn new_truncate_tx(&self) -> Result<Box<dyn TxHandle>, RdapServerError> {
        Ok(Box::new(PgTx::new_truncate(&self.pg_pool).await?))
    }

    async fn get_domain_by_ldh(&self, ldh: &str) -> Result<RdapResponse, RdapServerError> {
        let domain: Option<Json<RdapResponse>> =
            sqlx::query_scalar("SELECT content FROM domain WHERE LOWER(ldh_name) = $1")
                .bind(ldh.to_lowercase())
                .fetch_optional(&self.pg_pool)
                .await?;
        match domain {
            Some(Json(domain)) => Ok(domain),
            None => Ok(NOT_FOUND.clone()),
        }
    }

    async fn get_domain_by_unicode(&self, unicode: &str) -> Result<RdapResponse, RdapServerError> {
        let domain: Option<Json<RdapResponse>> =
            sqlx::query_scalar("SELECT content FROM domain WHERE unicode_name = $1")
                .bind(unicode)
                .fetch_optional(&self.pg_pool)
                .await?;
        match domain {
            Some(Json(domain)) => Ok(domain),
            None => Ok(NOT_FOUND.clone()),
        }
    }

    async fn get_entity_by_handle(&self, handle: &str) -> Result<RdapResponse, RdapServerError> {
        let entity: Option<Json<RdapResponse>> =
            sqlx::query_scalar("SELECT content FROM entity WHERE handle = $1")
                .bind(handle)
                .fetch_optional(&self.pg_pool)
                .await?;
        match entity {
            Some(Json(entity)) => Ok(entity),
            None => Ok(NOT_FOUND.clone()),
        }
    }

    async fn get_nameserver_by_ldh(&self, ldh: &str) -> Result<RdapResponse, RdapServerError> {
        let nameserver: Option<Json<RdapResponse>> =
            sqlx::query_scalar("SELECT content FROM nameserver WHERE LOWER(ldh_name) = $1")
                .bind(ldh.to_lowercase())
                .fetch_optional(&self.pg_pool)
                .await?;
        match nameserver {
            Some(Json(nameserver)) => Ok(nameserver),
            None => Ok(NOT_FOUND.clone()),
        }
    }

    async fn get_autnum_by_num(&self, num: u32) -> Result<RdapResponse, RdapServerError> {
        let autnum: Option<Json<RdapResponse>> = sqlx::query_scalar(
            "SELECT content FROM autnum WHERE start_autnum <= $1 AND end_autnum >= $1",
        )
        .bind(num as i64)
        .fetch_optional(&self.pg_pool)
        .await?;
        match autnum {
            Some(Json(autnum)) => Ok(autnum),
            None => Ok(NOT_FOUND.clone()),
        }
    }

    async fn get_network_by_ipaddr(&self, ipaddr: &str) -> Result<RdapResponse, RdapServerError> {
        let addr = ipaddr.parse::<IpAddr>()?;
        let rows: Vec<(Json<RdapResponse>, IpAddr, IpAddr)> = sqlx::query_as(
            "SELECT content, start_address, end_address FROM network \
             WHERE $1 BETWEEN start_address AND end_address",
        )
        .bind(addr)
        .fetch_all(&self.pg_pool)
        .await?;
        let best = rows
            .into_iter()
            .min_by_key(|(_, start, end)| ip_range_width(start, end));
        match best {
            Some((Json(network), _, _)) => Ok(network),
            None => Ok(NOT_FOUND.clone()),
        }
    }

    async fn get_network_by_cidr(&self, cidr: &str) -> Result<RdapResponse, RdapServerError> {
        let net = IpNet::from_str(cidr)?;
        let (first, last): (IpAddr, IpAddr) = match &net {
            IpNet::V4(v4) => (v4.network().into(), v4.broadcast().into()),
            IpNet::V6(v6) => (v6.network().into(), v6.broadcast().into()),
        };
        let rows: Vec<(Json<RdapResponse>, IpAddr, IpAddr)> = sqlx::query_as(
            "SELECT content, start_address, end_address FROM network \
             WHERE start_address <= $1 AND end_address >= $2",
        )
        .bind(first)
        .bind(last)
        .fetch_all(&self.pg_pool)
        .await?;
        let best = rows
            .into_iter()
            .min_by_key(|(_, start, end)| ip_range_width(start, end));
        match best {
            Some((Json(network), _, _)) => Ok(network),
            None => Ok(NOT_FOUND.clone()),
        }
    }

    async fn get_srv_help(&self, host: Option<&str>) -> Result<RdapResponse, RdapServerError> {
        let host = host.unwrap_or("default");
        let srv_help: Option<Json<RdapResponse>> =
            sqlx::query_scalar("SELECT content FROM srv_help WHERE host = $1")
                .bind(host)
                .fetch_optional(&self.pg_pool)
                .await?;
        match srv_help {
            Some(Json(srv_help)) => Ok(srv_help),
            None => Ok(NOT_FOUND.clone()),
        }
    }

    async fn search_domains_by_name(&self, _name: &str) -> Result<RdapResponse, RdapServerError> {
        Ok(NOT_IMPLEMENTED.clone())
    }

    async fn search_nameservers_by_name(
        &self,
        _name: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(NOT_IMPLEMENTED.clone())
    }

    async fn search_nameservers_by_ip(&self, _ip: IpAddr) -> Result<RdapResponse, RdapServerError> {
        Ok(NOT_IMPLEMENTED.clone())
    }

    async fn search_domains_by_ns_ip(&self, _ip: IpAddr) -> Result<RdapResponse, RdapServerError> {
        Ok(NOT_IMPLEMENTED.clone())
    }

    async fn search_domains_by_ns_ldh_name(
        &self,
        _name: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(NOT_IMPLEMENTED.clone())
    }

    async fn search_entities_by_handle(
        &self,
        handle: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        let pattern = wildcard_to_pattern(handle)?;
        let rows: Vec<Json<RdapResponse>> =
            sqlx::query_scalar("SELECT content FROM entity WHERE handle ILIKE $1")
                .bind(pattern)
                .fetch_all(&self.pg_pool)
                .await?;
        let results = rows
            .into_iter()
            .map(|Json(r)| r)
            .filter_map(|r| match r {
                RdapResponse::Entity(ent) => Some(*ent),
                _ => None,
            })
            .collect::<Vec<Entity>>();
        let response = EntitySearchResults::response_obj()
            .results(results)
            .build()
            .to_response();
        Ok(response)
    }

    async fn search_entities_by_full_name(
        &self,
        full_name: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        let pattern = wildcard_to_pattern(full_name)?;
        let rows: Vec<Json<RdapResponse>> =
            sqlx::query_scalar("SELECT content FROM entity WHERE fn ILIKE $1")
                .bind(pattern)
                .fetch_all(&self.pg_pool)
                .await?;
        let results = rows
            .into_iter()
            .map(|Json(r)| r)
            .filter_map(|r| match r {
                RdapResponse::Entity(ent) => Some(*ent),
                _ => None,
            })
            .collect::<Vec<Entity>>();
        let response = EntitySearchResults::response_obj()
            .results(results)
            .build()
            .to_response();
        Ok(response)
    }

    async fn search_networks_by_handle(
        &self,
        handle: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        let pattern = wildcard_to_pattern(handle)?;
        let rows: Vec<Json<RdapResponse>> =
            sqlx::query_scalar("SELECT content FROM network WHERE handle ILIKE $1")
                .bind(pattern)
                .fetch_all(&self.pg_pool)
                .await?;
        let results = rows
            .into_iter()
            .map(|Json(r)| r)
            .filter_map(|r| match r {
                RdapResponse::Network(net) => Some(*net),
                _ => None,
            })
            .collect::<Vec<Network>>();
        let response = IpSearchResults::response_obj()
            .results(results)
            .build()
            .to_response();
        Ok(response)
    }

    async fn search_networks_by_name(&self, _name: &str) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_ip_rdap_up_by_ipaddr(
        &self,
        _ipaddr: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_ip_rdap_up_by_cidr(
        &self,
        _cidr: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_ip_rdap_top_by_ipaddr(
        &self,
        _ipaddr: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_ip_rdap_top_by_cidr(
        &self,
        _cidr: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_ip_rdap_down_by_ipaddr(
        &self,
        _ipaddr: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_ip_rdap_down_by_cidr(
        &self,
        _cidr: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_ip_rdap_bottom_by_ipaddr(
        &self,
        _ipaddr: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_ip_rdap_bottom_by_cidr(
        &self,
        _cidr: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_autnum_rdap_up_by_num(
        &self,
        _num: u32,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_autnum_rdap_up_by_range(
        &self,
        _start: u32,
        _end: u32,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_autnum_rdap_top_by_num(
        &self,
        _num: u32,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_autnum_rdap_top_by_range(
        &self,
        _start: u32,
        _end: u32,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_autnum_rdap_down_by_num(
        &self,
        _num: u32,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_autnum_rdap_down_by_range(
        &self,
        _start: u32,
        _end: u32,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_autnum_rdap_bottom_by_num(
        &self,
        _num: u32,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_autnum_rdap_bottom_by_range(
        &self,
        _start: u32,
        _end: u32,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_autnums_by_handle(
        &self,
        handle: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        let pattern = wildcard_to_pattern(handle)?;
        let rows: Vec<Json<RdapResponse>> =
            sqlx::query_scalar("SELECT content FROM autnum WHERE handle ILIKE $1")
                .bind(pattern)
                .fetch_all(&self.pg_pool)
                .await?;
        let results = rows
            .into_iter()
            .map(|Json(r)| r)
            .filter_map(|r| match r {
                RdapResponse::Autnum(aut) => Some(*aut),
                _ => None,
            })
            .collect::<Vec<Autnum>>();
        let response = AutnumSearchResults::response_obj()
            .results(results)
            .build()
            .to_response();
        Ok(response)
    }

    async fn search_autnums_by_name(&self, name: &str) -> Result<RdapResponse, RdapServerError> {
        let pattern = wildcard_to_pattern(name)?;
        let rows: Vec<Json<RdapResponse>> =
            sqlx::query_scalar("SELECT content FROM autnum WHERE name ILIKE $1")
                .bind(pattern)
                .fetch_all(&self.pg_pool)
                .await?;
        let results = rows
            .into_iter()
            .map(|Json(r)| r)
            .filter_map(|r| match r {
                RdapResponse::Autnum(aut) => Some(*aut),
                _ => None,
            })
            .collect::<Vec<Autnum>>();
        let response = AutnumSearchResults::response_obj()
            .results(results)
            .build()
            .to_response();
        Ok(response)
    }

    async fn search_domain_rdap_up_by_ldh(
        &self,
        _ldh: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_domain_rdap_top_by_ldh(
        &self,
        _ldh: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_domain_rdap_down_by_ldh(
        &self,
        _ldh: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(crate::rdap::response::NOT_IMPLEMENTED.clone())
    }

    async fn search_domain_rdap_bottom_by_ldh(
        &self,
        _ldh: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        Ok(NOT_IMPLEMENTED.clone())
    }
}

fn ip_as_u128(addr: &IpAddr) -> u128 {
    match addr {
        IpAddr::V4(v4) => u32::from(*v4) as u128,
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            (u32::from(segments[0]) as u128) << 96
                | (u32::from(segments[1]) as u128) << 80
                | (u32::from(segments[2]) as u128) << 64
                | (u32::from(segments[3]) as u128) << 48
                | (u32::from(segments[4]) as u128) << 32
                | (u32::from(segments[5]) as u128) << 16
                | u32::from(segments[6]) as u128
                | u32::from(segments[7]) as u128
        }
    }
}

fn ip_range_width(start: &IpAddr, end: &IpAddr) -> u128 {
    ip_as_u128(end).saturating_sub(ip_as_u128(start)) + 1
}
