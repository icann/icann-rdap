#![allow(clippy::diverging_sub_expression)]
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use {
    async_trait::async_trait,
    icann_rdap_common::{
        prelude::ToResponse,
        rdns::{reverse_dns_to_ip, reverse_dns_to_ipnet},
        response::{
            Autnum, AutnumSearchResults, Domain, DomainSearchResults, Entity, EntitySearchResults,
            IpSearchResults, Nameserver, NameserverSearchResults, Network, RdapResponse,
        },
    },
    ipnet::IpNet,
    sqlx::types::Json,
    sqlx::{PgPool, query},
    tracing::{debug, info},
};

use crate::{
    config::CommonConfig,
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

fn wildcard_to_domain_regex(input: &str) -> Result<String, RdapServerError> {
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
    let at_end = star == input.chars().count() - 1;
    let replacement = if at_end { ".*" } else { "[^.]*" };
    Ok(format!("^{}$", input.replace('*', replacement)))
}

/// The `[start, end]` range of the immediate supernet of the IPv4 block `[s, e]`,
/// or `None` if the block is `/0` (which has no supernet) or is not a valid block.
fn supernet_v4(s: Ipv4Addr, e: Ipv4Addr) -> Option<(IpAddr, IpAddr)> {
    let (s, e) = (u64::from(u32::from(s)), u64::from(u32::from(e)));
    if e < s {
        return None;
    }
    let size = e - s + 1; // block size (a power of two), at most 2^32
    if size >= 1 << 32 {
        return None; // /0 has no supernet
    }
    let super_size = size * 2;
    let base = s / super_size * super_size;
    Some((
        IpAddr::V4(Ipv4Addr::from(base as u32)),
        IpAddr::V4(Ipv4Addr::from((base + super_size - 1) as u32)),
    ))
}

/// The `[start, end]` range of the immediate supernet of the IPv6 block `[s, e]`,
/// or `None` if the block is `/0` (which has no supernet) or is not a valid block.
fn supernet_v6(s: Ipv6Addr, e: Ipv6Addr) -> Option<(IpAddr, IpAddr)> {
    let (s, e) = (u128::from(s), u128::from(e));
    if e < s || (s == 0 && e == u128::MAX) {
        return None; // invalid block, or /0 which has no supernet
    }
    let size = e - s + 1; // at most 2^127 here (/0 excluded)
    if size >= 1 << 127 {
        // top is /1; its only supernet is /0
        return Some((
            IpAddr::V6(Ipv6Addr::from(0u128)),
            IpAddr::V6(Ipv6Addr::from(u128::MAX)),
        ));
    }
    let super_size = size * 2;
    let base = s / super_size * super_size;
    Some((
        IpAddr::V6(Ipv6Addr::from(base)),
        IpAddr::V6(Ipv6Addr::from(base + super_size - 1)),
    ))
}

/// The number of addresses in the block `[s, e]`, used to order networks by specificity.
fn ip_block_size(s: IpAddr, e: IpAddr) -> u128 {
    match (s, e) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let (a, b) = (u64::from(u32::from(a)), u64::from(u32::from(b)));
            (b.saturating_sub(a) + 1) as u128
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let (a, b) = (u128::from(a), u128::from(b));
            b.saturating_sub(a) + 1
        }
        _ => u128::MAX, // mismatched families should not occur for a single IP query
    }
}

/// An empty [`DomainSearchResults`] response for relationship searches that match nothing.
fn empty_domain_search_results() -> RdapResponse {
    DomainSearchResults::response_obj()
        .results(Vec::<Domain>::new())
        .build()
        .to_response()
}

#[derive(Clone)]
pub struct Pg {
    pg_pool: PgPool,
    config: PgConfig,
}

impl Pg {
    pub async fn new(config: PgConfig) -> Result<Self, RdapServerError> {
        let pg_pool = PgPool::connect(&config.db_url).await?;
        Ok(Self { pg_pool, config })
    }

    /// The underlying connection pool.
    pub(crate) fn pool(&self) -> &PgPool {
        &self.pg_pool
    }

    /// Build a store from an already-connected pool together with the supplied config.
    pub fn from_pool_with_config(pg_pool: PgPool, config: PgConfig) -> Self {
        Self { pg_pool, config }
    }

    /// Test convenience: build from a live pool with every search flag enabled, so
    /// storage tests that expect results (not `NOT_IMPLEMENTED`) keep passing.
    pub fn from_pool(pg_pool: PgPool) -> Self {
        let config = PgConfig::builder()
            .db_url("postgresql://unused") // ignored; the pool is already connected
            .common_config(
                CommonConfig::builder()
                    .autnum_rdap_up_enable(true)
                    .autnum_rdap_top_enable(true)
                    .autnum_rdap_down_enable(true)
                    .autnum_rdap_bottom_enable(true)
                    .ip_rdap_up_enable(true)
                    .ip_rdap_top_enable(true)
                    .ip_rdap_down_enable(true)
                    .ip_rdap_bottom_enable(true)
                    .domain_rdap_up_enable(true)
                    .domain_rdap_top_enable(true)
                    .domain_rdap_down_enable(true)
                    .domain_rdap_bottom_enable(true)
                    .domain_search_by_name_enable(true)
                    .nameserver_search_by_name_enable(true)
                    .nameserver_search_by_ip_enable(true)
                    .domain_search_by_ns_ip_enable(true)
                    .domain_search_by_ns_ldh_name_enable(true)
                    .entity_search_by_handle_enable(true)
                    .entity_search_by_full_name_enable(true)
                    .network_search_by_handle_enable(true)
                    .network_search_by_name_enable(true)
                    .autnum_search_by_name_enable(true)
                    .autnum_search_by_handle_enable(true)
                    .build(),
            )
            .build();
        Self { pg_pool, config }
    }

    /// The most-specific stored domain network range `[start, end]` whose range fully
    /// contains `[first, last]`, if any.
    async fn domain_range_containing(
        &self,
        first: IpAddr,
        last: IpAddr,
    ) -> Result<Option<(IpAddr, IpAddr)>, RdapServerError> {
        let rows: Vec<(IpAddr, IpAddr)> = sqlx::query_as(
            "SELECT net_start_address, net_end_address FROM domain \
             WHERE net_start_address <= $1::inet AND net_end_address >= $2::inet",
        )
        .bind(first)
        .bind(last)
        .fetch_all(&self.pg_pool)
        .await?;
        Ok(rows.into_iter().min_by_key(|(s, e)| ip_block_size(*s, *e)))
    }
}

impl Pg {
    /// RFC 9910 "up"/"top": the single stored autnum record whose range fully contains
    /// `[start, end]`. For a point query, pass `start == end`. Returns an
    /// [`AutnumSearchResults`] wrapping that record, or `NOT_FOUND` when no single block
    /// covers the whole range (or the row is not an autnum).
    async fn autnum_covering(&self, start: i64, end: i64) -> Result<RdapResponse, RdapServerError> {
        let row: Option<Json<RdapResponse>> = sqlx::query_scalar(
            "SELECT content FROM autnum \
             WHERE start_autnum <= $1 AND end_autnum >= $2 \
             ORDER BY start_autnum, end_autnum LIMIT 1",
        )
        .bind(start)
        .bind(end)
        .fetch_optional(&self.pg_pool)
        .await?;

        match row {
            Some(Json(RdapResponse::Autnum(a))) => Ok(AutnumSearchResults::response_obj()
                .results(vec![*a])
                .build()
                .to_response()),
            _ => Ok(NOT_FOUND.clone()),
        }
    }

    /// RFC 9910 "down"/"bottom": all stored autnum records overlapping `[start, end]`
    /// (inclusive), ordered by their range. For a point query, pass `start == end`.
    async fn autnum_overlapping(
        &self,
        start: i64,
        end: i64,
    ) -> Result<RdapResponse, RdapServerError> {
        let rows: Vec<Json<RdapResponse>> = sqlx::query_scalar(
            "SELECT content FROM autnum WHERE start_autnum <= $2 AND end_autnum >= $1 \
             ORDER BY start_autnum, end_autnum",
        )
        .bind(start)
        .bind(end)
        .fetch_all(&self.pg_pool)
        .await?;

        let results: Vec<Autnum> = rows
            .into_iter()
            .filter_map(|Json(r)| match r {
                RdapResponse::Autnum(a) => Some(*a),
                _ => None,
            })
            .collect();

        Ok(AutnumSearchResults::response_obj()
            .results(results)
            .build()
            .to_response())
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

    async fn search_domains_by_name(&self, name: &str) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.domain_search_by_name_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let pattern = wildcard_to_domain_regex(name)?;
        let rows: Vec<Json<RdapResponse>> =
            sqlx::query_scalar("SELECT content FROM domain WHERE ldh_name ~* $1")
                .bind(pattern)
                .fetch_all(&self.pg_pool)
                .await?;
        let results = rows
            .into_iter()
            .map(|Json(r)| r)
            .filter_map(|r| match r {
                RdapResponse::Domain(d) => Some(*d),
                _ => None,
            })
            .collect::<Vec<Domain>>();
        let response = DomainSearchResults::response_obj()
            .results(results)
            .build()
            .to_response();
        Ok(response)
    }

    async fn search_nameservers_by_name(
        &self,
        name: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.nameserver_search_by_name_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let pattern = wildcard_to_domain_regex(name)?;
        let rows: Vec<Json<RdapResponse>> =
            sqlx::query_scalar("SELECT content FROM nameserver WHERE ldh_name ~* $1")
                .bind(pattern)
                .fetch_all(&self.pg_pool)
                .await?;
        let results = rows
            .into_iter()
            .map(|Json(r)| r)
            .filter_map(|r| match r {
                RdapResponse::Nameserver(ns) => Some(*ns),
                _ => None,
            })
            .collect::<Vec<Nameserver>>();
        let response = NameserverSearchResults::response_obj()
            .results(results)
            .build()
            .to_response();
        Ok(response)
    }

    async fn search_nameservers_by_ip(&self, ip: IpAddr) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.nameserver_search_by_ip_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let query = match ip {
            IpAddr::V4(_) => "SELECT content FROM nameserver WHERE $1::inet = ANY(v4)",
            IpAddr::V6(_) => "SELECT content FROM nameserver WHERE $1::inet = ANY(v6)",
        };
        let rows: Vec<Json<RdapResponse>> = sqlx::query_scalar(query)
            .bind(ip)
            .fetch_all(&self.pg_pool)
            .await?;
        let results = rows
            .into_iter()
            .map(|Json(r)| r)
            .filter_map(|r| match r {
                RdapResponse::Nameserver(ns) => Some(*ns),
                _ => None,
            })
            .collect::<Vec<Nameserver>>();
        let response = NameserverSearchResults::response_obj()
            .results(results)
            .build()
            .to_response();
        Ok(response)
    }

    async fn search_domains_by_ns_ip(&self, ip: IpAddr) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.domain_search_by_ns_ip_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let query = match ip {
            IpAddr::V4(_) => "SELECT content FROM domain WHERE $1::inet = ANY(ns_v4)",
            IpAddr::V6(_) => "SELECT content FROM domain WHERE $1::inet = ANY(ns_v6)",
        };
        let rows: Vec<Json<RdapResponse>> = sqlx::query_scalar(query)
            .bind(ip)
            .fetch_all(&self.pg_pool)
            .await?;
        let results = rows
            .into_iter()
            .map(|Json(r)| r)
            .filter_map(|r| match r {
                RdapResponse::Domain(d) => Some(*d),
                _ => None,
            })
            .collect::<Vec<Domain>>();
        let response = DomainSearchResults::response_obj()
            .results(results)
            .build()
            .to_response();
        Ok(response)
    }

    async fn search_domains_by_ns_ldh_name(
        &self,
        name: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self
            .config
            .common_config
            .domain_search_by_ns_ldh_name_enable
        {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let pattern = wildcard_to_domain_regex(name)?;
        let rows: Vec<Json<RdapResponse>> = sqlx::query_scalar(
            "SELECT content FROM domain \
             WHERE EXISTS (SELECT 1 FROM unnest(ns_ldh_name) AS ns WHERE ns ~* $1)",
        )
        .bind(pattern)
        .fetch_all(&self.pg_pool)
        .await?;
        let results = rows
            .into_iter()
            .map(|Json(r)| r)
            .filter_map(|r| match r {
                RdapResponse::Domain(d) => Some(*d),
                _ => None,
            })
            .collect::<Vec<Domain>>();
        let response = DomainSearchResults::response_obj()
            .results(results)
            .build()
            .to_response();
        Ok(response)
    }

    async fn search_entities_by_handle(
        &self,
        handle: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.entity_search_by_handle_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
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
        if !self.config.common_config.entity_search_by_full_name_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
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
        if !self.config.common_config.network_search_by_handle_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
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

    async fn search_networks_by_name(&self, name: &str) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.network_search_by_name_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let pattern = wildcard_to_pattern(name)?;
        let rows: Vec<Json<RdapResponse>> =
            sqlx::query_scalar("SELECT content FROM network WHERE name ILIKE $1")
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

    async fn search_ip_rdap_up_by_ipaddr(
        &self,
        ipaddr: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.ip_rdap_up_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let ip = ipaddr.parse::<IpAddr>()?;
        let cidr = match ip {
            IpAddr::V4(_) => format!("{}/32", ip),
            IpAddr::V6(_) => format!("{}/128", ip),
        };
        self.search_ip_rdap_up_by_cidr(&cidr).await
    }

    async fn search_ip_rdap_up_by_cidr(&self, cidr: &str) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.ip_rdap_up_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let net = IpNet::from_str(cidr)?;
        let (first, last): (IpAddr, IpAddr) = match &net {
            IpNet::V4(v4) => (v4.network().into(), v4.broadcast().into()),
            IpNet::V6(v6) => (v6.network().into(), v6.broadcast().into()),
        };

        // Step 1 — the most-specific stored network whose range contains the entire block.
        let containing: Vec<(IpAddr, IpAddr)> = sqlx::query_as(
            "SELECT start_address, end_address FROM network \
             WHERE start_address <= $1::inet AND end_address >= $2::inet",
        )
        .bind(first)
        .bind(last)
        .fetch_all(&self.pg_pool)
        .await?;

        let Some((start, end)) = containing
            .into_iter()
            .min_by_key(|(s, e)| ip_block_size(*s, *e))
        else {
            return Ok(NOT_FOUND.clone());
        };

        // Step 2 — the immediate supernet of that block; find the most-specific stored network containing it.
        let supernet = match start {
            IpAddr::V4(s) => match end {
                IpAddr::V4(e) => supernet_v4(s, e),
                _ => None,
            },
            IpAddr::V6(s) => match end {
                IpAddr::V6(e) => supernet_v6(s, e),
                _ => None,
            },
        };
        let Some((sup_start, sup_end)) = supernet else {
            return Ok(NOT_FOUND.clone());
        };

        let rows: Vec<(Json<RdapResponse>, IpAddr, IpAddr)> = sqlx::query_as(
            "SELECT content, start_address, end_address FROM network \
             WHERE start_address <= $1::inet AND end_address >= $2::inet",
        )
        .bind(sup_start)
        .bind(sup_end)
        .fetch_all(&self.pg_pool)
        .await?;

        let best = rows
            .into_iter()
            .min_by_key(|(_, s, e)| ip_block_size(*s, *e));

        match best {
            Some((Json(content), _, _)) => Ok(content),
            None => Ok(NOT_FOUND.clone()),
        }
    }

    async fn search_ip_rdap_top_by_ipaddr(
        &self,
        ipaddr: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.ip_rdap_top_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let ip = ipaddr.parse::<IpAddr>()?;
        let cidr = match ip {
            IpAddr::V4(_) => format!("{}/32", ip),
            IpAddr::V6(_) => format!("{}/128", ip),
        };
        self.search_ip_rdap_top_by_cidr(&cidr).await
    }

    async fn search_ip_rdap_top_by_cidr(
        &self,
        cidr: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.ip_rdap_top_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let net = IpNet::from_str(cidr)?;
        let (first, last): (IpAddr, IpAddr) = match &net {
            IpNet::V4(v4) => (v4.network().into(), v4.broadcast().into()),
            IpNet::V6(v6) => (v6.network().into(), v6.broadcast().into()),
        };

        // The topmost stored network is the widest one whose range contains the entire block.
        let rows: Vec<(Json<RdapResponse>, IpAddr, IpAddr)> = sqlx::query_as(
            "SELECT content, start_address, end_address FROM network \
             WHERE start_address <= $1::inet AND end_address >= $2::inet",
        )
        .bind(first)
        .bind(last)
        .fetch_all(&self.pg_pool)
        .await?;

        let best = rows
            .into_iter()
            .max_by_key(|(_, s, e)| ip_block_size(*s, *e));

        match best {
            Some((Json(content), _, _)) => Ok(content),
            None => Ok(NOT_FOUND.clone()),
        }
    }

    async fn search_ip_rdap_down_by_ipaddr(
        &self,
        ipaddr: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.ip_rdap_down_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let ip = ipaddr.parse::<IpAddr>()?;
        let cidr = match ip {
            IpAddr::V4(_) => format!("{}/32", ip),
            IpAddr::V6(_) => format!("{}/128", ip),
        };
        self.search_ip_rdap_down_by_cidr(&cidr).await
    }

    async fn search_ip_rdap_down_by_cidr(
        &self,
        cidr: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.ip_rdap_down_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let net = IpNet::from_str(cidr)?;
        let (first, last): (IpAddr, IpAddr) = match &net {
            IpNet::V4(v4) => (v4.network().into(), v4.broadcast().into()),
            IpNet::V6(v6) => (v6.network().into(), v6.broadcast().into()),
        };

        // All stored networks strictly contained within the queried block.
        let candidates: Vec<(Json<RdapResponse>, IpAddr, IpAddr)> = sqlx::query_as(
            "SELECT content, start_address, end_address FROM network \
             WHERE start_address >= $1::inet AND end_address <= $2::inet \
               AND NOT (start_address = $1::inet AND end_address = $2::inet)",
        )
        .bind(first)
        .bind(last)
        .fetch_all(&self.pg_pool)
        .await?;

        // An immediate child is one not strictly contained in any other candidate.
        let mask: Vec<bool> = (0..candidates.len())
            .map(|i| {
                let (_, s, e) = &candidates[i];
                !(0..candidates.len())
                    .any(|j| j != i && candidates[j].1 <= *s && candidates[j].2 >= *e)
            })
            .collect();

        let results: Vec<Network> = candidates
            .into_iter()
            .zip(mask)
            .filter_map(|(cand, keep)| {
                if !keep {
                    return None;
                }
                let (Json(r), _, _) = cand;
                match r {
                    RdapResponse::Network(n) => Some(*n),
                    _ => None,
                }
            })
            .collect();

        Ok(IpSearchResults::response_obj()
            .results(results)
            .build()
            .to_response())
    }

    async fn search_ip_rdap_bottom_by_ipaddr(
        &self,
        ipaddr: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.ip_rdap_bottom_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let ip = ipaddr.parse::<IpAddr>()?;
        let cidr = match ip {
            IpAddr::V4(_) => format!("{}/32", ip),
            IpAddr::V6(_) => format!("{}/128", ip),
        };
        self.search_ip_rdap_bottom_by_cidr(&cidr).await
    }

    async fn search_ip_rdap_bottom_by_cidr(
        &self,
        cidr: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.ip_rdap_bottom_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let net = IpNet::from_str(cidr)?;
        let (first, last): (IpAddr, IpAddr) = match &net {
            IpNet::V4(v4) => (v4.network().into(), v4.broadcast().into()),
            IpNet::V6(v6) => (v6.network().into(), v6.broadcast().into()),
        };

        // All stored networks strictly contained within the queried block.
        let candidates: Vec<(Json<RdapResponse>, IpAddr, IpAddr)> = sqlx::query_as(
            "SELECT content, start_address, end_address FROM network \
             WHERE start_address >= $1::inet AND end_address <= $2::inet \
               AND NOT (start_address = $1::inet AND end_address = $2::inet)",
        )
        .bind(first)
        .bind(last)
        .fetch_all(&self.pg_pool)
        .await?;

        // A leaf is one that does not strictly contain any other candidate.
        let mask: Vec<bool> = (0..candidates.len())
            .map(|i| {
                let (_, s, e) = &candidates[i];
                !(0..candidates.len())
                    .any(|j| j != i && *s <= candidates[j].1 && *e >= candidates[j].2)
            })
            .collect();

        let results: Vec<Network> = candidates
            .into_iter()
            .zip(mask)
            .filter_map(|(cand, keep)| {
                if !keep {
                    return None;
                }
                let (Json(r), _, _) = cand;
                match r {
                    RdapResponse::Network(n) => Some(*n),
                    _ => None,
                }
            })
            .collect();

        Ok(IpSearchResults::response_obj()
            .results(results)
            .build()
            .to_response())
    }

    async fn search_autnum_rdap_up_by_num(
        &self,
        num: u32,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.autnum_rdap_up_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        self.autnum_covering(i64::from(num), i64::from(num)).await
    }

    async fn search_autnum_rdap_up_by_range(
        &self,
        start: u32,
        end: u32,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.autnum_rdap_up_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        self.autnum_covering(i64::from(start), i64::from(end)).await
    }

    async fn search_autnum_rdap_top_by_num(
        &self,
        num: u32,
    ) -> Result<RdapResponse, RdapServerError> {
        // RFC 9910 "top" is the topmost block covering the point; identical to "up".
        if !self.config.common_config.autnum_rdap_top_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        self.autnum_covering(i64::from(num), i64::from(num)).await
    }

    async fn search_autnum_rdap_top_by_range(
        &self,
        start: u32,
        end: u32,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.autnum_rdap_top_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        self.autnum_covering(i64::from(start), i64::from(end)).await
    }

    async fn search_autnum_rdap_down_by_num(
        &self,
        num: u32,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.autnum_rdap_down_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        self.autnum_overlapping(i64::from(num), i64::from(num))
            .await
    }

    async fn search_autnum_rdap_down_by_range(
        &self,
        start: u32,
        end: u32,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.autnum_rdap_down_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        self.autnum_overlapping(i64::from(start), i64::from(end))
            .await
    }

    async fn search_autnum_rdap_bottom_by_num(
        &self,
        num: u32,
    ) -> Result<RdapResponse, RdapServerError> {
        // RFC 9910 "bottom" is the set of blocks overlapping the point; identical to "down".
        if !self.config.common_config.autnum_rdap_bottom_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        self.autnum_overlapping(i64::from(num), i64::from(num))
            .await
    }

    async fn search_autnum_rdap_bottom_by_range(
        &self,
        start: u32,
        end: u32,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.autnum_rdap_bottom_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        self.autnum_overlapping(i64::from(start), i64::from(end))
            .await
    }

    async fn search_autnums_by_handle(
        &self,
        handle: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.autnum_search_by_handle_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
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
        if !self.config.common_config.autnum_search_by_name_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
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

    async fn search_domain_rdap_top_by_ldh(
        &self,
        ldh: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.domain_rdap_top_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let Some(ip) = reverse_dns_to_ip(ldh) else {
            return Ok(NOT_FOUND.clone());
        };

        // The most-specific stored domain network whose range contains the IP.
        let rows: Vec<(Json<RdapResponse>, IpAddr, IpAddr)> = sqlx::query_as(
            "SELECT content, net_start_address, net_end_address FROM domain \
             WHERE net_start_address <= $1::inet AND net_end_address >= $1::inet",
        )
        .bind(ip)
        .fetch_all(&self.pg_pool)
        .await?;

        let best = rows
            .into_iter()
            .min_by_key(|(_, s, e)| ip_block_size(*s, *e));
        let Some((Json(domain), _, _)) = best else {
            return Ok(NOT_FOUND.clone());
        };

        let domain = match domain {
            RdapResponse::Domain(d) => *d,
            _ => return Ok(NOT_FOUND.clone()),
        };
        Ok(DomainSearchResults::response_obj()
            .results(vec![domain])
            .build()
            .to_response())
    }

    async fn search_domain_rdap_up_by_ldh(
        &self,
        ldh: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.domain_rdap_up_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let Some(ip) = reverse_dns_to_ip(ldh) else {
            return Ok(NOT_FOUND.clone());
        };

        // Step 1 — the most-specific stored domain network whose range contains the IP.
        let Some((start, end)) = self.domain_range_containing(ip, ip).await? else {
            return Ok(NOT_FOUND.clone());
        };

        // Step 2 — the immediate supernet of that block; find the most-specific stored
        // domain network whose range contains it.
        let supernet = match start {
            IpAddr::V4(s) => match end {
                IpAddr::V4(e) => supernet_v4(s, e),
                _ => None,
            },
            IpAddr::V6(s) => match end {
                IpAddr::V6(e) => supernet_v6(s, e),
                _ => None,
            },
        };
        let Some((sup_start, sup_end)) = supernet else {
            return Ok(NOT_FOUND.clone());
        };

        let rows: Vec<(Json<RdapResponse>, IpAddr, IpAddr)> = sqlx::query_as(
            "SELECT content, net_start_address, net_end_address FROM domain \
             WHERE net_start_address <= $1::inet AND net_end_address >= $2::inet",
        )
        .bind(sup_start)
        .bind(sup_end)
        .fetch_all(&self.pg_pool)
        .await?;

        let best = rows
            .into_iter()
            .min_by_key(|(_, s, e)| ip_block_size(*s, *e));
        let Some((Json(domain), _, _)) = best else {
            return Ok(NOT_FOUND.clone());
        };

        let domain = match domain {
            RdapResponse::Domain(d) => *d,
            _ => return Ok(NOT_FOUND.clone()),
        };
        Ok(DomainSearchResults::response_obj()
            .results(vec![domain])
            .build()
            .to_response())
    }

    async fn search_domain_rdap_down_by_ldh(
        &self,
        ldh: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.domain_rdap_down_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let (first, last): (IpAddr, IpAddr) = match reverse_dns_to_ipnet(ldh) {
            Some(IpNet::V4(v4)) => (v4.network().into(), v4.broadcast().into()),
            Some(IpNet::V6(v6)) => (v6.network().into(), v6.broadcast().into()),
            None => return Ok(empty_domain_search_results()),
        };

        // The most-specific stored domain network whose range contains the queried block.
        let Some((c_start, c_end)) = self.domain_range_containing(first, last).await? else {
            return Ok(empty_domain_search_results());
        };

        // Immediate children: the maximal proper sub-ranges of the container.
        let rows: Vec<Json<RdapResponse>> = sqlx::query_scalar(
            "SELECT d.content FROM domain d \
             WHERE d.net_start_address >= $1::inet AND d.net_end_address <= $2::inet \
               AND NOT (d.net_start_address = $1::inet AND d.net_end_address = $2::inet) \
               AND NOT EXISTS ( \
                     SELECT 1 FROM domain o \
                     WHERE o.net_start_address >= $1::inet AND o.net_end_address <= $2::inet \
                       AND NOT (o.net_start_address = $1::inet AND o.net_end_address = $2::inet) \
                       AND o.net_start_address <= d.net_start_address \
                       AND o.net_end_address >= d.net_end_address \
                       AND NOT (o.net_start_address = d.net_start_address \
                                AND o.net_end_address = d.net_end_address) \
                   )",
        )
        .bind(c_start)
        .bind(c_end)
        .fetch_all(&self.pg_pool)
        .await?;

        let results: Vec<Domain> = rows
            .into_iter()
            .map(|Json(r)| r)
            .filter_map(|r| match r {
                RdapResponse::Domain(d) => Some(*d),
                _ => None,
            })
            .collect();
        Ok(DomainSearchResults::response_obj()
            .results(results)
            .build()
            .to_response())
    }

    async fn search_domain_rdap_bottom_by_ldh(
        &self,
        ldh: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        if !self.config.common_config.domain_rdap_bottom_enable {
            return Ok(NOT_IMPLEMENTED.clone());
        }
        let (first, last): (IpAddr, IpAddr) = match reverse_dns_to_ipnet(ldh) {
            Some(IpNet::V4(v4)) => (v4.network().into(), v4.broadcast().into()),
            Some(IpNet::V6(v6)) => (v6.network().into(), v6.broadcast().into()),
            None => return Ok(empty_domain_search_results()),
        };

        // The most-specific stored domain network whose range contains the queried block.
        let Some((c_start, c_end)) = self.domain_range_containing(first, last).await? else {
            return Ok(empty_domain_search_results());
        };

        // Leaf descendants: sub-ranges of the container that contain no other stored range.
        let rows: Vec<Json<RdapResponse>> = sqlx::query_scalar(
            "SELECT d.content FROM domain d \
             WHERE d.net_start_address >= $1::inet AND d.net_end_address <= $2::inet \
               AND NOT (d.net_start_address = $1::inet AND d.net_end_address = $2::inet) \
               AND NOT EXISTS ( \
                     SELECT 1 FROM domain o \
                     WHERE o.net_start_address >= $1::inet AND o.net_end_address <= $2::inet \
                       AND NOT (o.net_start_address = $1::inet AND o.net_end_address = $2::inet) \
                       AND o.net_start_address >= d.net_start_address \
                       AND o.net_end_address <= d.net_end_address \
                       AND NOT (o.net_start_address = d.net_start_address \
                                AND o.net_end_address = d.net_end_address) \
                   )",
        )
        .bind(c_start)
        .bind(c_end)
        .fetch_all(&self.pg_pool)
        .await?;

        let results: Vec<Domain> = rows
            .into_iter()
            .map(|Json(r)| r)
            .filter_map(|r| match r {
                RdapResponse::Domain(d) => Some(*d),
                _ => None,
            })
            .collect();
        Ok(DomainSearchResults::response_obj()
            .results(results)
            .build()
            .to_response())
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
