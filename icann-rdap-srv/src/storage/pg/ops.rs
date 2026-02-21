#![allow(clippy::diverging_sub_expression)]
use std::net::IpAddr;

use {
    async_trait::async_trait,
    icann_rdap_common::response::RdapResponse,
    sqlx::{query, PgPool},
    tracing::{debug, info},
};

use crate::{
    error::RdapServerError,
    storage::{StoreOps, TxHandle},
};

use super::{config::PgConfig, tx::PgTx};

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

    async fn get_domain_by_ldh(&self, _ldh: &str) -> Result<RdapResponse, RdapServerError> {
        todo!()
    }

    async fn get_domain_by_unicode(&self, _unicode: &str) -> Result<RdapResponse, RdapServerError> {
        todo!()
    }

    async fn get_entity_by_handle(&self, _handle: &str) -> Result<RdapResponse, RdapServerError> {
        todo!()
    }

    async fn get_nameserver_by_ldh(&self, _ldh: &str) -> Result<RdapResponse, RdapServerError> {
        todo!()
    }

    async fn get_autnum_by_num(&self, _num: u32) -> Result<RdapResponse, RdapServerError> {
        todo!()
    }

    async fn get_network_by_ipaddr(&self, _ipaddr: &str) -> Result<RdapResponse, RdapServerError> {
        todo!()
    }
    async fn get_network_by_cidr(&self, _cidr: &str) -> Result<RdapResponse, RdapServerError> {
        todo!()
    }
    async fn get_srv_help(&self, _host: Option<&str>) -> Result<RdapResponse, RdapServerError> {
        todo!()
    }
    async fn search_domains_by_name(&self, _name: &str) -> Result<RdapResponse, RdapServerError> {
        todo!()
    }
    async fn search_nameservers_by_name(
        &self,
        _name: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        todo!()
    }
    async fn search_nameservers_by_ip(&self, _ip: IpAddr) -> Result<RdapResponse, RdapServerError> {
        todo!()
    }
    async fn search_domains_by_ns_ip(&self, _ip: IpAddr) -> Result<RdapResponse, RdapServerError> {
        todo!()
    }
    async fn search_domains_by_ns_ldh_name(
        &self,
        _name: &str,
    ) -> Result<RdapResponse, RdapServerError> {
        todo!()
    }
}
