#![allow(clippy::diverging_sub_expression)]
use std::net::IpAddr;

use {
    async_trait::async_trait,
    icann_rdap_common::{
        prelude::ToResponse,
        response::{Autnum, Domain, Entity, Nameserver, Network, Rfc9083Error},
    },
    sqlx::{PgPool, Postgres},
};

use crate::{
    error::RdapServerError,
    storage::{
        TxHandle,
        data::{AutnumId, DomainId, EntityId, NameserverId, NetworkId, NetworkIdType},
    },
};

pub struct PgTx<'a> {
    db_tx: sqlx::Transaction<'a, Postgres>,
}

impl PgTx<'_> {
    pub async fn new(pg_pool: &PgPool) -> Result<Self, RdapServerError> {
        let db_tx = pg_pool.begin().await?;
        Ok(Self { db_tx })
    }

    pub async fn new_truncate(pg_pool: &PgPool) -> Result<Self, RdapServerError> {
        let mut db_tx = pg_pool.begin().await?;
        sqlx::query("TRUNCATE entity, domain, nameserver, autnum, network, srv_help")
            .execute(&mut *db_tx)
            .await?;
        Ok(Self { db_tx })
    }
}

#[async_trait]
impl TxHandle for PgTx<'_> {
    async fn add_entity(&mut self, entity: &Entity) -> Result<(), RdapServerError> {
        let content = serde_json::to_value(entity)?;
        let full_name = entity.contact().and_then(|c| c.full_name().map(String::from));
        sqlx::query(
            "INSERT INTO entity (fn, content) VALUES ($1, $2) ON CONFLICT (handle) DO NOTHING",
        )
        .bind(full_name)
        .bind(content)
        .execute(&mut *self.db_tx)
        .await?;
        Ok(())
    }

    async fn add_entity_err(
        &mut self,
        entity_id: &EntityId,
        error: &Rfc9083Error,
    ) -> Result<(), RdapServerError> {
        let content = serde_json::to_value(error.clone().to_response())?;
        sqlx::query(
            "INSERT INTO entity (handle, content) VALUES ($1, $2) ON CONFLICT (handle) DO NOTHING",
        )
        .bind(&entity_id.handle)
        .bind(content)
        .execute(&mut *self.db_tx)
        .await?;
        Ok(())
    }

    async fn add_domain(&mut self, domain: &Domain) -> Result<(), RdapServerError> {
        let content = serde_json::to_value(domain)?;
        sqlx::query("INSERT INTO domain (content) VALUES ($1) ON CONFLICT (ldh_name) DO NOTHING")
            .bind(content)
            .execute(&mut *self.db_tx)
            .await?;
        Ok(())
    }

    async fn add_domain_err(
        &mut self,
        domain_id: &DomainId,
        error: &Rfc9083Error,
    ) -> Result<(), RdapServerError> {
        let content = serde_json::to_value(error.clone().to_response())?;
        sqlx::query(
            "INSERT INTO domain (ldh_name, content) VALUES ($1, $2) \
             ON CONFLICT (ldh_name) DO NOTHING",
        )
        .bind(&domain_id.ldh_name)
        .bind(content)
        .execute(&mut *self.db_tx)
        .await?;
        Ok(())
    }

    async fn add_nameserver(&mut self, nameserver: &Nameserver) -> Result<(), RdapServerError> {
        let content = serde_json::to_value(nameserver)?;
        sqlx::query(
            "INSERT INTO nameserver (content) VALUES ($1) ON CONFLICT (ldh_name) DO NOTHING",
        )
        .bind(content)
        .execute(&mut *self.db_tx)
        .await?;
        Ok(())
    }

    async fn add_nameserver_err(
        &mut self,
        nameserver_id: &NameserverId,
        error: &Rfc9083Error,
    ) -> Result<(), RdapServerError> {
        let content = serde_json::to_value(error.clone().to_response())?;
        sqlx::query(
            "INSERT INTO nameserver (ldh_name, content) VALUES ($1, $2) \
             ON CONFLICT (ldh_name) DO NOTHING",
        )
        .bind(&nameserver_id.ldh_name)
        .bind(content)
        .execute(&mut *self.db_tx)
        .await?;
        Ok(())
    }

    async fn add_autnum(&mut self, autnum: &Autnum) -> Result<(), RdapServerError> {
        let content = serde_json::to_value(autnum)?;
        sqlx::query(
            "INSERT INTO autnum (content) VALUES ($1) \
             ON CONFLICT (start_autnum, end_autnum) DO NOTHING",
        )
        .bind(content)
        .execute(&mut *self.db_tx)
        .await?;
        Ok(())
    }

    async fn add_autnum_err(
        &mut self,
        autnum_id: &AutnumId,
        error: &Rfc9083Error,
    ) -> Result<(), RdapServerError> {
        let content = serde_json::to_value(error.clone().to_response())?;
        sqlx::query(
            "INSERT INTO autnum (start_autnum, end_autnum, content) VALUES ($1, $2, $3) \
             ON CONFLICT (start_autnum, end_autnum) DO NOTHING",
        )
        .bind(autnum_id.start_autnum as i64)
        .bind(autnum_id.end_autnum as i64)
        .bind(content)
        .execute(&mut *self.db_tx)
        .await?;
        Ok(())
    }

    async fn add_network(&mut self, network: &Network) -> Result<(), RdapServerError> {
        let content = serde_json::to_value(network)?;
        sqlx::query(
            "INSERT INTO network (content) VALUES ($1) \
             ON CONFLICT (start_address, end_address) DO NOTHING",
        )
        .bind(content)
        .execute(&mut *self.db_tx)
        .await?;
        Ok(())
    }

    async fn add_network_err(
        &mut self,
        network_id: &NetworkId,
        error: &Rfc9083Error,
    ) -> Result<(), RdapServerError> {
        let (start_address, end_address) = match &network_id.network_id {
            NetworkIdType::Cidr(cidr) => (cidr.network(), cidr.broadcast()),
            NetworkIdType::Range {
                start_address,
                end_address,
            } => {
                let start = start_address.parse::<IpAddr>()?;
                let end = end_address.parse::<IpAddr>()?;
                if start.is_ipv4() != end.is_ipv4() {
                    return Err(RdapServerError::EmptyIndexData(
                        "mismatch ip version".to_string(),
                    ));
                }
                (start, end)
            }
        };
        let content = serde_json::to_value(error.clone().to_response())?;
        sqlx::query(
            "INSERT INTO network (start_address, end_address, content) VALUES ($1, $2, $3) \
             ON CONFLICT (start_address, end_address) DO NOTHING",
        )
        .bind(start_address)
        .bind(end_address)
        .bind(content)
        .execute(&mut *self.db_tx)
        .await?;
        Ok(())
    }

    async fn add_srv_help(
        &mut self,
        help: &icann_rdap_common::response::Help,
        host: Option<&str>,
    ) -> Result<(), RdapServerError> {
        let content = serde_json::to_value(help)?;
        let host = host.unwrap_or("default");
        sqlx::query(
            "INSERT INTO srv_help (host, content) VALUES ($1, $2) ON CONFLICT (host) DO NOTHING",
        )
        .bind(host)
        .bind(content)
        .execute(&mut *self.db_tx)
        .await?;
        Ok(())
    }

    async fn commit(self: Box<Self>) -> Result<(), RdapServerError> {
        self.db_tx.commit().await?;
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> Result<(), RdapServerError> {
        self.db_tx.rollback().await?;
        Ok(())
    }
}
