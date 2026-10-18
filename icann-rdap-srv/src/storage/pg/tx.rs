#![allow(clippy::diverging_sub_expression)]
use std::net::IpAddr;

use {
    async_trait::async_trait,
    chrono::Utc,
    icann_rdap_common::{
        prelude::ToResponse,
        response::{Autnum, Domain, Entity, Nameserver, Network, Rfc9083Error},
    },
    sqlx::{PgPool, Postgres},
};

use crate::{
    error::RdapServerError,
    storage::{
        DEFAULT_HELPFILE_NAME, TxHandle,
        data::{AutnumId, DomainId, EntityId, NameserverId, NetworkId, NetworkIdType},
        timestamp::DbTimestamp,
    },
};

pub struct PgTx<'a> {
    db_tx: sqlx::Transaction<'a, Postgres>,
    db_timestamp: DbTimestamp,
}

impl PgTx<'_> {
    pub async fn new(pg_pool: &PgPool) -> Result<Self, RdapServerError> {
        let db_tx = pg_pool.begin().await?;
        Ok(Self {
            db_tx,
            db_timestamp: DbTimestamp::new(),
        })
    }

    pub async fn new_truncate(pg_pool: &PgPool) -> Result<Self, RdapServerError> {
        let mut db_tx = pg_pool.begin().await?;
        sqlx::query("TRUNCATE entity, domain, nameserver, autnum, network, srv_help, domain_ns")
            .execute(&mut *db_tx)
            .await?;
        Ok(Self {
            db_tx,
            db_timestamp: DbTimestamp::new(),
        })
    }

    /// Attach the store's shared last-update timestamp so that committing this
    /// transaction records it. The store calls this; standalone transactions (e.g. in
    /// tests) keep a private default that is never read.
    pub fn with_timestamp(mut self, db_timestamp: DbTimestamp) -> Self {
        self.db_timestamp = db_timestamp;
        self
    }
}

#[async_trait]
impl TxHandle for PgTx<'_> {
    async fn add_entity(&mut self, entity: &Entity) -> Result<(), RdapServerError> {
        let content = serde_json::to_value(entity)?;
        let full_name = entity
            .contact()
            .and_then(|c| c.full_name().map(String::from));
        sqlx::query(
            "INSERT INTO entity (fn, content) VALUES ($1, $2) \
             ON CONFLICT (handle) DO UPDATE SET fn = EXCLUDED.fn, content = EXCLUDED.content",
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
        // On conflict `fn` is NULLed alongside `content`: error responses carry no contact,
        // and a stale full name would let fn-based searches return this row.
        sqlx::query(
            "INSERT INTO entity (handle, content) VALUES ($1, $2) \
             ON CONFLICT (handle) DO UPDATE SET fn = NULL, content = EXCLUDED.content",
        )
        .bind(&entity_id.handle)
        .bind(content)
        .execute(&mut *self.db_tx)
        .await?;
        Ok(())
    }

    async fn add_domain(&mut self, domain: &Domain) -> Result<(), RdapServerError> {
        let content = serde_json::to_value(domain)?;
        sqlx::query(
            "INSERT INTO domain (content) VALUES ($1) \
             ON CONFLICT (ldh_name) DO UPDATE SET content = EXCLUDED.content",
        )
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
             ON CONFLICT (ldh_name) DO UPDATE SET content = EXCLUDED.content",
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
            "INSERT INTO nameserver (content) VALUES ($1) \
             ON CONFLICT (ldh_name) DO UPDATE SET content = EXCLUDED.content",
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
             ON CONFLICT (ldh_name) DO UPDATE SET content = EXCLUDED.content",
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
             ON CONFLICT (start_autnum, end_autnum) DO UPDATE SET content = EXCLUDED.content",
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
             ON CONFLICT (start_autnum, end_autnum) DO UPDATE SET content = EXCLUDED.content",
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
             ON CONFLICT (start_address, end_address) DO UPDATE SET content = EXCLUDED.content",
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
             ON CONFLICT (start_address, end_address) DO UPDATE SET content = EXCLUDED.content",
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
        let host = host.unwrap_or(DEFAULT_HELPFILE_NAME);
        sqlx::query(
            "INSERT INTO srv_help (host, content) VALUES ($1, $2) \
             ON CONFLICT (host) DO UPDATE SET content = EXCLUDED.content",
        )
        .bind(host)
        .bind(content)
        .execute(&mut *self.db_tx)
        .await?;
        Ok(())
    }

    async fn commit(mut self: Box<Self>) -> Result<(), RdapServerError> {
        // Record this instant in `last_rdap_update` inside the same transaction as the
        // data, so row and data commit (or roll back) atomically. The table trigger
        // emits the `rdap_db_update` NOTIFY on commit for other instances.
        let now = Utc::now();
        let now = chrono::DateTime::from_timestamp_micros(now.timestamp_micros())
            .expect("valid microsecond timestamp");
        sqlx::query(
            "INSERT INTO last_rdap_update (id, last_db_update) VALUES (1, $1) \
             ON CONFLICT (id) DO UPDATE SET last_db_update = EXCLUDED.last_db_update",
        )
        .bind(now)
        .execute(&mut *self.db_tx)
        .await?;
        self.db_tx.commit().await?;
        // Stamp the shared, server-wide "last data update" timestamp with the same
        // instant now that the transaction has committed.
        self.db_timestamp.mark(now);
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> Result<(), RdapServerError> {
        self.db_tx.rollback().await?;
        Ok(())
    }
}
