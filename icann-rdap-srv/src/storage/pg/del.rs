//! Deletion of RDAP entities from the PostgreSQL backend.

use std::net::IpAddr;

use async_trait::async_trait;

use crate::{error::RdapServerError, storage::DeleteOps};

use super::ops::Pg;

#[async_trait]
impl DeleteOps for Pg {
    async fn delete_entity(&self, handle: &str) -> Result<bool, RdapServerError> {
        let res = sqlx::query("DELETE FROM entity WHERE handle = $1")
            .bind(handle)
            .execute(self.pool())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn delete_domain(&self, ldh_name: &str) -> Result<bool, RdapServerError> {
        let res = sqlx::query("DELETE FROM domain WHERE ldh_name = $1")
            .bind(ldh_name)
            .execute(self.pool())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn delete_nameserver(&self, ldh_name: &str) -> Result<bool, RdapServerError> {
        let res = sqlx::query("DELETE FROM nameserver WHERE ldh_name = $1")
            .bind(ldh_name)
            .execute(self.pool())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn delete_autnum(&self, start: u32, end: u32) -> Result<bool, RdapServerError> {
        // Columns are BIGINT; bind as i64 rather than relying on implicit casts.
        let res = sqlx::query("DELETE FROM autnum WHERE start_autnum = $1 AND end_autnum = $2")
            .bind(i64::from(start))
            .bind(i64::from(end))
            .execute(self.pool())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn delete_network(&self, start: IpAddr, end: IpAddr) -> Result<bool, RdapServerError> {
        let res = sqlx::query(
            "DELETE FROM network WHERE start_address = $1::inet AND end_address = $2::inet",
        )
        .bind(start)
        .bind(end)
        .execute(self.pool())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn delete_srv_help(&self, host: &str) -> Result<bool, RdapServerError> {
        let res = sqlx::query("DELETE FROM srv_help WHERE host = $1")
            .bind(host)
            .execute(self.pool())
            .await?;
        Ok(res.rows_affected() > 0)
    }
}
