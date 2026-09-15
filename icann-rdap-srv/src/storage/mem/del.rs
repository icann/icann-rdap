//! Deletion of RDAP entities from the in-memory backend.
//!
//! Not supported: every method panics via [`unimplemented!`].

use std::net::IpAddr;

use async_trait::async_trait;

use crate::{error::RdapServerError, storage::DeleteOps};

use super::ops::Mem;

#[async_trait]
impl DeleteOps for Mem {
    async fn delete_entity(&self, _handle: &str) -> Result<bool, RdapServerError> {
        unimplemented!("DeleteOps is not supported by the mem backend")
    }

    async fn delete_domain(&self, _ldh_name: &str) -> Result<bool, RdapServerError> {
        unimplemented!("DeleteOps is not supported by the mem backend")
    }

    async fn delete_nameserver(&self, _ldh_name: &str) -> Result<bool, RdapServerError> {
        unimplemented!("DeleteOps is not supported by the mem backend")
    }

    async fn delete_autnum(&self, _start: u32, _end: u32) -> Result<bool, RdapServerError> {
        unimplemented!("DeleteOps is not supported by the mem backend")
    }

    async fn delete_network(&self, _start: IpAddr, _end: IpAddr) -> Result<bool, RdapServerError> {
        unimplemented!("DeleteOps is not supported by the mem backend")
    }

    async fn delete_srv_help(&self, _host: &str) -> Result<bool, RdapServerError> {
        unimplemented!("DeleteOps is not supported by the mem backend")
    }
}
