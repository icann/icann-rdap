use buildstructor::Builder;
use envmnt::get_or;
use strum_macros::Display;
use tracing::debug;

use crate::{
    error::RdapServerError,
    storage::{mem::config::MemConfig, pg::config::PgConfig},
};

pub const LOG: &str = "RDAP_SRV_LOG";
pub const LISTEN_ADDR: &str = "RDAP_SRV_LISTEN_ADDR";
pub const LISTEN_PORT: &str = "RDAP_SRV_LISTEN_PORT";
pub const STORAGE: &str = "RDAP_SRV_STORAGE";
pub const DB_URL: &str = "RDAP_SRV_DB_URL";
pub const STATE_DIR: &str = "RDAP_SRV_STATE_DIR";

pub fn debug_config_vars() {
    let var_list = [LOG, LISTEN_ADDR, LISTEN_PORT, STORAGE, DB_URL, STATE_DIR];
    envmnt::vars()
        .iter()
        .filter(|(k, _)| var_list.contains(&k.as_str()))
        .for_each(|(k, v)| debug!("environment variable {k} = {v}"));
}

/// RDAP server listening configuration.
#[derive(Debug, Builder, Default)]
pub struct ListenConfig {
    /// If specified, determines the IP address of the interface to bind to.
    /// If unspecified, the server will bind all interfaces.
    pub ip_addr: Option<String>,

    /// If specified, determines the port number the server will bind to.
    /// If unspecified, the server let's the OS determine the port.
    pub port: Option<u16>,
}

/// Determines the storage type.
#[derive(Debug, Display)]
#[strum(serialize_all = "lowercase")]
pub enum StorageType {
    /// Uses in-memory storage.
    Memory(MemConfig),

    /// Uses a PostgreSQL database.
    Postgres(PgConfig),
}

impl StorageType {
    pub fn new_from_env() -> Result<Self, RdapServerError> {
        let storage = get_or(STORAGE, "memory");
        let storage_type = if storage == "memory" {
            let mirror_dir = get_or(STATE_DIR, "/tmp/rdap-srv/state");
            StorageType::Memory(
                MemConfig::builder()
                    .state_dir(mirror_dir)
                    .auto_reload(true)
                    .build(),
            )
        } else if storage == "postgres" {
            let db_url = get_or(DB_URL, "postgresql://127.0.0.1/rdap");
            StorageType::Postgres(PgConfig::builder().db_url(db_url).build())
        } else {
            return Err(RdapServerError::Config(format!(
                "storage type of '{storage}' is invalid"
            )));
        };
        Ok(storage_type)
    }
}

/// RDAP service configuration.
#[derive(Debug, Builder)]
pub struct ServiceConfig {
    pub storage_type: StorageType,
}
