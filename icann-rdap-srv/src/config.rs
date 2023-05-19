use buildstructor::Builder;
use strum_macros::Display;

use crate::storage::{mem::config::MemConfig, pg::config::PgConfig};

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

/// RDAP service configuration.
#[derive(Debug, Builder)]
pub struct ServiceConfig {
    pub storage_type: StorageType,
}
