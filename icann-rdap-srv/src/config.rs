use std::path::{self};

use strum_macros::EnumString;

use {
    buildstructor::Builder,
    envmnt::{get_or, get_parse_or},
    strum_macros::Display,
    tracing::debug,
};

use crate::{
    error::RdapServerError,
    storage::{mem::config::MemConfig, pg::config::PgConfig, CommonConfig},
};

pub const LOG: &str = "RDAP_SRV_LOG";
pub const LISTEN_ADDR: &str = "RDAP_SRV_LISTEN_ADDR";
pub const LISTEN_PORT: &str = "RDAP_SRV_LISTEN_PORT";
pub const STORAGE: &str = "RDAP_SRV_STORAGE";
pub const DB_URL: &str = "RDAP_SRV_DB_URL";
pub const DATA_DIR: &str = "RDAP_SRV_DATA_DIR";
pub const AUTO_RELOAD: &str = "RDAP_SRV_AUTO_RELOAD";
pub const BOOTSTRAP: &str = "RDAP_SRV_BOOTSTRAP";
pub const UPDATE_ON_BOOTSTRAP: &str = "RDAP_SRV_UPDATE_ON_BOOTSTRAP";
pub const DOMAIN_SEARCH_BY_NAME_ENABLE: &str = "RDAP_SRV_DOMAIN_SEARCH_BY_NAME";
pub const NAMESERVER_SEARCH_BY_NAME_ENABLE: &str = "RDAP_SRV_NAMESERVER_SEARCH_BY_NAME";
pub const NAMESERVER_SEARCH_BY_IP_ENABLE: &str = "RDAP_SRV_NAMESERVER_SEARCH_BY_IP";
pub const DOMAIN_SEARCH_BY_NS_IP_ENABLE: &str = "RDAP_SRV_DOMAIN_SEARCH_BY_NS_IP";
pub const JSCONTACT_CONVERSION: &str = "RDAP_SRV_JSCONTACT_CONVERSION";

pub fn debug_config_vars() {
    let var_list = [
        LOG,
        LISTEN_ADDR,
        LISTEN_PORT,
        STORAGE,
        DB_URL,
        DATA_DIR,
        AUTO_RELOAD,
        BOOTSTRAP,
        UPDATE_ON_BOOTSTRAP,
        DOMAIN_SEARCH_BY_NAME_ENABLE,
        NAMESERVER_SEARCH_BY_NAME_ENABLE,
        NAMESERVER_SEARCH_BY_IP_ENABLE,
        DOMAIN_SEARCH_BY_NS_IP_ENABLE,
        JSCONTACT_CONVERSION,
    ];
    envmnt::vars()
        .iter()
        .filter(|(k, _)| var_list.contains(&k.as_str()))
        .for_each(|(k, v)| debug!("environment variable {k} = {v}"));
}

pub fn data_dir() -> Result<String, std::io::Error> {
    let path_name = get_or(DATA_DIR, "srv/data");
    let path = path::absolute(path_name)?;
    Ok(path.display().to_string())
}

pub const DEFAULT_DATA_RDAP_BASE_URL: &str = "http://localhost:3000/rdap";

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
#[derive(Debug, Display, Clone)]
#[strum(serialize_all = "lowercase")]
pub enum StorageType {
    /// Uses in-memory storage.
    Memory(MemConfig),

    /// Uses a PostgreSQL database.
    Postgres(PgConfig),
}

impl StorageType {
    pub fn new_from_env() -> Result<Self, RdapServerError> {
        let domain_search_by_name = get_parse_or(DOMAIN_SEARCH_BY_NAME_ENABLE, false)?;
        let nameserver_search_by_name = get_parse_or(NAMESERVER_SEARCH_BY_NAME_ENABLE, false)?;
        let nameserver_search_by_ip = get_parse_or(NAMESERVER_SEARCH_BY_IP_ENABLE, false)?;
        let domain_search_by_ns_ip = get_parse_or(DOMAIN_SEARCH_BY_NS_IP_ENABLE, false)?;
        let common_config = CommonConfig::builder()
            .domain_search_by_name_enable(domain_search_by_name)
            .nameserver_search_by_name_enable(nameserver_search_by_name)
            .nameserver_search_by_ip_enable(nameserver_search_by_ip)
            .domain_search_by_ns_ip_enable(domain_search_by_ns_ip)
            .build();
        let storage = get_or(STORAGE, "memory");
        if storage == "memory" {
            Ok(Self::Memory(
                MemConfig::builder().common_config(common_config).build(),
            ))
        } else if storage == "postgres" {
            let db_url = get_or(DB_URL, "postgresql://127.0.0.1/rdap");
            Ok(Self::Postgres(
                PgConfig::builder()
                    .db_url(db_url)
                    .common_config(common_config)
                    .build(),
            ))
        } else {
            Err(RdapServerError::Config(format!(
                "storage type of '{storage}' is invalid"
            )))
        }
    }
}

/// Determines how conversion of contact to JSContact.
#[derive(Debug, Display, Clone, EnumString, Copy)]
#[strum(serialize_all = "lowercase")]
pub enum JsContactConversion {
    /// Do no JSContact conversions.
    None,

    /// Convert vCard to JSContact.
    Also,

    /// Convert vCard to JSContact and remove vCard.
    Only,
}

/// RDAP service configuration.
#[derive(Debug, Builder, Clone)]
pub struct ServiceConfig {
    pub storage_type: StorageType,
    pub data_dir: String,
    pub auto_reload: bool,
    pub bootstrap: bool,
    pub update_on_bootstrap: bool,
    pub jscontact_conversion: JsContactConversion,
}

#[buildstructor::buildstructor]
impl ServiceConfig {
    #[builder(entry = "non_server")]
    pub fn new_non_server(
        data_dir: String,
        storage_type: Option<StorageType>,
    ) -> Result<Self, RdapServerError> {
        let storage_type = if let Some(storage_type) = storage_type {
            storage_type
        } else {
            StorageType::new_from_env()?
        };
        Ok(Self {
            storage_type,
            data_dir,
            auto_reload: false,
            bootstrap: false,
            update_on_bootstrap: false,
            jscontact_conversion: JsContactConversion::None,
        })
    }
}
