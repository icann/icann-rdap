use envmnt::{get_or, get_u16};
use icann_rdap_srv::{
    config::{ListenConfig, ServiceConfig, StorageType},
    error::RdapServerError,
    server::Listener,
};

const LISTEN_ADDR: &str = "RDAP_SRV_LISTEN_ADDR";
const LISTEN_PORT: &str = "RDAP_SRV_LISTEN_PORT";
const STORAGE: &str = "RDAP_SRV_STORAGE";
const DB_URL: &str = "RDAP_SRV_DB_URL";

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), RdapServerError> {
    dotenv::dotenv().ok();

    let listen_addr = get_or(LISTEN_ADDR, "127.0.0.1");
    let listen_port = get_u16(LISTEN_PORT, 3000);
    let storage = get_or(STORAGE, &StorageType::Memory.to_string());
    let storage_type = if storage == "memory" {
        StorageType::Memory
    } else if storage == "postgres" {
        let db_url = get_or(DB_URL, "postgresql://127.0.0.1/rdap");
        StorageType::Postgres { db_url }
    } else {
        return Err(RdapServerError::Config(format!(
            "storage type of '{storage}' is invalid"
        )));
    };

    let listener = Listener::listen(
        &ListenConfig::builder()
            .ip_addr(listen_addr)
            .port(listen_port)
            .build(),
    )?;
    listener
        .start_server(&ServiceConfig::builder().storage_type(storage_type).build())
        .await?;
    Ok(())
}
