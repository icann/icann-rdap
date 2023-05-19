use envmnt::{get_or, get_u16};
use icann_rdap_srv::{
    config::{
        debug_config_vars, ListenConfig, ServiceConfig, StorageType, LISTEN_ADDR, LISTEN_PORT, LOG,
    },
    error::RdapServerError,
    server::Listener,
};
use tracing_subscriber::{
    fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), RdapServerError> {
    dotenv::dotenv().ok();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_env(LOG))
        .init();

    debug_config_vars();

    let listen_addr = get_or(LISTEN_ADDR, "127.0.0.1");
    let listen_port = get_u16(LISTEN_PORT, 3000);
    let storage_type = StorageType::new_from_env()?;

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
