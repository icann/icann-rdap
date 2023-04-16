use icann_rdap_srv::{
    config::{ListenConfig, ServiceConfig},
    error::RdapServerError,
    server::Listener,
};

#[tokio::main]
async fn main() -> Result<(), RdapServerError> {
    let listener = Listener::listen(&ListenConfig::builder().build())?;
    listener
        .start_server(&ServiceConfig::builder().build())
        .await?;
    Ok(())
}
