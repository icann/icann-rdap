use envmnt::{get_or, get_u16};
use icann_rdap_srv::{
    config::{ListenConfig, ServiceConfig},
    error::RdapServerError,
    server::Listener,
};

const LISTEN_ADDR: &str = "RDAP_SRV_LISTEN_ADDR";
const LISTEN_PORT: &str = "RDAP_SRV_LISTEN_PORT";

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), RdapServerError> {
    dotenv::dotenv().ok();

    let listen_addr = get_or(LISTEN_ADDR, "127.0.0.1");
    let listen_port = get_u16(LISTEN_PORT, 3000);

    let listener = Listener::listen(
        &ListenConfig::builder()
            .ip_addr(listen_addr)
            .port(listen_port)
            .build(),
    )?;
    listener
        .start_server(&ServiceConfig::builder().build())
        .await?;
    Ok(())
}
