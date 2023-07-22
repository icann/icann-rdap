use std::{path::PathBuf, time::Duration};

use icann_rdap_common::{
    cache::HttpData,
    client::{create_client, ClientConfig},
    iana::{iana_request, IanaRegistry, IanaRegistryType},
};
use reqwest::Client;
use tokio::{
    fs::{self, File},
    io::{AsyncBufReadExt, BufReader},
    time::sleep,
};
use tracing::debug;

use crate::{config::ServiceConfig, error::RdapServerError, storage::data::trigger_reload};

pub async fn init_bootstrap(config: &ServiceConfig) -> Result<(), RdapServerError> {
    let client_config = ClientConfig::builder()
        .user_agent_suffix("icann-rdap-srv")
        .build();
    let client = create_client(&client_config)?;

    // do one run of the bootstrapping before starting the thread.
    fetch_bootstrap(config, &client).await?;

    // spawn bootstrap thread
    tokio::spawn(loop_bootstrap(config.clone(), client));
    Ok(())
}

async fn loop_bootstrap(config: ServiceConfig, client: Client) -> Result<(), RdapServerError> {
    loop {
        sleep(Duration::from_millis(60000)).await;
        fetch_bootstrap(&config, &client).await?;
    }
}

async fn fetch_bootstrap(config: &ServiceConfig, client: &Client) -> Result<(), RdapServerError> {
    if let Some(iana_reg) =
        fetch_iana_registry(IanaRegistryType::RdapBootstrapDns, client, &config.data_dir).await?
    {
        remove_previous_bootstrap(config, IanaRegistryType::RdapBootstrapDns).await?;
        make_dns_bootstrap(config, iana_reg).await?;
    }
    if let Some(iana_reg) =
        fetch_iana_registry(IanaRegistryType::RdapBootstrapAsn, client, &config.data_dir).await?
    {
        remove_previous_bootstrap(config, IanaRegistryType::RdapBootstrapAsn).await?;
        make_asn_bootstrap(config, iana_reg).await?;
    }
    if let Some(iana_reg) = fetch_iana_registry(
        IanaRegistryType::RdapBootstrapIpv4,
        client,
        &config.data_dir,
    )
    .await?
    {
        remove_previous_bootstrap(config, IanaRegistryType::RdapBootstrapIpv4).await?;
        make_ipv4_bootstrap(config, iana_reg).await?;
    }
    if let Some(iana_reg) = fetch_iana_registry(
        IanaRegistryType::RdapBootstrapIpv6,
        client,
        &config.data_dir,
    )
    .await?
    {
        remove_previous_bootstrap(config, IanaRegistryType::RdapBootstrapIpv6).await?;
        make_ipv6_bootstrap(config, iana_reg).await?;
    }
    trigger_reload(&config.data_dir).await?;
    // TODO or trigger_update
    Ok(())
}

async fn remove_previous_bootstrap(
    config: &ServiceConfig,
    iana: IanaRegistryType,
) -> Result<(), RdapServerError> {
    let prefix = iana.prefix();
    let mut entries = fs::read_dir(&config.data_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        if entry.file_name().to_string_lossy().starts_with(prefix) {
            fs::remove_file(entry.path()).await?;
        }
    }
    Ok(())
}

async fn make_dns_bootstrap(
    _config: &ServiceConfig,
    _iana: IanaRegistry,
) -> Result<(), RdapServerError> {
    Ok(())
}

async fn make_asn_bootstrap(
    _config: &ServiceConfig,
    _iana: IanaRegistry,
) -> Result<(), RdapServerError> {
    Ok(())
}

async fn make_ipv4_bootstrap(
    _config: &ServiceConfig,
    _iana: IanaRegistry,
) -> Result<(), RdapServerError> {
    Ok(())
}

async fn make_ipv6_bootstrap(
    _config: &ServiceConfig,
    _iana: IanaRegistry,
) -> Result<(), RdapServerError> {
    Ok(())
}

async fn fetch_iana_registry(
    reg_type: IanaRegistryType,
    client: &Client,
    data_dir: &str,
) -> Result<Option<IanaRegistry>, RdapServerError> {
    let path: PathBuf = [data_dir, (reg_type.file_name())].iter().collect();
    if path.exists() {
        let input = File::open(&path).await?;
        let buf = BufReader::new(input);
        let mut lines = Vec::new();
        let mut buf_lines = buf.lines();
        while let Some(buf_line) = buf_lines.next_line().await? {
            lines.push(buf_line);
        }
        let cache_data = HttpData::from_lines(&lines)?;
        if !cache_data.0.is_expired(604800i64) {
            debug!("No update for bootstrap from {}", reg_type.file_name());
            return Ok(None);
        }
    }
    debug!("Getting IANA bootstrap from {}", reg_type.url());
    let iana = iana_request(reg_type, client).await?;
    let data = serde_json::to_string_pretty(&iana.registry)?;
    let cache_contents = iana.http_data.to_lines(&data)?;
    fs::write(path, cache_contents).await?;
    Ok(Some(iana.registry))
}

/// Prefer HTTPS urls.
fn _get_preferred_url(urls: Vec<String>) -> Option<String> {
    if urls.is_empty() {
        None
    } else {
        let url = urls
            .iter()
            .find(|s| s.starts_with("https://"))
            .unwrap_or_else(|| urls.first().unwrap());
        Some(url.to_owned())
    }
}

trait BootstrapPrefix {
    fn prefix(&self) -> &str;
}

impl BootstrapPrefix for IanaRegistryType {
    fn prefix(&self) -> &str {
        match self {
            IanaRegistryType::RdapBootstrapDns => "bootstrap_dns",
            IanaRegistryType::RdapBootstrapAsn => "bootstrap_asn",
            IanaRegistryType::RdapBootstrapIpv4 => "bootstrap_ipv4",
            IanaRegistryType::RdapBootstrapIpv6 => "bootstrap_ipv6",
            IanaRegistryType::RdapObjectTags => "bootstrap_objtag",
        }
    }
}
