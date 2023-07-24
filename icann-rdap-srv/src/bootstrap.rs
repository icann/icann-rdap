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
use tracing::{debug, info};

use crate::{
    config::ServiceConfig,
    error::RdapServerError,
    storage::data::{
        trigger_reload, trigger_update, AutnumId, AutnumOrError, DomainId, DomainOrError,
        NetworkId, NetworkIdType, NetworkOrError, Template,
    },
};

pub async fn init_bootstrap(config: &ServiceConfig) -> Result<(), RdapServerError> {
    if config.bootstrap {
        info!("Initializing IANA Bootstrap.");
        let client_config = ClientConfig::builder()
            .user_agent_suffix("icann-rdap-srv")
            .build();
        let client = create_client(&client_config)?;

        // do one run of the bootstrapping before starting the thread.
        process_bootstrap(config, &client).await?;

        // spawn bootstrap thread
        tokio::spawn(loop_bootstrap(config.clone(), client));
    }
    Ok(())
}

async fn loop_bootstrap(config: ServiceConfig, client: Client) -> Result<(), RdapServerError> {
    loop {
        sleep(Duration::from_millis(60000)).await;
        process_bootstrap(&config, &client).await?;
    }
}

async fn process_bootstrap(config: &ServiceConfig, client: &Client) -> Result<(), RdapServerError> {
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
        make_ip_bootstrap(config, iana_reg, IanaRegistryType::RdapBootstrapIpv4).await?;
    }
    if let Some(iana_reg) = fetch_iana_registry(
        IanaRegistryType::RdapBootstrapIpv6,
        client,
        &config.data_dir,
    )
    .await?
    {
        remove_previous_bootstrap(config, IanaRegistryType::RdapBootstrapIpv6).await?;
        make_ip_bootstrap(config, iana_reg, IanaRegistryType::RdapBootstrapIpv6).await?;
    }
    if config.update_on_bootstrap {
        trigger_update(&config.data_dir).await?;
    } else {
        trigger_reload(&config.data_dir).await?;
    }
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
    config: &ServiceConfig,
    iana: IanaRegistry,
) -> Result<(), RdapServerError> {
    let IanaRegistry::RdapBootstrapRegistry(reg) = iana;
    for (num, service) in reg.services.iter().enumerate() {
        let tlds = service
            .first()
            .ok_or(RdapServerError::Bootstrap("no tlds found".to_string()))?;
        let urls = service
            .last()
            .ok_or(RdapServerError::Bootstrap("no urls for tlds".to_string()))?;
        let Some(url) = get_preferred_url(urls) else {return Err(RdapServerError::Bootstrap(format!("no bootstrap URL in DNS service")))};
        let ids = tlds
            .iter()
            .map(|tld| DomainId::builder().ldh_name(tld).build())
            .collect::<Vec<DomainId>>();
        let template = Template::Domain {
            domain: DomainOrError::ErrorResponse(
                icann_rdap_common::response::error::Error::redirect()
                    .url(url)
                    .build(),
            ),
            ids,
        };
        let content = serde_json::to_string_pretty(&template)?;
        let mut path = PathBuf::from(&config.data_dir);
        path.push(format!(
            "{}_{num}.template",
            IanaRegistryType::RdapBootstrapDns.prefix()
        ));
        fs::write(path, content).await?;
    }
    Ok(())
}

async fn make_asn_bootstrap(
    config: &ServiceConfig,
    iana: IanaRegistry,
) -> Result<(), RdapServerError> {
    let IanaRegistry::RdapBootstrapRegistry(reg) = iana;
    for (num, service) in reg.services.iter().enumerate() {
        let as_ranges = service
            .first()
            .ok_or(RdapServerError::Bootstrap("no ASN ranges fond".to_string()))?;
        let urls = service.last().ok_or(RdapServerError::Bootstrap(
            "no urls for ASN ranges".to_string(),
        ))?;
        let Some(url) = get_preferred_url(urls) else {return Err(RdapServerError::Bootstrap(format!("no bootstrap URL in Autnum service")))};
        let ids = as_ranges
            .iter()
            .map(|as_range| {
                let as_split = as_range.split('-').collect::<Vec<&str>>();
                let start_as = as_split
                    .first()
                    .ok_or(RdapServerError::Bootstrap("no start ASN".to_string()))?
                    .parse::<u32>()
                    .map_err(|_| RdapServerError::Bootstrap("ASN is not a number".to_string()))?;
                let end_as = as_split
                    .last()
                    .ok_or(RdapServerError::Bootstrap("no end ASN".to_string()))?
                    .parse::<u32>()
                    .map_err(|_| RdapServerError::Bootstrap("ASN is not a number".to_string()))?;
                Ok(AutnumId::builder()
                    .start_autnum(start_as)
                    .end_autnum(end_as)
                    .build())
            })
            .collect::<Result<Vec<AutnumId>, RdapServerError>>()?;
        let template = Template::Autnum {
            autnum: AutnumOrError::ErrorResponse(
                icann_rdap_common::response::error::Error::redirect()
                    .url(url)
                    .build(),
            ),
            ids,
        };
        let content = serde_json::to_string_pretty(&template)?;
        let mut path = PathBuf::from(&config.data_dir);
        path.push(format!(
            "{}_{num}.template",
            IanaRegistryType::RdapBootstrapAsn.prefix()
        ));
        fs::write(path, content).await?;
    }
    Ok(())
}

async fn make_ip_bootstrap(
    config: &ServiceConfig,
    iana: IanaRegistry,
    iana_type: IanaRegistryType,
) -> Result<(), RdapServerError> {
    let IanaRegistry::RdapBootstrapRegistry(reg) = iana;
    for (num, service) in reg.services.iter().enumerate() {
        let cidrs = service
            .first()
            .ok_or(RdapServerError::Bootstrap("no CIDRs fond".to_string()))?;
        let urls = service
            .last()
            .ok_or(RdapServerError::Bootstrap("no urls for CIDRs".to_string()))?;
        let Some(url) = get_preferred_url(urls) else {return Err(RdapServerError::Bootstrap(format!("no bootstrap URL in IP service")))};
        let ids = cidrs
            .iter()
            .map(|cidr| {
                Ok(NetworkId::builder()
                    .network_id(NetworkIdType::Cidr(cidr.parse().map_err(|_| {
                        RdapServerError::Bootstrap("invalid CIDR".to_string())
                    })?))
                    .build())
            })
            .collect::<Result<Vec<NetworkId>, RdapServerError>>()?;
        let template = Template::Network {
            network: NetworkOrError::ErrorResponse(
                icann_rdap_common::response::error::Error::redirect()
                    .url(url)
                    .build(),
            ),
            ids,
        };
        let content = serde_json::to_string_pretty(&template)?;
        let mut path = PathBuf::from(&config.data_dir);
        path.push(format!("{}_{num}.template", iana_type.prefix()));
        fs::write(path, content).await?;
    }
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
fn get_preferred_url(urls: &Vec<String>) -> Option<String> {
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

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use icann_rdap_common::{iana::IanaRegistry, response::RdapResponse};
    use test_dir::{DirBuilder, TestDir};

    use crate::{
        config::{ServiceConfig, StorageType},
        storage::{
            data::load_data,
            mem::{config::MemConfig, ops::Mem},
            StoreOps,
        },
    };

    use super::*;

    #[tokio::test]
    async fn GIVEN_dns_bootstrap_WHEN_make_dns_bootstrap_THEN_redirects_loaded() {
        // GIVEN
        let bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "Some text",
                "services": [
                  [
                    ["net", "com"],
                    [
                      "https://registry.example.com/myrdap/"
                    ]
                  ],
                  [
                    ["org", "mytld"],
                    [
                      "https://example.org/"
                    ]
                  ]
                ]
            }
        "#;
        let iana =
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse domain bootstrap");

        // WHEN
        let temp = TestDir::temp();
        let config = ServiceConfig::non_server()
            .data_dir(temp.root().to_string_lossy().to_string())
            .build()
            .expect("error making service config");
        make_dns_bootstrap(&config, iana)
            .await
            .expect("unable to make DNS bootstrap");

        // THEN
        let mem = new_and_init_mem(config.data_dir).await;
        // com
        let response = mem.get_domain_by_ldh("com").await.expect("lookup of com");
        let RdapResponse::ErrorResponse(error) = response else {panic!("not an error response")};
        assert_eq!(
            get_redirect_link(error),
            "https://registry.example.com/myrdap/"
        );
        // net
        let response = mem.get_domain_by_ldh("net").await.expect("lookup of net");
        let RdapResponse::ErrorResponse(error) = response else {panic!("not an error response")};
        assert_eq!(
            get_redirect_link(error),
            "https://registry.example.com/myrdap/"
        );
        // org
        let response = mem.get_domain_by_ldh("org").await.expect("lookup of org");
        let RdapResponse::ErrorResponse(error) = response else {panic!("not an error response")};
        assert_eq!(get_redirect_link(error), "https://example.org/");
        // mytld
        let response = mem
            .get_domain_by_ldh("mytld")
            .await
            .expect("lookup of mytld");
        let RdapResponse::ErrorResponse(error) = response else {panic!("not an error response")};
        assert_eq!(get_redirect_link(error), "https://example.org/");
    }

    async fn new_and_init_mem(data_dir: String) -> Mem {
        let mem_config = MemConfig::builder().build();
        let mem = Mem::new(mem_config.clone());
        mem.init().await.expect("initialzing memeory");
        load_data(
            &ServiceConfig::non_server()
                .data_dir(data_dir)
                .storage_type(StorageType::Memory(mem_config))
                .build()
                .expect("building service config"),
            &mem,
            false,
        )
        .await
        .expect("loading data");
        mem
    }

    fn get_redirect_link(error: icann_rdap_common::response::error::Error) -> String {
        let Some(notices) = error.common.notices else {panic!("no notices in error")};
        let Some(first_notice) = notices.first() else {panic!("notices are empty")};
        let Some(links) = &first_notice.links else {panic!("no links in notice")};
        let Some(first_link) = links.first() else {panic!("links are empty")};
        first_link.href.to_owned()
    }
}
