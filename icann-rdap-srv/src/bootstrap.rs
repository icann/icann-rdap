use std::{path::PathBuf, time::Duration};

use icann_rdap_client::{
    http::{create_client, Client, ClientConfig},
    iana::iana_request,
};
use icann_rdap_common::{
    httpdata::HttpData,
    iana::{IanaRegistry, IanaRegistryType},
};
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
        trigger_reload, trigger_update, AutnumId, AutnumOrError, DomainId, DomainOrError, EntityId,
        EntityOrError, NetworkId, NetworkIdType, NetworkOrError, Template,
    },
};

const IANA_JSON_SUFFIX: &str = ".iana_cache";

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
    let mut new_data = false;
    if let Some(iana_reg) =
        fetch_iana_registry(IanaRegistryType::RdapBootstrapDns, client, &config.data_dir).await?
    {
        remove_previous_bootstrap(config, IanaRegistryType::RdapBootstrapDns).await?;
        make_dns_bootstrap(config, iana_reg).await?;
        new_data = true;
    }
    if let Some(iana_reg) =
        fetch_iana_registry(IanaRegistryType::RdapBootstrapAsn, client, &config.data_dir).await?
    {
        remove_previous_bootstrap(config, IanaRegistryType::RdapBootstrapAsn).await?;
        make_asn_bootstrap(config, iana_reg).await?;
        new_data = true;
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
        new_data = true;
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
        new_data = true;
    }
    if let Some(iana_reg) =
        fetch_iana_registry(IanaRegistryType::RdapObjectTags, client, &config.data_dir).await?
    {
        remove_previous_bootstrap(config, IanaRegistryType::RdapObjectTags).await?;
        make_tag_registry(config, iana_reg).await?;
        new_data = true;
    }
    if new_data {
        if config.update_on_bootstrap {
            trigger_update(&config.data_dir).await?;
        } else {
            trigger_reload(&config.data_dir).await?;
        }
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
        let Some(url) = get_preferred_url(urls) else {
            return Err(RdapServerError::Bootstrap(
                "no bootstrap URL in DNS service".to_string(),
            ));
        };
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
        let Some(url) = get_preferred_url(urls) else {
            return Err(RdapServerError::Bootstrap(
                "no bootstrap URL in Autnum service".to_string(),
            ));
        };
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
        let Some(url) = get_preferred_url(urls) else {
            return Err(RdapServerError::Bootstrap(
                "no bootstrap URL in IP service".to_string(),
            ));
        };
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

async fn make_tag_registry(
    config: &ServiceConfig,
    iana: IanaRegistry,
) -> Result<(), RdapServerError> {
    let IanaRegistry::RdapBootstrapRegistry(reg) = iana;
    for (num, service) in reg.services.iter().enumerate() {
        if service.len() != 3 {
            return Err(RdapServerError::Bootstrap(
                "object tag registry has wrong number of arrays".to_string(),
            ));
        }
        let tags = service
            .get(1)
            .ok_or(RdapServerError::Bootstrap("no tags".to_string()))?;
        let urls = service
            .get(2)
            .ok_or(RdapServerError::Bootstrap("no urls for tags".to_string()))?;
        let Some(url) = get_preferred_url(urls) else {
            return Err(RdapServerError::Bootstrap(
                "no bootstrap URL in tag service".to_string(),
            ));
        };
        let ids = tags
            .iter()
            .map(|tag| {
                EntityId::builder()
                    .handle(format!("-{}", tag.to_ascii_uppercase()))
                    .build()
            })
            .collect::<Vec<EntityId>>();
        let template = Template::Entity {
            entity: EntityOrError::ErrorResponse(
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
            IanaRegistryType::RdapObjectTags.prefix()
        ));
        fs::write(path, content).await?;
    }
    Ok(())
}

async fn fetch_iana_registry(
    reg_type: IanaRegistryType,
    client: &Client,
    data_dir: &str,
) -> Result<Option<IanaRegistry>, RdapServerError> {
    let file_name = format!("{}{IANA_JSON_SUFFIX}", reg_type.file_name());
    let path: PathBuf = [data_dir, (file_name.as_str())].iter().collect();
    if path.exists() {
        let input = File::open(&path).await?;
        let buf = BufReader::new(input);
        let mut lines = vec![];
        let mut buf_lines = buf.lines();
        while let Some(buf_line) = buf_lines.next_line().await? {
            lines.push(buf_line);
        }
        let cache_data = HttpData::from_lines(&lines)?;
        if !cache_data.0.is_expired(604800i64) {
            debug!("No update for bootstrap from {}", file_name);
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
fn get_preferred_url(urls: &[String]) -> Option<String> {
    if urls.is_empty() {
        None
    } else {
        let url = urls
            .iter()
            .find(|s| s.starts_with("https://"))
            .unwrap_or_else(|| urls.first().unwrap());
        if !url.ends_with('/') {
            Some(format!("{url}/"))
        } else {
            Some(url.to_owned())
        }
    }
}

trait BootstrapPrefix {
    fn prefix(&self) -> &str;
}

impl BootstrapPrefix for IanaRegistryType {
    fn prefix(&self) -> &str {
        match self {
            Self::RdapBootstrapDns => "bootstrap_dns",
            Self::RdapBootstrapAsn => "bootstrap_asn",
            Self::RdapBootstrapIpv4 => "bootstrap_ipv4",
            Self::RdapBootstrapIpv6 => "bootstrap_ipv6",
            Self::RdapObjectTags => "bootstrap_objtag",
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
            CommonConfig, StoreOps,
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
        let RdapResponse::ErrorResponse(error) = response else {
            panic!("not an error response")
        };
        assert_eq!(307, error.error_code);
        assert_eq!(
            get_redirect_link(error),
            "https://registry.example.com/myrdap/"
        );
        // net
        let response = mem.get_domain_by_ldh("net").await.expect("lookup of net");
        let RdapResponse::ErrorResponse(error) = response else {
            panic!("not an error response")
        };
        assert_eq!(307, error.error_code);
        assert_eq!(
            get_redirect_link(error),
            "https://registry.example.com/myrdap/"
        );
        // org
        let response = mem.get_domain_by_ldh("org").await.expect("lookup of org");
        let RdapResponse::ErrorResponse(error) = response else {
            panic!("not an error response")
        };
        assert_eq!(307, error.error_code);
        assert_eq!(get_redirect_link(error), "https://example.org/");
        // mytld
        let response = mem
            .get_domain_by_ldh("mytld")
            .await
            .expect("lookup of mytld");
        let RdapResponse::ErrorResponse(error) = response else {
            panic!("not an error response")
        };
        assert_eq!(307, error.error_code);
        assert_eq!(get_redirect_link(error), "https://example.org/");
    }

    #[tokio::test]
    async fn GIVEN_asn_bootstrap_WHEN_make_asn_bootstrap_THEN_redirects_loaded() {
        // GIVEN
        let bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "RDAP Bootstrap file for example registries.",
                "services": [
                  [
                    ["64496-64496"],
                    [
                      "https://rir3.example.com/myrdap/"
                    ]
                  ],
                  [
                    ["64497-64510", "65536-65551"],
                    [
                      "https://example.org/"
                    ]
                  ],
                  [
                    ["64512-65534"],
                    [
                      "http://example.net/rdaprir2/",
                      "https://example.net/rdaprir2/"
                    ]
                  ]
                ]
            }
        "#;
        let iana =
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse ASN bootstrap");

        // WHEN
        let temp = TestDir::temp();
        let config = ServiceConfig::non_server()
            .data_dir(temp.root().to_string_lossy().to_string())
            .build()
            .expect("error making service config");
        make_asn_bootstrap(&config, iana)
            .await
            .expect("unable to make ASN bootstrap");

        // THEN
        let mem = new_and_init_mem(config.data_dir).await;
        // 64496-64496
        let response = mem.get_autnum_by_num(64496).await.expect("lookup of 64497");
        let RdapResponse::ErrorResponse(error) = response else {
            panic!("not an error response")
        };
        assert_eq!(307, error.error_code);
        assert_eq!(get_redirect_link(error), "https://rir3.example.com/myrdap/");
        // 64512-65534
        let response = mem.get_autnum_by_num(64512).await.expect("lookup of 64512");
        let RdapResponse::ErrorResponse(error) = response else {
            panic!("not an error response")
        };
        assert_eq!(307, error.error_code);
        assert_eq!(get_redirect_link(error), "https://example.net/rdaprir2/");
        // 64497-64510
        let response = mem.get_autnum_by_num(64510).await.expect("lookup of 64510");
        let RdapResponse::ErrorResponse(error) = response else {
            panic!("not an error response")
        };
        assert_eq!(307, error.error_code);
        assert_eq!(get_redirect_link(error), "https://example.org/");
        // 65536-65551
        let response = mem.get_autnum_by_num(65551).await.expect("lookup of 65551");
        let RdapResponse::ErrorResponse(error) = response else {
            panic!("not an error response")
        };
        assert_eq!(307, error.error_code);
        assert_eq!(get_redirect_link(error), "https://example.org/");
    }

    #[tokio::test]
    async fn GIVEN_ipv4_bootstrap_WHEN_make_asn_bootstrap_THEN_redirects_loaded() {
        // GIVEN
        let bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "RDAP Bootstrap file for example registries.",
                "services": [
                  [
                    ["198.51.100.0/24", "192.0.0.0/8"],
                    [
                      "https://rir1.example.com/myrdap/"
                    ]
                  ],
                  [
                    ["203.0.113.0/24", "192.0.2.0/24"],
                    [
                      "https://example.org/"
                    ]
                  ],
                  [
                    ["203.0.113.0/28"],
                    [
                      "https://example.net/rdaprir2/",
                      "http://example.net/rdaprir2/"
                    ]
                  ]
                ]
            }
        "#;
        let iana =
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse ipv4 bootstrap");

        // WHEN
        let temp = TestDir::temp();
        let config = ServiceConfig::non_server()
            .data_dir(temp.root().to_string_lossy().to_string())
            .build()
            .expect("error making service config");
        make_ip_bootstrap(&config, iana, IanaRegistryType::RdapBootstrapIpv4)
            .await
            .expect("unable to make IPv4 bootstrap");

        // THEN
        let mem = new_and_init_mem(config.data_dir).await;
        // 198.51.100.0/24
        let response = mem
            .get_network_by_ipaddr("198.51.100.0")
            .await
            .expect("lookup of 198.51.100.0");
        let RdapResponse::ErrorResponse(error) = response else {
            panic!("not an error response")
        };
        assert_eq!(307, error.error_code);
        assert_eq!(get_redirect_link(error), "https://rir1.example.com/myrdap/");
        // 192.0.0.0/8
        let response = mem
            .get_network_by_cidr("192.0.0.0/8")
            .await
            .expect("lookup of 192.0.0.0/8");
        let RdapResponse::ErrorResponse(error) = response else {
            panic!("not an error response")
        };
        assert_eq!(307, error.error_code);
        assert_eq!(get_redirect_link(error), "https://rir1.example.com/myrdap/");
        // 203.0.113.0/24
        let response = mem
            .get_network_by_cidr("203.0.113.0/24")
            .await
            .expect("lookup of 203.0.113.0/24");
        let RdapResponse::ErrorResponse(error) = response else {
            panic!("not an error response")
        };
        assert_eq!(307, error.error_code);
        assert_eq!(get_redirect_link(error), "https://example.org/");
    }

    async fn new_and_init_mem(data_dir: String) -> Mem {
        let mem_config = MemConfig::builder()
            .common_config(CommonConfig::default())
            .build();
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
        let Some(notices) = error.common.notices else {
            panic!("no notices in error")
        };
        let Some(first_notice) = notices.first() else {
            panic!("notices are empty")
        };
        let Some(links) = &first_notice.links else {
            panic!("no links in notice")
        };
        let Some(first_link) = links.first() else {
            panic!("links are empty")
        };
        let Some(href) = &first_link.href else {
            panic!("link has no href")
        };
        href.clone()
    }

    #[tokio::test]
    async fn GIVEN_tag_bootstrap_WHEN_make_tag_registry_THEN_redirects_loaded() {
        // GIVEN
        let bootstrap = r#"
            {
              "description": "RDAP bootstrap file for service provider object tags",
              "publication": "2023-07-05T22:00:02Z",
              "services": [
                [
                  [
                    "info@arin.net"
                  ],
                  [
                    "ARIN"
                  ],
                  [
                    "https://rdap.arin.net/registry/",
                    "http://rdap.arin.net/registry/"
                  ]
                ],
                [
                  [
                    "carlos@lacnic.net"
                  ],
                  [
                    "LACNIC"
                  ],
                  [
                    "https://rdap.lacnic.net/rdap/"
                  ]
                ],
                [
                  [
                    "bje@apnic.net"
                  ],
                  [
                    "APNIC"
                  ],
                  [
                    "https://rdap.apnic.net/"
                  ]
                ],
                [
                  [
                    "kranjbar@ripe.net"
                  ],
                  [
                    "RIPE"
                  ],
                  [
                    "https://rdap.db.ripe.net/"
                  ]
                ],
                [
                  [
                    "tld-tech@nic.fr"
                  ],
                  [
                    "FRNIC"
                  ],
                  [
                    "https://rdap.nic.fr/"
                  ]
                ],
                [
                  [
                    "hello@glauca.digital"
                  ],
                  [
                    "GLAUCA"
                  ],
                  [
                    "https://whois-web.as207960.net/rdap/"
                  ]
                ]
              ],
              "version": "1.0"
            }
        "#;
        let iana =
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse tag bootstrap");

        // WHEN
        let temp = TestDir::temp();
        let config = ServiceConfig::non_server()
            .data_dir(temp.root().to_string_lossy().to_string())
            .build()
            .expect("error making service config");
        make_tag_registry(&config, iana)
            .await
            .expect("unable to make DNS bootstrap");

        // THEN
        let mem = new_and_init_mem(config.data_dir).await;
        // arin
        let response = mem
            .get_entity_by_handle("-ARIN")
            .await
            .expect("lookup of -ARIN");
        let RdapResponse::ErrorResponse(error) = response else {
            panic!("not an error response")
        };
        assert_eq!(307, error.error_code);
        assert_eq!(get_redirect_link(error), "https://rdap.arin.net/registry/",);
        // GLAUCA
        let response = mem
            .get_entity_by_handle("-GLAUCA")
            .await
            .expect("lookup of -GLAUCA");
        let RdapResponse::ErrorResponse(error) = response else {
            panic!("not an error response")
        };
        assert_eq!(307, error.error_code);
        assert_eq!(
            get_redirect_link(error),
            "https://whois-web.as207960.net/rdap/"
        );
    }
}
