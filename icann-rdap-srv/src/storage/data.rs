use std::{
    net::IpAddr,
    path::PathBuf,
    time::{Duration, SystemTime},
};

use buildstructor::Builder;
use icann_rdap_common::response::{
    autnum::Autnum,
    domain::Domain,
    entity::Entity,
    nameserver::Nameserver,
    network::{Cidr0Cidr, Network, V4Cidr, V6Cidr},
    GetSelfLink, RdapResponse, SelfLink,
};
use ipnet::{IpNet, Ipv4Subnets, Ipv6Subnets};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum_macros::Display;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::{
    config::ServiceConfig,
    error::RdapServerError,
    storage::{StoreOps, TxHandle},
};

pub const UPDATE: &str = "update";
pub const RELOAD: &str = "reload";

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Display)]
#[serde(untagged)]
pub enum Template {
    Domain {
        domain: DomainOrError,
        ids: Vec<DomainId>,
    },
    Entity {
        entity: EntityOrError,
        ids: Vec<EntityId>,
    },
    Nameserver {
        nameserver: NameserverOrError,
        ids: Vec<NameserverId>,
    },
    Autnum {
        autnum: AutnumOrError,
        ids: Vec<AutnumId>,
    },
    Network {
        network: NetworkOrError,
        ids: Vec<NetworkId>,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum DomainOrError {
    #[serde(rename = "object")]
    DomainObject(Domain),
    #[serde(rename = "error")]
    ErrorResponse(icann_rdap_common::response::error::Error),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum EntityOrError {
    #[serde(rename = "object")]
    EntityObject(Entity),
    #[serde(rename = "error")]
    ErrorResponse(icann_rdap_common::response::error::Error),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum NameserverOrError {
    #[serde(rename = "object")]
    NameserverObject(Nameserver),
    #[serde(rename = "error")]
    ErrorResponse(icann_rdap_common::response::error::Error),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum AutnumOrError {
    #[serde(rename = "object")]
    AutnumObject(Autnum),
    #[serde(rename = "error")]
    ErrorResponse(icann_rdap_common::response::error::Error),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum NetworkOrError {
    #[serde(rename = "object")]
    NetworkObject(Network),
    #[serde(rename = "error")]
    ErrorResponse(icann_rdap_common::response::error::Error),
}

#[derive(Clone, Serialize, Deserialize, Builder, Debug, PartialEq, Eq)]
pub struct DomainId {
    #[serde(rename = "ldhName")]
    pub ldh_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "unicodeName")]
    pub unicode_name: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Builder, Debug, PartialEq, Eq)]
pub struct EntityId {
    pub handle: String,
}

#[derive(Clone, Serialize, Deserialize, Builder, Debug, PartialEq, Eq)]
pub struct NameserverId {
    #[serde(rename = "ldhName")]
    pub ldh_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "unicodeName")]
    pub unicode_name: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Builder, Debug, PartialEq, Eq)]
pub struct AutnumId {
    #[serde(rename = "startAutnum")]
    pub start_autnum: u32,
    #[serde(rename = "endAutnum")]
    pub end_autnum: u32,
}

#[derive(Clone, Serialize, Deserialize, Builder, Debug, PartialEq, Eq)]
pub struct NetworkId {
    #[serde(rename = "networkId")]
    pub network_id: NetworkIdType,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum NetworkIdType {
    Cidr(IpNet),
    Range {
        #[serde(rename = "startAddress")]
        start_address: String,
        #[serde(rename = "endAddress")]
        end_address: String,
    },
}

/// Loads files from the data directory into memory.
///
/// There are 2 types of files that will be selected. Files ending with a `.json` extension
/// are considered to be JSON files holding one RDAP response each.
///
/// Files ending with a `.template` extension are a means to quickly create RDAP objects using
/// a template. Templates follow a pattern of a set of IDs paired with an RDAP object:
///
/// ```json
/// {
///   "domain":
///     {
///       "object":
///         {
///           "objectClassName":"domain",
///           "ldhName":"example"
///         }
///     },
///   "ids":
///     [
///       {"ldhName":"bar.example"},
///       {"ldhName":"foo.example"}
///     ]
/// }
/// ```
/// In this example, 2 domains will be created for "foo.example" and "bar.exaple" using
/// the template.
pub async fn load_data(
    config: &ServiceConfig,
    store: &dyn StoreOps,
    truncate: bool,
) -> Result<(), RdapServerError> {
    let mut json_count: usize = 0;
    let mut template_count: usize = 0;
    let mut srvhelp_count: usize = 0;
    let mut tx = if truncate {
        store.new_truncate_tx().await?
    } else {
        store.new_tx().await?
    };
    let path = PathBuf::from(&config.data_dir);
    if !path.exists() || !path.is_dir() {
        warn!(
            "Directory {} does not exist or is not a directory. Server has no content to serve.",
            path.to_string_lossy()
        );
        return Ok(());
    }

    let mut entries = tokio::fs::read_dir(path).await?;
    while let Some(entry) = entries.next_entry().await? {
        let entry_path = entry.path();
        let contents = tokio::fs::read_to_string(&entry_path).await?;
        if entry_path
            .extension()
            .map_or(false, |ext| ext == "template")
        {
            load_rdap_template(&contents, &entry_path.to_string_lossy(), &mut tx).await?;
            template_count += 1;
        } else if entry_path.extension().map_or(false, |ext| ext == "json") {
            load_rdap(&contents, &entry_path.to_string_lossy(), &mut tx).await?;
            json_count += 1;
        } else if entry_path.extension().map_or(false, |ext| ext == "help") {
            load_srvhelp(
                &contents,
                &entry_path.to_string_lossy(),
                &entry.file_name().to_string_lossy(),
                &mut tx,
            )
            .await?;
            srvhelp_count += 1;
        }
    }

    info!("{json_count} RDAP JSON files loaded.");
    info!("{template_count} RDAP template files loaded.");
    info!("{srvhelp_count} RDAP server help files loaded.");
    if json_count == 0 && template_count == 0 && srvhelp_count == 0 {
        warn!("No data loaded. Server has no content to serve.");
    }
    tx.commit().await?;
    Ok(())
}

/// Loads the RDAP JSON files and puts them in storage.
async fn load_rdap(
    contents: &str,
    path_name: &str,
    tx: &mut Box<dyn TxHandle>,
) -> Result<(), RdapServerError> {
    debug!("loading {path_name} into storage");
    let json = serde_json::from_str::<Value>(contents);
    if let Ok(value) = json {
        let rdap = RdapResponse::try_from(value);
        if let Ok(rdap) = rdap {
            match rdap {
                RdapResponse::Entity(entity) => tx.add_entity(&entity).await,
                RdapResponse::Domain(domain) => tx.add_domain(&domain).await,
                RdapResponse::Nameserver(nameserver) => tx.add_nameserver(&nameserver).await,
                RdapResponse::Autnum(autnum) => tx.add_autnum(&autnum).await,
                RdapResponse::Network(network) => tx.add_network(&network).await,
                _ => return Err(RdapServerError::NonRdapJsonFile(path_name.to_owned())),
            }?;
        } else {
            return Err(RdapServerError::NonRdapJsonFile(path_name.to_owned()));
        }
    } else {
        return Err(RdapServerError::NonJsonFile(path_name.to_owned()));
    }
    Ok(())
}

/// Loads the RDAP HELP files and puts them in storage.
async fn load_srvhelp(
    contents: &str,
    path_name: &str,
    file_name: &str,
    tx: &mut Box<dyn TxHandle>,
) -> Result<(), RdapServerError> {
    debug!("loading {path_name} into storage");
    let Some(host) = file_name.strip_suffix(".help") else {
        return Err(RdapServerError::NonRdapJsonFile(path_name.to_string()));
    };
    let host = host.replace('_', ".");
    let json = serde_json::from_str::<Value>(contents);
    if let Ok(value) = json {
        let rdap = RdapResponse::try_from(value);
        if let Ok(rdap) = rdap {
            match rdap {
                RdapResponse::Help(srvhelp) => tx.add_srv_help(&srvhelp, Some(&host)).await,
                _ => return Err(RdapServerError::NonRdapJsonFile(path_name.to_owned())),
            }?;
        } else {
            return Err(RdapServerError::NonRdapJsonFile(path_name.to_owned()));
        }
    } else {
        return Err(RdapServerError::NonJsonFile(path_name.to_owned()));
    }
    Ok(())
}

/// Loads the template files, creates RDAP objects from the templates, and puts them
/// into storage.
async fn load_rdap_template(
    contents: &str,
    path_name: &str,
    tx: &mut Box<dyn TxHandle>,
) -> Result<(), RdapServerError> {
    debug!("processing {path_name} template");
    let json = serde_json::from_str::<Template>(contents);
    if let Ok(value) = json {
        match value {
            Template::Domain { domain, ids } => {
                for id in ids {
                    debug!("adding domain from template for {id:?}");
                    match &domain {
                        DomainOrError::DomainObject(domain) => {
                            let domain = make_domain_from_template(domain, id);
                            tx.add_domain(&domain).await?;
                        }
                        DomainOrError::ErrorResponse(error) => {
                            tx.add_domain_err(&id, error).await?;
                        }
                    };
                }
            }
            Template::Entity { entity, ids } => {
                for id in ids {
                    debug!("adding entity from template for {id:?}");
                    match &entity {
                        EntityOrError::EntityObject(entity) => {
                            let entity = make_entity_from_template(entity, id);
                            tx.add_entity(&entity).await?;
                        }
                        EntityOrError::ErrorResponse(error) => {
                            tx.add_entity_err(&id, error).await?;
                        }
                    };
                }
            }
            Template::Nameserver { nameserver, ids } => {
                for id in ids {
                    debug!("adding nameserver from template for {id:?}");
                    match &nameserver {
                        NameserverOrError::NameserverObject(nameserver) => {
                            let nameserver = make_nameserver_from_template(nameserver, id);
                            tx.add_nameserver(&nameserver).await?;
                        }
                        NameserverOrError::ErrorResponse(error) => {
                            tx.add_nameserver_err(&id, error).await?;
                        }
                    };
                }
            }
            Template::Autnum { autnum, ids } => {
                for id in ids {
                    debug!("adding autnum from template for {id:?}");
                    match &autnum {
                        AutnumOrError::AutnumObject(autnum) => {
                            let autnum = make_autnum_from_template(autnum, id);
                            tx.add_autnum(&autnum).await?;
                        }
                        AutnumOrError::ErrorResponse(error) => {
                            tx.add_autnum_err(&id, error).await?;
                        }
                    };
                }
            }
            Template::Network { network, ids } => {
                for id in ids {
                    debug!("adding network from template for {id:?}");
                    match &network {
                        NetworkOrError::NetworkObject(network) => {
                            let network = make_network_from_template(network, id)?;
                            tx.add_network(&network).await?;
                        }
                        NetworkOrError::ErrorResponse(error) => {
                            tx.add_network_err(&id, error).await?;
                        }
                    };
                }
            }
        };
    } else {
        return Err(RdapServerError::NonJsonFile(path_name.to_owned()));
    }
    Ok(())
}

pub(crate) async fn reload_data(
    store: Box<dyn StoreOps>,
    config: ServiceConfig,
) -> Result<(), RdapServerError> {
    let update_path = PathBuf::from(&config.data_dir);
    let update_path = update_path.join(UPDATE);
    let reload_path = PathBuf::from(&config.data_dir);
    let reload_path = reload_path.join(RELOAD);
    let mut last_time = SystemTime::now();
    loop {
        sleep(Duration::from_millis(1000)).await;
        let update_meta = tokio::fs::metadata(&update_path).await;
        if update_meta.is_ok() {
            let modified = update_meta.unwrap().modified()?;
            if modified > last_time {
                last_time = modified;
                info!("Data being updated.");
                load_data(&config, &*store, false).await?;
            }
        };
        let reload_meta = tokio::fs::metadata(&reload_path).await;
        if reload_meta.is_ok() {
            let modified = reload_meta.unwrap().modified()?;
            if modified > last_time {
                last_time = modified;
                info!("Data being reloaded.");
                load_data(&config, &*store, true).await?;
            }
        };
    }
}

pub async fn trigger_reload(data_dir: &str) -> Result<(), RdapServerError> {
    let reload_path = PathBuf::from(&data_dir);
    let reload_path = reload_path.join(RELOAD);
    tokio::fs::File::create(reload_path).await?;
    Ok(())
}

pub async fn trigger_update(data_dir: &str) -> Result<(), RdapServerError> {
    let update_path = PathBuf::from(&data_dir);
    let update_path = update_path.join(UPDATE);
    tokio::fs::File::create(update_path).await?;
    Ok(())
}

fn change_self_link<T: GetSelfLink + SelfLink>(mut object: T, segment: &str, id: &str) -> T {
    if let Some(self_link) = object.get_self_link() {
        if let Some(self_href) = self_link.href.rsplit_once(segment) {
            let mut new_self_link = self_link.clone();
            new_self_link.href = format!("{}{segment}/{}", self_href.0, id);
            object = object.set_self_link(new_self_link);
        } else {
            warn!("Unable to rewrite self link for {segment} {}", id);
        }
    } else {
        warn!("No self link for {segment} {}", id);
    }
    object
}

fn make_domain_from_template(domain: &Domain, id: DomainId) -> Domain {
    let mut domain = domain.clone();
    domain = change_self_link(domain, "domain", &id.ldh_name);
    domain.ldh_name = Some(id.ldh_name);
    if let Some(unicode_name) = id.unicode_name {
        domain.unicode_name = Some(unicode_name);
    };
    domain
}

fn make_entity_from_template(entity: &Entity, id: EntityId) -> Entity {
    let mut entity = entity.clone();
    entity = change_self_link(entity, "entity", &id.handle);
    entity.object_common.handle = Some(id.handle);
    entity
}

fn make_nameserver_from_template(nameserver: &Nameserver, id: NameserverId) -> Nameserver {
    let mut nameserver = nameserver.clone();
    nameserver = change_self_link(nameserver, "nameserver", &id.ldh_name);
    nameserver.ldh_name = Some(id.ldh_name);
    if let Some(unicode_name) = id.unicode_name {
        nameserver.unicode_name = Some(unicode_name);
    };
    nameserver
}

fn make_autnum_from_template(autnum: &Autnum, id: AutnumId) -> Autnum {
    let mut autnum = autnum.clone();
    autnum = change_self_link(autnum, "autnum", &id.start_autnum.to_string());
    autnum.start_autnum = Some(id.start_autnum);
    autnum.end_autnum = Some(id.end_autnum);
    autnum
}

fn make_network_from_template(
    network: &Network,
    id: NetworkId,
) -> Result<Network, RdapServerError> {
    let mut network = network.clone();
    match id.network_id {
        NetworkIdType::Cidr(cidr) => match cidr {
            IpNet::V4(v4) => {
                network.start_address = Some(v4.network().to_string());
                network.end_address = Some(v4.broadcast().to_string());
                network.ip_version = Some("v4".to_string());
                network.cidr0_cidrs = Some(vec![Cidr0Cidr::V4Cidr(V4Cidr {
                    v4prefix: v4.network().to_string(),
                    length: v4.prefix_len(),
                })]);
            }
            IpNet::V6(v6) => {
                network.start_address = Some(v6.network().to_string());
                network.end_address = Some(v6.broadcast().to_string());
                network.ip_version = Some("v6".to_string());
                network.cidr0_cidrs = Some(vec![Cidr0Cidr::V6Cidr(V6Cidr {
                    v6prefix: v6.network().to_string(),
                    length: v6.prefix_len(),
                })]);
            }
        },
        NetworkIdType::Range {
            start_address,
            end_address,
        } => {
            let addr: IpAddr = start_address.parse()?;
            if addr.is_ipv4() {
                network.ip_version = Some("v4".to_string());
                network.cidr0_cidrs = Some(
                    Ipv4Subnets::new(start_address.parse()?, end_address.parse()?, 0)
                        .map(|net| {
                            Cidr0Cidr::V4Cidr(V4Cidr {
                                v4prefix: net.network().to_string(),
                                length: net.prefix_len(),
                            })
                        })
                        .collect::<Vec<Cidr0Cidr>>(),
                );
            } else {
                network.ip_version = Some("v6".to_string());
                network.cidr0_cidrs = Some(
                    Ipv6Subnets::new(start_address.parse()?, end_address.parse()?, 0)
                        .map(|net| {
                            Cidr0Cidr::V6Cidr(V6Cidr {
                                v6prefix: net.network().to_string(),
                                length: net.prefix_len(),
                            })
                        })
                        .collect::<Vec<Cidr0Cidr>>(),
                );
            }
            network.start_address = Some(start_address);
            network.end_address = Some(end_address);
        }
    }
    let first_cidr = network
        .cidr0_cidrs
        .as_ref()
        .expect("cidrs should be on network")
        .first()
        .map(|cidr| match cidr {
            Cidr0Cidr::V4Cidr(cidr) => {
                format!("{}/{}", cidr.v4prefix, cidr.length)
            }
            Cidr0Cidr::V6Cidr(cidr) => {
                format!("{}/{}", cidr.v6prefix, cidr.length)
            }
        })
        .expect("cidrs on network are empty");
    network = change_self_link(network, "ip", &first_cidr);
    Ok(network)
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {

    use icann_rdap_common::response::{domain::Domain, types::Link};

    use super::*;

    #[test]
    fn GIVEN_template_domain_WHEN_serialize_THEN_success() {
        // GIVEN
        let template = Template::Domain {
            domain: DomainOrError::DomainObject(Domain::basic().ldh_name("foo.example").build()),
            ids: vec![DomainId::builder().ldh_name("bar.example").build()],
        };

        // WHEN
        let actual = serde_json::to_string(&template).expect("serializing template");

        // THEN
        assert_eq!(
            actual,
            r#"{"domain":{"object":{"objectClassName":"domain","ldhName":"foo.example"}},"ids":[{"ldhName":"bar.example"}]}"#
        );
    }

    #[test]
    fn GIVEN_template_domain_text_WHEN_deserialize_THEN_success() {
        // GIVEN
        let json_text = r#"{"domain":{"object":{"objectClassName":"domain","ldhName":"foo.example"}},"ids":[{"ldhName":"bar.example"}]}"#;

        // WHEN
        let actual: Template = serde_json::from_str(json_text).expect("deserializing template");

        // THEN
        let expected = Template::Domain {
            domain: DomainOrError::DomainObject(Domain::basic().ldh_name("foo.example").build()),
            ids: vec![DomainId::builder().ldh_name("bar.example").build()],
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn GIVEN_template_network_with_cidr_WHEN_serialize_THEN_success() {
        // GIVEN
        let template = Template::Network {
            network: NetworkOrError::NetworkObject(
                Network::basic()
                    .cidr("10.0.0.0/24")
                    .build()
                    .expect("cidr parsing"),
            ),
            ids: vec![NetworkId::builder()
                .network_id(NetworkIdType::Cidr(
                    "10.0.0.0/24".parse().expect("ipnet parsing"),
                ))
                .build()],
        };

        // WHEN
        let actual = serde_json::to_string(&template).expect("serializing template");
        let actual: Template = serde_json::from_str(&actual).expect("deserialize network template");

        // THEN
        let expected = r#"
        {
            "network":{
                "object":{
                    "rdapConformance":["cidr0","rdap_level_0"],
                    "objectClassName":"ip network",
                    "startAddress":"10.0.0.0",
                    "endAddress":"10.0.0.255",
                    "ipVersion":"v4",
                    "cidr0_cidrs":[{"v4prefix":"10.0.0.0","length":24}]
                }
            },
            "ids":[
                {"networkId":"10.0.0.0/24"}
            ]
        }"#;
        let expected: Template = serde_json::from_str(expected).expect("deserialize expected");
        assert_eq!(actual, expected);
    }

    #[test]
    fn GIVEN_template_network_with_start_and_end_WHEN_serialize_THEN_success() {
        // GIVEN
        let template = Template::Network {
            network: NetworkOrError::NetworkObject(
                Network::basic()
                    .cidr("10.0.0.0/24")
                    .build()
                    .expect("cidr parsing"),
            ),
            ids: vec![NetworkId::builder()
                .network_id(NetworkIdType::Range {
                    start_address: "10.0.0.0".to_string(),
                    end_address: "10.0.0.255".to_string(),
                })
                .build()],
        };

        // WHEN
        let actual = serde_json::to_string(&template).expect("serializing template");
        let actual: Template = serde_json::from_str(&actual).expect("deserialize network template");

        // THEN
        let expected = r#"
        {
            "network":{
                "object":{
                    "rdapConformance":["cidr0","rdap_level_0"],
                    "objectClassName":"ip network",
                    "startAddress":"10.0.0.0",
                    "endAddress":"10.0.0.255",
                    "ipVersion":"v4",
                    "cidr0_cidrs":[
                        {"v4prefix":"10.0.0.0","length":24}
                    ]
                }
            },
            "ids":[
                {"networkId":
                    {"startAddress":"10.0.0.0","endAddress":"10.0.0.255"}
                }
            ]
        }"#;
        let expected: Template = serde_json::from_str(expected).expect("deserialize expected");
        assert_eq!(actual, expected);
    }

    #[test]
    fn GIVEN_template_network_with_cidr_text_WHEN_deserialize_THEN_success() {
        // GIVEN
        let text = r#"
        {
            "network":{
                "object":{
                    "rdapConformance":["cidr0","rdap_level_0"],
                    "objectClassName":"ip network",
                    "startAddress":"10.0.0.0",
                    "endAddress":"10.0.0.255",
                    "ipVersion":"v4",
                    "cidr0_cidrs":[{"v4prefix":"10.0.0.0","length":24}]
                }
            },
            "ids":[
                {"networkId":"10.0.0.0/24"}
            ]
        }"#;

        // WHEN
        let actual: Template = serde_json::from_str(text).expect("deserialize network template");

        // THEN
        let expected = Template::Network {
            network: NetworkOrError::NetworkObject(
                Network::basic()
                    .cidr("10.0.0.0/24")
                    .build()
                    .expect("cidr parsing"),
            ),
            ids: vec![NetworkId::builder()
                .network_id(NetworkIdType::Cidr(
                    "10.0.0.0/24".parse().expect("ipnet parsing"),
                ))
                .build()],
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn GIVEN_template_network_with_range_text_WHEN_deserialize_THEN_success() {
        // GIVEN
        let text = r#"
        {
            "network":{
                "object":{
                    "rdapConformance":["cidr0","rdap_level_0"],
                    "objectClassName":"ip network",
                    "startAddress":"10.0.0.0",
                    "endAddress":"10.0.0.255",
                    "ipVersion":"v4",
                    "cidr0_cidrs":[
                        {"v4prefix":"10.0.0.0","length":24}
                    ]
                }
            },
            "ids":[
                {"networkId":
                    {"startAddress":"10.0.0.0","endAddress":"10.0.0.255"}
                }
            ]
        }"#;

        // WHEN
        let actual: Template = serde_json::from_str(text).expect("deserialize network template");

        // THEN
        let expected = Template::Network {
            network: NetworkOrError::NetworkObject(
                Network::basic()
                    .cidr("10.0.0.0/24")
                    .build()
                    .expect("cidr parsing"),
            ),
            ids: vec![NetworkId::builder()
                .network_id(NetworkIdType::Range {
                    start_address: "10.0.0.0".to_string(),
                    end_address: "10.0.0.255".to_string(),
                })
                .build()],
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn GIVEN_domain_and_id_WHEN_make_domain_THEN_ldh_and_self_change() {
        // GIVEN
        let domain = Domain::basic()
            .ldh_name("foo.example")
            .link(
                Link::builder()
                    .rel("self")
                    .href("http://reg.example/domain/foo.example")
                    .build(),
            )
            .build();
        let id = DomainId::builder().ldh_name("bar.example").build();

        // WHEN
        let actual = make_domain_from_template(&domain, id);

        // THEN
        assert_eq!(
            actual.ldh_name.as_ref().expect("no ldhname on domain"),
            "bar.example"
        );
        let self_link = actual.get_self_link().expect("self link messing");
        assert_eq!(self_link.href, "http://reg.example/domain/bar.example");
    }

    #[test]
    fn GIVEN_entity_and_id_WHEN_make_entity_THEN_handle_and_self_change() {
        // GIVEN
        let entity = Entity::basic()
            .handle("foo")
            .link(
                Link::builder()
                    .rel("self")
                    .href("http://reg.example/entity/foo")
                    .build(),
            )
            .build();
        let id = EntityId::builder().handle("bar").build();

        // WHEN
        let actual = make_entity_from_template(&entity, id);

        // THEN
        assert_eq!(
            actual
                .object_common
                .handle
                .as_ref()
                .expect("no handle on entity"),
            "bar"
        );
        let self_link = actual.get_self_link().expect("self link messing");
        assert_eq!(self_link.href, "http://reg.example/entity/bar");
    }

    #[test]
    fn GIVEN_nameserver_and_id_WHEN_make_nameserver_THEN_ldh_and_self_change() {
        // GIVEN
        let nameserver = Nameserver::basic()
            .ldh_name("ns.foo.example")
            .link(
                Link::builder()
                    .rel("self")
                    .href("http://reg.example/nameserver/ns.foo.example")
                    .build(),
            )
            .build()
            .expect("creation of nameserver");
        let id = NameserverId::builder().ldh_name("ns.bar.example").build();

        // WHEN
        let actual = make_nameserver_from_template(&nameserver, id);

        // THEN
        assert_eq!(
            actual.ldh_name.as_ref().expect("no ldhname on nameserver"),
            "ns.bar.example"
        );
        let self_link = actual.get_self_link().expect("self link messing");
        assert_eq!(
            self_link.href,
            "http://reg.example/nameserver/ns.bar.example"
        );
    }

    #[test]
    fn GIVEN_autnum_and_id_WHEN_make_autnum_THEN_nums_and_self_change() {
        // GIVEN
        let autnum = Autnum::basic()
            .autnum_range(700..710)
            .link(
                Link::builder()
                    .rel("self")
                    .href("http://reg.example/autnum/700")
                    .build(),
            )
            .build();
        let id = AutnumId::builder()
            .start_autnum(900)
            .end_autnum(999)
            .build();

        // WHEN
        let actual = make_autnum_from_template(&autnum, id);

        // THEN
        assert_eq!(
            *actual.start_autnum.as_ref().expect("no startnum on autnum"),
            900
        );
        assert_eq!(*actual.end_autnum.as_ref().expect("no end on autnum"), 999);
        let self_link = actual.get_self_link().expect("self link messing");
        assert_eq!(self_link.href, "http://reg.example/autnum/900");
    }

    #[test]
    fn GIVEN_network_and_id_with_range_WHEN_make_network_THEN_range_and_cidr_and_self_change() {
        // GIVEN
        let network = Network::basic()
            .cidr("10.0.0.0/24")
            .link(
                Link::builder()
                    .rel("self")
                    .href("http://reg.example/ip/10.0.0.0/24")
                    .build(),
            )
            .build()
            .expect("creating test network");
        let id = NetworkId::builder()
            .network_id(NetworkIdType::Range {
                start_address: "11.0.0.0".to_string(),
                end_address: "11.0.0.255".to_string(),
            })
            .build();

        // WHEN
        let actual = make_network_from_template(&network, id).expect("unable to make network");

        // THEN
        assert_eq!(
            actual
                .start_address
                .as_ref()
                .expect("no start address on network"),
            "11.0.0.0"
        );
        assert_eq!(
            actual
                .end_address
                .as_ref()
                .expect("no end address on network"),
            "11.0.0.255"
        );
        let cidr0 = actual.cidr0_cidrs.as_ref().expect("no cidr0");
        let Cidr0Cidr::V4Cidr(v4cidr) = cidr0.first().expect("cidr0 is empty") else {
            panic!("no v4 cidr")
        };
        assert_eq!(v4cidr.v4prefix, "11.0.0.0");
        assert_eq!(v4cidr.length, 24);
        let self_link = actual.get_self_link().expect("self link messing");
        assert_eq!(self_link.href, "http://reg.example/ip/11.0.0.0/24");
    }

    #[test]
    fn GIVEN_network_and_id_with_cdir_WHEN_make_network_THEN_range_and_cidr_and_self_change() {
        // GIVEN
        let network = Network::basic()
            .cidr("10.0.0.0/24")
            .link(
                Link::builder()
                    .rel("self")
                    .href("http://reg.example/ip/10.0.0.0/24")
                    .build(),
            )
            .build()
            .expect("creating test network");
        let id = NetworkId::builder()
            .network_id(NetworkIdType::Cidr(IpNet::V4(
                "11.0.0.0/24".parse().expect("bad cidr"),
            )))
            .build();

        // WHEN
        let actual = make_network_from_template(&network, id).expect("unable to make network");

        // THEN
        assert_eq!(
            actual
                .start_address
                .as_ref()
                .expect("no start address on network"),
            "11.0.0.0"
        );
        assert_eq!(
            actual
                .end_address
                .as_ref()
                .expect("no end address on network"),
            "11.0.0.255"
        );
        let cidr0 = actual.cidr0_cidrs.as_ref().expect("no cidr0");
        let Cidr0Cidr::V4Cidr(v4cidr) = cidr0.first().expect("cidr0 is empty") else {
            panic!("no v4 cidr")
        };
        assert_eq!(v4cidr.v4prefix, "11.0.0.0");
        assert_eq!(v4cidr.length, 24);
        let self_link = actual.get_self_link().expect("self link messing");
        assert_eq!(self_link.href, "http://reg.example/ip/11.0.0.0/24");
    }
}
