use std::{
    net::IpAddr,
    path::PathBuf,
    time::{Duration, SystemTime},
};

use buildstructor::Builder;
use icann_rdap_common::response::{
    autnum::Autnum, domain::Domain, entity::Entity, nameserver::Nameserver, network::Network,
    RdapResponse,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::{
    error::RdapServerError,
    storage::{StoreOps, TxHandle},
};

use super::ops::Mem;

pub const UPDATE: &str = "update";
pub const RELOAD: &str = "reload";

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum Template {
    Domain {
        domain: Domain,
        ids: Vec<DomainId>,
    },
    Entity {
        entity: Entity,
        ids: Vec<EntityId>,
    },
    Nameserver {
        nameserver: Nameserver,
        ids: Vec<NameserverId>,
    },
    Autnum {
        autnum: Autnum,
        ids: Vec<AutnumId>,
    },
    Network {
        network: Network,
        ids: Vec<NetworkId>,
    },
}

#[derive(Serialize, Deserialize, Builder, Debug, PartialEq, Eq)]
pub struct DomainId {
    #[serde(rename = "ldhName")]
    pub ldh_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "unicodeName")]
    pub unicode_name: Option<String>,
}

#[derive(Serialize, Deserialize, Builder, Debug, PartialEq, Eq)]
pub struct EntityId {
    pub handle: String,
}

#[derive(Serialize, Deserialize, Builder, Debug, PartialEq, Eq)]
pub struct NameserverId {
    #[serde(rename = "ldhName")]
    pub ldh_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "unicodeName")]
    pub unicode_name: Option<String>,
}

#[derive(Serialize, Deserialize, Builder, Debug, PartialEq, Eq)]
pub struct AutnumId {
    #[serde(rename = "startAutnum")]
    pub start_autnum: u32,
    #[serde(rename = "endAutnum")]
    pub end_autnum: u32,
}

#[derive(Serialize, Deserialize, Builder, Debug, PartialEq, Eq)]
pub struct NetworkId {
    #[serde(rename = "networkId")]
    pub network_id: NetworkIdType,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
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

/// Loads files from the state directory into memory.
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
///       "objectClassName":"domain",
///       "ldhName":"example"
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
pub(crate) async fn load_state(mem: &Mem, truncate: bool) -> Result<(), RdapServerError> {
    let mut json_count: usize = 0;
    let mut template_count: usize = 0;
    let mut tx = if truncate {
        mem.new_truncate_tx().await?
    } else {
        mem.new_tx().await?
    };
    let path = PathBuf::from(&mem.config.state_dir);
    if !path.exists() || !path.is_dir() {
        warn!(
            "Directory {} does not exist or is not a directory. Server has no content to serve.",
            path.to_string_lossy()
        );
        return Ok(());
    }

    let mut entries = tokio::fs::read_dir(path).await?;
    while let Some(entry) = entries.next_entry().await? {
        let entry = entry.path();
        let contents = tokio::fs::read_to_string(&entry).await?;
        if entry.extension().map_or(false, |ext| ext == "template") {
            load_rdap_template(&contents, &entry.to_string_lossy(), &mut tx).await?;
            template_count += 1;
        } else if entry.extension().map_or(false, |ext| ext == "json") {
            load_rdap(&contents, &entry.to_string_lossy(), &mut tx).await?;
            json_count += 1;
        }
    }

    info!("{json_count} RDAP JSON files loaded. {template_count} RDAP template files loaded.");
    if json_count == 0 && template_count == 0 {
        warn!("No state loaded. Server has no content to serve.");
    }
    tx.commit().await?;
    Ok(())
}

/// Loads the RDAP JSON files and puts them in memory.
async fn load_rdap(
    contents: &str,
    path_name: &str,
    tx: &mut Box<dyn TxHandle>,
) -> Result<(), RdapServerError> {
    debug!("loading {path_name} into memory");
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

/// Loads the template files, creates RDAP objects from the templates, and puts them
/// into memory.
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
                    let mut domain = domain.clone();
                    domain.ldh_name = Some(id.ldh_name);
                    if let Some(unicode_name) = id.unicode_name {
                        domain.unicode_name = Some(unicode_name);
                    };
                    tx.add_domain(&domain).await?;
                }
            }
            Template::Entity { entity, ids } => {
                for id in ids {
                    debug!("adding entity from template for {id:?}");
                    let mut entity = entity.clone();
                    entity.object_common.handle = Some(id.handle);
                    tx.add_entity(&entity).await?;
                }
            }
            Template::Nameserver { nameserver, ids } => {
                for id in ids {
                    debug!("adding nameserver from template for {id:?}");
                    let mut nameserver = nameserver.clone();
                    nameserver.ldh_name = Some(id.ldh_name);
                    if let Some(unicode_name) = id.unicode_name {
                        nameserver.unicode_name = Some(unicode_name);
                    };
                    tx.add_nameserver(&nameserver).await?;
                }
            }
            Template::Autnum { autnum, ids } => {
                for id in ids {
                    debug!("adding autnum from template for {id:?}");
                    let mut autnum = autnum.clone();
                    autnum.start_autnum = Some(id.start_autnum);
                    autnum.end_autnum = Some(id.end_autnum);
                    tx.add_autnum(&autnum).await?;
                }
            }
            Template::Network { network, ids } => {
                for id in ids {
                    debug!("adding network from template for {id:?}");
                    let mut network = network.clone();
                    match id.network_id {
                        NetworkIdType::Cidr(cidr) => match cidr {
                            IpNet::V4(v4) => {
                                network.start_address = Some(v4.network().to_string());
                                network.end_address = Some(v4.broadcast().to_string());
                                network.ip_version = Some("v4".to_string());
                            }
                            IpNet::V6(v6) => {
                                network.start_address = Some(v6.network().to_string());
                                network.end_address = Some(v6.broadcast().to_string());
                                network.ip_version = Some("v6".to_string());
                            }
                        },
                        NetworkIdType::Range {
                            start_address,
                            end_address,
                        } => {
                            let addr: IpAddr = start_address.parse()?;
                            if addr.is_ipv4() {
                                network.ip_version = Some("v4".to_string());
                            } else {
                                network.ip_version = Some("v6".to_string());
                            }
                            network.start_address = Some(start_address);
                            network.end_address = Some(end_address);
                        }
                    }
                    tx.add_network(&network).await?;
                }
            }
        };
    } else {
        return Err(RdapServerError::NonJsonFile(path_name.to_owned()));
    }
    Ok(())
}

pub(crate) async fn reload_state(mem: Mem) -> Result<(), RdapServerError> {
    let update_path = PathBuf::from(&mem.config.state_dir);
    let update_path = update_path.join(UPDATE);
    let reload_path = PathBuf::from(&mem.config.state_dir);
    let reload_path = reload_path.join(RELOAD);
    let mut last_time = SystemTime::now();
    loop {
        sleep(Duration::from_millis(1000)).await;
        let update_meta = tokio::fs::metadata(&update_path).await;
        if update_meta.is_ok() {
            let modified = update_meta.unwrap().modified()?;
            if modified > last_time {
                last_time = modified;
                info!("State being updated.");
                load_state(&mem, false).await?;
            }
        };
        let reload_meta = tokio::fs::metadata(&reload_path).await;
        if reload_meta.is_ok() {
            let modified = reload_meta.unwrap().modified()?;
            if modified > last_time {
                last_time = modified;
                info!("State being reloaded.");
                load_state(&mem, true).await?;
            }
        };
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use cidr_utils::cidr::IpCidr;
    use icann_rdap_common::response::domain::Domain;

    use super::*;

    #[test]
    fn GIVEN_template_domain_WHEN_serialize_THEN_success() {
        // GIVEN
        let template = Template::Domain {
            domain: Domain::basic().ldh_name("foo.example").build(),
            ids: vec![DomainId::builder().ldh_name("bar.example").build()],
        };

        // WHEN
        let actual = serde_json::to_string(&template).expect("serializing template");

        // THEN
        assert_eq!(
            actual,
            r#"{"domain":{"objectClassName":"domain","ldhName":"foo.example"},"ids":[{"ldhName":"bar.example"}]}"#
        );
    }

    #[test]
    fn GIVEN_template_domain_text_WHEN_deserialize_THEN_success() {
        // GIVEN
        let json_text = r#"{"domain":{"objectClassName":"domain","ldhName":"foo.example"},"ids":[{"ldhName":"bar.example"}]}"#;

        // WHEN
        let actual: Template = serde_json::from_str(json_text).expect("deserializing template");

        // THEN
        let expected = Template::Domain {
            domain: Domain::basic().ldh_name("foo.example").build(),
            ids: vec![DomainId::builder().ldh_name("bar.example").build()],
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn GIVEN_template_network_with_cidr_WHEN_serialize_THEN_success() {
        // GIVEN
        let template = Template::Network {
            network: Network::basic()
                .cidr(IpCidr::from_str("10.0.0.0/24").expect("cidr parsing"))
                .build(),
            ids: vec![NetworkId::builder()
                .network_id(NetworkIdType::Cidr(
                    "10.0.0.0/24".parse().expect("ipnet parsing"),
                ))
                .build()],
        };

        // WHEN
        let actual = serde_json::to_string(&template).expect("serializing template");

        // THEN
        assert_eq!(
            actual,
            r#"{"network":{"objectClassName":"ip network","startAddress":"10.0.0.0","endAddress":"10.0.0.255","ipVersion":"v4"},"ids":[{"networkId":"10.0.0.0/24"}]}"#
        );
    }

    #[test]
    fn GIVEN_template_network_with_start_and_end_WHEN_serialize_THEN_success() {
        // GIVEN
        let template = Template::Network {
            network: Network::basic()
                .cidr(IpCidr::from_str("10.0.0.0/24").expect("cidr parsing"))
                .build(),
            ids: vec![NetworkId::builder()
                .network_id(NetworkIdType::Range {
                    start_address: "10.0.0.0".to_string(),
                    end_address: "10.0.0.255".to_string(),
                })
                .build()],
        };

        // WHEN
        let actual = serde_json::to_string(&template).expect("serializing template");

        // THEN
        assert_eq!(
            actual,
            r#"{"network":{"objectClassName":"ip network","startAddress":"10.0.0.0","endAddress":"10.0.0.255","ipVersion":"v4"},"ids":[{"networkId":{"startAddress":"10.0.0.0","endAddress":"10.0.0.255"}}]}"#
        );
    }

    #[test]
    fn GIVEN_template_network_with_cidr_text_WHEN_deserialize_THEN_success() {
        // GIVEN
        let text = r#"{"network":{"objectClassName":"ip network","startAddress":"10.0.0.0","endAddress":"10.0.0.255","ipVersion":"v4"},"ids":[{"networkId":"10.0.0.0/24"}]}"#;

        // WHEN
        let actual: Template = serde_json::from_str(text).expect("deserialize network template");

        // THEN
        let expected = Template::Network {
            network: Network::basic()
                .cidr(IpCidr::from_str("10.0.0.0/24").expect("cidr parsing"))
                .build(),
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
        let text = r#"{"network":{"objectClassName":"ip network","startAddress":"10.0.0.0","endAddress":"10.0.0.255","ipVersion":"v4"},"ids":[{"networkId":{"startAddress":"10.0.0.0","endAddress":"10.0.0.255"}}]}"#;

        // WHEN
        let actual: Template = serde_json::from_str(text).expect("deserialize network template");

        // THEN
        let expected = Template::Network {
            network: Network::basic()
                .cidr(IpCidr::from_str("10.0.0.0/24").expect("cidr parsing"))
                .build(),
            ids: vec![NetworkId::builder()
                .network_id(NetworkIdType::Range {
                    start_address: "10.0.0.0".to_string(),
                    end_address: "10.0.0.255".to_string(),
                })
                .build()],
        };
        assert_eq!(actual, expected);
    }
}
