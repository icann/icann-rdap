use std::{fs, path::PathBuf};

use buildstructor::Builder;
use icann_rdap_common::response::{
    autnum::Autnum, domain::Domain, entity::Entity, nameserver::Nameserver, network::Network,
    RdapResponse,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info, warn};

use crate::{
    error::RdapServerError,
    storage::{StoreOps, TxHandle},
};

use super::ops::Mem;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(untagged)]
enum Template {
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
struct DomainId {
    #[serde(rename = "ldhName")]
    ldh_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "unicodeName")]
    unicode_name: Option<String>,
}

#[derive(Serialize, Deserialize, Builder, Debug, PartialEq, Eq)]
struct EntityId {
    handle: String,
}

#[derive(Serialize, Deserialize, Builder, Debug, PartialEq, Eq)]
struct NameserverId {
    #[serde(rename = "ldhName")]
    ldh_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "unicodeName")]
    unicode_name: Option<String>,
}

#[derive(Serialize, Deserialize, Builder, Debug, PartialEq, Eq)]
struct AutnumId {
    #[serde(rename = "startAutnum")]
    start_autnum: u32,
    #[serde(rename = "endAutnum")]
    end_autnum: u32,
}

#[derive(Serialize, Deserialize, Builder, Debug, PartialEq, Eq)]
struct NetworkId {
    ipnet: IpNet,
}

pub(crate) async fn load_state(mem: &Mem) -> Result<(), RdapServerError> {
    let mut json_count: usize = 0;
    let mut template_count: usize = 0;
    let mut tx = mem.new_tx().await?;
    let path = PathBuf::from(&mem.config.state_dir);
    if !path.exists() || !path.is_dir() {
        warn!(
            "Directory {} does not exist or is not a directory. Server has no content to serve.",
            path.to_string_lossy()
        );
        return Ok(());
    }
    for entry in std::fs::read_dir(path)? {
        let entry = entry?.path();
        let contents = fs::read_to_string(&entry)?;
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
            _ => return Err(RdapServerError::NonRdapJsonFile(path_name.to_owned())),
        };
    } else {
        return Err(RdapServerError::NonJsonFile(path_name.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use icann_rdap_common::response::domain::Domain;

    use super::*;

    #[test]
    fn GIVEN_template_WHEN_serialize_THEN_success() {
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
    fn GIVEN_template_text_WHEN_deserialize_THEN_success() {
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
}
