use std::{net::IpAddr, path::PathBuf};

use {
    clap::Parser,
    icann_rdap_common::{
        check::CheckClass,
        prelude::{Numberish, ToResponse},
        response::RdapResponse,
        VERSION,
    },
    icann_rdap_srv::{
        config::{data_dir, debug_config_vars, LOG},
        error::RdapServerError,
        storage::data::{
            trigger_reload, trigger_update, AutnumOrError, DomainOrError, EntityOrError,
            NameserverOrError, NetworkIdType, NetworkOrError, Template,
        },
        util::bin::check::{check_rdap, to_check_classes, CheckArgs},
    },
    ipnet::IpNet,
    serde_json::Value,
    tracing::{debug, error, warn},
    tracing_subscriber::{
        fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, EnvFilter,
    },
};

#[derive(Parser, Debug)]
#[command(author, version = VERSION, about, long_about)]
/// This program moves RDAP files into storage. Files are checked for validity
/// before moving them.
struct Cli {
    /// Directory containing RDAP JSON files.
    #[arg()]
    directory: Option<String>,

    #[clap(flatten)]
    check_args: CheckArgs,

    /// Update storage.
    ///
    /// If true, storage is updated.
    #[arg(long, required = false, conflicts_with = "reload")]
    update: bool,

    /// Reload storage.
    ///
    /// If true, storage is completely reloaded.
    #[arg(long, required = false, conflicts_with = "update")]
    reload: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), RdapServerError> {
    dotenv::dotenv().ok();
    let cli = Cli::parse();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_env(LOG))
        .init();

    debug_config_vars();

    let check_types = to_check_classes(&cli.check_args);

    let data_dir = data_dir();

    if let Some(directory) = cli.directory {
        if directory == data_dir {
            return Err(RdapServerError::InvalidArg(
                "Source directory is same as data (destination) directory.".to_string(),
            ));
        }
        do_validate_then_move(&directory, &check_types, &data_dir).await?;
    }

    // signal update or reload
    if cli.reload {
        trigger_reload(&data_dir).await?;
    } else if cli.update {
        trigger_update(&data_dir).await?;
    };

    Ok(())
}

async fn do_validate_then_move(
    directory: &str,
    check_types: &[CheckClass],
    data_dir: &str,
) -> Result<(), RdapServerError> {
    // validate files
    let src_path = PathBuf::from(directory);
    if !src_path.exists() || !src_path.is_dir() {
        error!(
            "Source Directory {} does not exist or is not a directory.",
            src_path.to_string_lossy()
        );
        return Err(RdapServerError::Config(
            "Source directory does not exist or is not a directory.".to_string(),
        ));
    };

    let mut entries = tokio::fs::read_dir(src_path.clone()).await?;
    let mut errors_found = false;
    while let Some(entry) = entries.next_entry().await? {
        let entry = entry.path();
        let contents = tokio::fs::read_to_string(&entry).await?;
        if entry.extension().is_some_and(|ext| ext == "template") {
            errors_found |= verify_rdap_template(&contents, &entry.to_string_lossy(), check_types)?;
        } else if entry.extension().is_some_and(|ext| ext == "json") {
            errors_found |= verify_rdap(&contents, &entry.to_string_lossy(), check_types)?;
        }
    }
    if errors_found {
        return Err(RdapServerError::ErrorOnChecks);
    }

    // if all files validate, then move them
    let dest_path = PathBuf::from(&data_dir);
    if !dest_path.exists() || !dest_path.is_dir() {
        warn!(
            "Destination Directory {} does not exist or is not a directory.",
            dest_path.to_string_lossy()
        );
        return Err(RdapServerError::Config(
            "Destination directory does not exist or is not a directory.".to_string(),
        ));
    };
    let mut entries = tokio::fs::read_dir(src_path).await?;
    while let Some(entry) = entries.next_entry().await? {
        let source = entry.path();
        let mut dest = dest_path.clone();
        dest.push(source.file_name().expect("cannot get source file name"));
        tokio::fs::copy(source, dest).await?;
    }
    Ok(())
}

/// Verifies the RDAP JSON file.
fn verify_rdap(
    contents: &str,
    path_name: &str,
    check_types: &[CheckClass],
) -> Result<bool, RdapServerError> {
    let mut errors_found = false;
    debug!("verifying {path_name}");
    let json = serde_json::from_str::<Value>(contents);
    if let Ok(value) = json {
        let rdap = RdapResponse::try_from(value);
        if let Ok(rdap) = rdap {
            if check_rdap(rdap, check_types) {
                errors_found = true;
            }
        } else {
            error!("Non RDAP file at {}", path_name.to_owned());
            errors_found = true;
        }
    } else {
        error!("Non JSON file at {}", path_name.to_owned());
        errors_found = true;
    };
    Ok(errors_found)
}

/// Verifies the template files.
fn verify_rdap_template(
    contents: &str,
    path_name: &str,
    check_types: &[CheckClass],
) -> Result<bool, RdapServerError> {
    let mut errors_found = false;
    debug!("processing {path_name} template");
    let json = serde_json::from_str::<Template>(contents);
    if let Ok(value) = json {
        match value {
            Template::Domain { domain, ids } => {
                for id in ids {
                    debug!("verifying domain from template for {id:?}");
                    match &domain {
                        DomainOrError::DomainObject(domain) => {
                            let mut domain = domain.clone();
                            domain.ldh_name = Some(id.ldh_name);
                            if let Some(unicode_name) = id.unicode_name {
                                domain.unicode_name = Some(unicode_name);
                            };
                            errors_found |= check_rdap(domain.to_response(), check_types);
                        }
                        DomainOrError::ErrorResponse(error) => {
                            errors_found |= check_rdap(error.clone().to_response(), check_types);
                        }
                    };
                }
            }
            Template::Entity { entity, ids } => {
                for id in ids {
                    debug!("verifying entity from template for {id:?}");
                    match &entity {
                        EntityOrError::EntityObject(entity) => {
                            let mut entity = entity.clone();
                            entity.object_common.handle = Some(id.handle.into());
                            errors_found |= check_rdap(entity.to_response(), check_types);
                        }
                        EntityOrError::ErrorResponse(error) => {
                            errors_found |= check_rdap(error.clone().to_response(), check_types);
                        }
                    };
                }
            }
            Template::Nameserver { nameserver, ids } => {
                for id in ids {
                    debug!("verifying nameserver from template for {id:?}");
                    match &nameserver {
                        NameserverOrError::NameserverObject(nameserver) => {
                            let mut nameserver = nameserver.clone();
                            nameserver.ldh_name = Some(id.ldh_name);
                            if let Some(unicode_name) = id.unicode_name {
                                nameserver.unicode_name = Some(unicode_name);
                            };
                            errors_found |= check_rdap(nameserver.to_response(), check_types);
                        }
                        NameserverOrError::ErrorResponse(error) => {
                            errors_found |= check_rdap(error.clone().to_response(), check_types);
                        }
                    };
                }
            }
            Template::Autnum { autnum, ids } => {
                for id in ids {
                    debug!("verifying autnum from template for {id:?}");
                    match &autnum {
                        AutnumOrError::AutnumObject(autnum) => {
                            let mut autnum = autnum.clone();
                            autnum.start_autnum = Some(Numberish::<u32>::from(id.start_autnum));
                            autnum.end_autnum = Some(Numberish::<u32>::from(id.end_autnum));
                            errors_found |= check_rdap(autnum.to_response(), check_types);
                        }
                        AutnumOrError::ErrorResponse(error) => {
                            errors_found |= check_rdap(error.clone().to_response(), check_types);
                        }
                    };
                }
            }
            Template::Network { network, ids } => {
                for id in ids {
                    debug!("verifying network from template for {id:?}");
                    match &network {
                        NetworkOrError::NetworkObject(network) => {
                            let mut network = network.clone();
                            match id.network_id {
                                NetworkIdType::Cidr(cidr) => match cidr {
                                    IpNet::V4(v4) => {
                                        network.start_address = Some(v4.network().to_string());
                                        network.end_address = Some(v4.broadcast().to_string());
                                        network.ip_version = Some("v4".to_string().into());
                                    }
                                    IpNet::V6(v6) => {
                                        network.start_address = Some(v6.network().to_string());
                                        network.end_address = Some(v6.broadcast().to_string());
                                        network.ip_version = Some("v6".to_string().into());
                                    }
                                },
                                NetworkIdType::Range {
                                    start_address,
                                    end_address,
                                } => {
                                    let addr: IpAddr = start_address.parse()?;
                                    if addr.is_ipv4() {
                                        network.ip_version = Some("v4".to_string().into());
                                    } else {
                                        network.ip_version = Some("v6".to_string().into());
                                    }
                                    network.start_address = Some(start_address);
                                    network.end_address = Some(end_address);
                                }
                            }
                            errors_found |= check_rdap(network.to_response(), check_types);
                        }
                        NetworkOrError::ErrorResponse(error) => {
                            errors_found |= check_rdap(error.clone().to_response(), check_types);
                        }
                    };
                }
            }
        };
    } else {
        error!("Non JSON template file at {}", path_name.to_owned());
        errors_found = true;
    }
    Ok(errors_found)
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {

    #[test]
    fn cli_debug_assert_test() {
        use clap::CommandFactory;
        crate::Cli::command().debug_assert()
    }
}
