use {
    clap::{Args, Parser, Subcommand},
    icann_rdap_common::{
        VERSION,
        media_types::RDAP_MEDIA_TYPE,
        prelude::RdapResponse,
        response::{Link, Notice, NoticeOrRemark, Rfc9083Error},
    },
    icann_rdap_srv::{
        config::{CommonConfig, LOG, ServiceConfig, data_dir, debug_config_vars},
        error::RdapServerError,
        storage::{
            StoreOps,
            data::{
                AutnumOrError, DomainOrError, EntityOrError, NameserverOrError, NetworkOrError,
                Template, load_data,
            },
            mem::{config::MemConfig, ops::Mem},
        },
        util::bin::{
            check::{CheckArgs, check_rdap, to_check_classes},
            data::{
                AutnumArgs, DomainArgs, EntityArgs, GenCommand, NameserverArgs, NetworkArgs,
                RdapId, SrvHelpArgs, acquire_json, build_object, parse_rdap_json,
            },
        },
    },
    pct_str::{PctString, UriReserved},
    std::{fs, path::PathBuf},
    tracing::{error, info},
    tracing_subscriber::{
        EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
    },
};

#[derive(Parser, Debug)]
#[command(author, version = VERSION, about, long_about)]
/// This program creates RDAP objects.
struct Cli {
    #[clap(flatten)]
    check_args: CheckArgs,

    /// Specifies the directory where data will be written.
    #[arg(long, env = "RDAP_SRV_DATA_DIR", default_value_t = data_dir().expect("data directory does not exist"))]
    data_dir: String,

    /// Output data as a redirect.
    ///
    /// When specified, the data will create a redirect template file to the given URL.
    /// This cannot be used with --template.
    #[arg(long, conflicts_with = "template")]
    redirect: Option<String>,

    /// Output data as a template.
    ///
    /// When specified, the data will be output as a template file.
    /// This cannot be used with --redirect.
    #[arg(long, conflicts_with = "redirect")]
    template: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Creates an RDAP entity.
    Entity(Box<EntityArgs>),

    /// Create a nameserver.
    Nameserver(Box<NameserverArgs>),

    /// Create a domain.
    Domain(Box<DomainArgs>),

    /// Create an autnum.
    Autnum(Box<AutnumArgs>),

    /// Create an IP network.
    Network(Box<NetworkArgs>),

    /// Creates a Help response.
    SrvHelp(SrvHelpArgs),

    /// Writes a raw RDAP JSON document to the data directory.
    ///
    /// An existing file with the same name is overwritten.
    Json(JsonArgs),
}

#[derive(Debug, Args)]
struct JsonArgs {
    /// Raw RDAP JSON document.
    ///
    /// If omitted, the document is read from stdin.
    json: Option<String>,

    /// Base name for the output file (e.g. "example.com").
    ///
    /// When omitted, it is derived from the content of the document.
    #[arg(long)]
    file_name: Option<String>,
}

/// Derives a deterministic output file base name from the content of an RDAP document.
fn json_file_name(rdap: &RdapResponse) -> Result<String, RdapServerError> {
    let missing = || {
        RdapServerError::InvalidArg(
            "cannot derive a file name from the document; specify --file-name".to_string(),
        )
    };
    match rdap {
        RdapResponse::Domain(domain) => domain.ldh_name.clone().ok_or_else(missing),
        RdapResponse::Nameserver(nameserver) => nameserver.ldh_name.clone().ok_or_else(missing),
        RdapResponse::Entity(entity) => entity
            .object_common
            .handle
            .as_ref()
            .map(|handle| handle.to_string())
            .ok_or_else(missing),
        RdapResponse::Autnum(autnum) => autnum
            .object_common
            .handle
            .as_ref()
            .map(|handle| handle.to_string())
            .ok_or_else(missing),
        RdapResponse::Network(network) => {
            if let (Some(start), Some(end)) = (&network.start_address, &network.end_address)
                && start == end
            {
                return Ok(start.clone());
            }
            network
                .object_common
                .handle
                .as_ref()
                .map(|handle| handle.to_string())
                .ok_or_else(missing)
        }
        _ => Err(missing()),
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), RdapServerError> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_env(LOG))
        .init();

    debug_config_vars();

    let data_dir = cli.data_dir.clone();
    let config = ServiceConfig::non_server().data_dir(&data_dir).build()?;
    let storage = Mem::new(
        MemConfig::builder()
            .common_config(CommonConfig::default())
            .build(),
    );
    storage.init().await?;
    load_data(&config, &storage, false).await?;

    let work = do_the_work(cli, &storage, &data_dir).await;
    match work {
        Ok(_) => Ok(()),
        Err(err) => {
            error!("Error: {err}");
            Err(err)
        }
    }
}

async fn do_the_work(
    cli: Cli,
    storage: &dyn StoreOps,
    data_dir: &str,
) -> Result<(), RdapServerError> {
    let command = match cli.command {
        Commands::Json(args) => {
            return json_work(cli.check_args, cli.template, cli.redirect, args, data_dir).await;
        }
        Commands::Entity(args) => GenCommand::Entity(*args),
        Commands::Nameserver(args) => GenCommand::Nameserver(*args),
        Commands::Domain(args) => GenCommand::Domain(*args),
        Commands::Autnum(args) => GenCommand::Autnum(*args),
        Commands::Network(args) => GenCommand::Network(*args),
        Commands::SrvHelp(args) => {
            if cli.template || cli.redirect.is_some() {
                return Err(RdapServerError::InvalidArg(
                    "help cannot use --redirect or --template options".to_string(),
                ));
            }
            GenCommand::SrvHelp(args)
        }
    };

    let output = build_object(command, storage).await?;

    let check_types = to_check_classes(&cli.check_args);
    let checks_found = check_rdap(output.rdap.clone(), &check_types);
    if checks_found {
        return Err(RdapServerError::ErrorOnChecks);
    } else {
        info!("Checks conducted and no issues were found.");
    }

    if let RdapId::Help = output.id {
        create_help_file(data_dir, &output.self_href, output.rdap)?;
    } else if cli.template {
        create_template_file(data_dir, &output.self_href, &output.id, &output.rdap)?;
    } else if let Some(redirect_url) = cli.redirect {
        create_redirect_file(data_dir, &output.self_href, &output.id, &redirect_url)?;
    } else {
        create_json_file(data_dir, &output.self_href, output.rdap)?;
    }

    Ok(())
}

/// Handles the `json` subcommand: acquires a raw RDAP document (argument or stdin),
/// validates it, and writes it as a `.json` data file for the server to load.
async fn json_work(
    check_args: CheckArgs,
    template: bool,
    redirect: Option<String>,
    args: JsonArgs,
    data_dir: &str,
) -> Result<(), RdapServerError> {
    if template || redirect.is_some() {
        return Err(RdapServerError::InvalidArg(
            "json input cannot be combined with --template or --redirect".to_string(),
        ));
    }

    let text = acquire_json(args.json).await?;
    let rdap = parse_rdap_json(&text)?;

    // Only object class documents can be loaded by the server as `.json` data files.
    match &rdap {
        RdapResponse::Domain(_)
        | RdapResponse::Entity(_)
        | RdapResponse::Nameserver(_)
        | RdapResponse::Autnum(_)
        | RdapResponse::Network(_) => {}
        _ => {
            return Err(RdapServerError::InvalidArg(
                "only domain, entity, nameserver, autnum and ip network documents can be stored as JSON data files".to_string(),
            ));
        }
    }

    let check_types = to_check_classes(&check_args);
    if check_rdap(rdap.clone(), &check_types) {
        return Err(RdapServerError::ErrorOnChecks);
    } else {
        info!("Checks conducted and no issues were found.");
    }

    let base = match args.file_name {
        Some(name) => name,
        None => json_file_name(&rdap)?,
    };
    create_json_file(data_dir, &base, rdap)?;
    Ok(())
}

fn create_file_name(self_href: &str, extension: &str) -> String {
    let file_name = self_href
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .replace(['.', '/', ':'], "_");
    format!(
        "{}.{extension}",
        PctString::encode(file_name.chars(), UriReserved::Any)
    )
}

fn create_json_file(
    data_dir: &str,
    self_href: &str,
    rdap: RdapResponse,
) -> Result<(), RdapServerError> {
    let file_name = create_file_name(self_href, "json");
    let mut path = PathBuf::from(data_dir);
    path.push(file_name);
    let content = serde_json::to_string_pretty(&rdap)?;
    fs::write(&path, content)?;
    info!("JSON data written to {}.", path.to_string_lossy());
    Ok(())
}

fn create_help_file(
    data_dir: &str,
    self_href: &str,
    rdap: RdapResponse,
) -> Result<(), RdapServerError> {
    let file_name = create_file_name(self_href, "help");
    let mut path = PathBuf::from(data_dir);
    path.push(file_name);
    let content = serde_json::to_string_pretty(&rdap)?;
    fs::write(&path, content)?;
    info!("HELP data written to {}.", path.to_string_lossy());
    Ok(())
}

fn create_redirect_file(
    data_dir: &str,
    self_href: &str,
    id: &RdapId,
    url: &str,
) -> Result<(), RdapServerError> {
    let file_name = create_file_name(self_href, "template");
    let mut path = PathBuf::from(data_dir);
    path.push(file_name);
    let error = Rfc9083Error::response_obj()
        .error_code(307)
        .notice(Notice(
            NoticeOrRemark::builder()
                .title("Temporary Redirect")
                .links(vec![
                    Link::builder()
                        .href(url)
                        .value(self_href)
                        .media_type(RDAP_MEDIA_TYPE)
                        .rel("related")
                        .build(),
                ])
                .build(),
        ))
        .build();
    let template = match id {
        RdapId::Entity(id) => Template::Entity {
            entity: EntityOrError::ErrorResponse(error),
            ids: vec![id.clone()],
        },
        RdapId::Domain(id) => Template::Domain {
            domain: DomainOrError::ErrorResponse(error),
            ids: vec![id.clone()],
        },
        RdapId::Nameserver(id) => Template::Nameserver {
            nameserver: NameserverOrError::ErrorResponse(error),
            ids: vec![id.clone()],
        },
        RdapId::Autnum(id) => Template::Autnum {
            autnum: AutnumOrError::ErrorResponse(error),
            ids: vec![id.clone()],
        },
        RdapId::Network(id) => Template::Network {
            network: NetworkOrError::ErrorResponse(error),
            ids: vec![id.clone()],
        },
        RdapId::Help => panic!("cannot create help redirect file"),
    };
    let content = serde_json::to_string_pretty(&template)?;
    fs::write(&path, content)?;
    info!("Redirect data written to {}.", path.to_string_lossy());
    Ok(())
}

fn create_template_file(
    data_dir: &str,
    self_href: &str,
    id: &RdapId,
    rdap: &RdapResponse,
) -> Result<(), RdapServerError> {
    let file_name = create_file_name(self_href, "template");
    let mut path = PathBuf::from(data_dir);
    path.push(file_name);
    let template = match id {
        RdapId::Entity(id) => {
            let RdapResponse::Entity(entity) = rdap else {
                panic!("non entity created with entity id")
            };
            Template::Entity {
                entity: EntityOrError::EntityObject(Box::new(*entity.clone())),
                ids: vec![id.clone()],
            }
        }
        RdapId::Domain(id) => {
            let RdapResponse::Domain(domain) = rdap else {
                panic!("non domain created with domain id")
            };
            Template::Domain {
                domain: DomainOrError::DomainObject(Box::new(*domain.clone())),
                ids: vec![id.clone()],
            }
        }
        RdapId::Nameserver(id) => {
            let RdapResponse::Nameserver(nameserver) = rdap else {
                panic!("non nameserver created with nameserver id")
            };
            Template::Nameserver {
                nameserver: NameserverOrError::NameserverObject(Box::new(*nameserver.clone())),
                ids: vec![id.clone()],
            }
        }
        RdapId::Autnum(id) => {
            let RdapResponse::Autnum(autnum) = rdap else {
                panic!("non autnum created with autnum id")
            };
            Template::Autnum {
                autnum: AutnumOrError::AutnumObject(Box::new(*autnum.clone())),
                ids: vec![id.clone()],
            }
        }
        RdapId::Network(id) => {
            let RdapResponse::Network(network) = rdap else {
                panic!("non network created with network id")
            };
            Template::Network {
                network: NetworkOrError::NetworkObject(Box::new(*network.clone())),
                ids: vec![id.clone()],
            }
        }
        RdapId::Help => panic!("cannot create help template file"),
    };
    let content = serde_json::to_string_pretty(&template)?;
    fs::write(&path, content)?;
    info!("Template data written to {}.", path.to_string_lossy());
    Ok(())
}

#[cfg(test)]
mod tests {
    use icann_rdap_srv::util::bin::data::parse_rdap_json;

    use crate::json_file_name;

    #[test]
    fn cli_debug_assert_test() {
        use clap::CommandFactory;
        crate::Cli::command().debug_assert()
    }

    #[test]
    fn test_json_file_name_domain() {
        // GIVEN
        let rdap = parse_rdap_json(r#"{"objectClassName":"domain","ldhName":"example.com"}"#)
            .expect("parsing rdap json");

        // WHEN
        let actual = json_file_name(&rdap).expect("deriving file name");

        // THEN
        assert_eq!(actual, "example.com");
    }

    #[test]
    fn test_json_file_name_nameserver() {
        // GIVEN
        let rdap =
            parse_rdap_json(r#"{"objectClassName":"nameserver","ldhName":"ns1.example.com"}"#)
                .expect("parsing rdap json");

        // WHEN
        let actual = json_file_name(&rdap).expect("deriving file name");

        // THEN
        assert_eq!(actual, "ns1.example.com");
    }

    #[test]
    fn test_json_file_name_entity() {
        // GIVEN
        let rdap = parse_rdap_json(r#"{"objectClassName":"entity","handle":"foo1234"}"#)
            .expect("parsing rdap json");

        // WHEN
        let actual = json_file_name(&rdap).expect("deriving file name");

        // THEN
        assert_eq!(actual, "foo1234");
    }

    #[test]
    fn test_json_file_name_autnum() {
        // GIVEN
        let rdap = parse_rdap_json(r#"{"objectClassName":"autnum","handle":"AS65537"}"#)
            .expect("parsing rdap json");

        // WHEN
        let actual = json_file_name(&rdap).expect("deriving file name");

        // THEN
        assert_eq!(actual, "AS65537");
    }

    #[test]
    fn test_json_file_name_network_single_address() {
        // GIVEN
        let rdap = parse_rdap_json(
            r#"{"objectClassName":"ip network","startAddress":"10.0.0.1","endAddress":"10.0.0.1"}"#,
        )
        .expect("parsing rdap json");

        // WHEN
        let actual = json_file_name(&rdap).expect("deriving file name");

        // THEN
        assert_eq!(actual, "10.0.0.1");
    }

    #[test]
    fn test_json_file_name_network_range_falls_back_to_handle() {
        // GIVEN
        let rdap = parse_rdap_json(
            r#"{"objectClassName":"ip network","handle":"NET-10-0-0-0","startAddress":"10.0.0.0","endAddress":"10.0.0.255"}"#,
        )
        .expect("parsing rdap json");

        // WHEN
        let actual = json_file_name(&rdap).expect("deriving file name");

        // THEN
        assert_eq!(actual, "NET-10-0-0-0");
    }

    #[test]
    fn test_json_file_name_domain_without_ldh_name() {
        // GIVEN
        let rdap = parse_rdap_json(r#"{"objectClassName":"domain"}"#).expect("parsing rdap json");

        // WHEN
        let actual = json_file_name(&rdap);

        // THEN
        assert!(actual.is_err());
    }
}
