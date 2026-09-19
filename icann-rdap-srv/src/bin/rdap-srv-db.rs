use {
    clap::{Args, Parser, Subcommand},
    icann_rdap_common::{VERSION, prelude::RdapResponse},
    icann_rdap_srv::{
        config::{CommonConfig, LOG},
        error::RdapServerError,
        storage::{
            DEFAULT_HELPFILE_NAME, DeleteOps, StoreOps,
            pg::{config::PgConfig, ops::Pg},
        },
        util::bin::{
            check::{CheckArgs, check_rdap, to_check_classes},
            data::{
                AutnumArgs, DomainArgs, EntityArgs, GenCommand, NameserverArgs, NetworkArgs,
                SrvHelpArgs, acquire_json, build_object, parse_rdap_json,
            },
        },
    },
    ipnet::IpNet,
    std::{net::IpAddr, str::FromStr},
    tracing::{error, info, warn},
    tracing_subscriber::{
        EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
    },
};

/// Add or delete RDAP objects in a live PostgreSQL database.
#[derive(Parser, Debug)]
#[command(name = "rdap-srv-db", author, version = VERSION, about, long_about)]
struct Cli {
    /// PostgreSQL connection URL for the RDAP database
    #[arg(
        long,
        env = "RDAP_SRV_DB_URL",
        default_value = "postgresql://127.0.0.1/rdap"
    )]
    db_url: String,

    #[clap(flatten)]
    check_args: CheckArgs,

    #[command(subcommand)]
    command: Command,
}

/// The object operations. Add operations upsert (last write wins); delete
/// operations remove the object by its primary key.
#[derive(Subcommand, Debug)]
enum Command {
    /// Adds or updates an entity.
    AddEntity(EntityArgs),
    /// Adds or updates a nameserver.
    AddNameserver(NameserverArgs),
    /// Adds or updates a domain.
    AddDomain(DomainArgs),
    /// Adds or updates an autnum.
    AddAutnum(AutnumArgs),
    /// Adds or updates an IP network.
    AddNetwork(NetworkArgs),
    /// Adds or updates the server help response.
    AddSrvHelp(SrvHelpArgs),
    /// Imports a raw RDAP JSON document (argument or stdin) into the database.
    AddJson(AddJsonArgs),
    /// Deletes an entity by handle.
    DeleteEntity(DeleteEntityArgs),
    /// Deletes a domain by LDH name.
    DeleteDomain(DeleteDomainArgs),
    /// Deletes a nameserver by LDH name.
    DeleteNameserver(DeleteNameserverArgs),
    /// Deletes an autnum by (start, end) range.
    DeleteAutnum(DeleteAutnumArgs),
    /// Deletes an IP network by CIDR or address range.
    DeleteNetwork(DeleteNetworkArgs),
    /// Deletes the server help response for a host.
    DeleteSrvHelp(DeleteSrvHelpArgs),
}

/// A delete operation, mapped from the `delete-*` subcommands.
enum DeleteOp {
    Entity(DeleteEntityArgs),
    Domain(DeleteDomainArgs),
    Nameserver(DeleteNameserverArgs),
    Autnum(DeleteAutnumArgs),
    Network(DeleteNetworkArgs),
    SrvHelp(DeleteSrvHelpArgs),
}

#[derive(Debug, Args)]
struct AddJsonArgs {
    /// Raw RDAP JSON document.
    ///
    /// If omitted, the document is read from stdin.
    json: Option<String>,
}

#[derive(Debug, Args)]
struct DeleteEntityArgs {
    /// The entity handle.
    #[arg(long)]
    handle: String,
}

#[derive(Debug, Args)]
struct DeleteDomainArgs {
    /// The domain LDH name (e.g. example.com).
    #[arg(long)]
    ldh: String,
}

#[derive(Debug, Args)]
struct DeleteNameserverArgs {
    /// The nameserver LDH name (e.g. ns1.example.com).
    #[arg(long)]
    ldh: String,
}

#[derive(Debug, Args)]
struct DeleteAutnumArgs {
    /// Start of the autnum range.
    #[arg(long)]
    start: u32,

    /// End of the autnum range.
    ///
    /// If not given, `start` is used (single-autnum block).
    #[arg(long)]
    end: Option<u32>,
}

#[derive(Debug, Args)]
struct DeleteNetworkArgs {
    /// IP CIDR (e.g. 192.0.2.0/24). Mutually exclusive with `--start`/`--end`.
    #[arg(long, value_parser = parse_ipnet, conflicts_with_all = ["start", "end"])]
    cidr: Option<IpNet>,

    /// Start address of the network range.
    #[arg(long)]
    start: Option<IpAddr>,

    /// End address of the network range.
    #[arg(long)]
    end: Option<IpAddr>,
}

#[derive(Debug, Args)]
struct DeleteSrvHelpArgs {
    /// The host the help response is served for.
    ///
    /// If not given, the default host is used.
    #[arg(long)]
    host: Option<String>,
}

/// Parses a CIDR string into an `IpNet`.
fn parse_ipnet(arg: &str) -> Result<IpNet, RdapServerError> {
    IpNet::from_str(arg).map_err(|e| RdapServerError::InvalidArg(e.to_string()))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), RdapServerError> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_env(LOG))
        .init();

    let config = PgConfig::builder()
        .db_url(&cli.db_url)
        .common_config(CommonConfig::default())
        .ignore_data_dir(false)
        .build();
    let store = Pg::new(config).await?;

    let result = match cli.command {
        Command::AddEntity(args) => {
            add_object(&store, GenCommand::Entity(args), &cli.check_args).await
        }
        Command::AddNameserver(args) => {
            add_object(&store, GenCommand::Nameserver(args), &cli.check_args).await
        }
        Command::AddDomain(args) => {
            add_object(&store, GenCommand::Domain(args), &cli.check_args).await
        }
        Command::AddAutnum(args) => {
            add_object(&store, GenCommand::Autnum(args), &cli.check_args).await
        }
        Command::AddNetwork(args) => {
            add_object(&store, GenCommand::Network(args), &cli.check_args).await
        }
        Command::AddSrvHelp(args) => {
            add_object(&store, GenCommand::SrvHelp(args), &cli.check_args).await
        }
        Command::AddJson(args) => add_json(&store, args.json, &cli.check_args).await,
        Command::DeleteEntity(args) => delete_object(&store, DeleteOp::Entity(args)).await,
        Command::DeleteDomain(args) => delete_object(&store, DeleteOp::Domain(args)).await,
        Command::DeleteNameserver(args) => delete_object(&store, DeleteOp::Nameserver(args)).await,
        Command::DeleteAutnum(args) => delete_object(&store, DeleteOp::Autnum(args)).await,
        Command::DeleteNetwork(args) => delete_object(&store, DeleteOp::Network(args)).await,
        Command::DeleteSrvHelp(args) => delete_object(&store, DeleteOp::SrvHelp(args)).await,
    };
    match result {
        Ok(()) => Ok(()),
        Err(err) => {
            error!("Error: {err}");
            Err(err)
        }
    }
}

/// Builds the object from CLI args (resolving references against the live database),
/// runs spec checks, and upserts it into the database.
async fn add_object(
    store: &Pg,
    cmd: GenCommand,
    check_args: &CheckArgs,
) -> Result<(), RdapServerError> {
    // Captured before `cmd` is consumed so the help host can be passed through
    // to `add_srv_help` (which defaults a `None` host itself).
    let help_host = match &cmd {
        GenCommand::SrvHelp(args) => args.host(),
        _ => None,
    }
    .map(str::to_string);

    let output = build_object(cmd, store).await?;

    let check_types = to_check_classes(check_args);
    if check_rdap(output.rdap.clone(), &check_types) {
        return Err(RdapServerError::ErrorOnChecks);
    }

    let mut tx = store.new_tx().await?;
    match &output.rdap {
        RdapResponse::Entity(entity) => tx.add_entity(entity).await?,
        RdapResponse::Domain(domain) => tx.add_domain(domain).await?,
        RdapResponse::Nameserver(nameserver) => tx.add_nameserver(nameserver).await?,
        RdapResponse::Autnum(autnum) => tx.add_autnum(autnum).await?,
        RdapResponse::Network(network) => tx.add_network(network).await?,
        RdapResponse::Help(help) => tx.add_srv_help(help, help_host.as_deref()).await?,
        other => {
            return Err(RdapServerError::InvalidArg(format!(
                "unsupported object class: {other:?}"
            )));
        }
    }
    Box::new(tx).commit().await?;

    info!("Object stored in database.");
    Ok(())
}

/// Imports a raw RDAP JSON document (positional argument or stdin), runs spec
/// checks, and upserts it into the database.
async fn add_json(
    store: &Pg,
    json: Option<String>,
    check_args: &CheckArgs,
) -> Result<(), RdapServerError> {
    let rdap = parse_rdap_json(&acquire_json(json).await?)?;

    let check_types = to_check_classes(check_args);
    if check_rdap(rdap.clone(), &check_types) {
        return Err(RdapServerError::ErrorOnChecks);
    }

    let mut tx = store.new_tx().await?;
    match rdap {
        RdapResponse::Entity(entity) => tx.add_entity(&entity).await?,
        RdapResponse::Domain(domain) => tx.add_domain(&domain).await?,
        RdapResponse::Nameserver(nameserver) => tx.add_nameserver(&nameserver).await?,
        RdapResponse::Autnum(autnum) => tx.add_autnum(&autnum).await?,
        RdapResponse::Network(network) => tx.add_network(&network).await?,
        RdapResponse::Help(help) => tx.add_srv_help(&help, None).await?,
        other => {
            return Err(RdapServerError::InvalidArg(format!(
                "unsupported object class: {other:?}"
            )));
        }
    }
    Box::new(tx).commit().await?;

    info!("Object stored in database.");
    Ok(())
}

/// Deletes an object from the database by its primary key.
async fn delete_object(store: &Pg, op: DeleteOp) -> Result<(), RdapServerError> {
    let (what, deleted) = match op {
        DeleteOp::Entity(args) => ("entity", store.delete_entity(&args.handle).await?),
        DeleteOp::Domain(args) => ("domain", store.delete_domain(&args.ldh).await?),
        DeleteOp::Nameserver(args) => ("nameserver", store.delete_nameserver(&args.ldh).await?),
        DeleteOp::Autnum(args) => {
            let end = args.end.unwrap_or(args.start);
            ("autnum", store.delete_autnum(args.start, end).await?)
        }
        DeleteOp::Network(args) => {
            let (start, end) = network_range(&args)?;
            ("network", store.delete_network(start, end).await?)
        }
        DeleteOp::SrvHelp(args) => {
            let host = args
                .host
                .unwrap_or_else(|| DEFAULT_HELPFILE_NAME.to_string());
            ("server help", store.delete_srv_help(&host).await?)
        }
    };

    if deleted {
        info!("{what} deleted from database.");
    } else {
        warn!("No matching {what} found; nothing deleted.");
    }
    Ok(())
}

/// Resolves the `(start_address, end_address)` primary key pair for a network delete.
fn network_range(args: &DeleteNetworkArgs) -> Result<(IpAddr, IpAddr), RdapServerError> {
    if let Some(net) = &args.cidr {
        return match net {
            IpNet::V4(v4) => Ok((v4.network().into(), v4.broadcast().into())),
            IpNet::V6(v6) => Ok((v6.network().into(), v6.broadcast().into())),
        };
    }
    match (&args.start, &args.end) {
        (Some(start), Some(end)) => {
            if start.is_ipv4() != end.is_ipv4() {
                return Err(RdapServerError::InvalidArg(
                    "mismatch ip version".to_string(),
                ));
            }
            Ok((*start, *end))
        }
        _ => Err(RdapServerError::InvalidArg(
            "network delete requires --cidr or both --start and --end".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_debug_assert_test() {
        use clap::CommandFactory;
        crate::Cli::command().debug_assert()
    }
}
