use bootstrap::BootstrapType;
use clap::builder::styling::AnsiColor;
use clap::builder::Styles;
use error::RdapCliError;
use icann_rdap_cli::dirs;
use icann_rdap_client::http::create_client;
use icann_rdap_client::http::ClientConfig;
use icann_rdap_common::check::CheckClass;
use query::InrBackupBootstrap;
use query::ProcessType;
use query::ProcessingParams;
use query::TldLookup;
use std::io::IsTerminal;
use std::str::FromStr;
use tracing::error;
use tracing::info;
#[cfg(debug_assertions)]
use tracing::warn;
use tracing_subscriber::filter::LevelFilter;
use write::FmtWrite;
use write::PagerWrite;

use clap::{ArgGroup, Parser, ValueEnum};
use icann_rdap_client::rdap::QueryType;
use icann_rdap_common::VERSION;
use query::OutputType;
use reqwest::Client;
use tokio::{join, task::spawn_blocking};

use crate::query::do_query;

pub mod bootstrap;
pub mod error;
pub mod query;
pub mod request;
pub mod write;

const BEFORE_LONG_HELP: &str = include_str!("before_long_help.txt");
const AFTER_LONG_HELP: &str = include_str!("after_long_help.txt");

struct CliStyles;

impl CliStyles {
    fn cli_styles() -> Styles {
        Styles::styled()
            .header(AnsiColor::Yellow.on_default())
            .usage(AnsiColor::Green.on_default())
            .literal(AnsiColor::Green.on_default())
            .placeholder(AnsiColor::Green.on_default())
    }
}

#[derive(Parser, Debug)]
#[command(author, version = VERSION, about, long_about, styles = CliStyles::cli_styles())]
#[command(group(
            ArgGroup::new("input")
                .required(true)
                .args(["query_value", "server_help", "reset"]),
        ))]
#[command(group(
            ArgGroup::new("base_specify")
                .args(["base", "base_url"]),
        ))]
#[command(before_long_help(BEFORE_LONG_HELP))]
#[command(after_long_help(AFTER_LONG_HELP))]
/// This program queries network registry information from domain name registries and registrars
/// and Internet number registries (i.e. Regional Internet Registries) using the Registry Data
/// Access Protocol (RDAP).
struct Cli {
    /// Value to be queried in RDAP.
    ///
    /// This is the value to query. For example, a domain name or IP address.
    #[arg()]
    query_value: Option<String>,

    /// Type of the query when using a query value.
    ///
    /// Without this option, the query type will be inferred based on the query value.
    /// To supress the infererence and explicitly specifty the query type, use this
    /// option.
    #[arg(
        short = 't',
        long,
        requires = "query_value",
        required = false,
        value_enum
    )]
    query_type: Option<QtypeArg>,

    /// Get an RDAP server's help information.
    ///
    /// Ask for a server's help information.
    #[arg(short = 'S', long, conflicts_with = "query_type")]
    server_help: bool,

    /// An RDAP base signifier.
    ///
    /// This option gets a base URL from the RDAP bootstrap registries maintained
    /// by IANA. For example, using "com" will get the base URL for the .com
    /// registry, and "arin" will get the base URL for the RDAP tags registry,
    /// which points to the ARIN RIR. This option checks the bootstrap registries
    /// in the following order: object tags, TLDs, IPv4, IPv6, ASN.
    #[arg(short = 'b', long, required = false, env = "RDAP_BASE")]
    base: Option<String>,

    /// An RDAP base URL for a specific RDAP server.
    ///
    /// Use this option to explicitly give an RDAP base URL when issuing queries.
    /// If not specified, the base URL will come from the RDAP boostrap process
    /// outlined in RFC 9224.
    #[arg(short = 'B', long, required = false, env = "RDAP_BASE_URL")]
    base_url: Option<String>,

    /// Specify where to send TLD queries.
    ///
    /// Defaults to IANA.
    #[arg(
        long,
        required = false,
        env = "RDAP_TLD_LOOKUP",
        value_enum,
        default_value_t = TldLookupArg::Iana,
    )]
    tld_lookup: TldLookupArg,

    /// Specify a backup INR bootstrap.
    ///
    /// This is used as a backup when the bootstrapping process cannot find an authoritative
    /// server for IP addresses and Autonomous System Numbers. Defaults to ARIN.
    #[arg(
        long,
        required = false,
        env = "RDAP_INR_BACKUP_BOOTSTRAP",
        value_enum,
        default_value_t = InrBackupBootstrapArg::Arin,
    )]
    inr_backup_bootstrap: InrBackupBootstrapArg,

    /// Output format.
    ///
    /// This option determines the format of the result.
    #[arg(
        short = 'O',
        long,
        required = false,
        env = "RDAP_OUTPUT",
        value_enum,
        default_value_t = OtypeArg::Auto,
    )]
    output_type: OtypeArg,

    /// Check type.
    ///
    /// Specifies the type of checks to conduct on the RDAP
    /// responses. These are RDAP specific checks and not
    /// JSON validation which is done automatically. This
    /// argument may be specified multiple times to include
    /// multiple check types.
    #[arg(short = 'C', long, required = false, value_enum)]
    check_type: Vec<CheckTypeArg>,

    /// Error if RDAP checks found.
    ///
    /// The program will log error messages for non-info
    /// checks found in the RDAP response(s) and exit with a
    /// non-zero status.
    #[arg(long, env = "RDAP_ERROR_ON_CHECK")]
    error_on_checks: bool,

    /// Process Type
    ///
    /// Specifies a process for handling the data.
    #[arg(
        short = 'p',
        long,
        required = false,
        env = "RDAP_PROCESS_TYPE",
        value_enum
    )]
    process_type: Option<ProcTypeArg>,

    /// Pager Usage.
    ///
    /// Determines how to handle paging output.
    /// When using the embedded pager, all log messages will be sent to the
    /// pager as well. Otherwise, log messages are sent to stderr.
    #[arg(
        short = 'P',
        long,
        required = false,
        env = "RDAP_PAGING",
        value_enum,
        default_value_t = PagerType::None,
    )]
    page_output: PagerType,

    /// Log level.
    ///
    /// This option determines the level of logging.
    #[arg(
        short = 'L',
        long,
        required = false,
        env = "RDAP_LOG",
        value_enum,
        default_value_t = LogLevel::Info
    )]
    log_level: LogLevel,

    /// Do not use the cache.
    ///
    /// When given, the cache will be neither read from nor written to.
    #[arg(short = 'N', long, required = false, env = "RDAP_NO_CACHE")]
    no_cache: bool,

    /// Max cache age.
    ///
    /// Specifies the maximum age in seconds of an item in the cache.
    #[arg(
        long,
        required = false,
        env = "RDAP_MAX_CACHE_AGE",
        default_value = "86400"
    )]
    max_cache_age: u32,

    /// Allow HTTP connections.
    ///
    /// When given, allows connections to RDAP servers using HTTP.
    /// Otherwise, only HTTPS is allowed.
    #[arg(short = 'T', long, required = false, env = "RDAP_ALLOW_HTTP")]
    allow_http: bool,

    /// Allow invalid host names.
    ///
    /// When given, allows HTTPS connections to servers where the host name does
    /// not match the certificate's host name.
    #[arg(
        short = 'K',
        long,
        required = false,
        env = "RDAP_ALLOW_INVALID_HOST_NAMES"
    )]
    allow_invalid_host_names: bool,

    /// Allow invalid certificates.
    ///
    /// When given, allows HTTPS connections to servers where the TLS certificates
    /// are invalid.
    #[arg(
        short = 'I',
        long,
        required = false,
        env = "RDAP_ALLOW_INVALID_CERTIFICATES"
    )]
    allow_invalid_certificates: bool,

    /// Reset.
    ///
    /// Removes the cache files and resets the config file.
    #[arg(long, required = false)]
    reset: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum QtypeArg {
    /// Ipv4 Address Lookup
    V4,

    /// Ipv6 Address Lookup
    V6,

    /// Ipv4 CIDR Lookup
    V4Cidr,

    /// Ipv6 CIDR Lookup
    V6Cidr,

    /// Autonomous System Number Lookup
    Autnum,

    /// Domain Lookup
    Domain,

    /// A-Label Domain Lookup
    ALabel,

    /// Entity Lookup
    Entity,

    /// Nameserver Lookup
    Ns,

    /// Entity Name Search
    EntityName,

    /// Entity Handle Search
    EntityHandle,

    /// Domain Name Search
    DomainName,

    /// Domain Nameserver Name Search
    DomainNsName,

    /// Domain Nameserver IP Address Search
    DomainNsIp,

    /// Nameserver Name Search
    NsName,

    /// Nameserver IP Address Search
    NsIp,

    /// RDAP URL
    Url,
}

/// Represents the output type possibilities.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OtypeArg {
    /// Results are rendered as Markdown in the terminal using ANSI terminal capabilities.
    RenderedMarkdown,

    /// Results are rendered as Markdown in plain text.
    Markdown,

    /// Results are output as RDAP JSON.
    Json,

    /// Results are output as Pretty RDAP JSON.
    PrettyJson,

    /// RDAP JSON with extra information.
    JsonExtra,

    /// Global Top Level Domain Output
    GtldWhois,

    /// Automatically determine the output type.
    Auto,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum CheckTypeArg {
    /// All checks.
    All,

    /// Informational items.
    Info,

    /// Specification Notes
    SpecNote,

    /// Checks for STD 95 warnings.
    StdWarn,

    /// Checks for STD 95 errors.
    StdError,

    /// Cidr0 errors.
    Cidr0Error,

    /// ICANN Profile errors.
    IcannError,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum LogLevel {
    /// No logging.
    Off,

    /// Log errors.
    Error,

    /// Log errors and warnings.
    Warn,

    /// Log informational messages, errors, and warnings.
    Info,

    /// Log debug messages, informational messages, errors and warnings.
    Debug,

    /// Log messages appropriate for software development.
    Trace,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum ProcTypeArg {
    /// Only display the data from the domain registrar.
    Registrar,

    /// Only display the data from the domain registry.
    Registry,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum PagerType {
    /// Use the embedded pager.
    Embedded,

    /// Use no pager.
    None,

    /// Automatically determine pager use.
    Auto,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum TldLookupArg {
    /// Use IANA for TLD lookups.
    Iana,

    /// No TLD specific lookups.
    None,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum InrBackupBootstrapArg {
    /// Use ARIN when no INR bootstrap can be found.
    Arin,

    /// No backup for INR bootstraps.
    None,
}

impl From<&LogLevel> for LevelFilter {
    fn from(log_level: &LogLevel) -> Self {
        match log_level {
            LogLevel::Off => LevelFilter::OFF,
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Warn => LevelFilter::WARN,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Trace => LevelFilter::TRACE,
        }
    }
}

#[tokio::main]
pub async fn main() -> RdapCliError {
    if let Err(e) = wrapped_main().await {
        eprintln!("\n{e}\n");
        return e;
    } else {
        return RdapCliError::Success;
    }
}

pub async fn wrapped_main() -> Result<(), RdapCliError> {
    dirs::init()?;
    dotenv::from_path(dirs::config_path()).ok();
    let cli = Cli::parse();

    if cli.reset {
        dirs::reset()?;
        return Ok(());
    }

    let level = LevelFilter::from(&cli.log_level);

    let query_type = query_type_from_cli(&cli)?;

    let use_pager = match cli.page_output {
        PagerType::Embedded => true,
        PagerType::None => false,
        PagerType::Auto => std::io::stdout().is_terminal(),
    };

    let output_type = match cli.output_type {
        OtypeArg::Auto => {
            if std::io::stdout().is_terminal() {
                OutputType::RenderedMarkdown
            } else {
                OutputType::Json
            }
        }
        OtypeArg::RenderedMarkdown => OutputType::RenderedMarkdown,
        OtypeArg::Markdown => OutputType::Markdown,
        OtypeArg::Json => OutputType::Json,
        OtypeArg::PrettyJson => OutputType::PrettyJson,
        OtypeArg::JsonExtra => OutputType::JsonExtra,
        OtypeArg::GtldWhois => OutputType::GtldWhois,
    };

    let process_type = match cli.process_type {
        Some(p) => match p {
            ProcTypeArg::Registrar => ProcessType::Registrar,
            ProcTypeArg::Registry => ProcessType::Registry,
        },
        None => ProcessType::Standard,
    };

    let check_types = if cli.check_type.is_empty() {
        vec![
            CheckClass::Informational,
            CheckClass::StdWarning,
            CheckClass::StdError,
            CheckClass::Cidr0Error,
            CheckClass::IcannError,
        ]
    } else if cli.check_type.contains(&CheckTypeArg::All) {
        vec![
            CheckClass::Informational,
            CheckClass::SpecificationNote,
            CheckClass::StdWarning,
            CheckClass::StdError,
            CheckClass::Cidr0Error,
            CheckClass::IcannError,
        ]
    } else {
        cli.check_type
            .iter()
            .map(|c| match c {
                CheckTypeArg::Info => CheckClass::Informational,
                CheckTypeArg::SpecNote => CheckClass::SpecificationNote,
                CheckTypeArg::StdWarn => CheckClass::StdWarning,
                CheckTypeArg::StdError => CheckClass::StdError,
                CheckTypeArg::Cidr0Error => CheckClass::Cidr0Error,
                CheckTypeArg::IcannError => CheckClass::IcannError,
                CheckTypeArg::All => panic!("check type for all should have been handled."),
            })
            .collect::<Vec<CheckClass>>()
    };

    let bootstrap_type = if let Some(ref tag) = cli.base {
        BootstrapType::Hint(tag.to_string())
    } else if let Some(ref base_url) = cli.base_url {
        BootstrapType::Url(base_url.to_string())
    } else {
        BootstrapType::Rfc9224
    };

    let tld_lookup = match cli.tld_lookup {
        TldLookupArg::Iana => TldLookup::Iana,
        TldLookupArg::None => TldLookup::None,
    };

    let inr_backup_bootstrap = match cli.inr_backup_bootstrap {
        InrBackupBootstrapArg::Arin => InrBackupBootstrap::Arin,
        InrBackupBootstrapArg::None => InrBackupBootstrap::None,
    };

    let processing_params = ProcessingParams {
        bootstrap_type,
        output_type,
        check_types,
        process_type,
        tld_lookup,
        inr_backup_bootstrap,
        error_on_checks: cli.error_on_checks,
        no_cache: cli.no_cache,
        max_cache_age: cli.max_cache_age,
    };

    let client_config = ClientConfig::builder()
        .user_agent_suffix("CLI")
        .https_only(!cli.allow_http)
        .accept_invalid_host_names(cli.allow_invalid_host_names)
        .accept_invalid_certificates(cli.allow_invalid_certificates)
        .build();
    let rdap_client = create_client(&client_config);
    if let Ok(client) = rdap_client {
        if !use_pager {
            tracing_subscriber::fmt()
                .with_max_level(level)
                .with_writer(std::io::stderr)
                .init();
            let output = &mut std::io::stdout();
            let res1 = join!(exec(
                cli.query_value,
                &query_type,
                &processing_params,
                &client,
                output,
            ));
            res1.0?;
        } else {
            let pager = minus::Pager::new();
            pager
                .set_prompt(format!(
                    "{query_type} - Q to quit, j/k or pgup/pgdn to scroll"
                ))
                .expect("unable to set prompt");
            let output = FmtWrite(pager.clone());
            let pager2 = pager.clone();

            tracing_subscriber::fmt()
                .with_max_level(level)
                .with_writer(move || -> Box<dyn std::io::Write> {
                    Box::new(PagerWrite(pager2.clone()))
                })
                .init();
            let pager = pager.clone();
            let (res1, res2) = join!(
                spawn_blocking(move || minus::dynamic_paging(pager)),
                exec(
                    cli.query_value,
                    &query_type,
                    &processing_params,
                    &client,
                    output
                )
            );
            res1.unwrap()?;
            res2?;
        }
    } else {
        error!("{}", rdap_client.err().unwrap())
    };
    Ok(())
}

async fn exec<W: std::io::Write>(
    query_value: Option<String>,
    query_type: &QueryType,
    processing_params: &ProcessingParams,
    client: &Client,
    mut output: W,
) -> Result<(), RdapCliError> {
    info!("ICANN RDAP {} Command Line Interface", VERSION);

    #[cfg(debug_assertions)]
    warn!("This is a development build of this software.");

    if let Some(query_value) = query_value {
        info!("query type is {query_type} for value '{}'", query_value);
    } else {
        info!("query is {query_type}");
    }
    let result = do_query(query_type, processing_params, client, &mut output).await;
    match result {
        Ok(_) => Ok(()),
        Err(error) => {
            error!("{}", error);
            Err(error)
        }
    }
}

fn query_type_from_cli(cli: &Cli) -> Result<QueryType, RdapCliError> {
    if let Some(query_value) = cli.query_value.clone() {
        if let Some(query_type) = cli.query_type {
            let q = match query_type {
                QtypeArg::V4 => QueryType::ipv4(&query_value)?,
                QtypeArg::V6 => QueryType::ipv6(&query_value)?,
                QtypeArg::V4Cidr => QueryType::ipv4cidr(&query_value)?,
                QtypeArg::V6Cidr => QueryType::ipv6cidr(&query_value)?,
                QtypeArg::Autnum => QueryType::autnum(&query_value)?,
                QtypeArg::Domain => QueryType::domain(&query_value)?,
                QtypeArg::ALabel => QueryType::alabel(&query_value)?,
                QtypeArg::Entity => QueryType::Entity(query_value),
                QtypeArg::Ns => QueryType::ns(&query_value)?,
                QtypeArg::EntityName => QueryType::EntityNameSearch(query_value),
                QtypeArg::EntityHandle => QueryType::EntityHandleSearch(query_value),
                QtypeArg::DomainName => QueryType::DomainNameSearch(query_value),
                QtypeArg::DomainNsName => QueryType::DomainNsNameSearch(query_value),
                QtypeArg::DomainNsIp => QueryType::domain_ns_ip_search(&query_value)?,
                QtypeArg::NsName => QueryType::NameserverNameSearch(query_value),
                QtypeArg::NsIp => QueryType::ns_ip_search(&query_value)?,
                QtypeArg::Url => QueryType::Url(query_value),
            };
            Ok(q)
        } else {
            Ok(QueryType::from_str(&query_value)?)
        }
    } else {
        Ok(QueryType::Help)
    }
}

#[cfg(test)]
mod tests {
    use crate::Cli;

    #[test]
    fn cli_debug_assert_test() {
        use clap::CommandFactory;
        Cli::command().debug_assert()
    }
}
