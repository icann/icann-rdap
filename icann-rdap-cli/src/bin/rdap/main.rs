use std::collections::HashSet;

use enumflags2::BitFlags;
use icann_rdap_cli::args::target::{LinkTargetArgs, params_from_args};
use icann_rdap_client::http::default_exts_list;
use icann_rdap_common::check::StringCheck;
#[cfg(debug_assertions)]
use tracing::warn;
use {
    bootstrap::BootstrapType,
    clap::builder::{Styles, styling::AnsiColor},
    error::RdapCliError,
    icann_rdap_cli::dirs,
    icann_rdap_client::http::{Client, ClientConfig, create_client},
    query::{InrBackupBootstrap, ProcessingParams, TldLookup},
    std::{io::IsTerminal, str::FromStr},
    tracing::{error, info},
    tracing_subscriber::filter::LevelFilter,
    write::{FmtWrite, PagerWrite},
};

use {
    clap::{ArgGroup, Parser, ValueEnum},
    icann_rdap_client::rdap::QueryType,
    icann_rdap_common::VERSION,
    query::OutputType,
    tokio::{join, task::spawn_blocking},
};

use crate::query::{RedactionFlag, exec_queries};

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
#[command(group(
            ArgGroup::new("output")
                .args(["output_type", "json", "rpsl"]),
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
    /// To suppress the inference and explicitly specify the query type, use this
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
    /// If not specified, the base URL will come from the RDAP bootstrap process
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

    /// Shortcut for "-O pretty-compact-json"
    #[arg(long, required = false, conflicts_with = "output_type")]
    json: bool,

    /// Shortcut for "-O rpsl"
    #[arg(long, required = false, conflicts_with = "output_type")]
    rpsl: bool,

    /// Convert vCard (jCard) to JSContact
    #[arg(long, required = false)]
    to_jscontact: bool,

    #[clap(flatten)]
    link_target_args: LinkTargetArgs,

    /// Redaction flags.
    ///
    /// Control the processing and display of redactions.
    #[arg(
        long,
        required = false,
        env = "RDAP_REDACTION_FLAGS",
        value_delimiter = ',',
        value_enum
    )]
    redaction_flag: Vec<RedactionFlagArg>,

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

    /// Self link caching.
    ///
    /// Cache objects with a self link, if caching is enabled.
    #[arg(long, required = false, env = "RDAP_CACHE_SELF_LINKS")]
    self_link_caching: bool,

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

    /// Set the query timeout.
    ///
    /// This values specifies, in seconds, the total time to connect and read all
    /// the data from a connection.
    #[arg(
        long,
        required = false,
        env = "RDAP_TIMEOUT_SECS",
        default_value = "60"
    )]
    timeout_secs: u64,

    /// Maximum retry wait time.
    ///
    /// Sets the maximum number of seconds to wait before retrying a query when
    /// a server has sent an HTTP 429 status code with a retry-after value.
    /// That is, the value to used is no greater than this setting.
    #[arg(
        long,
        required = false,
        env = "RDAP_MAX_RETRY_SECS",
        default_value = "120"
    )]
    max_retry_secs: u32,

    /// Default retry wait time.
    ///
    /// Sets the number of seconds to wait before retrying a query when
    /// a server has sent an HTTP 429 status code without a retry-after value
    /// or when the retry-after value does not make sense.
    #[arg(
        long,
        required = false,
        env = "RDAP_DEF_RETRY_SECS",
        default_value = "60"
    )]
    def_retry_secs: u32,

    /// Maximum number of retries.
    ///
    /// This sets the maximum number of retries when a server signals too many
    /// requests have been sent using an HTTP 429 status code.
    #[arg(long, required = false, env = "RDAP_MAX_RETRIES", default_value = "1")]
    max_retries: u16,

    /// Do not send an exts_list media type parameter.
    #[arg(long, required = false, env = "RDAP_NO_EXTS_LIST")]
    no_exts_list: bool,

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

    /// Reverse DNS IPv4 Lookup
    RdnsIpv4,

    /// Reverse DNS IPv6 Lookup
    RdnsIpv6,

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

    /// Ipv4 Address Rdap-Up Lookup
    V4Up,

    /// Ipv6 Address Rdap-Up Lookup
    V6Up,

    /// Ipv4 CIDR Rdap-Up Lookup
    V4CidrUp,

    /// Ipv6 CIDR Rdap-Up Lookup
    V6CidrUp,

    /// Ipv4 Address Rdap-Top Lookup
    V4Top,

    /// Ipv6 Address Rdap-Top Lookup
    V6Top,

    /// Ipv4 CIDR Rdap-Top Lookup
    V4CidrTop,

    /// Ipv6 CIDR Rdap-Top Lookup
    V6CidrTop,

    /// Ipv4 Address Rdap-Down Search
    V4Down,

    /// Ipv6 Address Rdap-Down Search
    V6Down,

    /// Ipv4 CIDR Rdap-Down Search
    V4CidrDown,

    /// Ipv6 CIDR Rdap-Down Search
    V6CidrDown,

    /// Ipv4 Address Rdap-Bottom Search
    V4Bottom,

    /// Ipv6 Address Rdap-Bottom Search
    V6Bottom,

    /// Ipv4 CIDR Rdap-Bottom Search
    V4CidrBottom,

    /// Ipv6 CIDR Rdap-Bottom Search
    V6CidrBottom,

    /// Reverse DNS IPv4 Rdap-Up Lookup
    RdnsIpv4Up,

    /// Reverse DNS IPv6 Rdap-Up Lookup
    RdnsIpv6Up,

    /// Reverse DNS IPv4 Rdap-Down Search
    RdnsIpv4Down,

    /// Reverse DNS IPv6 Rdap-Down Search
    RdnsIpv6Down,

    /// Reverse DNS IPv4 Rdap-Top Search
    RdnsIpv4Top,

    /// Reverse DNS IPv6 Rdap-Top Search
    RdnsIpv6Top,

    /// Reverse DNS IPv4 Rdap-Bottom Search
    RdnsIpv4Bottom,

    /// Reverse DNS IPv6 Rdap-Bottom Search
    RdnsIpv6Bottom,

    /// Autonomous System Number Rdap-Up Lookup
    AutnumUp,

    /// Autonomous System Number Rdap-Down Lookup
    AutnumDown,

    /// Autonomous System Number Rdap-Top Search
    AutnumTop,

    /// Autonomous System Number Rdap-Bottom Search
    AutnumBottom,

    /// Network Handle Search
    NetHandle,

    /// Network Name Search
    NetName,

    /// Autonomous System Number Handle Search
    AutnumHandle,

    /// Autonomous System Number Name Search
    AutnumName,
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

    /// JSON output that is compact and pretty.
    PrettyCompactJson,

    /// RDAP JSON with extra information.
    JsonExtra,

    /// Global Top Level Domain Output
    GtldWhois,

    /// Routing Policy Specification Language (RPSL).
    Rpsl,

    /// URL of RDAP servers.
    Url,

    /// Only print primary object's status, one per line.
    StatusText,

    /// Only print primary object's status as JSON.
    StatusJson,

    /// Only print primary object's events, one per line.
    EventText,

    /// Only print primary object's events as JSON.
    EventJson,

    /// Download geofeed files from RDAP response (RFC 9877).
    Geofeed,

    /// Automatically determine the output type.
    Auto,
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

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum RedactionFlagArg {
    /// Highlight Simple Redactions.
    HighlightSimpleRedactions,

    /// Show RFC 9537 redaction directives.
    ShowRfc9537,

    /// Do not turn RFC 9537 redactions into Simple Redactions.
    DoNotSimplifyRfc9537,

    /// Process RFC 9537 redactions.
    DoRfc9537Redactions,
}

impl From<&LogLevel> for LevelFilter {
    fn from(log_level: &LogLevel) -> Self {
        match log_level {
            LogLevel::Off => Self::OFF,
            LogLevel::Error => Self::ERROR,
            LogLevel::Warn => Self::WARN,
            LogLevel::Info => Self::INFO,
            LogLevel::Debug => Self::DEBUG,
            LogLevel::Trace => Self::TRACE,
        }
    }
}

#[tokio::main]
pub async fn main() -> RdapCliError {
    match wrapped_main().await {
        Err(e) => {
            let ec = e.exit_code();
            match ec {
                // we use eprintln! because when this is thrown, the tracing subscriber is not yet instantiated.
                205 => eprintln!("\n{e}\nRPSL format maybe more appropriate. Try: --rpsl.\n"),
                206 => eprintln!("Use -T or --allow-http to allow insecure HTTP connections."),
                _ => eprintln!("\n{e}\n"),
            };
            return e;
        }
        _ => {
            return RdapCliError::Success;
        }
    }
}

pub async fn wrapped_main() -> Result<(), RdapCliError> {
    dirs::init()?;
    dotenvy::from_path(dirs::config_path()).ok();
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

    let output_type = if cli.json {
        OutputType::PrettyCompactJson
    } else if cli.rpsl {
        OutputType::Rpsl
    } else {
        match cli.output_type {
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
            OtypeArg::PrettyCompactJson => OutputType::PrettyCompactJson,
            OtypeArg::JsonExtra => OutputType::JsonExtra,
            OtypeArg::GtldWhois => OutputType::GtldWhois,
            OtypeArg::Rpsl => OutputType::Rpsl,
            OtypeArg::Url => OutputType::Url,
            OtypeArg::StatusText => OutputType::StatusText,
            OtypeArg::StatusJson => OutputType::StatusJson,
            OtypeArg::EventText => OutputType::EventText,
            OtypeArg::EventJson => OutputType::EventJson,
            OtypeArg::Geofeed => OutputType::Geofeed,
        }
    };

    // throw error if output type is inappropriate
    if matches!(output_type, OutputType::GtldWhois) && !matches!(query_type, QueryType::Domain(_)) {
        return Err(RdapCliError::GtldWhoisOutputNotImplemented);
    }

    let link_params = params_from_args(&query_type, cli.link_target_args);

    let bootstrap_type = if let Some(ref tag) = cli.base {
        BootstrapType::Hint(tag.to_string())
    } else if let Some(ref base_url) = cli.base_url {
        BootstrapType::Url(hostname_to_baseurl(base_url))
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

    let mut redaction_flags: BitFlags<RedactionFlag> = BitFlags::EMPTY;
    for flag in cli.redaction_flag {
        match flag {
            RedactionFlagArg::HighlightSimpleRedactions => {
                redaction_flags |= RedactionFlag::HighlightSimpleRedactions
            }
            RedactionFlagArg::ShowRfc9537 => redaction_flags |= RedactionFlag::ShowRfc9537,
            RedactionFlagArg::DoNotSimplifyRfc9537 => {
                redaction_flags |= RedactionFlag::DoNotSimplifyRfc9537
            }
            RedactionFlagArg::DoRfc9537Redactions => {
                redaction_flags |= RedactionFlag::DoRfc9537Redactions
            }
        }
    }

    let processing_params = ProcessingParams {
        bootstrap_type,
        output_type,
        tld_lookup,
        inr_backup_bootstrap,
        no_cache: cli.no_cache,
        max_cache_age: cli.max_cache_age,
        redaction_flags,
        link_params,
        to_jscontact: cli.to_jscontact,
        self_link_caching: cli.self_link_caching,
    };

    let exts_list = if cli.no_exts_list {
        HashSet::default()
    } else {
        default_exts_list()
    };
    let client_config = ClientConfig::builder()
        .user_agent_suffix("CLI")
        .https_only(!cli.allow_http)
        .accept_invalid_host_names(cli.allow_invalid_host_names)
        .accept_invalid_certificates(cli.allow_invalid_certificates)
        .timeout_secs(cli.timeout_secs)
        .max_retry_secs(cli.max_retry_secs)
        .def_retry_secs(cli.def_retry_secs)
        .max_retries(cli.max_retries)
        .exts_list(exts_list)
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
    let result = exec_queries(query_type, processing_params, client, &mut output).await;
    match result {
        Ok(_) => Ok(()),
        Err(error) => {
            error!("{}", error);
            Err(error)
        }
    }
}

fn query_type_from_cli(cli: &Cli) -> Result<QueryType, RdapCliError> {
    let Some(query_value) = cli.query_value.clone() else {
        return Ok(QueryType::Help);
    };
    let Some(query_type) = cli.query_type else {
        return Ok(QueryType::from_str(&query_value)?);
    };
    let q = match query_type {
        QtypeArg::V4 => QueryType::ipv4(&query_value)?,
        QtypeArg::V6 => QueryType::ipv6(&query_value)?,
        QtypeArg::V4Cidr => QueryType::ipv4cidr(&query_value)?,
        QtypeArg::V6Cidr => QueryType::ipv6cidr(&query_value)?,
        QtypeArg::V4Up => QueryType::ipv4_up(&query_value)?,
        QtypeArg::V6Up => QueryType::ipv6_up(&query_value)?,
        QtypeArg::V4CidrUp => QueryType::ipv4cidr_up(&query_value)?,
        QtypeArg::V6CidrUp => QueryType::ipv6cidr_up(&query_value)?,
        QtypeArg::V4Top => QueryType::ipv4_top(&query_value)?,
        QtypeArg::V6Top => QueryType::ipv6_top(&query_value)?,
        QtypeArg::V4CidrTop => QueryType::ipv4cidr_top(&query_value)?,
        QtypeArg::V6CidrTop => QueryType::ipv6cidr_top(&query_value)?,
        QtypeArg::V4Down => QueryType::ipv4_down(&query_value)?,
        QtypeArg::V6Down => QueryType::ipv6_down(&query_value)?,
        QtypeArg::V4CidrDown => QueryType::ipv4cidr_down(&query_value)?,
        QtypeArg::V6CidrDown => QueryType::ipv6cidr_down(&query_value)?,
        QtypeArg::V4Bottom => QueryType::ipv4_bottom(&query_value)?,
        QtypeArg::V6Bottom => QueryType::ipv6_bottom(&query_value)?,
        QtypeArg::V4CidrBottom => QueryType::ipv4cidr_bottom(&query_value)?,
        QtypeArg::V6CidrBottom => QueryType::ipv6cidr_bottom(&query_value)?,
        QtypeArg::Autnum => QueryType::autnum(&query_value)?,
        QtypeArg::AutnumUp => QueryType::autnum_up(&query_value)?,
        QtypeArg::AutnumDown => QueryType::autnum_down(&query_value)?,
        QtypeArg::AutnumTop => QueryType::autnum_top(&query_value)?,
        QtypeArg::AutnumBottom => QueryType::autnum_bottom(&query_value)?,
        QtypeArg::Domain => QueryType::domain(&query_value)?,
        QtypeArg::ALabel => QueryType::alabel(&query_value)?,
        QtypeArg::RdnsIpv4 => QueryType::rdns_ipstr(&query_value)?,
        QtypeArg::RdnsIpv6 => QueryType::rdns_ipstr(&query_value)?,
        QtypeArg::RdnsIpv4Up => QueryType::rdns_ipv4_up(&query_value)?,
        QtypeArg::RdnsIpv6Up => QueryType::rdns_ipv6_up(&query_value)?,
        QtypeArg::RdnsIpv4Down => QueryType::rdns_ipv4_down(&query_value)?,
        QtypeArg::RdnsIpv6Down => QueryType::rdns_ipv6_down(&query_value)?,
        QtypeArg::RdnsIpv4Top => QueryType::rdns_ipv4_top(&query_value)?,
        QtypeArg::RdnsIpv6Top => QueryType::rdns_ipv6_top(&query_value)?,
        QtypeArg::RdnsIpv4Bottom => QueryType::rdns_ipv4_bottom(&query_value)?,
        QtypeArg::RdnsIpv6Bottom => QueryType::rdns_ipv6_bottom(&query_value)?,
        QtypeArg::Entity => QueryType::Entity(query_value),
        QtypeArg::Ns => QueryType::ns(&query_value)?,
        QtypeArg::EntityName => QueryType::EntityNameSearch(query_value),
        QtypeArg::EntityHandle => QueryType::EntityHandleSearch(query_value),
        QtypeArg::NetHandle => QueryType::NetworkHandleSearch(query_value),
        QtypeArg::NetName => QueryType::NetworkNameSearch(query_value),
        QtypeArg::AutnumHandle => QueryType::AutnumHandleSearch(query_value),
        QtypeArg::AutnumName => QueryType::AutnumNameSearch(query_value),
        QtypeArg::DomainName => QueryType::DomainNameSearch(query_value),
        QtypeArg::DomainNsName => QueryType::DomainNsNameSearch(query_value),
        QtypeArg::DomainNsIp => QueryType::domain_ns_ip_search(&query_value)?,
        QtypeArg::NsName => QueryType::NameserverNameSearch(query_value),
        QtypeArg::NsIp => QueryType::ns_ip_search(&query_value)?,
        QtypeArg::Url => QueryType::Url(query_value),
    };
    Ok(q)
}

/// If something is a hostname, then convert it to base URL
fn hostname_to_baseurl(s: &str) -> String {
    if s.is_ldh_hostname() {
        format!("https://{s}")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use std::collections::HashSet;

    use crate::{Cli, hostname_to_baseurl};

    #[test]
    fn cli_debug_assert_test() {
        use clap::CommandFactory;
        Cli::command().debug_assert()
    }

    #[rstest]
    #[case("foo.bar", "https://foo.bar")]
    #[case("https://foo.bar", "https://foo.bar")]
    fn test_hostname_to_baseurl(#[case] test_string: &str, #[case] expected: &str) {
        // GIVEN in parameters

        // WHEN
        let actual = hostname_to_baseurl(test_string);

        // THEN
        assert_eq!(&actual, expected);
    }

    #[test]
    fn test_rdap_env_has_all_cli_env_vars() {
        use clap::CommandFactory;

        // GIVEN - parse rdap.env and collect env var names (both commented and uncommented)
        let env_content = include_str!("../../dirs/rdap.env");
        let mut env_vars: HashSet<String> = HashSet::new();
        for line in env_content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // uncommented line: VARNAME=value
            if let Some(eq_pos) = trimmed.find('=') {
                env_vars.insert(trimmed[..eq_pos].to_string());
            }
        }
        // also check commented lines: #VARNAME=value, # VARNAME=value, or #VARNAME
        for line in env_content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let check = if let Some(my_trimmed) = trimmed.strip_prefix('#') {
                my_trimmed
            } else {
                trimmed
            };
            let check = check.trim_start();
            if let Some(eq_pos) = check.find('=') {
                env_vars.insert(check[..eq_pos].trim().to_string());
            } else {
                // line like #RDAP_BASE_URL with no = sign
                let name = check.trim();
                if !name.is_empty() && !name.starts_with('#') {
                    env_vars.insert(name.to_string());
                }
            }
        }

        // WHEN - collect env var names from Cli arguments
        let command = Cli::command();
        let mut missing: Vec<String> = Vec::new();
        for arg in command.get_arguments() {
            if let Some(env_name) = arg.get_env() {
                let env_str = env_name.to_str().unwrap_or_default();
                if !env_vars.contains(env_str) {
                    missing.push(env_str.to_string());
                }
            }
        }

        // THEN - all Cli args with env attributes must have a corresponding line in rdap.env
        if !missing.is_empty() {
            missing.sort();
            panic!(
                "rdap.env is missing environment variables for the following Cli args: {}",
                missing.join(", ")
            );
        }
    }
}
