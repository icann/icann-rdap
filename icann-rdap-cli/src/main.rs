use std::{io::ErrorKind, str::FromStr};

use clap::{ArgGroup, Parser, ValueEnum};
use error::CliError;
use icann_rdap_client::{
    check::CheckType,
    client::{create_client, ClientConfig},
    md::{MdOptions, MdParams, ToMd},
    query::{qtype::QueryType, request::rdap_request},
};
use icann_rdap_common::{response::RdapResponse, VERSION};
use is_terminal::IsTerminal;
use reqwest::Client;
use simplelog::{
    error, info, ColorChoice, Config, LevelFilter, TermLogger, TerminalMode, WriteLogger,
};
use termimad::{crossterm::style::Color::*, MadSkin};
use tokio::{join, task::spawn_blocking};

pub mod error;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about)]
#[command(group(
            ArgGroup::new("input")
                .required(true)
                .args(["query_value", "url", "server_help"]),
        ))]
#[command(group(
            ArgGroup::new("base_specify")
                .args(["base", "base_url"]),
        ))]
/// An RDAP client.
///
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

    /// Perform a query using a specifc URL.
    ///
    /// When used, no query or base URL lookup will be used. Insteead, the
    /// given URL will be sent to the RDAP server in the URL directly.
    #[arg(short = 'u', long)]
    url: Option<String>,

    /// Get an RDAP server's help information.
    ///
    /// Ask for a server's help information.
    #[arg(short = 'S', long, conflicts_with = "query_type")]
    server_help: bool,

    /// An RDAP base signifier.
    ///
    /// This option gets a base URL from the RDAP bootstrap registry maintained
    /// by IANA. For example, using "com" will get the base URL for the .com
    /// registry.
    #[arg(
        short = 'b',
        long,
        conflicts_with = "url",
        required = false,
        env = "RDAP_BASE"
    )]
    base: Option<String>,

    /// An RDAP base URL for a specific RDAP server.
    ///
    /// Use this option to explicitly give an RDAP base URL when issuing queries.
    /// If not specified, the base URL will come from the RDAP boostrap process
    /// outline in RFC 9224.
    #[arg(
        short = 'B',
        long,
        conflicts_with = "url",
        required = false,
        env = "RDAP_BASE_URL"
    )]
    base_url: Option<String>,

    /// Output format.
    ///
    /// This option determines the format of the result.
    #[arg(
        short = 'O',
        long,
        required = false,
        env = "RDAP_OUTPUT",
        value_enum,
        default_value_t = OutputType::Auto,
    )]
    output_type: OutputType,

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
        default_value_t = PagerType::Auto,
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
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OutputType {
    /// Results are rendered as Markdown in the terminal using ANSI terminal capabilities.
    AnsiText,

    /// Results are rendered as Markdown in plain text.
    Markdown,

    /// Results are output as JSON.
    Json,

    /// Results are output as Pretty JSON.
    PrettyJson,

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

impl From<&LogLevel> for LevelFilter {
    fn from(log_level: &LogLevel) -> Self {
        match log_level {
            LogLevel::Off => LevelFilter::Off,
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Trace => LevelFilter::Trace,
        }
    }
}

#[tokio::main]
pub async fn main() -> Result<(), CliError> {
    dotenv::dotenv().ok();
    let cli = Cli::parse();

    let level = LevelFilter::from(&cli.log_level);

    let query_type = query_type_from_cli(&cli);

    let use_pager = match cli.page_output {
        PagerType::Embedded => true,
        PagerType::None => false,
        PagerType::Auto => std::io::stdout().is_terminal(),
    };

    let output_type = match cli.output_type {
        OutputType::Auto => {
            if std::io::stdout().is_terminal() {
                OutputType::AnsiText
            } else {
                OutputType::Json
            }
        }
        _ => cli.output_type,
    };

    let client_config = ClientConfig {
        user_agent_suffix: "CLI".to_string(),
    };
    let rdap_client = create_client(&client_config);
    if let Ok(client) = rdap_client {
        if !use_pager {
            TermLogger::init(
                level,
                Config::default(),
                TerminalMode::Stderr,
                ColorChoice::Auto,
            )
            .expect("Error instantiating log output.");
            info!("ICANN RDAP {} Command Line Interface", VERSION);
            if let Some(query_value) = cli.query_value {
                info!("query type is {query_type} for value '{}'", query_value);
            } else {
                info!("query is {query_type}");
            }
            let result = do_query(
                "https://rdap-bootstrap.arin.net/bootstrap",
                &query_type,
                &output_type,
                &client,
                &mut std::io::stdout(),
            )
            .await;
            match result {
                Ok(_) => {}
                Err(error) => error!("{}", error),
            }
        } else {
            let pager = minus::Pager::new();
            let mut output = BridgeWriter(pager.clone());

            let exec = async {
                WriteLogger::init(level, Config::default(), output.clone())
                    .expect("Error instantiating log output.");
                info!("ICANN RDAP {} Command Line Interface", VERSION);
                if let Some(query_value) = cli.query_value {
                    info!("query type is {query_type} for value '{}'", query_value);
                } else {
                    info!("query is {query_type}");
                }
                let result = do_query(
                    "https://rdap-bootstrap.arin.net/bootstrap",
                    &query_type,
                    &output_type,
                    &client,
                    &mut output,
                )
                .await;
                match result {
                    Ok(_) => {}
                    Err(error) => error!("{}", error),
                }
            };
            let pager = pager.clone();
            let (res1, _res2) = join!(spawn_blocking(move || minus::dynamic_paging(pager)), exec);
            res1.unwrap()?;
        }
    } else {
        error!("{}", rdap_client.err().unwrap())
    };
    Ok(())
}

fn query_type_from_cli(cli: &Cli) -> QueryType {
    if let Some(query_value) = cli.query_value.clone() {
        if let Some(query_type) = cli.query_type {
            match query_type {
                QtypeArg::V4 => QueryType::IpV4Addr(query_value),
                QtypeArg::V6 => QueryType::IpV6Addr(query_value),
                QtypeArg::V4Cidr => QueryType::IpV4Cidr(query_value),
                QtypeArg::V6Cidr => QueryType::IpV6Cidr(query_value),
                QtypeArg::Autnum => QueryType::AsNumber(query_value),
                QtypeArg::Domain => QueryType::Domain(query_value),
                QtypeArg::Entity => QueryType::Entity(query_value),
                QtypeArg::Ns => QueryType::Nameserver(query_value),
                QtypeArg::EntityName => QueryType::EntityNameSearch(query_value),
                QtypeArg::EntityHandle => QueryType::EntityHandleSearch(query_value),
                QtypeArg::DomainName => QueryType::DomainNameSearch(query_value),
                QtypeArg::DomainNsName => QueryType::DomainNsNameSearch(query_value),
                QtypeArg::DomainNsIp => QueryType::DomainNsIpSearch(query_value),
                QtypeArg::NsName => QueryType::NameserverNameSearch(query_value),
                QtypeArg::NsIp => QueryType::NameserverIpSearch(query_value),
            }
        } else {
            QueryType::from_str(&query_value).unwrap()
        }
    } else if let Some(url) = cli.url.clone() {
        QueryType::Url(url)
    } else {
        QueryType::Help
    }
}

async fn do_query<W: std::io::Write>(
    base_url: &str,
    query_type: &QueryType,
    output_type: &OutputType,
    client: &Client,
    write: &mut W,
) -> Result<(), CliError> {
    let result = rdap_request(base_url, query_type, client).await;
    match result {
        Ok(result) => print_response(output_type, result, write)?,
        Err(error) => return Err(CliError::RdapClient(error)),
    };
    Ok(())
}

fn print_response<W: std::io::Write>(
    output_type: &OutputType,
    response: RdapResponse,
    write: &mut W,
) -> Result<(), CliError> {
    match output_type {
        OutputType::AnsiText => {
            let mut skin = MadSkin::default_dark();
            skin.set_headers_fg(Yellow);
            skin.bold.set_fg(Magenta);
            skin.italic.set_fg(Blue);
            skin.quote_mark.set_fg(White);
            skin.write_text_on(
                write,
                &response.to_md(MdParams {
                    heading_level: 1,
                    check_types: &[CheckType::Informational, CheckType::SpecificationCompliance],
                    options: &MdOptions::default(),
                }),
            )?;
        }
        OutputType::Markdown => writeln!(
            write,
            "{}",
            response.to_md(MdParams {
                heading_level: 1,
                check_types: &[CheckType::Informational, CheckType::SpecificationCompliance],
                options: &MdOptions {
                    text_style_char: '_',
                    style_in_justify: true,
                    ..MdOptions::default()
                }
            })
        )?,
        OutputType::Json => writeln!(write, "{}", serde_json::to_string(&response).unwrap())?,
        OutputType::PrettyJson => writeln!(
            write,
            "{}",
            serde_json::to_string_pretty(&response).unwrap()
        )?,
        OutputType::Auto => return Err(CliError::UnknownOutputType),
    };
    Ok(())
}

#[derive(Clone)]
struct BridgeWriter<W: std::fmt::Write>(W);

impl<W: std::fmt::Write> std::io::Write for BridgeWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .write_str(&String::from_utf8_lossy(buf))
            .map_err(|e| std::io::Error::new(ErrorKind::Other, e))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
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
