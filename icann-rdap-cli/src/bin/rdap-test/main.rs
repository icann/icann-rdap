use std::io::stdout;
use std::str::FromStr;

use clap::builder::styling::AnsiColor;
use clap::builder::Styles;
use error::RdapTestError;
use icann_rdap_cli::dirs;
use icann_rdap_cli::dirs::fcbs::FileCacheBootstrapStore;
use icann_rdap_cli::rt::exec::execute_tests;
use icann_rdap_cli::rt::exec::TestOptions;
use icann_rdap_client::client::ClientConfig;
use icann_rdap_client::md::MdOptions;
use icann_rdap_client::QueryType;
use icann_rdap_common::check::CheckClass;
use termimad::crossterm::style::Color::*;
use termimad::Alignment;
use termimad::MadSkin;
use tracing_subscriber::filter::LevelFilter;

use clap::{Parser, ValueEnum};
use icann_rdap_common::VERSION;

pub mod error;

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
/// This program aids in the troubleshooting of issues with RDAP servers.
struct Cli {
    /// Value to be queried in RDAP.
    ///
    /// This is the value to query. For example, a domain name or IP address.
    #[arg()]
    query_value: String,

    /// Output format.
    ///
    /// This option determines the format of the result.
    #[arg(
        short = 'O',
        long,
        required = false,
        env = "RDAP_TEST_OUTPUT",
        value_enum,
        default_value_t = OtypeArg::RenderedMarkdown,
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

    /// Log level.
    ///
    /// This option determines the level of logging.
    #[arg(
        short = 'L',
        long,
        required = false,
        env = "RDAP_TEST_LOG",
        value_enum,
        default_value_t = LogLevel::Info
    )]
    log_level: LogLevel,

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
        env = "RDAP_TEST_ALLOW_INVALID_HOST_NAMES"
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
        env = "RDAP_TEST_ALLOW_INVALID_CERTIFICATES"
    )]
    allow_invalid_certificates: bool,

    /// Reset.
    ///
    /// Removes the cache files and resets the config file.
    #[arg(long, required = false)]
    reset: bool,
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
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum CheckTypeArg {
    /// Informational items.
    Info,

    /// Checks for STD 95 warnings.
    SpecWarn,

    /// Checks for STD 95 errors.
    SpecError,

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
pub async fn main() -> RdapTestError {
    if let Err(e) = wrapped_main().await {
        eprintln!("\n{e}\n");
        return e;
    } else {
        return RdapTestError::Success;
    }
}

pub async fn wrapped_main() -> Result<(), RdapTestError> {
    dirs::init()?;
    dotenv::from_path(dirs::config_path()).ok();
    let cli = Cli::parse();

    if cli.reset {
        dirs::reset()?;
        return Ok(());
    }

    let level = LevelFilter::from(&cli.log_level);
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .init();

    let query_type = QueryType::from_str(&cli.query_value)?;

    let _check_types = if cli.check_type.is_empty() {
        vec![
            CheckClass::SpecificationWarning,
            CheckClass::SpecificationError,
            CheckClass::Cidr0Error,
            CheckClass::IcannError,
        ]
    } else {
        cli.check_type
            .iter()
            .map(|c| match c {
                CheckTypeArg::Info => CheckClass::Informational,
                CheckTypeArg::SpecWarn => CheckClass::SpecificationWarning,
                CheckTypeArg::SpecError => CheckClass::SpecificationError,
                CheckTypeArg::Cidr0Error => CheckClass::Cidr0Error,
                CheckTypeArg::IcannError => CheckClass::IcannError,
            })
            .collect::<Vec<CheckClass>>()
    };

    let bs = FileCacheBootstrapStore;

    let options = TestOptions::default();

    let client_config = ClientConfig::builder()
        .user_agent_suffix("RT")
        .https_only(!cli.allow_http)
        .accept_invalid_host_names(cli.allow_invalid_host_names)
        .accept_invalid_certificates(cli.allow_invalid_certificates)
        .build();

    // execute tests
    let test_results = execute_tests(&bs, &query_type, &options, &client_config).await?;

    // output results
    let md_options = MdOptions::default();
    match cli.output_type {
        OtypeArg::RenderedMarkdown => {
            let mut skin = MadSkin::default_dark();
            skin.set_headers_fg(Yellow);
            skin.headers[1].align = Alignment::Center;
            skin.headers[2].align = Alignment::Center;
            skin.headers[3].align = Alignment::Center;
            skin.headers[4].compound_style.set_fg(DarkGreen);
            skin.headers[5].compound_style.set_fg(Magenta);
            skin.headers[6].compound_style.set_fg(Cyan);
            skin.headers[7].compound_style.set_fg(Red);
            skin.bold.set_fg(DarkBlue);
            skin.italic.set_fg(Red);
            skin.quote_mark.set_fg(DarkBlue);
            skin.table.set_fg(DarkGreen);
            skin.table.align = Alignment::Center;
            skin.inline_code.set_fgbg(Cyan, Reset);
            skin.write_text_on(&mut stdout(), &test_results.to_md(&md_options))?;
        }
        OtypeArg::Markdown => {
            println!("{}", test_results.to_md(&md_options));
        }
        OtypeArg::Json => {
            println!("{}", serde_json::to_string(&test_results).unwrap());
        }
        OtypeArg::PrettyJson => {
            println!("{}", serde_json::to_string_pretty(&test_results).unwrap());
        }
    }

    Ok(())
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
