use std::io::stdout;
use std::str::FromStr;

use clap::builder::styling::AnsiColor;
use clap::builder::Styles;
use error::RdapTestError;
use icann_rdap_cli::dirs;
use icann_rdap_cli::dirs::fcbs::FileCacheBootstrapStore;
use icann_rdap_cli::rt::exec::execute_tests;
use icann_rdap_cli::rt::exec::ExtensionGroup;
use icann_rdap_cli::rt::exec::TestOptions;
use icann_rdap_cli::rt::results::RunOutcome;
use icann_rdap_cli::rt::results::TestResults;
use icann_rdap_client::client::ClientConfig;
use icann_rdap_client::md::MdOptions;
use icann_rdap_client::QueryType;
use icann_rdap_common::check::traverse_checks;
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

    /// Skip v4.
    ///
    /// Skip testing of IPv4 connections.
    #[arg(long, required = false, env = "RDAP_TEST_SKIP_v4")]
    skip_v4: bool,

    /// Skip v6.
    ///
    /// Skip testing of IPv6 connections.
    #[arg(long, required = false, env = "RDAP_TEST_SKIP_V6")]
    skip_v6: bool,

    /// Skip origin tests.
    ///
    /// Skip testing with the HTTP origin header.
    #[arg(long, required = false, env = "RDAP_TEST_SKIP_ORIGIN")]
    skip_origin: bool,

    /// Origin header value.
    ///
    /// Specifies the origin header value.
    /// This value is not used if the 'skip-origin' option is used.
    #[arg(
        long,
        required = false,
        env = "RDAP_TEST_ORIGIN_VALUE",
        default_value = "https://example.com"
    )]
    origin_value: String,

    /// Follow redirects.
    ///
    /// When set, follows HTTP redirects.
    #[arg(
        short = 'R',
        long,
        required = false,
        env = "RDAP_TEST_FOLLOW_REDIRECTS"
    )]
    follow_redirects: bool,

    /// Chase a referral.
    ///
    /// Get a referral in the first response and use that for testing. This is useful
    /// for testing registrars by using the normal bootstrapping process to get the
    /// referral to the registrar from the registry.
    #[arg(short = 'r', long, required = false)]
    referral: bool,

    /// Expect extension.
    ///
    /// Expect the RDAP response to contain a specific extension ID.
    /// If a response does not contain the expected RDAP extension ID,
    /// it will be added as an failed check. This parameter may also
    /// take the form of "foo1|foo2" to be mean either expect "foo1" or
    /// "foo2".
    ///
    /// This value may be repeated more than once.
    #[arg(
        short = 'e',
        long,
        required = false,
        env = "RDAP_TEST_EXPECT_EXTENSIONS"
    )]
    expect_extensions: Vec<String>,

    /// Expect extension group.
    ///
    /// Extension groups are known sets of extensions.
    ///
    /// This value may be repeated more than once.
    #[arg(
        short = 'g',
        long,
        required = false,
        value_enum,
        env = "RDAP_TEST_EXPECT_EXTENSION_GROUP"
    )]
    expect_group: Vec<ExtensionGroupArg>,

    /// Allow unregistered extensions.
    ///
    /// Do not flag unregistered extensions.
    #[arg(
        short = 'E',
        long,
        required = false,
        env = "RDAP_TEST_ALLOW_UNREGISTERED_EXTENSIONS"
    )]
    allow_unregistered_extensions: bool,
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
enum ExtensionGroupArg {
    /// The gTLD RDAP profiles.
    Gtld,

    /// The base NRO profiles.
    Nro,

    /// The NRO ASN profiles including the base profile.
    NroAsn,
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

    let level = LevelFilter::from(&cli.log_level);
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .init();

    let query_type = QueryType::from_str(&cli.query_value)?;

    let check_classes = if cli.check_type.is_empty() {
        vec![
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

    let mut expect_groups = vec![];
    for g in cli.expect_group {
        match g {
            ExtensionGroupArg::Gtld => expect_groups.push(ExtensionGroup::Gtld),
            ExtensionGroupArg::Nro => expect_groups.push(ExtensionGroup::Nro),
            ExtensionGroupArg::NroAsn => expect_groups.push(ExtensionGroup::NroAsn),
        }
    }

    let bs = FileCacheBootstrapStore;

    let options = TestOptions {
        skip_v4: cli.skip_v4,
        skip_v6: cli.skip_v6,
        skip_origin: cli.skip_origin,
        origin_value: cli.origin_value,
        chase_referral: cli.referral,
        expect_extensions: cli.expect_extensions,
        expect_groups,
        allow_unregistered_extensions: cli.allow_unregistered_extensions,
    };

    let client_config = ClientConfig::builder()
        .user_agent_suffix("RT")
        .https_only(!cli.allow_http)
        .accept_invalid_host_names(cli.allow_invalid_host_names)
        .accept_invalid_certificates(cli.allow_invalid_certificates)
        .follow_redirects(cli.follow_redirects)
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
            skin.write_text_on(
                &mut stdout(),
                &test_results.to_md(&md_options, &check_classes),
            )?;
        }
        OtypeArg::Markdown => {
            println!("{}", test_results.to_md(&md_options, &check_classes));
        }
        OtypeArg::Json => {
            println!("{}", serde_json::to_string(&test_results).unwrap());
        }
        OtypeArg::PrettyJson => {
            println!("{}", serde_json::to_string_pretty(&test_results).unwrap());
        }
    }

    // if some tests could not execute
    //
    let execution_errors = test_results
        .test_runs
        .iter()
        .filter(|r| !matches!(r.outcome, RunOutcome::Tested | RunOutcome::Skipped))
        .count();
    if execution_errors != 0 {
        return Err(RdapTestError::TestsCompletedExecutionErrors);
    }

    // if tests had check errors
    //
    // get the error classes but only if they were specified.
    let error_classes = check_classes
        .iter()
        .filter(|c| {
            matches!(
                c,
                CheckClass::StdError | CheckClass::Cidr0Error | CheckClass::IcannError
            )
        })
        .copied()
        .collect::<Vec<CheckClass>>();
    // return proper exit code if errors found
    if are_there_checks(error_classes, &test_results) {
        return Err(RdapTestError::TestsCompletedErrorsFound);
    }

    // if tests had check warnings
    //
    // get the warning classes but only if they were specified.
    let warning_classes = check_classes
        .iter()
        .filter(|c| matches!(c, CheckClass::StdWarning))
        .copied()
        .collect::<Vec<CheckClass>>();
    // return proper exit code if errors found
    if are_there_checks(warning_classes, &test_results) {
        return Err(RdapTestError::TestsCompletedWarningsFound);
    }

    Ok(())
}

fn are_there_checks(classes: Vec<CheckClass>, test_results: &TestResults) -> bool {
    // see if there are any checks in the test runs
    let run_count = test_results
        .test_runs
        .iter()
        .filter(|r| {
            if let Some(checks) = &r.checks {
                traverse_checks(checks, &classes, None, &mut |_, _| {})
            } else {
                false
            }
        })
        .count();
    // see if there are any classes in the service checks
    let service_count = test_results
        .service_checks
        .iter()
        .filter(|c| classes.contains(&c.check_class))
        .count();
    run_count + service_count != 0
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
