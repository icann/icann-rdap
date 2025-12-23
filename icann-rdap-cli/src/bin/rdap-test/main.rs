use std::{
    io::{stdout, Read},
    str::FromStr,
};

use clap::Args;
use icann_rdap_cli::rt::exec::{HttpTestOptions, StringTestOptions, TestType};
use icann_rdap_common::check::{ALL_CHECK_CLASSES, ERROR_CHECK_CLASSES, WARNING_CHECK_CLASSES};
#[cfg(debug_assertions)]
use tracing::warn;
use {
    clap::builder::{styling::AnsiColor, Styles},
    error::RdapTestError,
    icann_rdap_cli::{
        dirs,
        dirs::fcbs::FileCacheBootstrapStore,
        rt::exec::{execute_tests, ExtensionGroup, TestOptions},
    },
    icann_rdap_client::{http::ClientConfig, md::MdOptions, rdap::QueryType},
    icann_rdap_common::check::CheckClass,
    termimad::{crossterm::style::Color::*, Alignment, MadSkin},
    tracing::info,
    tracing_subscriber::filter::LevelFilter,
};

use {
    clap::{Parser, ValueEnum},
    icann_rdap_common::VERSION,
};

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
    #[command(flatten)]
    http: HttpArgGroup,

    #[command(flatten)]
    file: FileInputArgGroup,

    #[command(flatten)]
    pipe: PipeInputArgGroup,

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

#[derive(Args, Debug)]
#[group(id = "http", multiple = true, conflicts_with_all = ["file", "pipe"])]
struct HttpArgGroup {
    /// Value to be queried in RDAP.
    ///
    /// This is the value to query. For example, a domain name or IP address.
    #[arg(required = false)]
    query_value: Option<String>,

    /// DNS Resolver
    ///
    /// Specifies the address and port of the DNS resolver to query.
    #[arg(
        long,
        required = false,
        env = "RDAP_TEST_DNS_RESOLVER",
        default_value = "8.8.8.8:53"
    )]
    dns_resolver: String,

    /// Allow HTTP connections.
    ///
    /// When given, allows connections to RDAP servers using HTTP.
    /// Otherwise, only HTTPS is allowed.
    #[arg(short = 'T', long, required = false, env = "RDAP_TEST_ALLOW_HTTP")]
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

    /// Maximum retry wait time.
    ///
    /// Sets the maximum number of seconds to wait before retrying a query when
    /// a server has sent an HTTP 429 status code with a retry-after value.
    /// That is, the value to used is no greater than this setting.
    #[arg(
        long,
        required = false,
        env = "RDAP_TEST_MAX_RETRY_SECS",
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
        env = "RDAP_TEST_DEF_RETRY_SECS",
        default_value = "60"
    )]
    def_retry_secs: u32,

    /// Maximum number of retries.
    ///
    /// This sets the maximum number of retries when a server signals too many
    /// requests have been sent using an HTTP 429 status code.
    #[arg(
        long,
        required = false,
        env = "RDAP_TEST_MAX_RETRIES",
        default_value = "1"
    )]
    max_retries: u16,

    /// Set the query timeout.
    ///
    /// This values specifies, in seconds, the total time to connect and read all
    /// the data from a connection.
    #[arg(
        long,
        required = false,
        env = "RDAP_TEST_TIMEOUT_SECS",
        default_value = "60"
    )]
    timeout_secs: u64,

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

    /// Only test one address.
    ///
    /// Only test one address per address family.
    #[arg(long, required = false, env = "RDAP_TEST_ONE_ADDR")]
    one_addr: bool,

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
}

#[derive(Args, Debug)]
#[group(id = "file", multiple = true, conflicts_with_all = ["http", "pipe"])]
struct FileInputArgGroup {
    /// File to test.
    ///
    /// Specifies a file to read.
    #[arg(long, required = false)]
    in_file: Option<String>,
}

#[derive(Args, Debug)]
#[group(id = "pipe", multiple = true, conflicts_with_all = ["http", "file"])]
struct PipeInputArgGroup {
    /// Read file from stdin.
    #[arg(long, required = false)]
    stdin: bool,
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
    /// All warnings and errors.
    Warning,

    /// All errors.
    Error,

    /// Informational items.
    Info,

    /// Specification Notes
    SpecNote,

    /// Checks for STD 95 warnings.
    Std95Warn,

    /// Checks for STD 95 errors.
    Std95Error,

    /// Cidr0 errors.
    Cidr0Error,

    /// Gtld Profile errors.
    GtldProfileError,
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
pub async fn main() -> RdapTestError {
    if let Err(e) = wrapped_main().await {
        eprintln!("\n{e}");
        match e {
            RdapTestError::TestsCompletedExecutionErrors
            | RdapTestError::TestsCompletedWarningsFound
            | RdapTestError::TestsCompletedErrorsFound
            | RdapTestError::RdapClient(_)
            | RdapTestError::IoError(_)
            | RdapTestError::Json(_) => {
                eprintln!("Service issues may be reported to globalsupport@icann.org.\n")
            }
            _ => {
                eprintln!()
            }
        }
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

    info!("ICANN RDAP {} Testing Tool", VERSION);

    #[cfg(debug_assertions)]
    warn!("This is a development build of this software.");

    let check_classes = if cli.check_type.is_empty() {
        ALL_CHECK_CLASSES.to_owned()
    } else if cli.check_type.contains(&CheckTypeArg::Warning) {
        WARNING_CHECK_CLASSES.to_owned()
    } else if cli.check_type.contains(&CheckTypeArg::Error) {
        ERROR_CHECK_CLASSES.to_owned()
    } else {
        cli.check_type
            .iter()
            .map(|c| match c {
                CheckTypeArg::Info => CheckClass::Informational,
                CheckTypeArg::SpecNote => CheckClass::SpecificationNote,
                CheckTypeArg::Std95Warn => CheckClass::Std95Warning,
                CheckTypeArg::Std95Error => CheckClass::Std95Error,
                CheckTypeArg::Cidr0Error => CheckClass::Cidr0Error,
                CheckTypeArg::GtldProfileError => CheckClass::GtldProfileError,
                _ => panic!("check type should have been handled."),
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

    let client_config = ClientConfig::builder()
        .user_agent_suffix("RT")
        .https_only(!cli.http.allow_http)
        .accept_invalid_host_names(cli.http.allow_invalid_host_names)
        .accept_invalid_certificates(cli.http.allow_invalid_certificates)
        .follow_redirects(cli.http.follow_redirects)
        .timeout_secs(cli.http.timeout_secs)
        .max_retry_secs(cli.http.max_retry_secs)
        .def_retry_secs(cli.http.def_retry_secs)
        .max_retries(cli.http.max_retries)
        .build();

    let test_type = if cli.http.query_value.is_some() {
        TestType::Http(HttpTestOptions {
            skip_v4: cli.http.skip_v4,
            skip_v6: cli.http.skip_v6,
            skip_origin: cli.http.skip_origin,
            origin_value: cli.http.origin_value,
            chase_referral: cli.http.referral,
            one_addr: cli.http.one_addr,
            dns_resolver: Some(cli.http.dns_resolver),
            value: QueryType::from_str(&cli.http.query_value.unwrap_or_default())?,
            client_config,
        })
    } else {
        let mut json = String::new();
        if let Some(in_file) = cli.file.in_file {
            json.push_str(&std::fs::read_to_string(in_file)?);
        } else {
            std::io::stdin().read_to_string(&mut json)?;
        };
        TestType::String(StringTestOptions { json })
    };

    let options = TestOptions {
        expect_extensions: cli.expect_extensions,
        expect_groups,
        allow_unregistered_extensions: cli.allow_unregistered_extensions,
        test_type,
    };

    // execute tests
    let test_results = execute_tests(&bs, &options).await?;

    // filtered test results
    let test_results = test_results.filter_test_results(check_classes.clone());

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
            skin.table.set_fg(DarkGrey);
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

    // if some tests could not execute
    //
    if test_results.execution_errors() {
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
                CheckClass::Std95Error | CheckClass::Cidr0Error | CheckClass::GtldProfileError
            )
        })
        .copied()
        .collect::<Vec<CheckClass>>();
    // return proper exit code if errors found
    if test_results.are_there_checks(error_classes) {
        return Err(RdapTestError::TestsCompletedErrorsFound);
    }

    // if tests had check warnings
    //
    // get the warning classes but only if they were specified.
    let warning_classes = check_classes
        .iter()
        .filter(|c| matches!(c, CheckClass::Std95Warning))
        .copied()
        .collect::<Vec<CheckClass>>();
    // return proper exit code if errors found
    if test_results.are_there_checks(warning_classes) {
        return Err(RdapTestError::TestsCompletedWarningsFound);
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
