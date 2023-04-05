use std::str::FromStr;

use clap::{ArgGroup, Parser, ValueEnum};
use icann_rdap_client::query::qtype::QueryType;

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
        default_value_t = OutputType::AnsiText,
    )]
    output: OutputType,
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
}

pub fn main() {
    dotenv::dotenv().ok();
    let cli = Cli::parse();
    let query_type = query_type_from_cli(&cli);
    println!("query type is {query_type}");
    println!(
        "rdap url is {}",
        query_type.query_url("https://example.com").unwrap()
    );
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

#[cfg(test)]
mod tests {
    use crate::Cli;

    #[test]
    fn cli_debug_assert_test() {
        use clap::CommandFactory;
        Cli::command().debug_assert()
    }
}
