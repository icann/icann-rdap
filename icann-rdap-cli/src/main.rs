use clap::{ArgGroup, Parser, ValueEnum};

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
    #[arg(short = 'b', long, conflicts_with = "url", required = false)]
    base: Option<String>,

    /// An RDAP base URL for a specific RDAP server.
    ///
    /// Use this option to explicitly give an RDAP base URL when issuing queries.
    /// If not specified, the base URL will come from the RDAP boostrap process
    /// outline in RFC 9224.
    #[arg(short = 'B', long, conflicts_with = "url", required = false)]
    base_url: Option<String>,
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

pub fn main() {
    let _cli = Cli::parse();
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
