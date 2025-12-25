use clap::{arg, ArgGroup, Parser};
use icann_rdap_client::rdap::QueryType;

#[derive(Parser, Debug)]
#[command(group(
            ArgGroup::new("target")
                .args(["link_target", "registry", "registrar", "up", "down", "bottom", "top"]),
        ))]
pub struct LinkTargetArgs {
    /// Link Target
    ///
    /// Specifies a link target. If no link target is given, the
    /// default is "related". More than one link target may be given.
    /// A value of "_none" indicates no link target.
    #[arg(long, required = false, value_enum)]
    link_target: Vec<String>,

    /// Only Show Link Target
    ///
    /// Unless specified, all responses are shown.
    /// When specified, only the link target is shown.
    #[arg(long, required = false)]
    only_show_target: Option<bool>,

    /// The minimum number of times to query for a link target.
    #[arg(long, required = false)]
    min_link_depth: Option<usize>,

    /// The maximum number of times to query for a link target.
    #[arg(long, required = false)]
    max_link_depth: Option<usize>,

    /// Set link target parameters for a domain registry.
    #[arg(long, required = false, conflicts_with = "link_target")]
    registry: bool,

    /// Set link target parameters for a domain registrar.
    #[arg(long, required = false, conflicts_with = "link_target")]
    registrar: bool,

    /// Set link target parameters for a parent network.
    #[arg(long, required = false, conflicts_with = "link_target")]
    up: bool,

    /// Set link target parameters for the child networks.
    #[arg(long, required = false, conflicts_with = "link_target")]
    down: bool,

    /// Set link target parameters for the least specific network.
    #[arg(long, required = false, conflicts_with = "link_target")]
    top: bool,

    /// Set link target parameters for the most specific networks.
    #[arg(long, required = false, conflicts_with = "link_target")]
    bottom: bool,
}

#[derive(Clone)]
pub struct LinkParams {
    pub link_targets: Vec<String>,
    pub only_show_target: bool,
    pub min_link_depth: usize,
    pub max_link_depth: usize,
}

pub fn default_link_params(query_type: &QueryType) -> LinkParams {
    match query_type {
        QueryType::IpV4Addr(_)
        | QueryType::IpV6Addr(_)
        | QueryType::IpV4Cidr(_)
        | QueryType::IpV6Cidr(_)
        | QueryType::AsNumber(_) => LinkParams {
            link_targets: vec![],
            only_show_target: false,
            min_link_depth: 1,
            max_link_depth: 1,
        },
        QueryType::Domain(_) => LinkParams {
            link_targets: vec!["related".to_string()],
            only_show_target: false,
            min_link_depth: 1,
            max_link_depth: 3,
        },
        _ => LinkParams {
            link_targets: vec![],
            only_show_target: false,
            min_link_depth: 1,
            max_link_depth: 1,
        },
    }
}

pub fn params_from_args(query_type: &QueryType, args: LinkTargetArgs) -> LinkParams {
    if args.registry {
        LinkParams {
            link_targets: vec![],
            only_show_target: false,
            min_link_depth: 1,
            max_link_depth: 1,
        }
    } else if args.registrar {
        LinkParams {
            link_targets: vec!["related".to_string()],
            only_show_target: true,
            min_link_depth: 2,
            max_link_depth: 3,
        }
    } else if args.up {
        LinkParams {
            link_targets: vec!["rdap-up".to_string(), "rdap-active".to_string()],
            only_show_target: true,
            min_link_depth: 2,
            max_link_depth: 2,
        }
    } else if args.down {
        LinkParams {
            link_targets: vec!["rdap-down".to_string(), "rdap-active".to_string()],
            only_show_target: true,
            min_link_depth: 2,
            max_link_depth: 2,
        }
    } else if args.top {
        LinkParams {
            link_targets: vec!["rdap-top".to_string(), "rdap-active".to_string()],
            only_show_target: true,
            min_link_depth: 2,
            max_link_depth: 2,
        }
    } else if args.bottom {
        LinkParams {
            link_targets: vec!["rdap-bottom".to_string(), "rdap-active".to_string()],
            only_show_target: true,
            min_link_depth: 2,
            max_link_depth: 2,
        }
    } else if args.link_target.contains(&"_none".to_string()) {
        let def_link_params = default_link_params(query_type);
        LinkParams {
            link_targets: vec![],
            only_show_target: args
                .only_show_target
                .unwrap_or(def_link_params.only_show_target),
            min_link_depth: args
                .min_link_depth
                .unwrap_or(def_link_params.min_link_depth),
            max_link_depth: args
                .max_link_depth
                .unwrap_or(def_link_params.max_link_depth),
        }
    } else {
        let def_link_params = default_link_params(query_type);
        LinkParams {
            link_targets: match args.link_target.is_empty() {
                true => def_link_params.link_targets,
                false => args.link_target,
            },
            only_show_target: args
                .only_show_target
                .unwrap_or(def_link_params.only_show_target),
            min_link_depth: args
                .min_link_depth
                .unwrap_or(def_link_params.min_link_depth),
            max_link_depth: args
                .max_link_depth
                .unwrap_or(def_link_params.max_link_depth),
        }
    }
}
