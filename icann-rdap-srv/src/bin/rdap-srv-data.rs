use {
    chrono::{DateTime, FixedOffset, Utc},
    cidr::{IpCidr, IpInet},
    clap::{Args, Parser, Subcommand},
    icann_rdap_client::rdap::QueryType,
    icann_rdap_common::{
        contact::{Contact, PostalAddress},
        media_types::RDAP_MEDIA_TYPE,
        prelude::{RdapResponse, ToNotices, ToRemarks, ToResponse, VectorStringish},
        response::{
            Autnum, Domain, DsDatum, Entity, Event, Events, Help, Link, Links, Nameserver, Network,
            Notice, NoticeOrRemark, Rfc9083Error, SecureDns, ToChild,
        },
        VERSION,
    },
    icann_rdap_srv::{
        config::{debug_config_vars, ServiceConfig, LOG},
        error::RdapServerError,
        storage::{
            data::{
                load_data, AutnumId, AutnumOrError, DomainId, DomainOrError, EntityId,
                EntityOrError, NameserverId, NameserverOrError, NetworkId, NetworkOrError,
                Template,
            },
            mem::{config::MemConfig, ops::Mem},
            CommonConfig, StoreOps,
        },
        util::bin::check::{check_rdap, to_check_classes, CheckArgs},
    },
    pct_str::{PctString, URIReserved},
    regex::Regex,
    std::{fs, path::PathBuf, str::FromStr},
    tracing::{error, info},
    tracing_subscriber::{
        fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, EnvFilter,
    },
};

#[derive(Parser, Debug)]
#[command(author, version = VERSION, about, long_about)]
/// This program creates RDAP objects.
struct Cli {
    #[clap(flatten)]
    check_args: CheckArgs,

    /// Specifies the directory where data will be written.
    #[arg(long, env = "RDAP_SRV_DATA_DIR")]
    data_dir: String,

    /// Output data as a redirect.
    ///
    /// When specified, the data will create a redirect template file to the given URL.
    /// This cannot be used with --template.
    #[arg(long, conflicts_with = "template")]
    redirect: Option<String>,

    /// Output data as a template.
    ///
    /// When specified, the data will be output as a template file.
    /// This cannot be used with --redirect.
    #[arg(long, conflicts_with = "redirect")]
    template: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Args)]
struct ObjectArgs {
    /// Base URL of the server where the object is to be served.
    #[arg(short = 'B', long, env = "RDAP_BASE_URL")]
    base_url: String,

    /// Status of the object (e.g. "active").
    ///
    /// This argument may be specified multiple times.
    #[arg(long)]
    status: Vec<String>,

    /// Created date and time.
    ///
    /// This argument should be in RFC3339 format.
    /// If not specified, the current date and time will be used.
    #[arg(long, value_parser = parse_datetime)]
    created: Option<DateTime<FixedOffset>>,

    /// Updated date and time.
    ///
    /// This argument should be in RFC3339 format.
    /// If not specified, the current date and time will be used.
    #[arg(long, value_parser = parse_datetime)]
    updated: Option<DateTime<FixedOffset>>,

    /// Adds a server notice.
    ///
    /// Takes the form of "\[LINK\] description" where the optional \[LINK\] takes
    /// the form of "(REL;TYPE)\[HREF\]". This argument maybe specified multiple times.
    #[arg(long, value_parser = parse_notice_or_remark)]
    notice: Vec<NoticeOrRemark>,

    /// Adds an object remark.
    ///
    /// Takes the form of "\[LINK\] description" where the optional \[LINK\] takes
    /// the form of "(REL;TYPE)\[HREF\]". This argument maybe specified multiple times.
    #[arg(long, value_parser = parse_notice_or_remark)]
    remark: Vec<NoticeOrRemark>,

    /// Registrant entity handle.
    #[arg(long)]
    registrant: Option<String>,

    /// Administrative entity handle.
    #[arg(long)]
    administrative: Option<String>,

    /// Technical entity handle.
    #[arg(long)]
    technical: Option<String>,

    /// Abuse entity handle.
    #[arg(long)]
    abuse: Option<String>,

    /// Billing entity handle.
    #[arg(long)]
    billing: Option<String>,

    /// Registrar entity handle.
    #[arg(long)]
    registrar: Option<String>,

    /// NOC entity handle.
    #[arg(long)]
    noc: Option<String>,
}

fn parse_datetime(arg: &str) -> Result<DateTime<FixedOffset>, chrono::format::ParseError> {
    let dt = DateTime::parse_from_rfc3339(arg)?;
    Ok(dt)
}

fn parse_notice_or_remark(arg: &str) -> Result<NoticeOrRemark, RdapServerError> {
    let re = Regex::new(r"^(?P<l>\(\S+\)\[\S+\])?\s*(?P<t>.+)$")
        .expect("creating notice/remark argument regex");
    let Some(cap) = re.captures(arg) else {
        return Err(RdapServerError::ArgParse(
            "Unable to parse Notice/Remark argumnet.".to_string(),
        ));
    };
    let Some(description) = cap.name("t") else {
        return Err(RdapServerError::ArgParse(
            "Unable to parse Notice/Remark description".to_string(),
        ));
    };
    let mut links = vec![];
    if let Some(link_data) = cap.name("l") {
        let link_re =
            Regex::new(r"^\((?P<r>\w+);(?P<t>\S+)\)\[(?P<h>\S+)\]$").expect("creating link regex");
        let Some(link_cap) = link_re.captures(link_data.as_str()) else {
            return Err(RdapServerError::ArgParse(
                "Unable to parse link in Notice/Remark".to_string(),
            ));
        };
        let Some(link_rel) = link_cap.name("r") else {
            return Err(RdapServerError::ArgParse(
                "unable to parse link rel in Notice/Remark".to_string(),
            ));
        };
        let Some(link_type) = link_cap.name("t") else {
            return Err(RdapServerError::ArgParse(
                "unable to parse link type in Notice/Remark".to_string(),
            ));
        };
        let Some(link_href) = link_cap.name("h") else {
            return Err(RdapServerError::ArgParse(
                "unable to parse link href in Notice/Remark".to_string(),
            ));
        };
        links = vec![Link::builder()
            .media_type(link_type.as_str().to_string())
            .href(link_href.as_str().to_string())
            .value(link_href.as_str().to_string())
            .rel(link_rel.as_str().to_string())
            .build()];
    }
    let not_rem = NoticeOrRemark::builder()
        .description(vec![description.as_str().to_string()])
        .links(links)
        .build();
    Ok(not_rem)
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Creates an RDAP entity.
    Entity(Box<EntityArgs>),

    /// Create a nameserver.
    Nameserver(Box<NameserverArgs>),

    /// Create a domain.
    Domain(Box<DomainArgs>),

    /// Create an autnum.
    Autnum(Box<AutnumArgs>),

    /// Create an IP network.
    Network(Box<NetworkArgs>),

    /// Creates a Help response.
    SrvHelp(SrvHelpArgs),
}

#[derive(Debug, Args)]
struct EntityArgs {
    #[clap(flatten)]
    object_args: ObjectArgs,

    /// Entity handle.
    #[arg(long)]
    handle: String,

    /// Full name of contact.
    ///
    /// If not specified, an org-name will be used.
    #[arg(long)]
    full_name: Option<String>,

    /// Title.
    ///
    /// This argument may be specified multiple times.
    #[arg(long)]
    title: Vec<String>,

    /// Organization name.
    ///
    /// This argument may be specified multiple times.
    #[arg(long)]
    org_name: Vec<String>,

    /// Email.
    ///
    /// Specifies the email for the contact of the entity.
    /// This argument may be specified multiple times.
    #[arg(long)]
    email: Vec<String>,

    /// Voice phone.
    ///
    /// Specifies the voice phone for the contact of the entity.
    /// This argument may be specified multiple times.
    #[arg(long)]
    voice: Vec<String>,

    /// Fax phone.
    ///
    /// Specifies the fax phone for the contact of the entity.
    /// This argument may be specified multiple times.
    #[arg(long)]
    fax: Vec<String>,

    /// Street address line.
    ///
    /// Specifies a line in the "street" part of an address.
    /// Street lines are parts of an address that are more
    /// specific than a locality or city, and are not necessarily
    /// a street address. That is, it maybe a post office box.
    /// This argument may be specified multiple times.
    #[arg(long)]
    street: Vec<String>,

    /// Locality (e.g. city).
    #[arg(long)]
    locality: Option<String>,

    /// Region name (e.g. province or state).
    #[arg(long)]
    region_name: Option<String>,

    /// Region code.
    ///
    /// This should be the 2 letter code for the region.
    #[arg(long)]
    region_code: Option<String>,

    /// Country name.
    #[arg(long)]
    country_name: Option<String>,

    /// Country code.
    ///
    /// This should be the 2 letter code for the country.
    #[arg(long)]
    country_code: Option<String>,

    /// Postal code (e.g. zip code).
    #[arg(long)]
    postal_code: Option<String>,

    /// Do not represent the entity with vCard.
    #[arg(long)]
    no_vcard: bool,

    /// Represent the entity with JSContact.
    #[arg(long)]
    jscontact: bool,
}

#[derive(Debug, Args)]
struct NameserverArgs {
    #[clap(flatten)]
    object_args: ObjectArgs,

    /// Entity handle.
    #[arg(long)]
    handle: Option<String>,

    /// Letters-Digits-Hyphen name.
    #[arg(long)]
    ldh: String,

    /// Ipv4 Address.
    ///
    /// This argument may be given multiple times.
    #[arg(long)]
    v4: Vec<String>,

    /// Ipv6 Address.
    ///
    /// This argument may be given multiple times.
    #[arg(long)]
    v6: Vec<String>,
}

#[derive(Debug, Args)]
struct DomainArgs {
    #[clap(flatten)]
    object_args: ObjectArgs,

    /// Domain handle.
    #[arg(long)]
    handle: Option<String>,

    /// Letters-Digits-Hyphen name.
    #[arg(long)]
    ldh: Option<String>,

    /// IDN U-Label name.
    #[arg(long)]
    idn: Option<String>,

    /// Zone is signed.
    #[arg(long)]
    zone_signed: Option<bool>,

    /// Delegation is signed.
    #[arg(long)]
    delegation_signed: Option<bool>,

    /// Maximum Signature Life.
    ///
    /// This value is specified in seconds.
    #[arg(long)]
    max_sig_life: Option<u64>,

    /// Adds DS Information.
    ///
    /// Takes the form of "KEYTAG ALGORITHM DIGEST_TYPE DIGEST".
    /// This argument maybe specified multiple times.
    #[arg(long, value_parser = parse_ds_datum)]
    ds: Vec<DsDatum>,

    /// Nameserver LDH.
    ///
    /// The DNS LDH (letters, digits, hyphens) name of the name server.
    /// This argument may be given multiple times.
    #[arg(long)]
    ns: Vec<String>,
}

fn parse_ds_datum(arg: &str) -> Result<DsDatum, RdapServerError> {
    let strings = arg.split_whitespace().collect::<Vec<&str>>();
    if strings.len() != 4 {
        return Err(RdapServerError::InvalidArg(
            "not enough DS data".to_string(),
        ));
    }
    let key_tag: u32 = strings[0]
        .parse()
        .map_err(|_e| RdapServerError::InvalidArg("cannot parse keyTag".to_string()))?;
    let algorithm: u8 = strings[1]
        .parse()
        .map_err(|_e| RdapServerError::InvalidArg("cannot parse algorithm".to_string()))?;
    let digest_type: u8 = strings[2]
        .parse()
        .map_err(|_e| RdapServerError::InvalidArg("cannot parse digestType".to_string()))?;
    let ds_datum = DsDatum::builder()
        .key_tag(key_tag)
        .algorithm(algorithm)
        .digest_type(digest_type)
        .digest(strings[3].to_owned())
        .build();
    Ok(ds_datum)
}

#[derive(Debug, Args)]
struct AutnumArgs {
    #[clap(flatten)]
    object_args: ObjectArgs,

    /// Start Autnum
    #[arg(long)]
    start_autnum: u32,

    /// End Autnum
    ///
    /// If not given, start_autnum will be used.
    #[arg(long)]
    end_autnum: Option<u32>,

    /// Autnum handle.
    #[arg(long)]
    handle: Option<String>,

    /// Autnum type.
    #[arg(long)]
    autnum_type: Option<String>,

    /// Country.
    #[arg(long)]
    country: Option<String>,

    /// Name.
    #[arg(long)]
    name: Option<String>,
}

#[derive(Debug, Args)]
struct NetworkArgs {
    #[clap(flatten)]
    object_args: ObjectArgs,

    /// IP CIDR.
    ///
    /// The RDAP start and end address and IP type will be derived from this.
    #[arg(long, value_parser = parse_cidr)]
    cidr: IpCidr,

    /// Network handle.
    #[arg(long)]
    handle: Option<String>,

    /// Parent network handle.
    #[arg(long)]
    parent_handle: Option<String>,

    /// Network type.
    #[arg(long)]
    network_type: Option<String>,

    /// Country.
    #[arg(long)]
    country: Option<String>,

    /// Name.
    #[arg(long)]
    name: Option<String>,
}

#[derive(Debug, Args)]
struct SrvHelpArgs {
    /// Host.
    ///
    /// The host name for which help is given. If not given, then the default host is assumed.
    #[arg(long)]
    host: Option<String>,

    /// Adds a server notice.
    ///
    /// Takes the form of "\[LINK\] description" where the optional \[LINK\] takes
    /// the form of "(REL;TYPE)\[HREF\]". This argument maybe specified multiple times.
    #[arg(long, value_parser = parse_notice_or_remark)]
    notice: Vec<NoticeOrRemark>,
}

fn parse_cidr(arg: &str) -> Result<IpCidr, RdapServerError> {
    let ip_inet = IpInet::from_str(arg).map_err(|e| RdapServerError::InvalidArg(e.to_string()))?;
    Ok(ip_inet.network())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), RdapServerError> {
    dotenv::dotenv().ok();
    let cli = Cli::parse();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_env(LOG))
        .init();

    debug_config_vars();

    let data_dir = cli.data_dir.clone();
    let config = ServiceConfig::non_server().data_dir(&data_dir).build()?;
    let storage = Mem::new(
        MemConfig::builder()
            .common_config(CommonConfig::default())
            .build(),
    );
    storage.init().await?;
    load_data(&config, &storage, false).await?;

    let work = do_the_work(cli, &storage, &data_dir).await;
    match work {
        Ok(_) => Ok(()),
        Err(err) => {
            error!("Error: {err}");
            Err(err)
        }
    }
}

async fn do_the_work(
    cli: Cli,
    storage: &dyn StoreOps,
    data_dir: &str,
) -> Result<(), RdapServerError> {
    let output = match cli.command {
        Commands::Entity(args) => make_entity(args, storage).await?,
        Commands::Nameserver(args) => make_nameserver(args, storage).await?,
        Commands::Domain(args) => {
            if args.ldh.is_none() && args.idn.is_none() {
                return Err(RdapServerError::InvalidArg(
                    "domain must specify either LDH or U-Label (idn) options".to_string(),
                ));
            }
            make_domain(args, storage).await?
        }
        Commands::Autnum(args) => make_autnum(args, storage).await?,
        Commands::Network(args) => make_network(args, storage).await?,
        Commands::SrvHelp(args) => {
            if cli.template || cli.redirect.is_some() {
                return Err(RdapServerError::InvalidArg(
                    "help cannot use --redirect or --template options".to_string(),
                ));
            }
            make_help(args)?
        }
    };

    let check_types = to_check_classes(&cli.check_args);
    let checks_found = check_rdap(output.rdap.clone(), &check_types);
    if checks_found {
        return Err(RdapServerError::ErrorOnChecks);
    } else {
        info!("Checks conducted and no issues were found.");
    }

    if let RdapId::Help = output.id {
        create_help_file(data_dir, &output.self_href, output.rdap)?;
    } else if cli.template {
        create_template_file(data_dir, &output.self_href, &output.id, &output.rdap)?;
    } else if let Some(redirect_url) = cli.redirect {
        create_redirect_file(data_dir, &output.self_href, &output.id, &redirect_url)?;
    } else {
        create_json_file(data_dir, &output.self_href, output.rdap)?;
    }

    Ok(())
}

fn create_file_name(self_href: &str, extension: &str) -> String {
    let file_name = self_href
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .replace(['.', '/', ':'], "_");
    format!(
        "{}.{extension}",
        PctString::encode(file_name.chars(), URIReserved)
    )
}

fn create_json_file(
    data_dir: &str,
    self_href: &str,
    rdap: RdapResponse,
) -> Result<(), RdapServerError> {
    let file_name = create_file_name(self_href, "json");
    let mut path = PathBuf::from(data_dir);
    path.push(file_name);
    let content = serde_json::to_string_pretty(&rdap)?;
    fs::write(&path, content)?;
    info!("JSON data written to {}.", path.to_string_lossy());
    Ok(())
}

fn create_help_file(
    data_dir: &str,
    self_href: &str,
    rdap: RdapResponse,
) -> Result<(), RdapServerError> {
    let file_name = create_file_name(self_href, "help");
    let mut path = PathBuf::from(data_dir);
    path.push(file_name);
    let content = serde_json::to_string_pretty(&rdap)?;
    fs::write(&path, content)?;
    info!("HELP data written to {}.", path.to_string_lossy());
    Ok(())
}

fn create_redirect_file(
    data_dir: &str,
    self_href: &str,
    id: &RdapId,
    url: &str,
) -> Result<(), RdapServerError> {
    let file_name = create_file_name(self_href, "template");
    let mut path = PathBuf::from(data_dir);
    path.push(file_name);
    let error = Rfc9083Error::response_obj()
        .error_code(307)
        .notice(Notice(
            NoticeOrRemark::builder()
                .title("Temporary Redirect")
                .links(vec![Link::builder()
                    .href(url)
                    .value(self_href)
                    .media_type(RDAP_MEDIA_TYPE)
                    .rel("related")
                    .build()])
                .build(),
        ))
        .build();
    let template = match id {
        RdapId::Entity(id) => Template::Entity {
            entity: EntityOrError::ErrorResponse(error),
            ids: vec![id.clone()],
        },
        RdapId::Domain(id) => Template::Domain {
            domain: DomainOrError::ErrorResponse(error),
            ids: vec![id.clone()],
        },
        RdapId::Nameserver(id) => Template::Nameserver {
            nameserver: NameserverOrError::ErrorResponse(error),
            ids: vec![id.clone()],
        },
        RdapId::Autnum(id) => Template::Autnum {
            autnum: AutnumOrError::ErrorResponse(error),
            ids: vec![id.clone()],
        },
        RdapId::Netowrk(id) => Template::Network {
            network: NetworkOrError::ErrorResponse(error),
            ids: vec![id.clone()],
        },
        RdapId::Help => panic!("cannot create help redirect file"),
    };
    let content = serde_json::to_string_pretty(&template)?;
    fs::write(&path, content)?;
    info!("Redirect data written to {}.", path.to_string_lossy());
    Ok(())
}

fn create_template_file(
    data_dir: &str,
    self_href: &str,
    id: &RdapId,
    rdap: &RdapResponse,
) -> Result<(), RdapServerError> {
    let file_name = create_file_name(self_href, "template");
    let mut path = PathBuf::from(data_dir);
    path.push(file_name);
    let template = match id {
        RdapId::Entity(id) => {
            let RdapResponse::Entity(entity) = rdap else {
                panic!("non entity created with entity id")
            };
            Template::Entity {
                entity: EntityOrError::EntityObject(Box::new(*entity.clone())),
                ids: vec![id.clone()],
            }
        }
        RdapId::Domain(id) => {
            let RdapResponse::Domain(domain) = rdap else {
                panic!("non domain created with domain id")
            };
            Template::Domain {
                domain: DomainOrError::DomainObject(Box::new(*domain.clone())),
                ids: vec![id.clone()],
            }
        }
        RdapId::Nameserver(id) => {
            let RdapResponse::Nameserver(nameserver) = rdap else {
                panic!("non nameserver created with nameserver id")
            };
            Template::Nameserver {
                nameserver: NameserverOrError::NameserverObject(Box::new(*nameserver.clone())),
                ids: vec![id.clone()],
            }
        }
        RdapId::Autnum(id) => {
            let RdapResponse::Autnum(autnum) = rdap else {
                panic!("non autnum created with autnum id")
            };
            Template::Autnum {
                autnum: AutnumOrError::AutnumObject(Box::new(*autnum.clone())),
                ids: vec![id.clone()],
            }
        }
        RdapId::Netowrk(id) => {
            let RdapResponse::Network(network) = rdap else {
                panic!("non network created with network id")
            };
            Template::Network {
                network: NetworkOrError::NetworkObject(Box::new(*network.clone())),
                ids: vec![id.clone()],
            }
        }
        RdapId::Help => panic!("cannot create help template file"),
    };
    let content = serde_json::to_string_pretty(&template)?;
    fs::write(&path, content)?;
    info!("Template data written to {}.", path.to_string_lossy());
    Ok(())
}

enum RdapId {
    Entity(EntityId),
    Domain(DomainId),
    Nameserver(NameserverId),
    Autnum(AutnumId),
    Netowrk(NetworkId),
    Help,
}

struct Output {
    pub rdap: RdapResponse,
    pub id: RdapId,
    pub self_href: String,
}

async fn entities(store: &dyn StoreOps, args: &ObjectArgs) -> Result<Vec<Entity>, RdapServerError> {
    let mut entities: Vec<Entity> = Vec::new();
    if let Some(handle) = &args.registrant {
        entities.push(get_entity(store, handle, "registrant".to_string()).await?);
    }
    if let Some(handle) = &args.administrative {
        entities.push(get_entity(store, handle, "administrative".to_string()).await?);
    }
    if let Some(handle) = &args.technical {
        entities.push(get_entity(store, handle, "technical".to_string()).await?);
    }
    if let Some(handle) = &args.abuse {
        entities.push(get_entity(store, handle, "abuse".to_string()).await?);
    }
    if let Some(handle) = &args.billing {
        entities.push(get_entity(store, handle, "billing".to_string()).await?);
    }
    if let Some(handle) = &args.registrar {
        entities.push(get_entity(store, handle, "registrar".to_string()).await?);
    }
    if let Some(handle) = &args.noc {
        entities.push(get_entity(store, handle, "noc".to_string()).await?);
    }
    Ok(entities)
}

async fn get_entity(
    store: &dyn StoreOps,
    handle: &str,
    role: String,
) -> Result<Entity, RdapServerError> {
    let e = store.get_entity_by_handle(handle).await?;
    if let RdapResponse::Entity(mut e) = e {
        e.roles = Some(VectorStringish::from(role));
        Ok(e.to_child())
    } else {
        Err(RdapServerError::InvalidArg(handle.to_string()))
    }
}

async fn nameservers(
    store: &dyn StoreOps,
    ns_names: Vec<String>,
) -> Result<Vec<Nameserver>, RdapServerError> {
    let mut nameservers: Vec<Nameserver> = Vec::new();
    for ns in ns_names {
        let ns = get_ns(store, &ns).await?;
        nameservers.push(ns);
    }
    Ok(nameservers)
}

async fn get_ns(store: &dyn StoreOps, ldh: &str) -> Result<Nameserver, RdapServerError> {
    let n = store.get_nameserver_by_ldh(ldh).await?;
    if let RdapResponse::Nameserver(n) = n {
        Ok(n.to_child())
    } else {
        Err(RdapServerError::InvalidArg(ldh.to_string()))
    }
}

fn events(args: &ObjectArgs) -> Option<Events> {
    let mut events: Events = vec![];
    let created_at = if let Some(dt) = args.created {
        dt
    } else {
        Utc::now().into()
    };
    let created = Event::builder()
        .event_date(created_at.to_rfc3339())
        .event_action("registration".to_string())
        .build();
    events.push(created);
    let updated_at = if let Some(dt) = args.created {
        dt
    } else {
        Utc::now().into()
    };
    let updated = Event::builder()
        .event_date(updated_at.to_rfc3339())
        .event_action("last changed".to_string())
        .build();
    events.push(updated);
    (!events.is_empty()).then_some(events)
}

fn links(self_href: &str) -> Option<Links> {
    let mut links: Links = vec![];
    let self_link = Link::builder()
        .value(self_href.to_owned())
        .href(self_href.to_owned())
        .rel("self".to_string())
        .media_type(RDAP_MEDIA_TYPE.to_string())
        .build();
    links.push(self_link);
    (!links.is_empty()).then_some(links)
}

async fn make_entity(
    args: Box<EntityArgs>,
    store: &dyn StoreOps,
) -> Result<Output, RdapServerError> {
    let self_href = QueryType::Entity(args.handle.to_owned())
        .query_url(&args.object_args.base_url)
        .expect("entity self href");
    let full_name = if let Some(full_name) = args.full_name {
        full_name
    } else if let Some(first_org) = args.org_name.first() {
        first_org.clone()
    } else {
        return Err(RdapServerError::InvalidArg(
            "a full name or org name is required".to_string(),
        ));
    };
    let mut contact = Contact::builder()
        .full_name(full_name)
        .organization_names(if !args.org_name.is_empty() {
            args.org_name
        } else {
            Default::default()
        })
        .titles(if !args.title.is_empty() {
            args.title
        } else {
            Default::default()
        })
        .build();
    contact = contact.with_email_addresses(&args.email);
    contact = contact.with_voice_phone_numbers(&args.voice);
    contact = contact.with_fax_phone_numbers(&args.fax);
    let postal_address = PostalAddress::builder()
        .street_parts(args.street.clone())
        .and_locality(args.locality)
        .and_region_name(args.region_name)
        .and_region_code(args.region_code)
        .and_country_name(args.country_name)
        .and_country_code(args.country_code)
        .and_postal_code(args.postal_code)
        .build();
    contact = contact.with_postal_address(postal_address);
    let entity = Entity::response_obj()
        .contact(contact)
        .no_vacard(args.no_vcard)
        .jscontact(args.jscontact)
        .notices(args.object_args.notice.clone().to_notices())
        .remarks(args.object_args.remark.clone().to_remarks())
        .entities(entities(store, &args.object_args).await?)
        .statuses(args.object_args.status.clone())
        .events(events(&args.object_args).unwrap_or_default())
        .links(links(&self_href).unwrap_or_default())
        .handle(args.handle);
    let entity = entity.build();
    let id = RdapId::Entity(EntityId {
        handle: entity
            .object_common
            .handle
            .clone()
            .expect("entity created without a handle")
            .to_string(),
    });
    let output = Output {
        rdap: entity.to_response(),
        id,
        self_href,
    };
    Ok(output)
}

async fn make_nameserver(
    args: Box<NameserverArgs>,
    store: &dyn StoreOps,
) -> Result<Output, RdapServerError> {
    let self_href = QueryType::ns(&args.ldh)?
        .query_url(&args.object_args.base_url)
        .expect("nameserver self href");
    let mut addrs: Vec<String> = args.v4.clone();
    addrs.append(&mut args.v6.clone());
    let ns = Nameserver::response_obj()
        .ldh_name(args.ldh)
        .addresses(addrs)
        .notices(args.object_args.notice.clone().to_notices())
        .remarks(args.object_args.remark.clone().to_remarks())
        .entities(entities(store, &args.object_args).await?)
        .statuses(args.object_args.status.clone())
        .events(events(&args.object_args).unwrap_or_default())
        .links(links(&self_href).unwrap_or_default())
        .and_handle(args.handle);
    let ns = ns.build()?;
    let id = RdapId::Nameserver(NameserverId {
        ldh_name: ns
            .ldh_name
            .clone()
            .expect("nameserver created without ldhName"),
        unicode_name: ns.unicode_name.clone(),
    });
    let output = Output {
        rdap: ns.to_response(),
        id,
        self_href,
    };
    Ok(output)
}

async fn make_domain(
    args: Box<DomainArgs>,
    store: &dyn StoreOps,
) -> Result<Output, RdapServerError> {
    // get ldh from idn u-label if ldh is not given
    let ldh = if let Some(ldh_arg) = args.ldh.as_ref() {
        ldh_arg.to_owned()
    } else if let Some(idn_arg) = args.idn.as_ref() {
        idna::domain_to_ascii(idn_arg)
            .map_err(|_| RdapServerError::InvalidArg("Invalid IDN U-Lable".to_string()))?
    } else {
        panic!("neither ldh or idn specified. this should have been caught in arg parsing.")
    }

    // get unicodeName (idn) from ldh if idn is not given
    ;
    let unicode_name = if let Some(idn_arg) = args.idn {
        idn_arg
    } else {
        idna::domain_to_unicode(&ldh).0
    };

    let self_href = QueryType::domain(&ldh)?
        .query_url(&args.object_args.base_url)
        .expect("domain self href");
    let secure_dns = if !args.ds.is_empty()
        || args.zone_signed.is_some()
        || args.delegation_signed.is_some()
        || args.max_sig_life.is_some()
    {
        let secure_dns = SecureDns::builder()
            .and_zone_signed(args.zone_signed)
            .and_delegation_signed(args.delegation_signed)
            .and_max_sig_life(args.max_sig_life)
            .ds_datas(args.ds.clone())
            .build();
        Some(secure_dns)
    } else {
        None
    };
    let domain = Domain::response_obj()
        .ldh_name(ldh)
        .unicode_name(unicode_name)
        .and_secure_dns(secure_dns)
        .nameservers(nameservers(store, args.ns).await?)
        .notices(args.object_args.notice.clone().to_notices())
        .remarks(args.object_args.remark.clone().to_remarks())
        .entities(entities(store, &args.object_args).await?)
        .statuses(args.object_args.status.clone())
        .events(events(&args.object_args).unwrap_or_default())
        .links(links(&self_href).unwrap_or_default())
        .and_handle(args.handle);
    let domain = domain.build();
    let id = RdapId::Domain(DomainId {
        ldh_name: domain
            .ldh_name
            .clone()
            .expect("domain created without ldhName"),
        unicode_name: domain.unicode_name.clone(),
    });
    let output = Output {
        rdap: domain.to_response(),
        id,
        self_href,
    };
    Ok(output)
}

async fn make_autnum(
    args: Box<AutnumArgs>,
    store: &dyn StoreOps,
) -> Result<Output, RdapServerError> {
    let self_href = QueryType::AsNumber(args.start_autnum)
        .query_url(&args.object_args.base_url)
        .expect("autnum self href");
    let autnum_range = args.start_autnum..args.end_autnum.unwrap_or(args.start_autnum);
    let autnum = Autnum::response_obj()
        .autnum_range(autnum_range)
        .and_autnum_type(args.autnum_type)
        .and_country(args.country)
        .and_name(args.name)
        .notices(args.object_args.notice.clone().to_notices())
        .remarks(args.object_args.remark.clone().to_remarks())
        .entities(entities(store, &args.object_args).await?)
        .statuses(args.object_args.status.clone())
        .events(events(&args.object_args).unwrap_or_default())
        .links(links(&self_href).unwrap_or_default())
        .and_handle(args.handle);
    let autnum = autnum.build();
    let id = RdapId::Autnum(AutnumId {
        start_autnum: autnum
            .start_autnum
            .as_ref()
            .and_then(|n| n.as_u32())
            .expect("autnum created with no start"),
        end_autnum: autnum
            .end_autnum
            .as_ref()
            .and_then(|n| n.as_u32())
            .expect("autnum create with no end"),
    });
    let output = Output {
        rdap: autnum.to_response(),
        id,
        self_href,
    };
    Ok(output)
}

async fn make_network(
    args: Box<NetworkArgs>,
    store: &dyn StoreOps,
) -> Result<Output, RdapServerError> {
    let self_href = match &args.cidr {
        IpCidr::V4(cidr) => QueryType::ipv4cidr(&cidr.to_string())?
            .query_url(&args.object_args.base_url)
            .expect("ipv4 network self href"),
        IpCidr::V6(cidr) => QueryType::ipv6cidr(&cidr.to_string())?
            .query_url(&args.object_args.base_url)
            .expect("ipv6 network self href"),
    };
    let network = Network::response_obj()
        .cidr(args.cidr.to_string())
        .and_country(args.country)
        .and_name(args.name)
        .and_network_type(args.network_type)
        .and_parent_handle(args.parent_handle)
        .notices(args.object_args.notice.clone().to_notices())
        .remarks(args.object_args.remark.clone().to_remarks())
        .entities(entities(store, &args.object_args).await?)
        .statuses(args.object_args.status.clone())
        .events(events(&args.object_args).unwrap_or_default())
        .links(links(&self_href).unwrap_or_default())
        .and_handle(args.handle);
    let network = network.build()?;
    let id = RdapId::Netowrk(NetworkId {
        network_id: icann_rdap_srv::storage::data::NetworkIdType::Range {
            start_address: network
                .start_address
                .clone()
                .expect("netowrk created without start address"),
            end_address: network
                .end_address
                .clone()
                .expect("network created without end address"),
        },
    });
    let output = Output {
        rdap: network.to_response(),
        id,
        self_href,
    };
    Ok(output)
}

fn make_help(args: SrvHelpArgs) -> Result<Output, RdapServerError> {
    let help = Help::response().notices(args.notice.to_notices()).build();
    let output = Output {
        rdap: help.to_response(),
        id: RdapId::Help,
        self_href: args.host.unwrap_or("__default".to_string()),
    };
    Ok(output)
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use icann_rdap_common::response::DsDatum;

    use crate::{parse_ds_datum, parse_notice_or_remark};

    #[test]
    fn cli_debug_assert_test() {
        use clap::CommandFactory;
        crate::Cli::command().debug_assert()
    }

    #[test]
    fn GIVEN_notice_arg_WHEN_parse_THEN_correct() {
        // GIVEN
        let arg = "This is a notice.";

        // WHEN
        let actual = parse_notice_or_remark(arg).expect("parsing notice");

        // THEN
        assert!(
            Into::<Vec<String>>::into(actual.description.expect("no description!"))
                .contains(&arg.to_string())
        );
    }

    #[test]
    fn GIVEN_notice_with_link_arg_WHEN_parse_THEN_correct() {
        // GIVEN
        let description = "This is a notice.";
        let media_type = "text/html";
        let rel = "about";
        let href = "https://example.com/stuff";
        let arg = format!("({rel};{media_type})[{href}] {description}");

        // WHEN
        let actual = parse_notice_or_remark(&arg).expect("parsing notice");

        // THEN
        assert!(actual
            .description
            .expect("no description!")
            .into_vec()
            .contains(&description.to_string()));
        let Some(links) = actual.links else {
            panic!("no links in notice")
        };
        let Some(link) = links.first() else {
            panic!("links are empty")
        };
        assert_eq!(link.rel.as_ref().expect("no rel in link"), rel);
        assert_eq!(link.href.as_ref().expect("link has no href"), href);
        assert_eq!(
            link.media_type.as_ref().expect("no media_type in link"),
            media_type
        );
    }

    #[test]
    fn GIVEN_ds_data_WHEN_parse_THEN_correct() {
        // GIVEN
        let data = "123456 1 2 THISISADIGEST";

        // WHEN
        let actual = parse_ds_datum(data).expect("parsing ds datum");

        // THEN
        let expected = DsDatum::builder()
            .key_tag(123456)
            .algorithm(1)
            .digest_type(2)
            .digest("THISISADIGEST".to_string())
            .build();
        assert_eq!(expected, actual);
    }
}
