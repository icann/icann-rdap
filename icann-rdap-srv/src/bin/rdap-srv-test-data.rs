use std::{fs, path::PathBuf};

use {
    clap::Parser,
    icann_rdap_common::{
        contact::{Contact, Email, Phone, PostalAddress},
        media_types::RDAP_MEDIA_TYPE,
        prelude::VectorStringish,
        response::{
            Autnum, Domain, Entity, Link, Nameserver, Network, Notice, NoticeOrRemark, Remark,
        },
        VERSION,
    },
    icann_rdap_srv::{
        config::{debug_config_vars, LOG},
        error::RdapServerError,
        storage::data::{
            AutnumId, AutnumOrError, DomainId, DomainOrError, EntityId, EntityOrError,
            NameserverId, NameserverOrError, NetworkId, NetworkIdType, NetworkOrError, Template,
        },
    },
    ipnet::{Ipv4Subnets, Ipv6Subnets},
    pct_str::{PctString, URIReserved},
    tracing::info,
    tracing_subscriber::{
        fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, EnvFilter,
    },
};

#[derive(Parser, Debug)]
#[command(author, version = VERSION, about, long_about)]
/// This program creates test RDAP data templates.
struct Cli {
    /// Specifies the directory where data will be written.
    #[arg(long, env = "RDAP_SRV_DATA_DIR")]
    data_dir: String,

    /// Base URL of the server where the object is to be served.
    #[arg(short = 'B', long, env = "RDAP_BASE_URL")]
    base_url: String,

    /// Number of test entities to create.
    #[arg(long)]
    entities: Option<u32>,

    /// Number of test nameservers to create.
    #[arg(long)]
    nameservers: Option<u32>,

    /// Number of test domains to create.
    #[arg(long)]
    domains: Option<u32>,

    /// Number of test autnums to create.
    #[arg(long)]
    autnums: Option<u32>,

    /// Number of test ipv4 networks to create.
    #[arg(long)]
    v4s: Option<u32>,

    /// Number of test ipv6 networks to create.
    #[arg(long)]
    v6s: Option<u32>,
}

fn main() -> Result<(), RdapServerError> {
    dotenv::dotenv().ok();
    let cli = Cli::parse();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_env(LOG))
        .init();

    debug_config_vars();

    let data_dir = cli.data_dir;
    let base_url = cli.base_url;
    if let Some(entities) = cli.entities {
        make_entity_template(&data_dir, &base_url, entities)?
    }
    if let Some(nameservers) = cli.nameservers {
        make_nameserver_template(&data_dir, &base_url, nameservers)?
    }
    if let Some(domains) = cli.domains {
        make_domain_template(&data_dir, &base_url, domains)?
    }
    if let Some(autnums) = cli.autnums {
        make_autnum_template(&data_dir, &base_url, autnums)?
    }
    if let Some(v4s) = cli.v4s {
        make_netv4_template(&data_dir, &base_url, v4s)?
    }
    if let Some(v6s) = cli.v6s {
        make_netv6_template(&data_dir, &base_url, v6s)?
    }
    Ok(())
}

fn make_entity_template(
    data_dir: &str,
    base_url: &str,
    num_entities: u32,
) -> Result<(), RdapServerError> {
    let entity = make_test_entity(base_url, None);
    let ids: Vec<EntityId> = (0..num_entities)
        .map(|x| {
            EntityId::builder()
                .handle(format!("test-entity-{x}"))
                .build()
        })
        .collect();
    let template = Template::Entity {
        entity: EntityOrError::EntityObject(Box::new(entity)),
        ids,
    };
    save_template(data_dir, base_url, template, None)
}

fn make_nameserver_template(
    data_dir: &str,
    base_url: &str,
    num_nameservers: u32,
) -> Result<(), RdapServerError> {
    let nameserver = make_test_nameserver(base_url, None)?;
    let ids: Vec<NameserverId> = (0..num_nameservers)
        .map(|x| {
            NameserverId::builder()
                .ldh_name(format!("ns.test-nameserver-{x}.example"))
                .build()
        })
        .collect();
    let template = Template::Nameserver {
        nameserver: NameserverOrError::NameserverObject(Box::new(nameserver)),
        ids,
    };
    save_template(data_dir, base_url, template, None)
}

fn make_domain_template(
    data_dir: &str,
    base_url: &str,
    num_domains: u32,
) -> Result<(), RdapServerError> {
    let mut entity = make_test_entity(base_url, Some("domain"));
    entity.roles = Some(VectorStringish::from("registrant"));
    let nameserver = make_test_nameserver(base_url, None)?;
    let domain = Domain::response_obj()
        .ldh_name("example.net")
        .entity(entity)
        .nameservers(vec![nameserver])
        .link(
            Link::builder()
                .rel("self")
                .href(format!("https://{base_url}/domain/test-domain",))
                .value(format!("https://{base_url}/domain/test-domain",))
                .media_type(RDAP_MEDIA_TYPE)
                .build(),
        )
        .status("active")
        .remark(Remark(
            NoticeOrRemark::builder()
                .title("Test Domain")
                .description(vec![
                    "This is a test domain. Don't get so hung up over it.".to_string()
                ])
                .build(),
        ))
        .notice(Notice(
            NoticeOrRemark::builder()
                .title("Test Server")
                .description(vec!["This is a server contains test data.".to_string()])
                .build(),
        ))
        .build();
    let ids: Vec<DomainId> = (0..num_domains)
        .map(|x| {
            DomainId::builder()
                .ldh_name(format!("test-domain-{x}.example"))
                .build()
        })
        .collect();
    let template = Template::Domain {
        domain: DomainOrError::DomainObject(Box::new(domain)),
        ids,
    };
    save_template(data_dir, base_url, template, None)
}

fn make_autnum_template(
    data_dir: &str,
    base_url: &str,
    num_autnums: u32,
) -> Result<(), RdapServerError> {
    let mut entity = make_test_entity(base_url, Some("autnum"));
    entity.roles = Some(VectorStringish::from("registrant"));
    let autnum = Autnum::builder()
        .autnum_range(1..1)
        .entity(entity)
        .link(
            Link::builder()
                .rel("self")
                .href(format!("https://{base_url}/autnum/test-autnum",))
                .value(format!("https://{base_url}/autnum/test-autnum",))
                .media_type(RDAP_MEDIA_TYPE)
                .build(),
        )
        .status("active")
        .remark(Remark(
            NoticeOrRemark::builder()
                .title("Test Autnum")
                .description(vec![
                    "This is a test autnum. Don't get so hung up over it.".to_string()
                ])
                .build(),
        ))
        .notice(Notice(
            NoticeOrRemark::builder()
                .title("Test Server")
                .description(vec!["This is a server contains test data.".to_string()])
                .build(),
        ))
        .build();
    let ids: Vec<AutnumId> = (0..num_autnums)
        .map(|x| AutnumId::builder().start_autnum(x).end_autnum(x).build())
        .collect();
    let template = Template::Autnum {
        autnum: AutnumOrError::AutnumObject(Box::new(autnum)),
        ids,
    };
    save_template(data_dir, base_url, template, None)
}

fn make_netv4_template(
    data_dir: &str,
    base_url: &str,
    num_netv4: u32,
) -> Result<(), RdapServerError> {
    let network = make_test_network(base_url)?;
    let ids: Vec<NetworkId> = Ipv4Subnets::new("1.0.0.0".parse()?, "254.255.255.255".parse()?, 26)
        .into_iter()
        .take(num_netv4.try_into().unwrap())
        .map(|x| {
            NetworkId::builder()
                .network_id(NetworkIdType::Cidr(ipnet::IpNet::V4(x)))
                .build()
        })
        .collect();
    let template = Template::Network {
        network: NetworkOrError::NetworkObject(Box::new(network)),
        ids,
    };
    save_template(data_dir, base_url, template, Some("v4"))
}

fn make_netv6_template(
    data_dir: &str,
    base_url: &str,
    num_netv6: u32,
) -> Result<(), RdapServerError> {
    let network = make_test_network(base_url)?;
    let ids: Vec<NetworkId> = Ipv6Subnets::new(
        "2000::".parse()?,
        "2000:ef:ffff:ffff:ffff:ffff:ffff:ffff".parse()?,
        64,
    )
    .into_iter()
    .take(num_netv6.try_into().unwrap())
    .map(|x| {
        NetworkId::builder()
            .network_id(NetworkIdType::Cidr(ipnet::IpNet::V6(x)))
            .build()
    })
    .collect();
    let template = Template::Network {
        network: NetworkOrError::NetworkObject(Box::new(network)),
        ids,
    };
    save_template(data_dir, base_url, template, Some("v6"))
}

fn make_test_entity(base_url: &str, child_of: Option<&str>) -> Entity {
    let notices = if child_of.is_none() {
        vec![Notice(
            NoticeOrRemark::builder()
                .title("Test Server")
                .description(vec!["This is a server contains test data.".to_string()])
                .build(),
        )]
    } else {
        vec![]
    };
    let contact = Contact::builder()
        .kind("individual")
        .full_name(format!("Alfred E. {}", child_of.unwrap_or("Nueman")))
        .emails(vec![Email::builder().email("alfred@example.net").build()])
        .phones(vec![Phone::builder()
            .phone("+12025555555")
            .features(vec!["voice".to_string()])
            .contexts(vec!["work".to_string()])
            .build()])
        .postal_addresses(vec![PostalAddress::builder()
            .street_parts(vec![
                "123 Mocking Bird Lane".to_string(),
                "Suite 900000".to_string(),
            ])
            .locality("Springfield")
            .region_name("MA")
            .country_code("US")
            .build()])
        .build();
    Entity::builder()
        .handle("TEMPLATE")
        .link(
            Link::builder()
                .rel("self")
                .href(format!(
                    "https://{base_url}/entity/child_of_{}",
                    child_of.unwrap_or("none")
                ))
                .value(format!(
                    "https://{base_url}/entity/child_of_{}",
                    child_of.unwrap_or("none")
                ))
                .media_type(RDAP_MEDIA_TYPE)
                .build(),
        )
        .status("active")
        .contact(contact)
        .remark(Remark(
            NoticeOrRemark::builder()
                .title("Test Entity")
                .description(vec![
                    "This is a test entity. Don't get so hung up over it.".to_string()
                ])
                .build(),
        ))
        .notices(notices)
        .build()
}

fn make_test_nameserver(
    base_url: &str,
    child_of: Option<&str>,
) -> Result<Nameserver, RdapServerError> {
    let notices = if child_of.is_none() {
        vec![Notice(
            NoticeOrRemark::builder()
                .title("Test Server")
                .description(vec!["This is a server contains test data.".to_string()])
                .build(),
        )]
    } else {
        vec![]
    };
    let mut entity = make_test_entity(base_url, Some("nameserver"));
    entity.roles = Some(VectorStringish::from("tech"));
    Ok(Nameserver::response_obj()
        .ldh_name("ns.template.example")
        .link(
            Link::builder()
                .rel("self")
                .href(format!(
                    "https://{base_url}/nameserver/child_of_{}",
                    child_of.unwrap_or("none")
                ))
                .value(format!(
                    "https://{base_url}/nameserver/child_of_{}",
                    child_of.unwrap_or("none")
                ))
                .media_type(RDAP_MEDIA_TYPE)
                .build(),
        )
        .entity(entity)
        .remark(Remark(
            NoticeOrRemark::builder()
                .title("Test Nameserver")
                .description(vec![
                    "This is a test nameserver. Don't get so hung up over it.".to_string(),
                ])
                .build(),
        ))
        .notices(notices)
        .build()?)
}

fn make_test_network(base_url: &str) -> Result<Network, RdapServerError> {
    let mut entity = make_test_entity(base_url, Some("network"));
    entity.roles = Some(VectorStringish::from("registrant"));
    let network = Network::builder()
        .cidr("0.0.0.0/0")
        .entity(entity)
        .link(
            Link::builder()
                .rel("self")
                .href(format!("https://{base_url}/ip/test_network",))
                .value(format!("https://{base_url}/ip/test_network",))
                .media_type(RDAP_MEDIA_TYPE)
                .build(),
        )
        .status("active")
        .remark(Remark(
            NoticeOrRemark::builder()
                .title("Test Network")
                .description(vec![
                    "This is a test network. Don't get so hung up over it.".to_string(),
                ])
                .build(),
        ))
        .notice(Notice(
            NoticeOrRemark::builder()
                .title("Test Server")
                .description(vec!["This is a server contains test data.".to_string()])
                .build(),
        ))
        .build()?;
    Ok(network)
}

fn save_template(
    data_dir: &str,
    base_url: &str,
    template: Template,
    type_suffix: Option<&str>,
) -> Result<(), RdapServerError> {
    let file_name = base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .replace(['.', '/', ':'], "_");
    let type_suffix = if let Some(type_suffix) = type_suffix {
        format!("_{type_suffix}")
    } else {
        "".to_string()
    };
    let file_name = format!(
        "{}_test_data_{}{type_suffix}.template",
        PctString::encode(file_name.chars(), URIReserved),
        template
    );
    let mut path = PathBuf::from(data_dir);
    path.push(file_name);
    let content = serde_json::to_string_pretty(&template)?;
    fs::write(&path, content)?;
    info!("JSON data template written to {}.", path.to_string_lossy());
    Ok(())
}
