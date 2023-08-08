use std::{fs, path::PathBuf};

use clap::Parser;
use icann_rdap_common::{
    contact::{Contact, Email, PostalAddress},
    media_types::RDAP_MEDIA_TYPE,
    response::{domain::Domain, entity::Entity, nameserver::Nameserver, types::Link},
    VERSION,
};
use icann_rdap_srv::{
    config::{debug_config_vars, LOG},
    error::RdapServerError,
    storage::data::{
        DomainId, DomainOrError, EntityId, EntityOrError, NameserverId, NameserverOrError, Template,
    },
};
use pct_str::{PctString, URIReserved};
use tracing::info;
use tracing_subscriber::{
    fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, EnvFilter,
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
    num_entities: Option<u32>,

    /// Number of test nameservers to create.
    #[arg(long)]
    num_nameservers: Option<u32>,

    /// Number of test domains to create.
    #[arg(long)]
    num_domains: Option<u32>,
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
    if let Some(num_entities) = cli.num_entities {
        make_entity_template(&data_dir, &base_url, num_entities)?
    }
    if let Some(num_nameservers) = cli.num_nameservers {
        make_nameserver_template(&data_dir, &base_url, num_nameservers)?
    }
    if let Some(num_domains) = cli.num_domains {
        make_domain_template(&data_dir, &base_url, num_domains)?
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
        .into_iter()
        .map(|x| {
            EntityId::builder()
                .handle(format!("test_entity_{x}"))
                .build()
        })
        .collect();
    let template = Template::Entity {
        entity: EntityOrError::EntityObject(entity),
        ids,
    };
    save_template(data_dir, base_url, template)
}

fn make_nameserver_template(
    data_dir: &str,
    base_url: &str,
    num_nameservers: u32,
) -> Result<(), RdapServerError> {
    let nameserver = make_test_nameserver(base_url, None)?;
    let ids: Vec<NameserverId> = (0..num_nameservers)
        .into_iter()
        .map(|x| {
            NameserverId::builder()
                .ldh_name(format!("ns.test_nameserver_{x}.example"))
                .build()
        })
        .collect();
    let template = Template::Nameserver {
        nameserver: NameserverOrError::NameserverObject(nameserver),
        ids,
    };
    save_template(data_dir, base_url, template)
}

fn make_domain_template(
    data_dir: &str,
    base_url: &str,
    num_domains: u32,
) -> Result<(), RdapServerError> {
    let mut entity = make_test_entity(base_url, Some("nameserver"));
    entity.roles = Some(vec!["registrant".to_string()]);
    let nameserver = make_test_nameserver(base_url, None)?;
    let domain = Domain::basic()
        .ldh_name("example.net")
        .entity(entity)
        .nameservers(vec![nameserver])
        .link(
            Link::builder()
                .rel("self")
                .href(format!("https://{base_url}/domain/test_domain",))
                .media_type(RDAP_MEDIA_TYPE)
                .build(),
        )
        .status("active")
        .build();
    let ids: Vec<DomainId> = (0..num_domains)
        .into_iter()
        .map(|x| {
            DomainId::builder()
                .ldh_name(format!("test_domain_{x}.example"))
                .build()
        })
        .collect();
    let template = Template::Domain {
        domain: DomainOrError::DomainObject(domain),
        ids,
    };
    save_template(data_dir, base_url, template)
}

fn make_test_entity(base_url: &str, child_of: Option<&str>) -> Entity {
    let contact = Contact::builder()
        .kind("individual")
        .full_name(format!("Alfred E. {}", child_of.unwrap_or("Nueman")))
        .emails(vec![Email::builder().email("alfred@example.net").build()])
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
    Entity::basic()
        .handle("TEMPLATE")
        .link(
            Link::builder()
                .rel("self")
                .href(format!(
                    "https://{base_url}/entity/child_of_{}",
                    child_of.unwrap_or("none")
                ))
                .media_type(RDAP_MEDIA_TYPE)
                .build(),
        )
        .status("active")
        .contact(contact)
        .build()
}

fn make_test_nameserver(
    base_url: &str,
    child_of: Option<&str>,
) -> Result<Nameserver, RdapServerError> {
    let mut entity = make_test_entity(base_url, Some("nameserver"));
    entity.roles = Some(vec!["tech".to_string()]);
    Ok(Nameserver::basic()
        .ldh_name("ns.template.example")
        .link(
            Link::builder()
                .rel("self")
                .href(format!(
                    "https://{base_url}/nameserver/child_of_{}",
                    child_of.unwrap_or("none")
                ))
                .media_type(RDAP_MEDIA_TYPE)
                .build(),
        )
        .entity(entity)
        .build()?)
}

fn save_template(
    data_dir: &str,
    base_url: &str,
    template: Template,
) -> Result<(), RdapServerError> {
    let file_name = base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .replace(['.', '/', ':'], "_");
    let file_name = format!(
        "{}_test_data_{}.template",
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
