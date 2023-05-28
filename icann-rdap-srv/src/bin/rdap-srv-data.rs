use chrono::DateTime;
use chrono::FixedOffset;
use clap::{Args, Parser, Subcommand};
use icann_rdap_common::contact::Contact;
use icann_rdap_common::response::entity::Entity;
use icann_rdap_common::response::types::Common;
use icann_rdap_common::response::types::Link;
use icann_rdap_common::response::types::Links;
use icann_rdap_common::response::types::Notice;
use icann_rdap_common::response::types::NoticeOrRemark;
use icann_rdap_common::response::types::Notices;
use icann_rdap_common::response::types::ObjectCommon;
use icann_rdap_common::response::types::Remark;
use icann_rdap_common::response::types::Remarks;
use icann_rdap_common::response::RdapResponse;
use icann_rdap_common::VERSION;
use icann_rdap_srv::config::data_dir;
use icann_rdap_srv::config::ServiceConfig;
use icann_rdap_srv::config::StorageType;
use icann_rdap_srv::storage::data::load_data;
use icann_rdap_srv::storage::mem::config::MemConfig;
use icann_rdap_srv::storage::mem::ops::Mem;
use icann_rdap_srv::storage::StoreOps;
use icann_rdap_srv::{
    config::{debug_config_vars, LOG},
    error::RdapServerError,
};
use pct_str::PctString;
use pct_str::URIReserved;
use regex::Regex;
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use tracing::info;
use tracing_subscriber::{
    fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

#[derive(Parser, Debug)]
#[command(author, version = VERSION, about, long_about)]
/// This program creates RDAP objects.
struct Cli {
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
    /// Takes the form of "[LINK] description" where the optional [LINK] takes
    /// the form of "(REL;TYPE)[HREF]". This argument maybe specified multiple times.
    #[arg(long, value_parser = parse_notice_or_remark)]
    notice: Vec<NoticeOrRemark>,

    /// Adds an object remark.
    ///
    /// Takes the form of "[LINK] description" where the optional [LINK] takes
    /// the form of "(REL;TYPE)[HREF]". This argument maybe specified multiple times.
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
    let Some(cap) = re.captures(arg) else {return Err(RdapServerError::ArgParse("Unable to parse Notice/Remark argumnet.".to_string()))};
    let Some(description) = cap.name("t") else {return Err(RdapServerError::ArgParse("Unable to parse Notice/Remark description".to_string()))};
    let mut links: Option<Links> = None;
    if let Some(link_data) = cap.name("l") {
        let link_re =
            Regex::new(r"^\((?P<r>\w+);(?P<t>\S+)\)\[(?P<h>\S+)\]$").expect("creating link regex");
        let Some(link_cap) = link_re.captures(link_data.as_str()) else {return Err(RdapServerError::ArgParse("Unable to parse link in Notice/Remark".to_string()))};
        let Some(link_rel) = link_cap.name("r") else {return Err(RdapServerError::ArgParse("unable to parse link rel in Notice/Remark".to_string()))};
        let Some(link_type) = link_cap.name("t") else {return Err(RdapServerError::ArgParse("unable to parse link type in Notice/Remark".to_string()))};
        let Some(link_href) = link_cap.name("h") else {return Err(RdapServerError::ArgParse("unable to parse link href in Notice/Remark".to_string()))};
        links = Some(vec![Link::builder()
            .media_type(link_type.as_str().to_string())
            .href(link_href.as_str().to_string())
            .rel(link_rel.as_str().to_string())
            .build()]);
    }
    let not_rem = NoticeOrRemark::builder()
        .description(vec![description.as_str().to_string()])
        .and_links(links)
        .build();
    Ok(not_rem)
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Creates an RDAP entity.
    Entity(EntityArgs),
}

#[derive(Debug, Args)]
struct EntityArgs {
    #[clap(flatten)]
    object_args: ObjectArgs,

    /// Entity handle.
    #[arg(long)]
    handle: Option<String>,

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

    let data_dir = data_dir();
    let storage_type = StorageType::new_from_env()?;
    let config = ServiceConfig::builder()
        .storage_type(storage_type)
        .data_dir(&data_dir)
        .auto_reload(false)
        .build();
    let storage = Mem::new(MemConfig::builder().build());
    storage.init().await?;
    load_data(&config, &storage, false).await?;

    let mut output = match cli.command {
        Commands::Entity(args) => make_entity(args, &storage)?,
    };
    output.id.get_or_insert(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("getting epoch time")
            .as_secs()
            .to_string(),
    );

    let mut path = PathBuf::from(data_dir);
    path.push(
        PctString::encode(
            format!(
                "{}_{}.json",
                output.descriminator,
                output.id.unwrap_or_default()
            )
            .chars(),
            URIReserved,
        )
        .to_string(),
    );
    fs::write(&path, serde_json::to_string_pretty(&output.rdap)?)?;
    info!("Data written to {}.", path.to_string_lossy());

    Ok(())
}

struct Output {
    pub rdap: RdapResponse,
    pub descriminator: &'static str,
    pub id: Option<String>,
}

fn notices(v: &[NoticeOrRemark]) -> Option<Vec<Notice>> {
    let notices = v.iter().map(|n| Notice(n.clone())).collect::<Notices>();
    (!notices.is_empty()).then_some(notices)
}

fn remarks(v: &[NoticeOrRemark]) -> Option<Vec<Remark>> {
    let remarks = v.iter().map(|n| Remark(n.clone())).collect::<Remarks>();
    (!remarks.is_empty()).then_some(remarks)
}

fn make_entity(args: EntityArgs, _store: &dyn StoreOps) -> Result<Output, RdapServerError> {
    let contact = Contact::builder().and_full_name(args.full_name).build();
    let vcard = contact.is_non_empty().then_some(contact.to_vcard());
    let entity = Entity::builder()
        .and_vcard_array(vcard)
        .common(
            Common::builder()
                .and_notices(notices(&args.object_args.notice))
                .build(),
        )
        .object_common(
            ObjectCommon::builder()
                .object_class_name("entity")
                .and_remarks(remarks(&args.object_args.remark))
                .and_handle(args.handle.clone())
                .build(),
        );
    let mut id = Option::None;
    if let Some(handle) = &args.handle {
        id.get_or_insert(handle.clone());
    }
    if let Some(full_name) = &contact.full_name {
        id.get_or_insert(full_name.clone());
    }
    let output = Output {
        rdap: RdapResponse::Entity(entity.build()),
        descriminator: "entity",
        id,
    };
    Ok(output)
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use crate::parse_notice_or_remark;

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
        assert!(actual.description.contains(&arg.to_string()));
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
        assert!(actual.description.contains(&description.to_string()));
        let Some(links) = actual.links else {panic!("no links in notice")};
        let Some(link) = links.first() else {panic!("links are empty")};
        assert_eq!(link.rel.as_ref().expect("no rel in link"), rel);
        assert_eq!(link.href, href);
        assert_eq!(
            link.media_type.as_ref().expect("no media_type in link"),
            media_type
        );
    }
}
