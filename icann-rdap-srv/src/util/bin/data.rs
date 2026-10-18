//! Shared RDAP object-building logic for data-management binaries.
//!
//! Contains the CLI argument definitions, value parsers, and builder functions
//! used to construct RDAP objects from command-line arguments. Shared between
//! the `rdap-srv-data` binary (which writes generated objects to files) and
//! database-oriented management binaries.

use {
    crate::{
        config::DEFAULT_DATA_RDAP_BASE_URL,
        error::RdapServerError,
        storage::{
            StoreOps,
            data::{AutnumId, DomainId, EntityId, NameserverId, NetworkId, NetworkIdType},
        },
    },
    chrono::{DateTime, FixedOffset, Utc},
    cidr::{IpCidr, IpInet},
    clap::Args,
    icann_rdap_client::rdap::QueryType,
    icann_rdap_common::{
        contact::{Contact, PostalAddress},
        media_types::RDAP_MEDIA_TYPE,
        prelude::{RdapResponse, ToNotices, ToRemarks, ToResponse, VectorStringish},
        response::{
            Autnum, Domain, DsDatum, Entity, Event, EventActionValue, Events, Help, Link, Links,
            Nameserver, Network, NoticeOrRemark, SecureDns, ToChild,
        },
    },
    regex::Regex,
    std::{io::IsTerminal, str::FromStr},
    tokio::io::AsyncReadExt,
};

#[derive(Debug, Args)]
struct ObjectArgs {
    /// Base URL of the server where the object is to be served.
    #[arg(short = 'B', long, env = "RDAP_BASE_URL", default_value = DEFAULT_DATA_RDAP_BASE_URL)]
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

    /// Expiration date and time.
    ///
    /// This argument should be in RFC3339 format. Only emitted as an event when specified.
    #[arg(long, value_parser = parse_datetime)]
    expiration: Option<DateTime<FixedOffset>>,

    /// Registrar expiration date and time.
    ///
    /// This argument should be in RFC3339 format. Only emitted as an event when specified.
    #[arg(long, value_parser = parse_datetime)]
    registrar_expiration: Option<DateTime<FixedOffset>>,

    /// Last update of RDAP database date and time.
    ///
    /// Accepts an RFC3339 date-time or the literal value "now". Only emitted as an event when specified.
    #[arg(long, value_parser = parse_last_update)]
    last_update_of_rdap_database: Option<DateTime<FixedOffset>>,

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

/// Accepts an RFC3339 date-time or the literal string "now".
fn parse_last_update(arg: &str) -> Result<DateTime<FixedOffset>, String> {
    if arg == "now" {
        Ok(Utc::now().into())
    } else {
        DateTime::parse_from_rfc3339(arg)
            .map_err(|e| format!("expected RFC3339 date-time or \"now\": {e}"))
    }
}

fn parse_notice_or_remark(arg: &str) -> Result<NoticeOrRemark, RdapServerError> {
    let re = Regex::new(r"^(?P<l>\(\S+\)\[\S+\])?\s*(?P<t>.+)$")
        .expect("creating notice/remark argument regex");
    let Some(cap) = re.captures(arg) else {
        return Err(RdapServerError::ArgParse(
            "Unable to parse Notice/Remark argument.".to_string(),
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
        links = vec![
            Link::builder()
                .media_type(link_type.as_str().to_string())
                .href(link_href.as_str().to_string())
                .value(link_href.as_str().to_string())
                .rel(link_rel.as_str().to_string())
                .build(),
        ];
    }
    let not_rem = NoticeOrRemark::builder()
        .description(vec![description.as_str().to_string()])
        .links(links)
        .build();
    Ok(not_rem)
}

#[derive(Debug, Args)]
pub struct EntityArgs {
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
pub struct NameserverArgs {
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
pub struct DomainArgs {
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

    /// Network CIDR for reverse DNS domains.
    ///
    /// The network must already exist in storage.
    #[arg(long)]
    net: Option<String>,
}

fn parse_ds_datum(arg: &str) -> Result<DsDatum, RdapServerError> {
    let strings = arg.split_whitespace().collect::<Vec<&str>>();
    if strings.len() != 4 {
        return Err(RdapServerError::InvalidArg(
            "not enough DS data".to_string(),
        ));
    }
    let digest = strings[3].to_owned();
    if digest.chars().any(|c| !c.is_ascii_hexdigit()) {
        return Err(RdapServerError::InvalidArg("invalid DS digest".to_string()));
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
        .digest(digest)
        .build();
    Ok(ds_datum)
}

#[derive(Debug, Args)]
pub struct AutnumArgs {
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
pub struct NetworkArgs {
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
pub struct SrvHelpArgs {
    /// Host.
    ///
    /// The host name for which help is given. If not given, then the default host is assumed.
    #[arg(long)]
    host: Option<String>,

    /// Adds a server notice.
    ///
    /// At least one notice is required: it is the only content that makes the help
    /// document identifiable when read back from storage.
    /// Takes the form of "\[LINK\] description" where the optional \[LINK\] takes
    /// the form of "(REL;TYPE)\[HREF\]". This argument maybe specified multiple times.
    #[arg(long, value_parser = parse_notice_or_remark)]
    notice: Vec<NoticeOrRemark>,
}

impl SrvHelpArgs {
    /// The host for which help is given, if one was specified.
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }
}

pub fn parse_cidr(arg: &str) -> Result<IpCidr, RdapServerError> {
    let ip_inet = IpInet::from_str(arg).map_err(|e| RdapServerError::InvalidArg(e.to_string()))?;
    Ok(ip_inet.network())
}

/// Acquires the raw JSON document text. The positional argument takes precedence;
/// otherwise the document is read from stdin when stdin is not a terminal.
pub async fn acquire_json(arg: Option<String>) -> Result<String, RdapServerError> {
    match arg {
        Some(json) => Ok(json),
        None if std::io::stdin().is_terminal() => Err(RdapServerError::InvalidArg(
            "no JSON given: pass it as an argument or pipe it via stdin".to_string(),
        )),
        None => {
            let mut buf = String::new();
            tokio::io::stdin().read_to_string(&mut buf).await?;
            if buf.trim().is_empty() {
                return Err(RdapServerError::InvalidArg(
                    "no JSON given on stdin".to_string(),
                ));
            }
            Ok(buf)
        }
    }
}

/// Parses and validates a raw JSON text as an RDAP document.
///
/// This uses the same path the server takes when loading `.json` data files, so any
/// document accepted here is guaranteed to be loadable by the server.
pub fn parse_rdap_json(text: &str) -> Result<RdapResponse, RdapServerError> {
    // Strip a UTF-8 byte order mark if present (e.g. files saved on Windows).
    let text = text.trim_start_matches('\u{feff}');
    let value: serde_json::Value = serde_json::from_str(text)?;
    RdapResponse::try_from(value)
        .map_err(|e| RdapServerError::InvalidArg(format!("not a valid RDAP document: {e}")))
}

pub enum RdapId {
    Entity(EntityId),
    Domain(DomainId),
    Nameserver(NameserverId),
    Autnum(AutnumId),
    Network(NetworkId),
    Help,
}

pub struct Output {
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

async fn get_network(store: &dyn StoreOps, cidr: &str) -> Result<Network, RdapServerError> {
    let n = store.get_network_by_cidr(cidr).await?;
    if let RdapResponse::Network(n) = n {
        Ok(n.to_child())
    } else {
        Err(RdapServerError::InvalidArg(cidr.to_string()))
    }
}

async fn network(
    store: &dyn StoreOps,
    network_cidr: Option<String>,
) -> Result<Option<Network>, RdapServerError> {
    if let Some(cidr) = network_cidr {
        let n = get_network(store, &cidr).await?;
        Ok(Some(n))
    } else {
        Ok(None)
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
        .event_action(EventActionValue::Registration.to_string())
        .build();
    events.push(created);
    let updated_at = if let Some(dt) = args.updated {
        dt
    } else {
        Utc::now().into()
    };
    let updated = Event::builder()
        .event_date(updated_at.to_rfc3339())
        .event_action(EventActionValue::LastChanged.to_string())
        .build();
    events.push(updated);
    if let Some(expiration) = args.expiration {
        let expiration = Event::builder()
            .event_date(expiration.to_rfc3339())
            .event_action(EventActionValue::Expiration.to_string())
            .build();
        events.push(expiration);
    }
    if let Some(registrar_expiration) = args.registrar_expiration {
        let registrar_expiration = Event::builder()
            .event_date(registrar_expiration.to_rfc3339())
            .event_action(EventActionValue::RegistrarExpiration.to_string())
            .build();
        events.push(registrar_expiration);
    }
    if let Some(last_update) = args.last_update_of_rdap_database {
        let event = Event::builder()
            .event_date(last_update.to_rfc3339())
            .event_action(EventActionValue::LastUpdateOfRDAPDatabase.to_string())
            .build();
        events.push(event);
    }
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
        .no_vcard(args.no_vcard)
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
            .map_err(|_| RdapServerError::InvalidArg("Invalid IDN U-Label".to_string()))?
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
        .and_network(network(store, args.net).await?)
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
    let id = RdapId::Network(NetworkId {
        network_id: NetworkIdType::Range {
            start_address: network
                .start_address
                .clone()
                .expect("network created without start address"),
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
    // An empty help document serializes without a "notices" array, which is the
    // field RdapResponse::try_from dispatches on — such a row could never be read
    // back. Reject it up front instead of storing an unreadable document.
    if args.notice.is_empty() {
        return Err(RdapServerError::InvalidArg(
            "help requires at least one --notice argument".to_string(),
        ));
    }
    let help = Help::response().notices(args.notice.to_notices()).build();
    let output = Output {
        rdap: help.to_response(),
        id: RdapId::Help,
        self_href: args.host.unwrap_or("__default".to_string()),
    };
    Ok(output)
}

/// A single RDAP object-building command.
#[derive(Debug)]
pub enum GenCommand {
    /// Build an entity.
    Entity(EntityArgs),
    /// Build a nameserver.
    Nameserver(NameserverArgs),
    /// Build a domain.
    Domain(DomainArgs),
    /// Build an autnum.
    Autnum(AutnumArgs),
    /// Build an IP network.
    Network(NetworkArgs),
    /// Build a server help response.
    SrvHelp(SrvHelpArgs),
}

/// Builds an RDAP object from CLI args, resolving references against `store`.
pub async fn build_object(
    cmd: GenCommand,
    store: &dyn StoreOps,
) -> Result<Output, RdapServerError> {
    match cmd {
        GenCommand::Entity(args) => make_entity(Box::new(args), store).await,
        GenCommand::Nameserver(args) => make_nameserver(Box::new(args), store).await,
        GenCommand::Domain(args) => {
            if args.ldh.is_none() && args.idn.is_none() {
                return Err(RdapServerError::InvalidArg(
                    "domain must specify either LDH or U-Label (idn) options".to_string(),
                ));
            }
            make_domain(Box::new(args), store).await
        }
        GenCommand::Autnum(args) => make_autnum(Box::new(args), store).await,
        GenCommand::Network(args) => make_network(Box::new(args), store).await,
        GenCommand::SrvHelp(args) => Ok(make_help(args)?),
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, FixedOffset, Utc};
    use icann_rdap_common::{prelude::RdapResponse, response::DsDatum};

    use super::{
        ObjectArgs, SrvHelpArgs, events, make_help, parse_ds_datum, parse_last_update,
        parse_notice_or_remark, parse_rdap_json,
    };

    fn object_args() -> ObjectArgs {
        ObjectArgs {
            base_url: "https://rdap.example.com".to_string(),
            status: vec![],
            created: None,
            updated: None,
            expiration: None,
            registrar_expiration: None,
            last_update_of_rdap_database: None,
            notice: vec![],
            remark: vec![],
            registrant: None,
            administrative: None,
            technical: None,
            abuse: None,
            billing: None,
            registrar: None,
            noc: None,
        }
    }

    fn rfc3339(s: &str) -> DateTime<FixedOffset> {
        DateTime::parse_from_rfc3339(s).expect("valid RFC3339 datetime")
    }

    #[test]
    fn test_events_omit_last_update_and_expirations_when_unspecified() {
        // GIVEN
        let args = object_args();

        // WHEN
        let evts = events(&args).expect("events should be present");

        // THEN
        let actions: Vec<String> = evts
            .iter()
            .filter_map(|e| e.event_action().map(String::from))
            .collect();
        assert_eq!(actions.len(), 2);
        assert!(actions.contains(&"registration".to_string()));
        assert!(actions.contains(&"last changed".to_string()));
        assert!(!actions.contains(&"last update of RDAP database".to_string()));
        assert!(!actions.contains(&"expiration".to_string()));
        assert!(!actions.contains(&"registrar expiration".to_string()));
    }

    #[test]
    fn test_events_include_new_events_when_specified() {
        // GIVEN
        let mut args = object_args();
        let expiration = rfc3339("2026-12-31T23:59:59Z");
        let registrar_expiration = rfc3339("2027-06-15T00:00:00Z");
        let last_update = rfc3339("2026-01-01T00:00:00Z");
        args.expiration = Some(expiration);
        args.registrar_expiration = Some(registrar_expiration);
        args.last_update_of_rdap_database = Some(last_update);

        // WHEN
        let evts = events(&args).expect("events should be present");

        // THEN
        let date_for = |action: &str| -> Option<String> {
            evts.iter()
                .find(|e| e.event_action().is_some_and(|a| a == action))
                .and_then(|e| e.event_date().map(String::from))
        };
        assert_eq!(date_for("expiration"), Some(expiration.to_rfc3339()));
        assert_eq!(
            date_for("registrar expiration"),
            Some(registrar_expiration.to_rfc3339())
        );
        assert_eq!(
            date_for("last update of RDAP database"),
            Some(last_update.to_rfc3339())
        );
    }

    #[test]
    fn test_parse_last_update_now() {
        // GIVEN
        let before = Utc::now();

        // WHEN
        let actual = parse_last_update("now").expect("parsing now");

        // THEN
        let diff = (actual.with_timezone(&Utc) - before).num_seconds().abs();
        assert!(diff < 2);
    }

    #[test]
    fn test_parse_last_update_rfc3339() {
        // GIVEN
        let arg = "2025-06-15T12:00:00Z";

        // WHEN
        let actual = parse_last_update(arg).expect("parsing rfc3339");

        // THEN
        assert_eq!(actual, rfc3339(arg));
    }

    #[test]
    fn test_parse_last_update_invalid() {
        // GIVEN
        let arg = "garbage";

        // WHEN
        let actual = parse_last_update(arg);

        // THEN
        assert!(actual.is_err());
    }

    #[test]
    fn test_parse_notice_arg() {
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
    fn test_parse_notice_with_link_arg() {
        // GIVEN
        let description = "This is a notice.";
        let media_type = "text/html";
        let rel = "about";
        let href = "https://example.com/stuff";
        let arg = format!("({rel};{media_type})[{href}] {description}");

        // WHEN
        let actual = parse_notice_or_remark(&arg).expect("parsing notice");

        // THEN
        assert!(
            actual
                .description
                .expect("no description!")
                .into_vec()
                .contains(&description.to_string())
        );
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
    fn test_parse_ds_data() {
        // GIVEN
        let data = "123456 1 2 0123456789ABCDEF";

        // WHEN
        let actual = parse_ds_datum(data).expect("parsing ds datum");

        // THEN
        let expected = DsDatum::builder()
            .key_tag(123456)
            .algorithm(1)
            .digest_type(2)
            .digest("0123456789ABCDEF".to_string())
            .build();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_bad_ds_digest() {
        // GIVEN
        let data = "123456 1 2 THISISNOTAVALIDDIGEST";

        // WHEN
        let actual = parse_ds_datum(data);

        // THEN
        assert!(actual.is_err());
    }

    #[test]
    fn test_parse_rdap_json_domain() {
        // GIVEN
        let json = r#"{"objectClassName":"domain","ldhName":"example.com"}"#;

        // WHEN
        let actual = parse_rdap_json(json).expect("parsing rdap json");

        // THEN
        assert!(matches!(actual, RdapResponse::Domain(_)));
    }

    #[test]
    fn test_parse_rdap_json_invalid_json() {
        // GIVEN
        let json = r#"{"objectClassName":"domain","ldhName":""#;

        // WHEN
        let actual = parse_rdap_json(json);

        // THEN
        assert!(actual.is_err());
    }

    #[test]
    fn test_parse_rdap_json_not_rdap() {
        // GIVEN
        let json = r#"{"foo":"bar"}"#;

        // WHEN
        let actual = parse_rdap_json(json);

        // THEN
        assert!(actual.is_err());
    }

    #[test]
    fn test_parse_rdap_json_with_byte_order_mark() {
        // GIVEN
        let json = "\u{feff}{\"objectClassName\":\"domain\",\"ldhName\":\"example.com\"}";

        // WHEN
        let actual = parse_rdap_json(json).expect("parsing rdap json");

        // THEN
        assert!(matches!(actual, RdapResponse::Domain(_)));
    }

    #[test]
    fn make_help_without_notice_errors() {
        // GIVEN
        let args = SrvHelpArgs {
            host: None,
            notice: vec![],
        };

        // WHEN
        let actual = make_help(args);

        // THEN
        assert!(actual.is_err());
    }
}
