use {
    icann_rdap_client::http::Client,
    tracing::{debug, info},
};

use {
    icann_rdap_client::{
        gtld::{GtldParams, ToGtldWhois},
        md::{MdOptions, MdParams, ToMd},
        rdap::{QueryType, RequestData, RequestResponse, ResponseData},
    },
    termimad::{Alignment, MadSkin, crossterm::style::Color::*},
};

use chrono::DateTime;
use enumflags2::{BitFlags, bitflags};
use icann_rdap_cli::args::target::LinkParams;
use icann_rdap_client::rpsl::{RpslParams, ToRpsl};
use icann_rdap_common::{
    check::{
        ALL_CHECK_CLASSES, WARNING_CHECK_CLASSES, process::do_check_processing, traverse_checks,
    },
    prelude::{Event, Link, RdapResponse, get_relationship_links},
    response::ObjectCommonFields,
};
use json_pretty_compact::PrettyCompactFormatter;
use serde::Serialize;
use serde_json::Serializer;
use tracing::warn;

use crate::{
    bootstrap::{BootstrapType, get_base_url},
    dirs,
    error::RdapCliError,
    request::request_and_process,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum OutputType {
    /// Results are rendered as Markdown in the terminal using ANSI terminal capabilities.
    RenderedMarkdown,

    /// Results are rendered as Markdown in plain text.
    Markdown,

    /// Results are output as RDAP JSON.
    Json,

    /// Results are output as Pretty RDAP JSON.
    PrettyJson,

    /// JSON output that is compact and pretty.
    PrettyCompactJson,

    /// Global Top Level Domain Output
    GtldWhois,

    /// Routing Policy Specification Language (RPSL).
    Rpsl,

    /// RDAP JSON with extra information.
    JsonExtra,

    /// URL
    Url,

    /// Only print primary object's status, one per line.
    StatusText,

    /// Only print primary object's status as JSON.
    StatusJson,

    /// Only print primary object's events, one per line.
    EventText,

    /// Only print primary object's events as JSON.
    EventJson,

    /// Download geofeed files from RDAP response (RFC 9877).
    Geofeed,
}

/// Used for doing TLD Lookups.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TldLookup {
    /// Use IANA for TLD lookups.
    Iana,

    /// No TLD specific lookups.
    None,
}

/// Used for doing TLD Lookups.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum InrBackupBootstrap {
    /// Use ARIN if no bootstraps can be found for INR queries.
    Arin,

    /// No INR bootstrap backup.
    None,
}

/// Redaction Flags.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[bitflags]
#[repr(u64)]
pub(crate) enum RedactionFlag {
    /// Highlight Simple Redactions.
    HighlightSimpleRedactions,

    /// Show RFC 9537 redaction directives.
    ShowRfc9537,

    /// Do not turn RFC 9537 redactions into Simple Redactions.
    DoNotSimplifyRfc9537,

    /// Process RFC 9537 Redactions
    DoRfc9537Redactions,
}

pub(crate) struct ProcessingParams {
    pub bootstrap_type: BootstrapType,
    pub output_type: OutputType,
    pub tld_lookup: TldLookup,
    pub inr_backup_bootstrap: InrBackupBootstrap,
    pub no_cache: bool,
    pub max_cache_age: u32,
    pub redaction_flags: BitFlags<RedactionFlag>,
    pub link_params: LinkParams,
    pub to_jscontact: bool,
    pub self_link_caching: bool,
    pub geofeed_file: Option<std::path::PathBuf>,
}

pub(crate) async fn exec_queries<W: std::io::Write>(
    query_type: &QueryType,
    processing_params: &ProcessingParams,
    client: &Client,
    write: &mut W,
) -> Result<(), RdapCliError> {
    let mut transactions: Vec<RequestResponse> = Vec::new();
    let base_url = determine_base_url(query_type, processing_params, client).await?;
    debug!(
        "Link targets: '{}'",
        processing_params.link_params.link_targets.join(" ")
    );
    debug!(
        "Link depth: min {} max {}",
        processing_params.link_params.min_link_depth, processing_params.link_params.max_link_depth
    );
    debug!(
        "Only show targets: {}",
        processing_params.link_params.only_show_target
    );

    let mut received_non_200 = false;

    let mut query_type = query_type.to_owned();
    for req_number in 1..=processing_params.link_params.max_link_depth {
        debug!("Querying {}", query_type.query_url(&base_url)?);
        debug!("Request Number: {}", req_number);

        let response =
            request_and_process(&base_url, &query_type, processing_params, client).await?;
        let is_target = if processing_params.link_params.only_show_target {
            req_number > 1
        } else {
            true
        };
        let req_data = RequestData {
            req_number,
            req_target: is_target,
        };

        if response.http_data.status_code() != 200 {
            received_non_200 = true;
        }

        // Output immediately for streaming behavior
        if is_target {
            output_immediately(processing_params, &req_data, &response, write)?;
        }

        if let Some(url) =
            get_relationship_links(&processing_params.link_params.link_targets, &response.rdap)
                .first()
        {
            info!(
                "Found next target with relationship(s) of '{}'.",
                processing_params.link_params.link_targets.join(" ")
            );
            query_type = QueryType::Url(url.to_string());
            transactions.push(RequestResponse {
                req_data,
                res_data: response,
            });
        } else if req_number < processing_params.link_params.min_link_depth {
            return Err(RdapCliError::LinkTargetNotFound(
                processing_params.link_params.link_targets.join(" "),
            ));
        } else {
            transactions.push(RequestResponse {
                req_data,
                res_data: response,
            });
            break;
        }
    }

    // Handle geofeed output type - download geofeed files
    if processing_params.output_type == OutputType::Geofeed {
        let geofeed_path = if let Some(ref path) = processing_params.geofeed_file {
            // Create the parent directory if it doesn't exist
            if let Some(parent) = path.parent()
                && !parent.exists()
            {
                std::fs::create_dir_all(parent)?;
            }
            path.clone()
        } else {
            dirs::geofeed_download_path()?
        };

        // Collect all geofeed links from all transactions
        let mut all_urls = Vec::new();
        for tx in &transactions {
            if tx.req_data.req_target {
                let urls = extract_geofeed_links(&tx.res_data.rdap);
                all_urls.extend(urls);
            }
        }

        // Download each geofeed URL
        for url in all_urls {
            info!("Downloading geofeed from: {}", url);
            match download_geofeed(&url, &geofeed_path).await {
                Ok(file_path) => {
                    info!("Geofeed downloaded to: {}", file_path.display());
                }
                Err(e) => {
                    warn!("Failed to download geofeed from {}: {}", url, e);
                }
            }
        }
    }

    final_output(processing_params, write, transactions)?;

    if received_non_200 {
        return Err(RdapCliError::ResponseWasNot200Ok);
    }

    Ok(())
}

async fn determine_base_url(
    query_type: &QueryType,
    processing_params: &ProcessingParams,
    client: &Client,
) -> Result<String, RdapCliError> {
    // for number based lookups, if a base URL cannot be made from the bootstrap
    // then use the INR backup if configured to do so.
    match query_type {
        QueryType::IpV4Addr(_)
        | QueryType::IpV6Addr(_)
        | QueryType::IpV4Cidr(_)
        | QueryType::IpV6Cidr(_)
        | QueryType::IpV4AddrUp(_)
        | QueryType::IpV6AddrUp(_)
        | QueryType::IpV4CidrUp(_)
        | QueryType::IpV6CidrUp(_)
        | QueryType::IpV4AddrDown(_)
        | QueryType::IpV6AddrDown(_)
        | QueryType::IpV4CidrDown(_)
        | QueryType::IpV6CidrDown(_)
        | QueryType::IpV4AddrTop(_)
        | QueryType::IpV6AddrTop(_)
        | QueryType::IpV4CidrTop(_)
        | QueryType::IpV6CidrTop(_)
        | QueryType::IpV4AddrBottom(_)
        | QueryType::IpV6AddrBottom(_)
        | QueryType::IpV4CidrBottom(_)
        | QueryType::IpV6CidrBottom(_)
        | QueryType::AsNumber(_)
        | QueryType::AsNumberUp(_)
        | QueryType::AsNumberDown(_)
        | QueryType::AsNumberTop(_)
        | QueryType::AsNumberBottom(_)
        | QueryType::RdnsIpv4(_)
        | QueryType::RdnsIpv6(_)
        | QueryType::RdnsIpv4Up(_)
        | QueryType::RdnsIpv6Up(_)
        | QueryType::RdnsIpv4Down(_)
        | QueryType::RdnsIpv6Down(_)
        | QueryType::RdnsIpv4Top(_)
        | QueryType::RdnsIpv6Top(_)
        | QueryType::RdnsIpv4Bottom(_)
        | QueryType::RdnsIpv6Bottom(_) => {
            let mut base_url =
                get_base_url(&processing_params.bootstrap_type, client, query_type).await;
            if base_url.is_err()
                && matches!(
                    processing_params.inr_backup_bootstrap,
                    InrBackupBootstrap::Arin
                )
            {
                base_url = Ok("https://rdap.arin.net/registry".to_string());
            };
            base_url
        }

        // for domain based lookups, check to see if they are asking for a TLD.
        QueryType::Domain(_) | QueryType::ALabel(_) => {
            let domain = match query_type {
                QueryType::Domain(d) => Some(d),
                QueryType::ALabel(a) => Some(a),
                _ => None,
            };
            // special processing for TLD Lookups
            if let Some(domain) = domain {
                if domain.is_tld() && matches!(processing_params.tld_lookup, TldLookup::Iana) {
                    Ok("https://rdap.iana.org".to_string())
                } else {
                    get_base_url(&processing_params.bootstrap_type, client, query_type).await
                }
            } else {
                get_base_url(&processing_params.bootstrap_type, client, query_type).await
            }
        }
        _ => get_base_url(&processing_params.bootstrap_type, client, query_type).await,
    }
}

fn output_immediately<W: std::io::Write>(
    processing_params: &ProcessingParams,
    req_data: &RequestData,
    response: &ResponseData,
    write: &mut W,
) -> Result<(), RdapCliError> {
    if req_data.req_target {
        match processing_params.output_type {
            OutputType::RenderedMarkdown => {
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
                skin.horizontal_rule.set_fg(DarkGreen);
                skin.inline_code.set_fgbg(Cyan, Reset);
                let options = MdOptions {
                    bullet_char: '-',
                    indent_simulate_bullet: true,
                    ..MdOptions::default()
                };
                skin.write_text_on(
                    write,
                    &response.rdap.to_md(MdParams {
                        heading_level: 1,
                        root: &response.rdap,
                        http_data: &response.http_data,
                        options: &options,
                        req_data,
                        show_rfc9537_redactions: processing_params
                            .redaction_flags
                            .contains(RedactionFlag::ShowRfc9537),
                        highlight_simple_redactions: processing_params
                            .redaction_flags
                            .contains(RedactionFlag::HighlightSimpleRedactions),
                    }),
                )?;
            }
            OutputType::Markdown => {
                writeln!(
                    write,
                    "{}",
                    response.rdap.to_md(MdParams {
                        heading_level: 1,
                        root: &response.rdap,
                        http_data: &response.http_data,
                        options: &MdOptions {
                            text_style_char: '_',
                            style_in_justify: true,
                            ..MdOptions::default()
                        },
                        req_data,
                        show_rfc9537_redactions: processing_params
                            .redaction_flags
                            .contains(RedactionFlag::ShowRfc9537),
                        highlight_simple_redactions: processing_params
                            .redaction_flags
                            .contains(RedactionFlag::HighlightSimpleRedactions),
                    })
                )?;
            }
            OutputType::GtldWhois => {
                let mut params = GtldParams {
                    label: "".to_string(),
                };
                writeln!(write, "{}", response.rdap.to_gtld_whois(&mut params))?;
            }
            OutputType::Rpsl => {
                let params = RpslParams {
                    http_data: &response.http_data,
                };
                writeln!(write, "{}", response.rdap.to_rpsl(params))?;
            }
            OutputType::Url => {
                if let Some(url) = response.http_data.request_uri() {
                    writeln!(write, "{url}")?;
                }
            }
            OutputType::StatusText => {
                use icann_rdap_common::response::RdapResponse as RR;
                let statuses: Option<&[String]> = match &response.rdap {
                    RR::Entity(e) => Some(e.status()),
                    RR::Domain(d) => Some(d.status()),
                    RR::Nameserver(n) => Some(n.status()),
                    RR::Autnum(a) => Some(a.status()),
                    RR::Network(n) => Some(n.status()),
                    _ => None,
                };
                if let Some(list) = statuses {
                    for s in list {
                        writeln!(write, "{}", s)?;
                    }
                }
            }
            OutputType::EventText => {
                use icann_rdap_common::response::RdapResponse as RR;
                let events: Option<&[Event]> = match &response.rdap {
                    RR::Entity(e) => Some(e.events()),
                    RR::Domain(d) => Some(d.events()),
                    RR::Nameserver(n) => Some(n.events()),
                    RR::Autnum(a) => Some(a.events()),
                    RR::Network(n) => Some(n.events()),
                    _ => None,
                };
                if let Some(events) = events {
                    for event in events {
                        if let Some(event_action) = &event.event_action
                            && let Some(date) = &event.event_date
                        {
                            let date = DateTime::parse_from_rfc3339(date).ok();
                            if let Some(date) = date {
                                writeln!(
                                    write,
                                    "{} = {}",
                                    event_action,
                                    date.format("%a, %v %X %Z")
                                )?;
                            } else {
                                writeln!(write, "{} = BAD DATE", event_action,)?;
                            }
                        }
                    }
                }
            }
            _ => {} // do nothing for JSON types, handled in final output
        }
    }
    Ok(())
}

fn final_output<W: std::io::Write>(
    processing_params: &ProcessingParams,
    write: &mut W,
    transactions: Vec<RequestResponse>,
) -> Result<(), RdapCliError> {
    match processing_params.output_type {
        OutputType::Json | OutputType::PrettyJson | OutputType::PrettyCompactJson => {
            let output_count = transactions
                .iter()
                .filter(|t| t.req_data.req_target)
                .count();
            if output_count == 1 {
                for req_res in &transactions {
                    if req_res.req_data.req_target {
                        write_json(processing_params, write, &req_res.res_data.rdap)?;
                        break;
                    }
                }
            } else {
                let output_vec = transactions
                    .iter()
                    .filter(|t| t.req_data.req_target)
                    .map(|t| &t.res_data.rdap)
                    .collect::<Vec<&RdapResponse>>();
                write_json(processing_params, write, &output_vec)?;
            }
        }
        OutputType::JsonExtra => {
            writeln!(write, "{}", serde_json::to_string(&transactions).unwrap())?
        }
        OutputType::StatusJson => {
            use icann_rdap_common::response::RdapResponse as RR;
            let mut statuses = vec![];
            for rr in &transactions {
                if rr.req_data.req_target {
                    let obj_status = match &rr.res_data.rdap {
                        RR::Entity(e) => e.status(),
                        RR::Domain(d) => d.status(),
                        RR::Nameserver(n) => n.status(),
                        RR::Autnum(a) => a.status(),
                        RR::Network(n) => n.status(),
                        _ => &[],
                    };
                    obj_status.iter().for_each(|s| statuses.push(s.clone()));
                }
            }
            let obj = serde_json::json!({"status": statuses});
            writeln!(write, "{}", serde_json::to_string(&obj).unwrap())?;
        }
        OutputType::EventJson => {
            use icann_rdap_common::response::RdapResponse as RR;
            let mut events = vec![];
            for rr in &transactions {
                if rr.req_data.req_target {
                    let obj_event: Option<&[Event]> = match &rr.res_data.rdap {
                        RR::Entity(e) => Some(e.events()),
                        RR::Domain(d) => Some(d.events()),
                        RR::Nameserver(n) => Some(n.events()),
                        RR::Autnum(a) => Some(a.events()),
                        RR::Network(n) => Some(n.events()),
                        _ => None,
                    };
                    obj_event.iter().for_each(|evs| {
                        evs.iter()
                            .filter(|e| e.event_action.as_ref().is_some())
                            .filter(|e| {
                                e.event_date
                                    .as_ref()
                                    .is_some_and(|ed| DateTime::parse_from_rfc3339(ed).is_ok())
                            })
                            .for_each(|e| events.push(e.clone()))
                    });
                }
            }
            let obj = serde_json::json!({"events": events});
            writeln!(write, "{}", serde_json::to_string(&obj).unwrap())?;
        }
        _ => {} // do nothing, already handled in immediate output
    };

    for tx in transactions {
        if let Some(request_uri) = tx.res_data.http_data.request_uri() {
            let mut checks_found = false;
            let mut warnings_found = false;
            let checks =
                do_check_processing(&tx.res_data.rdap, Some(&tx.res_data.http_data), None, true);
            traverse_checks(
                &checks,
                ALL_CHECK_CLASSES,
                None,
                &mut |_struct_name, item| {
                    if WARNING_CHECK_CLASSES.contains(&item.check_class) {
                        warnings_found = true;
                    } else {
                        checks_found = true;
                    }
                },
            );
            if warnings_found {
                warn!("Service issues found. To analyze, use 'rdap-test {request_uri}'.");
            } else if checks_found {
                info!("Use 'rdap-test {request_uri}' to see service notes.");
            }
        }
    }

    Ok(())
}

fn write_json<W: std::io::Write, T: Serialize>(
    processing_params: &ProcessingParams,
    write: &mut W,
    data: &T,
) -> Result<(), RdapCliError> {
    match processing_params.output_type {
        OutputType::PrettyJson => {
            writeln!(write, "{}", serde_json::to_string_pretty(&data).unwrap())?;
        }
        OutputType::PrettyCompactJson => {
            let formatter = PrettyCompactFormatter::new();
            let mut serializer = Serializer::with_formatter(write, formatter);
            data.serialize(&mut serializer)?;
        }
        _ => {
            writeln!(write, "{}", serde_json::to_string(&data).unwrap())?;
        }
    };
    Ok(())
}

/// Extracts geofeed links from an RDAP response.
///
/// Per RFC 9877, geofeed links have rel="geofeed". Unlike other relationship
/// links, these point to external resources (typically CSV files), not RDAP JSON.
fn extract_geofeed_links(rdap_response: &RdapResponse) -> Vec<String> {
    let mut urls = Vec::new();

    fn collect_geofeed_links(links: &[Link], urls: &mut Vec<String>) {
        for link in links {
            if link
                .rel
                .as_ref()
                .is_some_and(|r| r.eq_ignore_ascii_case("geofeed"))
                && let Some(href) = &link.href
            {
                urls.push(href.clone());
            }
        }
    }

    match rdap_response {
        RdapResponse::Domain(d) => {
            collect_geofeed_links(d.links(), &mut urls);
        }
        RdapResponse::Entity(e) => {
            collect_geofeed_links(e.links(), &mut urls);
        }
        RdapResponse::Nameserver(n) => {
            collect_geofeed_links(n.links(), &mut urls);
        }
        RdapResponse::Autnum(a) => {
            collect_geofeed_links(a.links(), &mut urls);
        }
        RdapResponse::Network(n) => {
            collect_geofeed_links(n.links(), &mut urls);
        }
        RdapResponse::DomainSearchResults(s) => {
            for domain in &s.results {
                collect_geofeed_links(domain.links(), &mut urls);
            }
        }
        RdapResponse::EntitySearchResults(s) => {
            for entity in &s.results {
                collect_geofeed_links(entity.links(), &mut urls);
            }
        }
        RdapResponse::NameserverSearchResults(s) => {
            for ns in &s.results {
                collect_geofeed_links(ns.links(), &mut urls);
            }
        }
        RdapResponse::IpSearchResults(s) => {
            for network in &s.results {
                collect_geofeed_links(network.links(), &mut urls);
            }
        }
        RdapResponse::AutnumSearchResults(s) => {
            for autnum in &s.results {
                collect_geofeed_links(autnum.links(), &mut urls);
            }
        }
        _ => {}
    }

    urls
}

/// Downloads a geofeed URL to the specified file path.
///
/// If the path is a directory, the filename is derived from the URL.
/// If the path is a file, it is written directly to that location.
async fn download_geofeed(
    url: &str,
    output_path: &std::path::Path,
) -> Result<std::path::PathBuf, RdapCliError> {
    let file_path = if output_path.is_dir() {
        // Derive filename from URL
        let filename = url.split('/').next_back().unwrap_or("geofeed.csv");
        let filename = if filename.is_empty() {
            "geofeed.csv"
        } else {
            filename
        };
        output_path.join(filename)
    } else {
        output_path.to_path_buf()
    };

    // Download the file
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| RdapCliError::GeofeedDownload(format!("failed to send request: {}", e)))?;

    let bytes = response
        .bytes()
        .await
        .map_err(|e| RdapCliError::GeofeedDownload(format!("failed to read response: {}", e)))?;

    // Write to file
    std::fs::write(&file_path, &bytes)?;

    Ok(file_path)
}
