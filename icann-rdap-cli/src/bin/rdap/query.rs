use {
    icann_rdap_client::http::Client,
    icann_rdap_common::{
        check::{traverse_checks, CheckClass, CheckParams, Checks, GetChecks},
        response::get_related_links,
    },
    tracing::{debug, error, info},
};

use {
    icann_rdap_client::{
        gtld::{GtldParams, ToGtldWhois},
        md::{redacted::replace_redacted_items, MdOptions, MdParams, ToMd},
        rdap::{
            QueryType, RequestData, RequestResponse, RequestResponses, ResponseData, SourceType,
        },
    },
    termimad::{crossterm::style::Color::*, Alignment, MadSkin},
};

use chrono::DateTime;
use icann_rdap_client::rpsl::{RpslParams, ToRpsl};
use icann_rdap_common::{
    prelude::{Event, RdapResponse},
    response::ObjectCommonFields,
};
use json_pretty_compact::PrettyCompactFormatter;
use serde::Serialize;
use serde_json::Serializer;

use crate::{
    bootstrap::{get_base_url, BootstrapType},
    error::RdapCliError,
    request::do_request,
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
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProcessType {
    /// Standard data processing.
    Standard,

    /// Process data specifically from a registrar.
    Registrar,

    /// Process data specifically from a registry.
    Registry,
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

pub(crate) struct ProcessingParams {
    pub bootstrap_type: BootstrapType,
    pub output_type: OutputType,
    pub check_types: Vec<CheckClass>,
    pub process_type: ProcessType,
    pub tld_lookup: TldLookup,
    pub inr_backup_bootstrap: InrBackupBootstrap,
    pub error_on_checks: bool,
    pub no_cache: bool,
    pub max_cache_age: u32,
}

pub(crate) async fn do_query<W: std::io::Write>(
    query_type: &QueryType,
    processing_params: &ProcessingParams,
    client: &Client,
    write: &mut W,
) -> Result<(), RdapCliError> {
    match query_type {
        QueryType::IpV4Addr(_)
        | QueryType::IpV6Addr(_)
        | QueryType::IpV4Cidr(_)
        | QueryType::IpV6Cidr(_)
        | QueryType::AsNumber(_) => {
            do_inr_query(query_type, processing_params, client, write).await
        }
        QueryType::Domain(_) | QueryType::DomainNameSearch(_) => {
            do_domain_query(query_type, processing_params, client, write).await
        }
        _ => do_basic_query(query_type, processing_params, None, client, write).await,
    }
}

async fn do_domain_query<W: std::io::Write>(
    query_type: &QueryType,
    processing_params: &ProcessingParams,
    client: &Client,
    write: &mut W,
) -> Result<(), RdapCliError> {
    let mut transactions = RequestResponses::new();

    // special processing for TLD Lookups
    let base_url = if let QueryType::Domain(ref domain) = query_type {
        if domain.is_tld() && matches!(processing_params.tld_lookup, TldLookup::Iana) {
            "https://rdap.iana.org".to_string()
        } else {
            get_base_url(&processing_params.bootstrap_type, client, query_type).await?
        }
    } else {
        get_base_url(&processing_params.bootstrap_type, client, query_type).await?
    };

    let response = do_request(&base_url, query_type, processing_params, client).await;
    let registrar_response;
    match response {
        Ok(response) => {
            let user_wants_registrar =
                matches!(processing_params.process_type, ProcessType::Registrar);
            let source_host = response.http_data.host.to_owned();
            let req_data = RequestData {
                req_number: 1,
                req_target: !user_wants_registrar,
                source_host: &source_host,
                source_type: SourceType::DomainRegistry,
            };
            let replaced_rdap = replace_redacted_items(response.rdap.clone());
            let replaced_data = ResponseData {
                rdap: replaced_rdap,
                // copy other fields from `response`
                ..response.clone()
            };
            transactions = do_output(
                processing_params,
                &req_data,
                &replaced_data,
                write,
                transactions,
            )?;
            let regr_source_host;
            let regr_req_data: RequestData;
            if !matches!(processing_params.process_type, ProcessType::Registry) {
                if let Some(url) = get_related_links(&response.rdap).first() {
                    info!("Querying domain name from registrar.");
                    debug!("Registrar RDAP Url: {url}");
                    let query_type = QueryType::Url(url.to_string());
                    let registrar_response_result =
                        do_request(&base_url, &query_type, processing_params, client).await;
                    match registrar_response_result {
                        Ok(response_data) => {
                            registrar_response = response_data;
                            regr_source_host = registrar_response.http_data.host.to_owned();
                            let user_wants_registy =
                                matches!(processing_params.process_type, ProcessType::Registry);
                            regr_req_data = RequestData {
                                req_number: 2,
                                req_target: !user_wants_registy,
                                source_host: &regr_source_host,
                                source_type: SourceType::DomainRegistrar,
                            };
                            transactions = do_output(
                                processing_params,
                                &regr_req_data,
                                &registrar_response,
                                write,
                                transactions,
                            )?;
                        }
                        Err(error) => return Err(error),
                    }
                } else if matches!(processing_params.process_type, ProcessType::Registrar) {
                    return Err(RdapCliError::NoRegistrarFound);
                }
            }
            do_final_output(processing_params, write, transactions)?;
        }
        Err(error) => {
            if matches!(processing_params.process_type, ProcessType::Registry) {
                return Err(RdapCliError::NoRegistryFound);
            } else {
                return Err(error);
            }
        }
    };
    Ok(())
}

async fn do_inr_query<W: std::io::Write>(
    query_type: &QueryType,
    processing_params: &ProcessingParams,
    client: &Client,
    write: &mut W,
) -> Result<(), RdapCliError> {
    let mut transactions = RequestResponses::new();
    let mut base_url = get_base_url(&processing_params.bootstrap_type, client, query_type).await;
    if base_url.is_err()
        && matches!(
            processing_params.inr_backup_bootstrap,
            InrBackupBootstrap::Arin
        )
    {
        base_url = Ok("https://rdap.arin.net/registry".to_string());
    };
    let response = do_request(&base_url?, query_type, processing_params, client).await;
    match response {
        Ok(response) => {
            let source_host = response.http_data.host.to_owned();
            let req_data = RequestData {
                req_number: 1,
                req_target: true,
                source_host: &source_host,
                source_type: SourceType::RegionalInternetRegistry,
            };
            let replaced_rdap = replace_redacted_items(response.rdap.clone());
            let replaced_data = ResponseData {
                rdap: replaced_rdap,
                // copy other fields from `response`
                ..response.clone()
            };
            transactions = do_output(
                processing_params,
                &req_data,
                &replaced_data,
                write,
                transactions,
            )?;
            do_final_output(processing_params, write, transactions)?;
        }
        Err(error) => return Err(error),
    };
    Ok(())
}

async fn do_basic_query<'a, W: std::io::Write>(
    query_type: &QueryType,
    processing_params: &ProcessingParams,
    req_data: Option<&'a RequestData<'a>>,
    client: &Client,
    write: &mut W,
) -> Result<(), RdapCliError> {
    let mut transactions = RequestResponses::new();
    let base_url = get_base_url(&processing_params.bootstrap_type, client, query_type).await?;
    let response = do_request(&base_url, query_type, processing_params, client).await;
    match response {
        Ok(response) => {
            let source_host = response.http_data.host.to_owned();
            let req_data = if let Some(meta) = req_data {
                RequestData {
                    req_number: meta.req_number + 1,
                    req_target: true,
                    source_host: meta.source_host,
                    source_type: SourceType::UncategorizedRegistry,
                }
            } else {
                RequestData {
                    req_number: 1,
                    req_target: true,
                    source_host: &source_host,
                    source_type: SourceType::UncategorizedRegistry,
                }
            };
            let replaced_rdap = replace_redacted_items(response.rdap.clone());
            let replaced_data = ResponseData {
                rdap: replaced_rdap,
                // copy other fields from `response`
                ..response.clone()
            };
            transactions = do_output(
                processing_params,
                &req_data,
                &replaced_data,
                write,
                transactions,
            )?;
            do_final_output(processing_params, write, transactions)?;
        }
        Err(error) => return Err(error),
    };
    Ok(())
}

/// Sends output according to output.
///
/// This function is to allow output from a server shortly after it is
/// received so users see progress. This may work with some output types
/// and not others. Even after all iterations are made with this
/// function, [do_final_output] should be called.
fn do_output<'a, W: std::io::Write>(
    processing_params: &ProcessingParams,
    req_data: &'a RequestData,
    response: &'a ResponseData,
    write: &mut W,
    mut transactions: RequestResponses<'a>,
) -> Result<RequestResponses<'a>, RdapCliError> {
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
                skin.table.set_fg(DarkGreen);
                skin.table.align = Alignment::Center;
                skin.inline_code.set_fgbg(Cyan, Reset);
                skin.write_text_on(
                    write,
                    &response.rdap.to_md(MdParams {
                        heading_level: 1,
                        root: &response.rdap,
                        http_data: &response.http_data,
                        parent_type: response.rdap.get_type(),
                        check_types: &processing_params.check_types,
                        options: &MdOptions::default(),
                        req_data,
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
                        parent_type: response.rdap.get_type(),
                        check_types: &processing_params.check_types,
                        options: &MdOptions {
                            text_style_char: '_',
                            style_in_justify: true,
                            ..MdOptions::default()
                        },
                        req_data,
                    })
                )?;
            }
            OutputType::GtldWhois => {
                let mut params = GtldParams {
                    root: &response.rdap,
                    parent_type: response.rdap.get_type(),
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
                        if let Some(event_action) = &event.event_action {
                            if let Some(date) = &event.event_date {
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
            }
            _ => {} // do nothing
        }
    }

    let req_res = RequestResponse {
        checks: do_output_checks(response),
        req_data,
        res_data: response,
    };
    transactions.push(req_res);
    Ok(transactions)
}

fn do_output_checks(response: &ResponseData) -> Checks {
    let check_params = CheckParams {
        do_subchecks: true,
        root: &response.rdap,
        parent_type: response.rdap.get_type(),
        allow_unreg_ext: false,
    };
    let mut checks = response.rdap.get_checks(check_params);
    checks
        .items
        .append(&mut response.http_data.get_checks(check_params).items);
    checks
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

/// Finishes up output.
///
/// Some output types will have to do all their processing in this function
/// instead of [do_output].
fn do_final_output<W: std::io::Write>(
    processing_params: &ProcessingParams,
    write: &mut W,
    transactions: RequestResponses<'_>,
) -> Result<(), RdapCliError> {
    match processing_params.output_type {
        OutputType::Json | OutputType::PrettyJson | OutputType::PrettyCompactJson => {
            let output_count = transactions
                .iter()
                .filter(|t| t.req_data.req_target)
                .count();
            // let pretty = matches!(processing_params.output_type, OutputType::PrettyJson);
            if output_count == 1 {
                for req_res in &transactions {
                    if req_res.req_data.req_target {
                        write_json(processing_params, write, &req_res.res_data.rdap)?;
                        // if !pretty {
                        //     writeln!(
                        //         write,
                        //         "{}",
                        //         serde_json::to_string(&req_res.res_data.rdap).unwrap()
                        //     )?;
                        // } else {
                        //     writeln!(
                        //         write,
                        //         "{}",
                        //         serde_json::to_string_pretty(&req_res.res_data.rdap).unwrap()
                        //     )?;
                        // }
                        break;
                    }
                }
            } else {
                let output_vec = transactions
                    .iter()
                    .map(|t| &t.res_data.rdap)
                    .collect::<Vec<&RdapResponse>>();
                write_json(processing_params, write, &output_vec)?;
                // if !pretty {
                //     writeln!(write, "{}", serde_json::to_string(&output_vec).unwrap())?;
                // } else {
                //     writeln!(
                //         write,
                //         "{}",
                //         serde_json::to_string_pretty(&output_vec).unwrap()
                //     )?;
                // }
            }
        }
        OutputType::JsonExtra => {
            writeln!(write, "{}", serde_json::to_string(&transactions).unwrap())?
        }
        OutputType::GtldWhois => {}
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
                    obj_status.iter().for_each(|s| statuses.push(s));
                }
            }
            // Always print a JSON object with a status array, even if empty
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
                            .for_each(|e| events.push(e))
                    });
                }
            }
            // Always print a JSON object with a status array, even if empty
            let obj = serde_json::json!({"events": events});
            writeln!(write, "{}", serde_json::to_string(&obj).unwrap())?;
        }
        _ => {} // do nothing
    };

    let mut checks_found = false;
    // we don't want to error on informational
    let error_check_types: Vec<CheckClass> = processing_params
        .check_types
        .iter()
        .filter(|ct| *ct != &CheckClass::Informational)
        .copied()
        .collect();
    for req_res in &transactions {
        let found = traverse_checks(
            &req_res.checks,
            &error_check_types,
            None,
            &mut |struct_tree, check_item| {
                if processing_params.error_on_checks {
                    error!("{struct_tree} -> {check_item}")
                }
            },
        );
        if found {
            checks_found = true
        }
    }
    if checks_found && processing_params.error_on_checks {
        return Err(RdapCliError::ErrorOnChecks);
    }

    Ok(())
}
