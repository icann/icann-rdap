use icann_rdap_common::check::traverse_checks;
use icann_rdap_common::check::CheckClass;
use icann_rdap_common::check::CheckParams;
use icann_rdap_common::check::GetChecks;
use simplelog::error;
use std::io::ErrorKind;

use icann_rdap_client::{
    md::{MdOptions, MdParams, ToMd},
    query::{
        qtype::QueryType,
        request::{rdap_request, ResponseData},
    },
    request::{RequestData, RequestResponse, RequestResponses, SourceType},
};
use icann_rdap_common::{media_types::RDAP_MEDIA_TYPE, response::RdapResponse};
use reqwest::Client;
use simplelog::info;
use termimad::{crossterm::style::Color::*, Alignment, MadSkin};

use crate::error::CliError;

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

    /// RDAP JSON with extra information.
    JsonExtra,
}

pub(crate) struct OutputParams {
    pub output_type: OutputType,
    pub check_types: Vec<CheckClass>,
    pub error_on_checks: bool,
}

pub(crate) async fn do_query<'a, W: std::io::Write>(
    base_url: &str,
    query_type: &QueryType,
    output_params: &OutputParams,
    client: &Client,
    write: &mut W,
) -> Result<(), CliError> {
    match query_type {
        QueryType::IpV4Addr(_)
        | QueryType::IpV6Addr(_)
        | QueryType::IpV4Cidr(_)
        | QueryType::IpV6Cidr(_)
        | QueryType::AsNumber(_) => {
            do_inr_query(base_url, query_type, output_params, client, write).await
        }
        QueryType::Domain(_) | QueryType::DomainNameSearch(_) => {
            do_domain_query(base_url, query_type, output_params, client, write).await
        }
        _ => do_basic_query(base_url, query_type, output_params, None, client, write).await,
    }
}

async fn do_domain_query<'a, W: std::io::Write>(
    base_url: &str,
    query_type: &QueryType,
    output_params: &OutputParams,
    client: &Client,
    write: &mut W,
) -> Result<(), CliError> {
    let mut transactions = RequestResponses::new();
    let response = rdap_request(base_url, query_type, client).await;
    match response {
        Ok(response) => {
            let source_host = response.host.to_owned();
            let req_data = RequestData {
                req_number: 1,
                source_host: &source_host,
                source_type: SourceType::DomainRegistry,
            };
            transactions = do_output(output_params, &req_data, &response, write, transactions)?;
            let regr_source_host;
            let regr_req_data: RequestData;
            if let Some(url) = get_related_link(&response.rdap).first() {
                info!("Querying domain name from registrar.");
                let query_type = QueryType::Url(url.to_string());
                let registrar_response = rdap_request(base_url, &query_type, client).await;
                match registrar_response {
                    Ok(registrar_response) => {
                        regr_source_host = registrar_response.host;
                        regr_req_data = RequestData {
                            req_number: 2,
                            source_host: &regr_source_host,
                            source_type: SourceType::DomainRegistrar,
                        };
                        transactions = do_output(
                            output_params,
                            &regr_req_data,
                            &response,
                            write,
                            transactions,
                        )?;
                    }
                    Err(error) => return Err(CliError::RdapClient(error)),
                }
            }
            do_final_output(output_params, write, transactions)?;
        }
        Err(error) => return Err(CliError::RdapClient(error)),
    };
    Ok(())
}

async fn do_inr_query<'a, W: std::io::Write>(
    base_url: &str,
    query_type: &QueryType,
    output_params: &OutputParams,
    client: &Client,
    write: &mut W,
) -> Result<(), CliError> {
    let mut transactions = RequestResponses::new();
    let response = rdap_request(base_url, query_type, client).await;
    match response {
        Ok(response) => {
            let source_host = response.host.to_owned();
            let req_data = RequestData {
                req_number: 1,
                source_host: &source_host,
                source_type: SourceType::RegionalInternetRegistry,
            };
            transactions = do_output(output_params, &req_data, &response, write, transactions)?;
            do_final_output(output_params, write, transactions)?;
        }
        Err(error) => return Err(CliError::RdapClient(error)),
    };
    Ok(())
}

async fn do_basic_query<'a, W: std::io::Write>(
    base_url: &str,
    query_type: &QueryType,
    output_params: &OutputParams,
    req_data: Option<&'a RequestData<'a>>,
    client: &Client,
    write: &mut W,
) -> Result<(), CliError> {
    let mut transactions = RequestResponses::new();
    let response = rdap_request(base_url, query_type, client).await;
    match response {
        Ok(response) => {
            let source_host = response.host.to_owned();
            let req_data = if let Some(meta) = req_data {
                RequestData {
                    req_number: meta.req_number + 1,
                    source_host: meta.source_host,
                    source_type: SourceType::UncategorizedRegistry,
                }
            } else {
                RequestData {
                    req_number: 1,
                    source_host: &source_host,
                    source_type: SourceType::UncategorizedRegistry,
                }
            };
            transactions = do_output(output_params, &req_data, &response, write, transactions)?;
            do_final_output(output_params, write, transactions)?;
        }
        Err(error) => return Err(CliError::RdapClient(error)),
    };
    Ok(())
}

fn do_output<'a, W: std::io::Write>(
    output_params: &OutputParams,
    req_data: &'a RequestData,
    response: &'a ResponseData,
    write: &mut W,
    mut transactions: RequestResponses<'a>,
) -> Result<RequestResponses<'a>, CliError> {
    match output_params.output_type {
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
                    parent_type: response.rdap.get_type(),
                    check_types: &output_params.check_types,
                    options: &MdOptions::default(),
                    req_data,
                }),
            )?;
        }
        OutputType::Markdown => writeln!(
            write,
            "{}",
            response.rdap.to_md(MdParams {
                heading_level: 1,
                root: &response.rdap,
                parent_type: response.rdap.get_type(),
                check_types: &output_params.check_types,
                options: &MdOptions {
                    text_style_char: '_',
                    style_in_justify: true,
                    ..MdOptions::default()
                },
                req_data,
            })
        )?,
        _ => {} // do nothing
    };
    let checks = response.rdap.get_checks(CheckParams {
        do_subchecks: true,
        root: &response.rdap,
        parent_type: response.rdap.get_type(),
    });
    let req_res = RequestResponse {
        checks,
        req_data,
        res_data: response,
    };
    transactions.push(req_res);
    Ok(transactions)
}

fn do_final_output<W: std::io::Write>(
    output_params: &OutputParams,
    write: &mut W,
    transactions: RequestResponses<'_>,
) -> Result<(), CliError> {
    match output_params.output_type {
        OutputType::Json => {
            for req_res in &transactions {
                writeln!(
                    write,
                    "{}",
                    serde_json::to_string(&req_res.res_data.rdap).unwrap()
                )?;
            }
        }
        OutputType::PrettyJson => {
            for req_res in &transactions {
                writeln!(
                    write,
                    "{}",
                    serde_json::to_string_pretty(&req_res.res_data.rdap).unwrap()
                )?;
            }
        }
        OutputType::JsonExtra => {
            writeln!(write, "{}", serde_json::to_string(&transactions).unwrap())?
        }
        _ => {} // do nothing
    };

    let mut checks_found = false;
    // we don't want to error on informational
    let error_check_types: Vec<CheckClass> = output_params
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
                if output_params.error_on_checks {
                    error!("{struct_tree} -> {check_item}")
                }
            },
        );
        if found {
            checks_found = true
        }
    }
    if checks_found && output_params.error_on_checks {
        return Err(CliError::ErrorOnChecks);
    }

    Ok(())
}

#[derive(Clone)]
pub(crate) struct BridgeWriter<W: std::fmt::Write>(pub(crate) W);

impl<W: std::fmt::Write> std::io::Write for BridgeWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .write_str(&String::from_utf8_lossy(buf))
            .map_err(|e| std::io::Error::new(ErrorKind::Other, e))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn get_related_link(rdap_response: &RdapResponse) -> Vec<&str> {
    if let Some(links) = rdap_response.get_links() {
        let urls: Vec<&str> = links
            .iter()
            .filter(|l| {
                if let Some(rel) = &l.rel {
                    if let Some(media_type) = &l.media_type {
                        rel.eq_ignore_ascii_case("related")
                            && media_type.eq_ignore_ascii_case(RDAP_MEDIA_TYPE)
                    } else {
                        false
                    }
                } else {
                    false
                }
            })
            .map(|l| l.href.as_str())
            .collect::<Vec<&str>>();
        urls
    } else {
        Vec::new()
    }
}
