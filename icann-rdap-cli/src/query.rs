use std::io::ErrorKind;

use icann_rdap_client::{
    check::CheckType,
    md::{MdOptions, MdParams, ToMd},
    query::{
        qtype::QueryType,
        request::{rdap_request, ResponseData},
    },
    request::{RequestData, SourceType},
};
use icann_rdap_common::response::RdapResponse;
use reqwest::Client;
use simplelog::info;
use termimad::{crossterm::style::Color::*, MadSkin};

use crate::error::CliError;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum OutputType {
    /// Results are rendered as Markdown in the terminal using ANSI terminal capabilities.
    AnsiText,

    /// Results are rendered as Markdown in plain text.
    Markdown,

    /// Results are output as JSON.
    Json,

    /// Results are output as Pretty JSON.
    PrettyJson,
}

pub(crate) async fn do_query<'a, W: std::io::Write>(
    base_url: &str,
    query_type: &QueryType,
    output_type: &OutputType,
    client: &Client,
    write: &mut W,
) -> Result<(), CliError> {
    match query_type {
        QueryType::IpV4Addr(_)
        | QueryType::IpV6Addr(_)
        | QueryType::IpV4Cidr(_)
        | QueryType::IpV6Cidr(_)
        | QueryType::AsNumber(_) => {
            do_inr_query(base_url, query_type, output_type, client, write).await
        }
        QueryType::Domain(_) | QueryType::DomainNameSearch(_) => {
            do_domain_query(base_url, query_type, output_type, client, write).await
        }
        _ => do_basic_query(base_url, query_type, output_type, None, client, write).await,
    }
}

async fn do_domain_query<'a, W: std::io::Write>(
    base_url: &str,
    query_type: &QueryType,
    output_type: &OutputType,
    client: &Client,
    write: &mut W,
) -> Result<(), CliError> {
    let response = rdap_request(base_url, query_type, client).await;
    match response {
        Ok(response) => {
            let source_host = response.host.to_owned();
            let req_data = RequestData {
                req_number: 1,
                source_host: &source_host,
                source_type: SourceType::DomainRegistry,
            };
            print_response(output_type, &req_data, &response, write)?;
            if let Some(url) = get_related_link(&response.rdap).first() {
                info!("Querying domain name from registrar.");
                let query_type = QueryType::Url(url.to_string());
                let registrar_response = rdap_request(base_url, &query_type, client).await;
                match registrar_response {
                    Ok(registrar_response) => {
                        let source_host = registrar_response.host.to_owned();
                        let req_data = RequestData {
                            req_number: 2,
                            source_host: &source_host,
                            source_type: SourceType::DomainRegistrar,
                        };
                        print_response(output_type, &req_data, &registrar_response, write)?;
                    }
                    Err(error) => return Err(CliError::RdapClient(error)),
                }
            }
        }
        Err(error) => return Err(CliError::RdapClient(error)),
    };
    Ok(())
}

async fn do_inr_query<'a, W: std::io::Write>(
    base_url: &str,
    query_type: &QueryType,
    output_type: &OutputType,
    client: &Client,
    write: &mut W,
) -> Result<(), CliError> {
    let response = rdap_request(base_url, query_type, client).await;
    match response {
        Ok(response) => {
            let source_host = response.host.to_owned();
            let req_data = RequestData {
                req_number: 1,
                source_host: &source_host,
                source_type: SourceType::UncategorizedRegistry,
            };
            print_response(output_type, &req_data, &response, write)?;
        }
        Err(error) => return Err(CliError::RdapClient(error)),
    };
    Ok(())
}

async fn do_basic_query<'a, W: std::io::Write>(
    base_url: &str,
    query_type: &QueryType,
    output_type: &OutputType,
    req_data: Option<&'a RequestData<'a>>,
    client: &Client,
    write: &mut W,
) -> Result<(), CliError> {
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
            print_response(output_type, &req_data, &response, write)?;
        }
        Err(error) => return Err(CliError::RdapClient(error)),
    };
    Ok(())
}

fn print_response<W: std::io::Write>(
    output_type: &OutputType,
    req_data: &RequestData,
    response: &ResponseData,
    write: &mut W,
) -> Result<(), CliError> {
    match output_type {
        OutputType::AnsiText => {
            let mut skin = MadSkin::default_dark();
            skin.set_headers_fg(Yellow);
            skin.bold.set_fg(Magenta);
            skin.italic.set_fg(Blue);
            skin.quote_mark.set_fg(White);
            skin.write_text_on(
                write,
                &response.rdap.to_md(MdParams {
                    heading_level: 1,
                    check_types: &[CheckType::Informational, CheckType::SpecificationCompliance],
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
                check_types: &[CheckType::Informational, CheckType::SpecificationCompliance],
                options: &MdOptions {
                    text_style_char: '_',
                    style_in_justify: true,
                    ..MdOptions::default()
                },
                req_data,
            })
        )?,
        OutputType::Json => writeln!(write, "{}", serde_json::to_string(&response).unwrap())?,
        OutputType::PrettyJson => writeln!(
            write,
            "{}",
            serde_json::to_string_pretty(&response).unwrap()
        )?,
    };
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
                    rel.eq_ignore_ascii_case("related")
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
