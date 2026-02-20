use icann_rdap_common::{
    prelude::{ExtensionId, ToResponse},
    response::{jscontact::JsContactConvert, RdapResponse, Rfc9083Error},
};

use crate::config::JsContactConversion;

pub mod autnum;
pub mod domain;
pub mod domains;
pub mod entity;
pub mod ip;
pub mod nameserver;
pub mod nameservers;
pub mod response;
pub mod router;
pub mod srvhelp;

trait ToBootStrap {
    fn to_ip_bootstrap(self, ip_id: &str) -> RdapResponse;
    fn to_domain_bootstrap(self, domain_id: &str) -> RdapResponse;
    fn to_autnum_bootstrap(self, autnum_id: u32) -> RdapResponse;
    fn to_entity_bootstrap(self, entity_id: &str) -> RdapResponse;
    fn to_nameserver_bootstrap(self, nameserver_id: &str) -> RdapResponse;
}

impl ToBootStrap for RdapResponse {
    fn to_ip_bootstrap(self, ip_id: &str) -> RdapResponse {
        match self {
            Self::ErrorResponse(e) => bootstrap_redirect(*e, "ip", ip_id),
            _ => self,
        }
    }

    fn to_domain_bootstrap(self, domain_id: &str) -> RdapResponse {
        match self {
            Self::ErrorResponse(e) => bootstrap_redirect(*e, "domain", domain_id),
            _ => self,
        }
    }

    fn to_autnum_bootstrap(self, autnum_id: u32) -> RdapResponse {
        match self {
            Self::ErrorResponse(e) => bootstrap_redirect(*e, "autnum", &autnum_id.to_string()),
            _ => self,
        }
    }

    fn to_entity_bootstrap(self, entity_id: &str) -> RdapResponse {
        match self {
            Self::ErrorResponse(e) => bootstrap_redirect(*e, "entity", entity_id),
            _ => self,
        }
    }

    fn to_nameserver_bootstrap(self, nameserver_id: &str) -> RdapResponse {
        match self {
            Self::ErrorResponse(e) => bootstrap_redirect(*e, "nameserver", nameserver_id),
            _ => self,
        }
    }
}

fn bootstrap_redirect(error: Rfc9083Error, path: &str, id: &str) -> RdapResponse {
    let Some(ref notices) = error.common.notices else {
        return error.to_response();
    };
    let Some(notice) = notices.first() else {
        return error.to_response();
    };
    let Some(links) = &notice.links else {
        return error.to_response();
    };
    let Some(link) = links.first() else {
        return error.to_response();
    };
    let Some(href) = &link.href else {
        return error.to_response();
    };
    let href = format!("{}{path}/{id}", href);
    let redirect = Rfc9083Error::redirect().url(href).build();
    redirect.to_response()
}

fn parse_extensions(accept_header: &str) -> Vec<String> {
    accept_header
        .split(',')
        .map(|media_type| media_type.trim())
        .find(|media_type| media_type.starts_with("application/rdap+json"))
        .unwrap_or_default()
        .split(';')
        .map(|s| s.trim())
        .find(|parameter| parameter.starts_with("exts_list"))
        .unwrap_or_default()
        .trim_start_matches("exts_list")
        .trim_start_matches([' ', '=', '"'])
        .trim_end_matches('"')
        .split_terminator(' ')
        .map(String::from)
        .collect::<Vec<String>>()
}

fn jscontact_conversion(
    rdap: RdapResponse,
    conversion: JsContactConversion,
    exts_list: &[String],
) -> RdapResponse {
    if exts_list.contains(&ExtensionId::JsContact.to_string()) {
        match conversion {
            JsContactConversion::None => rdap,
            JsContactConversion::Also => rdap.to_jscontact(),
            JsContactConversion::Only => rdap.only_jscontact(),
        }
    } else {
        rdap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accept_header_with_multiple_extensions() {
        // GIVEN an Accept header with application/rdap+json containing multiple extensions
        let accept_header = "application/rdap+json;exts_list=\"cidr0 redacted\", application/json";

        // WHEN parsing extensions from the header
        let result = parse_extensions(accept_header);

        // THEN the function should return a vector with the extensions in order
        assert_eq!(result, vec!["cidr0", "redacted"]);
    }

    #[test]
    fn test_accept_header_with_single_extension() {
        // GIVEN an Accept header with application/rdap+json containing a single extension
        let accept_header = "application/rdap+json;exts_list=\"jscontact\"";

        // WHEN parsing extensions from the header
        let result = parse_extensions(accept_header);

        // THEN the function should return a vector with the single extension
        assert_eq!(result, vec!["jscontact"]);
    }

    #[test]
    fn test_accept_header_with_no_extensions() {
        // GIVEN an Accept header with application/rdap+json but no exts_list parameter
        let accept_header = "application/rdap+json, application/json";

        // WHEN parsing extensions from the header
        let result = parse_extensions(accept_header);

        // THEN the function should return an empty vector
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_accept_header_with_empty_exts_list() {
        // GIVEN an Accept header with application/rdap+json containing an empty exts_list
        let accept_header = "application/rdap+json;exts_list=\"\", application/json";

        // WHEN parsing extensions from the header
        let result = parse_extensions(accept_header);

        // THEN the function should return an empty vector
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_accept_header_without_rdap_media_type() {
        // GIVEN an Accept header without application/rdap+json media type
        let accept_header = "application/json, text/html";

        // WHEN parsing extensions from the header
        let result = parse_extensions(accept_header);

        // THEN the function should return an empty vector
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_accept_header_with_multiple_media_types_and_extensions() {
        // GIVEN an Accept header with multiple media types and extensions in the RDAP media type
        let accept_header = "text/html, application/rdap+json;exts_list=\"sorting paging\", application/json; charset=utf-8";

        // WHEN parsing extensions from the header
        let result = parse_extensions(accept_header);

        // THEN the function should return the extensions from the application/rdap+json media type
        assert_eq!(result, vec!["sorting", "paging"]);
    }

    #[test]
    fn test_accept_header_with_spaces_and_various_formatting() {
        // GIVEN an Accept header with leading/trailing spaces but no spaces around semicolon
        let accept_header =
            " application/rdap+json; exts_list = \" nro_rdap_profile_0 jscontact \" ";

        // WHEN parsing extensions from the header
        let result = parse_extensions(accept_header);

        // THEN the function should handle the formatting correctly and return extensions
        assert_eq!(result, vec!["nro_rdap_profile_0", "jscontact"]);
    }

    #[test]
    fn test_empty_accept_header() {
        // GIVEN an empty Accept header
        let accept_header = "";

        // WHEN parsing extensions from the header
        let result = parse_extensions(accept_header);

        // THEN the function should return an empty vector
        assert_eq!(result, Vec::<String>::new());
    }
}
