use icann_rdap_common::prelude::ObjectCommonFields;
use icann_rdap_common::response::{
    Rpk1Aspa, Rpk1AspaSearchResults, Rpk1Roa, Rpk1RoaSearchResults, Rpk1X509ResourceCert,
    Rpk1X509ResourceCertSearchResults,
};

use super::MdHeaderText;
use super::{
    MdParams, MdUtil, ToMd,
    string::StringUtil,
    table::{MultiPartTable, ToMpTable},
};

impl ToMd for Rpk1Roa {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent()));

        let header_text = self.get_header_text();
        md.push_str(
            &header_text
                .to_string()
                .to_header(params.heading_level, params.options),
        );

        let mut table = if params.highlight_simple_redactions {
            MultiPartTable::new_with_value_highlights_from_remarks(self.remarks())
        } else {
            MultiPartTable::new()
        };

        table = table.summary(header_text, params.options);

        table = table
            .header_ref(&"Identifiers")
            .and_nv_ref_maybe(&"Handle", &self.object_common.handle)
            .and_nv_ref_maybe(&"Name", &self.name);

        if let Some(roa_ips) = &self.roa_ips
            && !roa_ips.is_empty()
        {
            table = table.header_ref(&"ROA IP Blocks");
            for roa_ip in roa_ips {
                let ip = roa_ip.ip.as_deref().unwrap_or("");
                let max_len = roa_ip
                    .max_length
                    .as_ref()
                    .map(|m| m.to_string())
                    .unwrap_or_default();
                table = table.nv(&"IP", format!("{}/{}", ip, max_len));
            }
        }

        table = table.and_nv_ref_maybe(
            &"Origin AS",
            &self.origin_autnum.as_ref().map(|n| n.to_string()),
        );

        if self.roa_ips.is_some() || self.origin_autnum.is_some() {
            table = table.add_separator();
        }

        table = table
            .header_ref(&"Validity")
            .and_nv_ref_maybe(
                &"Not Valid Before",
                &self
                    .not_valid_before
                    .as_ref()
                    .map(|d| d.format_date_time(params).unwrap_or_default()),
            )
            .and_nv_ref_maybe(
                &"Not Valid After",
                &self
                    .not_valid_after
                    .as_ref()
                    .map(|d| d.format_date_time(params).unwrap_or_default()),
            );

        table = table
            .header_ref(&"URIs")
            .and_nv_ref_maybe(&"Publication", &self.publication_uri)
            .and_nv_ref_maybe(&"Notification", &self.notification_uri);

        table = table
            .header_ref(&"RPKI")
            .and_nv_ref_maybe(&"Type", &self.rpki_type.as_ref().map(|t| t.to_string()));

        if let Some(digests) = &self.digests
            && !digests.is_empty()
        {
            table = table.header_ref(&"Digests");
            for digest in digests {
                let algo = digest.digest_algorithm.as_deref().unwrap_or("");
                let dig = digest.digest.as_deref().unwrap_or("");
                table = table.nv(&"Algorithm", algo);
                table = table.nv(&"Hash", dig);
            }
        }

        table = self.object_common.add_to_mptable(table, params);
        table = self.remarks().add_to_mptable(table, params);

        md.push_str(&table.to_md(params));
        md.push_str(&self.object_common.entities.to_md(params.from_parent()));

        if params.show_rfc9537_redactions
            && let Some(redacted) = &self.object_common.redacted
        {
            md.push_str(&redacted.as_slice().to_md(params.from_parent()));
        }

        md.push('\n');
        md
    }
}

impl MdUtil for Rpk1Roa {
    fn get_header_text(&self) -> MdHeaderText {
        let header_text = if let Some(handle) = &self.object_common.handle {
            format!("Route Origin Authorization {}", handle)
        } else if let Some(origin) = &self.origin_autnum {
            format!("Route Origin Authorization AS{}", origin)
        } else if let Some(name) = &self.name {
            format!("Route Origin Authorization {}", name)
        } else {
            "Route Origin Authorization".to_string()
        };
        let mut header_text = MdHeaderText::builder().header_text(header_text);
        if let Some(entities) = &self.object_common.entities {
            for entity in entities {
                header_text = header_text.children_entry(entity.get_header_text());
            }
        };
        header_text.build()
    }
}

impl ToMd for Rpk1Aspa {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent()));

        let header_text = self.get_header_text();
        md.push_str(
            &header_text
                .to_string()
                .to_header(params.heading_level, params.options),
        );

        let mut table = if params.highlight_simple_redactions {
            MultiPartTable::new_with_value_highlights_from_remarks(self.remarks())
        } else {
            MultiPartTable::new()
        };

        table = table.summary(header_text, params.options);

        table = table
            .header_ref(&"Identifiers")
            .and_nv_ref_maybe(&"Handle", &self.object_common.handle)
            .and_nv_ref_maybe(&"Name", &self.name);

        table = table.header_ref(&"Autonomous Systems").and_nv_ref_maybe(
            &"Customer AS",
            &self.customer_autnum.as_ref().map(|n| n.to_string()),
        );

        if self.customer_autnum.is_some() || self.provider_autnums.is_some() {
            table = table.add_separator();
        }

        match &self.provider_autnums {
            Some(providers) if !providers.is_empty() => {
                let provider_list: Vec<String> = providers
                    .iter()
                    .filter_map(|p| p.as_u32().map(|a| format!("AS{}", a)))
                    .collect();
                table = table.nv_ul(&"Provider AS", provider_list, params.options);
            }
            _ => (),
        }

        table = table
            .header_ref(&"Validity")
            .and_nv_ref_maybe(
                &"Not Valid Before",
                &self
                    .not_valid_before
                    .as_ref()
                    .map(|d| d.format_date_time(params).unwrap_or_default()),
            )
            .and_nv_ref_maybe(
                &"Not Valid After",
                &self
                    .not_valid_after
                    .as_ref()
                    .map(|d| d.format_date_time(params).unwrap_or_default()),
            );

        table = table
            .header_ref(&"URIs")
            .and_nv_ref_maybe(&"Publication", &self.publication_uri)
            .and_nv_ref_maybe(&"Notification", &self.notification_uri);

        table = table
            .header_ref(&"RPKI")
            .and_nv_ref_maybe(&"Type", &self.rpki_type.as_ref().map(|t| t.to_string()));

        if let Some(digests) = &self.digests
            && !digests.is_empty()
        {
            table = table.header_ref(&"Digests");
            for digest in digests {
                let algo = digest.digest_algorithm.as_deref().unwrap_or("");
                let dig = digest.digest.as_deref().unwrap_or("");
                table = table.nv(&"Algorithm", algo);
                table = table.nv(&"Hash", dig);
            }
        }

        table = self.object_common.add_to_mptable(table, params);
        table = self.remarks().add_to_mptable(table, params);

        md.push_str(&table.to_md(params));
        md.push_str(&self.object_common.entities.to_md(params.from_parent()));

        if params.show_rfc9537_redactions
            && let Some(redacted) = &self.object_common.redacted
        {
            md.push_str(&redacted.as_slice().to_md(params.from_parent()));
        }

        md.push('\n');
        md
    }
}

impl MdUtil for Rpk1Aspa {
    fn get_header_text(&self) -> MdHeaderText {
        let header_text = if let Some(handle) = &self.object_common.handle {
            format!("Autonomous System Provider Authorization {}", handle)
        } else if let Some(customer) = &self.customer_autnum {
            format!("ASPA AS{}", customer)
        } else if let Some(name) = &self.name {
            format!("ASPA {}", name)
        } else {
            "Autonomous System Provider Authorization".to_string()
        };
        let mut header_text = MdHeaderText::builder().header_text(header_text);
        if let Some(entities) = &self.object_common.entities {
            for entity in entities {
                header_text = header_text.children_entry(entity.get_header_text());
            }
        };
        header_text.build()
    }
}

impl ToMd for Rpk1X509ResourceCert {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent()));

        let header_text = self.get_header_text();
        md.push_str(
            &header_text
                .to_string()
                .to_header(params.heading_level, params.options),
        );

        let mut table = if params.highlight_simple_redactions {
            MultiPartTable::new_with_value_highlights_from_remarks(self.remarks())
        } else {
            MultiPartTable::new()
        };

        table = table.summary(header_text, params.options);

        table = table
            .header_ref(&"Identifiers")
            .and_nv_ref_maybe(&"Handle", &self.object_common.handle);

        table = table
            .header_ref(&"Certificate")
            .and_nv_ref_maybe(&"Serial Number", &self.serial_number)
            .and_nv_ref_maybe(&"Issuer", &self.issuer)
            .and_nv_ref_maybe(&"Subject", &self.subject)
            .and_nv_ref_maybe(&"Signature Algorithm", &self.signature_algorithm)
            .and_nv_ref_maybe(&"Subject Key Identifier", &self.subject_key_identifier);

        if self.serial_number.is_some()
            || self.issuer.is_some()
            || self.subject.is_some()
            || self.signature_algorithm.is_some()
            || self.subject_key_identifier.is_some()
        {
            table = table.add_separator();
        }

        if let Some(spki) = &self.subject_public_key_info {
            table = table
                .header_ref(&"Public Key")
                .and_nv_ref_maybe(&"Algorithm", &spki.public_key_algorithm)
                .and_nv_ref_maybe(&"Key", &spki.public_key);
        }

        if self.subject_public_key_info.is_some() {
            table = table.add_separator();
        }

        if let Some(ips) = &self.ips
            && !ips.is_empty()
        {
            table = table.header_ref(&"Resources");
            let ip_list: Vec<String> = ips.to_vec();
            table = table.nv_ul(&"IP Blocks", ip_list, params.options);
        }

        if self.ips.is_some() || self.autnums.is_some() {
            table = table.add_separator();
        }

        if let Some(autnums) = &self.autnums
            && !autnums.is_empty()
        {
            let asn_list: Vec<String> = autnums
                .iter()
                .filter_map(|a| a.as_u32().map(|asn| format!("AS{}", asn)))
                .collect();
            table = table.nv_ul(&"AS Numbers", asn_list, params.options);
        }

        table = table
            .header_ref(&"Validity")
            .and_nv_ref_maybe(
                &"Not Valid Before",
                &self
                    .not_valid_before
                    .as_ref()
                    .map(|d| d.format_date_time(params).unwrap_or_default()),
            )
            .and_nv_ref_maybe(
                &"Not Valid After",
                &self
                    .not_valid_after
                    .as_ref()
                    .map(|d| d.format_date_time(params).unwrap_or_default()),
            );

        table = table
            .header_ref(&"URIs")
            .and_nv_ref_maybe(&"Publication", &self.publication_uri)
            .and_nv_ref_maybe(&"Notification", &self.notification_uri);

        table = table
            .header_ref(&"RPKI")
            .and_nv_ref_maybe(&"Type", &self.rpki_type.as_ref().map(|t| t.to_string()));

        if let Some(digests) = &self.digests
            && !digests.is_empty()
        {
            table = table.header_ref(&"Digests");
            for digest in digests {
                let algo = digest.digest_algorithm.as_deref().unwrap_or("");
                let dig = digest.digest.as_deref().unwrap_or("");
                table = table.nv(&"Algorithm", algo);
                table = table.nv(&"Hash", dig);
            }
        }

        table = self.object_common.add_to_mptable(table, params);
        table = self.remarks().add_to_mptable(table, params);

        md.push_str(&table.to_md(params));
        md.push_str(&self.object_common.entities.to_md(params.from_parent()));

        if params.show_rfc9537_redactions
            && let Some(redacted) = &self.object_common.redacted
        {
            md.push_str(&redacted.as_slice().to_md(params.from_parent()));
        }

        md.push('\n');
        md
    }
}

impl MdUtil for Rpk1X509ResourceCert {
    fn get_header_text(&self) -> MdHeaderText {
        let header_text = if let Some(handle) = &self.object_common.handle {
            format!("X.509 Resource Certificate {}", handle)
        } else if let Some(serial) = &self.serial_number {
            format!("X.509 Certificate {}", serial)
        } else if let Some(subject) = &self.subject {
            format!("X.509 Certificate {}", subject)
        } else {
            "X.509 Resource Certificate".to_string()
        };
        let mut header_text = MdHeaderText::builder().header_text(header_text);
        if let Some(entities) = &self.object_common.entities {
            for entity in entities {
                header_text = header_text.children_entry(entity.get_header_text());
            }
        };
        header_text.build()
    }
}

impl ToMd for Rpk1RoaSearchResults {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent()));

        for result in &self.results {
            md.push_str(&result.to_md(MdParams {
                heading_level: params.heading_level + 1,
                ..params
            }));
        }

        md.push('\n');
        md
    }
}

impl MdUtil for Rpk1RoaSearchResults {
    fn get_header_text(&self) -> MdHeaderText {
        MdHeaderText::builder()
            .header_text("ROA Search Results")
            .build()
    }
}

impl ToMd for Rpk1AspaSearchResults {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent()));

        for result in &self.results {
            md.push_str(&result.to_md(MdParams {
                heading_level: params.heading_level + 1,
                ..params
            }));
        }

        md.push('\n');
        md
    }
}

impl MdUtil for Rpk1AspaSearchResults {
    fn get_header_text(&self) -> MdHeaderText {
        MdHeaderText::builder()
            .header_text("ASPA Search Results")
            .build()
    }
}

impl ToMd for Rpk1X509ResourceCertSearchResults {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent()));

        for result in &self.results {
            md.push_str(&result.to_md(MdParams {
                heading_level: params.heading_level + 1,
                ..params
            }));
        }

        md.push('\n');
        md
    }
}

impl MdUtil for Rpk1X509ResourceCertSearchResults {
    fn get_header_text(&self) -> MdHeaderText {
        MdHeaderText::builder()
            .header_text("X.509 Certificate Search Results")
            .build()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use goldenfile::Mint;
    use icann_rdap_common::{
        httpdata::HttpData,
        prelude::{
            ToResponse,
            redacted::{Method, Name, Redacted},
        },
    };

    use crate::{
        md::{MdOptions, MdParams, ToMd},
        rdap::RequestData,
    };

    use icann_rdap_common::response::{
        Rpk1Aspa, Rpk1Digest, Rpk1Roa, Rpk1RoaIp, Rpk1SubjectPublicKeyInfo, Rpk1X509ResourceCert,
    };

    static MINT_PATH: &str = "src/test_files/md/rpki";

    #[test]
    fn test_md_roa_with_handle() {
        // GIVEN
        let roa = Rpk1Roa::builder()
            .handle("ROA-1")
            .name("ROA-1 Example")
            .roa_ips(vec![
                Rpk1RoaIp::builder()
                    .ip("2001:db8::/48".to_string())
                    .max_length(64)
                    .build(),
                Rpk1RoaIp::builder()
                    .ip("192.0.2.0/24".to_string())
                    .max_length(28)
                    .build(),
            ])
            .origin_autnum(65536)
            .not_valid_before("2024-01-01T00:00:00Z".to_string())
            .not_valid_after("2025-01-01T00:00:00Z".to_string())
            .rpki_type(icann_rdap_common::response::Rpk1RpkiType::Hosted)
            .build();
        let response = roa.clone().to_response();

        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
        };
        let params = MdParams {
            heading_level: 1,
            root: &response,
            http_data: &http_data,
            options: &MdOptions::default(),
            req_data: &req_data,
            show_rfc9537_redactions: false,
            highlight_simple_redactions: false,
        };

        // WHEN
        let actual = roa.to_md(params);

        // THEN
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("roa_with_handle.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_roa_with_digests() {
        // GIVEN
        let roa = Rpk1Roa::builder()
            .handle("ROA-2")
            .origin_autnum(65537)
            .roa_ips(vec![
                Rpk1RoaIp::builder()
                    .ip("10.0.0.0/8".to_string())
                    .max_length(16)
                    .build(),
            ])
            .digests(vec![
                Rpk1Digest::builder()
                    .digest(
                        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
                            .to_string(),
                    )
                    .digest_algorithm("SHA-256".to_string())
                    .build(),
            ])
            .build();
        let response = roa.clone().to_response();

        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
        };
        let params = MdParams {
            heading_level: 1,
            root: &response,
            http_data: &http_data,
            options: &MdOptions::default(),
            req_data: &req_data,
            show_rfc9537_redactions: false,
            highlight_simple_redactions: false,
        };

        // WHEN
        let actual = roa.to_md(params);

        // THEN
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("roa_with_digests.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_aspa_with_handle() {
        // GIVEN
        let aspa = Rpk1Aspa::builder()
            .handle("ASPA-1")
            .name("ASPA-1 Example")
            .customer_autnum(65536)
            .provider_autnums(vec![65542, 65543])
            .not_valid_before("2024-02-01T00:00:00Z".to_string())
            .not_valid_after("2025-02-01T00:00:00Z".to_string())
            .rpki_type(icann_rdap_common::response::Rpk1RpkiType::Delegated)
            .build();
        let response = aspa.clone().to_response();

        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
        };
        let params = MdParams {
            heading_level: 1,
            root: &response,
            http_data: &http_data,
            options: &MdOptions::default(),
            req_data: &req_data,
            show_rfc9537_redactions: false,
            highlight_simple_redactions: false,
        };

        // WHEN
        let actual = aspa.to_md(params);

        // THEN
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("aspa_with_handle.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_x509_cert_with_handle() {
        // GIVEN
        let cert = Rpk1X509ResourceCert::builder()
            .handle("CERT-1")
            .serial_number("1234")
            .issuer("CN=RIR-CA")
            .subject("CN=ISP-CA")
            .signature_algorithm("ecdsa-with-SHA256")
            .subject_public_key_info(
                Rpk1SubjectPublicKeyInfo::builder()
                    .public_key_algorithm("id-ecPublicKey".to_string())
                    .public_key("04...".to_string())
                    .build(),
            )
            .subject_key_identifier("hOcGgxqXDa7mYv78fR+sGBKMtWJqItSLfaIYJDKYi8A=".to_string())
            .ips(vec![
                "192.0.2.0/24".to_string(),
                "2001:db8::/48".to_string(),
            ])
            .autnums(vec![65536, 65537])
            .not_valid_before("2024-03-01T00:00:00Z".to_string())
            .not_valid_after("2025-03-01T00:00:00Z".to_string())
            .rpki_type(icann_rdap_common::response::Rpk1RpkiType::Hybrid)
            .build();
        let response = cert.clone().to_response();

        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
        };
        let params = MdParams {
            heading_level: 1,
            root: &response,
            http_data: &http_data,
            options: &MdOptions::default(),
            req_data: &req_data,
            show_rfc9537_redactions: false,
            highlight_simple_redactions: false,
        };

        // WHEN
        let actual = cert.to_md(params);

        // THEN
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("x509_cert_with_handle.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_roa_search_results() {
        // GIVEN
        let roa1 = Rpk1Roa::builder()
            .handle("ROA-1")
            .origin_autnum(65536)
            .roa_ips(vec![
                Rpk1RoaIp::builder()
                    .ip("2001:db8::/48".to_string())
                    .max_length(64)
                    .build(),
            ])
            .build();
        let roa2 = Rpk1Roa::builder()
            .handle("ROA-2")
            .origin_autnum(65536)
            .roa_ips(vec![
                Rpk1RoaIp::builder()
                    .ip("192.0.2.0/24".to_string())
                    .max_length(28)
                    .build(),
            ])
            .build();
        use icann_rdap_common::response::Rpk1RoaSearchResults;
        let results = Rpk1RoaSearchResults::response_obj()
            .results(vec![roa1, roa2])
            .build();
        let response = results.clone().to_response();

        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
        };
        let params = MdParams {
            heading_level: 1,
            root: &response,
            http_data: &http_data,
            options: &MdOptions::default(),
            req_data: &req_data,
            show_rfc9537_redactions: false,
            highlight_simple_redactions: false,
        };

        // WHEN
        let actual = results.to_md(params);

        // THEN
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("roa_search_results.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_aspa_search_results() {
        // GIVEN
        let aspa1 = Rpk1Aspa::builder()
            .handle("ASPA-1")
            .customer_autnum(65536)
            .provider_autnums(vec![65542])
            .build();
        let aspa2 = Rpk1Aspa::builder()
            .handle("ASPA-2")
            .customer_autnum(65537)
            .provider_autnums(vec![65542])
            .build();
        use icann_rdap_common::response::Rpk1AspaSearchResults;
        let results = Rpk1AspaSearchResults::response_obj()
            .results(vec![aspa1, aspa2])
            .build();
        let response = results.clone().to_response();

        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
        };
        let params = MdParams {
            heading_level: 1,
            root: &response,
            http_data: &http_data,
            options: &MdOptions::default(),
            req_data: &req_data,
            show_rfc9537_redactions: false,
            highlight_simple_redactions: false,
        };

        // WHEN
        let actual = results.to_md(params);

        // THEN
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("aspa_search_results.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_roa_with_redactions() {
        // GIVEN
        let redactions = vec![
            Redacted::builder()
                .name(Name::builder().type_field("Tech Name").build())
                .method(Method::Removal)
                .build(),
        ];
        let roa = Rpk1Roa::builder()
            .handle("ROA-3")
            .origin_autnum(65538)
            .roa_ips(vec![
                Rpk1RoaIp::builder()
                    .ip("10.0.0.0/8".to_string())
                    .max_length(16)
                    .build(),
            ])
            .redacted(redactions)
            .build();
        let response = roa.clone().to_response();

        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
        };
        let params = MdParams {
            heading_level: 1,
            root: &response,
            http_data: &http_data,
            options: &MdOptions::default(),
            req_data: &req_data,
            show_rfc9537_redactions: true,
            highlight_simple_redactions: false,
        };

        // WHEN
        let actual = roa.to_md(params);

        // THEN
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("roa_with_redactions.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }
}
