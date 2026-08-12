use icann_rdap_common::prelude::{CommonFields, ObjectCommonFields};
use icann_rdap_common::response::{
    Rpk1Aspa, Rpk1AspaSearchResults, Rpk1Roa, Rpk1RoaSearchResults, Rpk1X509ResourceCert,
    Rpk1X509ResourceCertSearchResults,
};

use crate::rpsl::{RpslParams, ToRpsl};

use super::{
    AttrName, KeyRef, push_entities, push_mandatory_attribute, push_notices, push_obj_common,
    push_optional_attribute,
};

impl ToRpsl for Rpk1Roa {
    fn to_rpsl(&self, params: RpslParams) -> String {
        let mut rpsl = String::new();

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        // key
        let (key_name, key_value) = self.key_ref(params);
        rpsl = push_mandatory_attribute(rpsl, key_name, &key_value);

        // name
        rpsl = push_optional_attribute(rpsl, AttrName::NetName, self.name.as_deref());

        // roaIps
        if let Some(roa_ips) = &self.roa_ips {
            for roa_ip in roa_ips {
                let ip = roa_ip.ip.as_deref().unwrap_or("");
                let max_len = roa_ip
                    .max_length
                    .as_ref()
                    .map(|m| m.to_string())
                    .unwrap_or_default();
                rpsl = push_mandatory_attribute(
                    rpsl,
                    AttrName::RoaIps,
                    &format!("{}/{}", ip, max_len),
                );
            }
        }

        // originAutnum
        if let Some(origin) = self.origin_autnum() {
            rpsl = push_mandatory_attribute(rpsl, AttrName::OriginAutnum, &format!("AS{}", origin));
        }

        // validity
        rpsl = push_optional_attribute(
            rpsl,
            AttrName::NotValidBefore,
            self.not_valid_before.as_deref(),
        );
        rpsl = push_optional_attribute(
            rpsl,
            AttrName::NotValidAfter,
            self.not_valid_after.as_deref(),
        );

        // URIs
        rpsl = push_optional_attribute(
            rpsl,
            AttrName::PublicationUri,
            self.publication_uri.as_deref(),
        );
        rpsl = push_optional_attribute(
            rpsl,
            AttrName::NotificationUri,
            self.notification_uri.as_deref(),
        );

        // rpkiType
        rpsl = push_optional_attribute(
            rpsl,
            AttrName::Rpkitype,
            self.rpki_type.as_ref().map(|t| t.to_string()).as_deref(),
        );

        // digests
        if let Some(digests) = &self.digests {
            for digest in digests {
                rpsl = push_mandatory_attribute(
                    rpsl,
                    AttrName::Digests,
                    digest.digest.as_deref().unwrap_or(""),
                );
                rpsl = push_mandatory_attribute(
                    rpsl,
                    AttrName::DigestAlgorithm,
                    digest.digest_algorithm.as_deref().unwrap_or(""),
                );
            }
        }

        // push things common to object classes
        rpsl = push_obj_common(rpsl, params, self);

        // end
        rpsl.push('\n');

        // output entities
        rpsl = push_entities(rpsl, self.entities(), params);

        rpsl
    }
}

impl KeyRef for Rpk1Roa {
    fn key_ref(&self, _params: RpslParams) -> (super::AttrName, String) {
        let value = self.handle().unwrap_or("NO HANDLE");
        (AttrName::Autnum, format!("rpki1_roa/{}", value))
    }
}

impl ToRpsl for Rpk1Aspa {
    fn to_rpsl(&self, params: RpslParams) -> String {
        let mut rpsl = String::new();

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        // key
        let (key_name, key_value) = self.key_ref(params);
        rpsl = push_mandatory_attribute(rpsl, key_name, &key_value);

        // name
        rpsl = push_optional_attribute(rpsl, AttrName::NetName, self.name.as_deref());

        // customerAutnum
        if let Some(customer) = self.customer_autnum() {
            rpsl = push_mandatory_attribute(
                rpsl,
                AttrName::CustomerAutnum,
                &format!("AS{}", customer),
            );
        }

        // providerAutnums
        if let Some(providers) = &self.provider_autnums {
            for provider in providers {
                if let Some(asn) = provider.as_u32() {
                    rpsl = push_mandatory_attribute(
                        rpsl,
                        AttrName::ProviderAutnums,
                        &format!("AS{}", asn),
                    );
                }
            }
        }

        // validity
        rpsl = push_optional_attribute(
            rpsl,
            AttrName::NotValidBefore,
            self.not_valid_before.as_deref(),
        );
        rpsl = push_optional_attribute(
            rpsl,
            AttrName::NotValidAfter,
            self.not_valid_after.as_deref(),
        );

        // URIs
        rpsl = push_optional_attribute(
            rpsl,
            AttrName::PublicationUri,
            self.publication_uri.as_deref(),
        );
        rpsl = push_optional_attribute(
            rpsl,
            AttrName::NotificationUri,
            self.notification_uri.as_deref(),
        );

        // rpkiType
        rpsl = push_optional_attribute(
            rpsl,
            AttrName::Rpkitype,
            self.rpki_type.as_ref().map(|t| t.to_string()).as_deref(),
        );

        // digests
        if let Some(digests) = &self.digests {
            for digest in digests {
                rpsl = push_mandatory_attribute(
                    rpsl,
                    AttrName::Digests,
                    digest.digest.as_deref().unwrap_or(""),
                );
                rpsl = push_mandatory_attribute(
                    rpsl,
                    AttrName::DigestAlgorithm,
                    digest.digest_algorithm.as_deref().unwrap_or(""),
                );
            }
        }

        // push things common to object classes
        rpsl = push_obj_common(rpsl, params, self);

        // end
        rpsl.push('\n');

        // output entities
        rpsl = push_entities(rpsl, self.entities(), params);

        rpsl
    }
}

impl KeyRef for Rpk1Aspa {
    fn key_ref(&self, _params: RpslParams) -> (super::AttrName, String) {
        let value = self.handle().unwrap_or("NO HANDLE");
        (AttrName::Autnum, format!("rpki1_aspa/{}", value))
    }
}

impl ToRpsl for Rpk1X509ResourceCert {
    fn to_rpsl(&self, params: RpslParams) -> String {
        let mut rpsl = String::new();

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        // key
        let (key_name, key_value) = self.key_ref(params);
        rpsl = push_mandatory_attribute(rpsl, key_name, &key_value);

        // serialNumber
        rpsl = push_optional_attribute(rpsl, AttrName::SerialNumber, self.serial_number.as_deref());

        // issuer
        rpsl = push_optional_attribute(rpsl, AttrName::Issuer, self.issuer.as_deref());

        // subject
        rpsl = push_optional_attribute(rpsl, AttrName::Subject, self.subject.as_deref());

        // signatureAlgorithm
        rpsl = push_optional_attribute(
            rpsl,
            AttrName::SignatureAlgorithm,
            self.signature_algorithm.as_deref(),
        );

        // subjectKeyIdentifier
        rpsl = push_optional_attribute(
            rpsl,
            AttrName::SubjectKeyIdentifier,
            self.subject_key_identifier.as_deref(),
        );

        // subjectPublicKeyInfo
        if let Some(spki) = &self.subject_public_key_info {
            rpsl = push_optional_attribute(
                rpsl,
                AttrName::PublicKeyAlgorithm,
                spki.public_key_algorithm.as_deref(),
            );
            rpsl = push_optional_attribute(rpsl, AttrName::PublicKey, spki.public_key.as_deref());
        }

        // ips
        if let Some(ips) = &self.ips {
            for ip in ips {
                rpsl = push_mandatory_attribute(rpsl, AttrName::RoaIps, ip);
            }
        }

        // autnums
        if let Some(autnums) = &self.autnums {
            for autnum in autnums {
                if let Some(asn) = autnum.as_u32() {
                    rpsl = push_mandatory_attribute(rpsl, AttrName::Autnums, &format!("AS{}", asn));
                }
            }
        }

        // validity
        rpsl = push_optional_attribute(
            rpsl,
            AttrName::NotValidBefore,
            self.not_valid_before.as_deref(),
        );
        rpsl = push_optional_attribute(
            rpsl,
            AttrName::NotValidAfter,
            self.not_valid_after.as_deref(),
        );

        // URIs
        rpsl = push_optional_attribute(
            rpsl,
            AttrName::PublicationUri,
            self.publication_uri.as_deref(),
        );
        rpsl = push_optional_attribute(
            rpsl,
            AttrName::NotificationUri,
            self.notification_uri.as_deref(),
        );

        // rpkiType
        rpsl = push_optional_attribute(
            rpsl,
            AttrName::Rpkitype,
            self.rpki_type.as_ref().map(|t| t.to_string()).as_deref(),
        );

        // digests
        if let Some(digests) = &self.digests {
            for digest in digests {
                rpsl = push_mandatory_attribute(
                    rpsl,
                    AttrName::Digests,
                    digest.digest.as_deref().unwrap_or(""),
                );
                rpsl = push_mandatory_attribute(
                    rpsl,
                    AttrName::DigestAlgorithm,
                    digest.digest_algorithm.as_deref().unwrap_or(""),
                );
            }
        }

        // push things common to object classes
        rpsl = push_obj_common(rpsl, params, self);

        // end
        rpsl.push('\n');

        // output entities
        rpsl = push_entities(rpsl, self.entities(), params);

        rpsl
    }
}

impl KeyRef for Rpk1X509ResourceCert {
    fn key_ref(&self, _params: RpslParams) -> (super::AttrName, String) {
        let value = self.handle().unwrap_or("NO HANDLE");
        (
            AttrName::Autnum,
            format!("rpki1_x509ResourceCert/{}", value),
        )
    }
}

impl ToRpsl for Rpk1RoaSearchResults {
    fn to_rpsl(&self, params: RpslParams) -> String {
        let mut rpsl = String::new();

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        for roa in &self.results {
            rpsl.push_str(&roa.to_rpsl(params));
        }

        // end
        rpsl.push('\n');

        rpsl
    }
}

impl ToRpsl for Rpk1AspaSearchResults {
    fn to_rpsl(&self, params: RpslParams) -> String {
        let mut rpsl = String::new();

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        for aspa in &self.results {
            rpsl.push_str(&aspa.to_rpsl(params));
        }

        // end
        rpsl.push('\n');

        rpsl
    }
}

impl ToRpsl for Rpk1X509ResourceCertSearchResults {
    fn to_rpsl(&self, params: RpslParams) -> String {
        let mut rpsl = String::new();

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        for cert in &self.results {
            rpsl.push_str(&cert.to_rpsl(params));
        }

        // end
        rpsl.push('\n');

        rpsl
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

    use crate::rpsl::{RpslParams, ToRpsl};

    use icann_rdap_common::response::{
        Rpk1Aspa, Rpk1Digest, Rpk1Roa, Rpk1RoaIp, Rpk1SubjectPublicKeyInfo, Rpk1X509ResourceCert,
    };

    static MINT_PATH: &str = "src/test_files/rpsl/rpki";

    #[test]
    fn test_rpsl_roa_with_handle() {
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
        let _response = roa.clone().to_response();

        let http_data = HttpData::example().build();
        let params = RpslParams {
            http_data: &http_data,
        };

        // WHEN
        let actual = roa.to_rpsl(params);

        // THEN
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("roa_with_handle.txt").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_rpsl_roa_with_digests() {
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
        let _response = roa.clone().to_response();

        let http_data = HttpData::example().build();
        let params = RpslParams {
            http_data: &http_data,
        };

        // WHEN
        let actual = roa.to_rpsl(params);

        // THEN
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("roa_with_digests.txt").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_rpsl_roa_with_redactions() {
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
        let _response = roa.clone().to_response();

        let http_data = HttpData::example().build();
        let params = RpslParams {
            http_data: &http_data,
        };

        // WHEN
        let actual = roa.to_rpsl(params);

        // THEN
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("roa_with_redactions.txt").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_rpsl_aspa_with_handle() {
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
        let _response = aspa.clone().to_response();

        let http_data = HttpData::example().build();
        let params = RpslParams {
            http_data: &http_data,
        };

        // WHEN
        let actual = aspa.to_rpsl(params);

        // THEN
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("aspa_with_handle.txt").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_rpsl_x509_cert_with_handle() {
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
        let _response = cert.clone().to_response();

        let http_data = HttpData::example().build();
        let params = RpslParams {
            http_data: &http_data,
        };

        // WHEN
        let actual = cert.to_rpsl(params);

        // THEN
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("x509_cert_with_handle.txt").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_rpsl_roa_search_results() {
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
        let _response = results.clone().to_response();

        let http_data = HttpData::example().build();
        let params = RpslParams {
            http_data: &http_data,
        };

        // WHEN
        let actual = results.to_rpsl(params);

        // THEN
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("roa_search_results.txt").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_rpsl_aspa_search_results() {
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
        let _response = results.clone().to_response();

        let http_data = HttpData::example().build();
        let params = RpslParams {
            http_data: &http_data,
        };

        // WHEN
        let actual = results.to_rpsl(params);

        // THEN
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("aspa_search_results.txt").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }
}
