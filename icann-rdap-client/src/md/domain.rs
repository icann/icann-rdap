use icann_rdap_common::{
    dns_types::{DnsAlgorithmType, DnsDigestType},
    prelude::ObjectCommonFields,
    response::{Domain, SecureDns, Variant},
};

use super::{
    string::{StringListUtil, StringUtil},
    table::{MultiPartTable, ToMpTable},
    types::{events_to_table, links_to_table, public_ids_to_table},
    MdHeaderText, MdParams, MdUtil, ToMd,
};

impl ToMd for Domain {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent()));

        // header
        let header_text = self.get_header_text();
        md.push_str(
            &header_text
                .to_string()
                .to_header(params.heading_level, params.options),
        );

        // multipart data
        let mut table = if params.highlight_simple_redactions {
            MultiPartTable::new_with_value_hightlights_from_remarks(self.remarks())
        } else {
            MultiPartTable::new()
        };

        // summary
        table = table.summary(header_text);

        // identifiers
        //
        // due to the nature of domains, we are guaranteed to have at least one of
        // ldhName or unicodeName.
        table = table
            .header_ref(&"Identifiers")
            .and_nv_ref_maybe(&"LDH Name", &self.ldh_name)
            .and_nv_ref_maybe(&"Unicode Name", &self.unicode_name)
            .and_nv_ref_maybe(&"Handle", &self.handle());
        if let Some(public_ids) = &self.public_ids {
            table = public_ids_to_table(public_ids, table);
        }

        // common object stuff
        table = self.object_common.add_to_mptable(table, params);

        // domain variants
        table = self.variants().add_to_mptable(table, params);

        // secure dns
        if let Some(secure_dns) = self.secure_dns() {
            table = secure_dns.add_to_mptable(table, params);
        }

        // remarks
        table = self.remarks().add_to_mptable(table, params);

        // render table
        md.push_str(&table.to_md(params));

        // entities
        md.push_str(&self.object_common.entities.to_md(params.from_parent()));

        // nameservers
        if let Some(nameservers) = &self.nameservers {
            nameservers
                .iter()
                .for_each(|ns| md.push_str(&ns.to_md(params.next_level())));
        }

        // network
        if let Some(network) = &self.network {
            md.push_str(&network.to_md(params.next_level()));
        }

        // redacted
        if params.show_rfc9537_redactions {
            if let Some(redacted) = &self.object_common.redacted {
                md.push_str(&redacted.as_slice().to_md(params.from_parent()));
            }
        }

        md.push('\n');
        md
    }
}

impl ToMpTable for &[Variant] {
    fn add_to_mptable(&self, mut table: MultiPartTable, _params: MdParams) -> MultiPartTable {
        if self.is_empty() {
            return table;
        }
        table = table.header_ref(&"Domain Variants");
        for variant in self.iter() {
            for names in variant.variant_names() {
                table = table.nv_ref(
                    &variant.relations().make_title_case_list(),
                    &format!(
                        "tbl:{} ldh:'{}' utf:'{}'",
                        variant.idn_table().unwrap_or_default(),
                        names.ldh_name().unwrap_or_default(),
                        names.unicode_name().unwrap_or_default()
                    ),
                )
            }
        }
        table
    }
}

impl ToMpTable for &SecureDns {
    fn add_to_mptable(&self, mut table: MultiPartTable, params: MdParams) -> MultiPartTable {
        if self.zone_signed().is_none()
            && self.delegation_signed.is_none()
            && self.max_sig_life().is_none()
            && self.ds_data().is_empty()
            && self.key_data().is_empty()
        {
            return table;
        }

        // Signing summary information
        table = table
            .header_ref(&"DNSSEC Information")
            .and_nv_ref_maybe(
                &"Zone Signed",
                &self.zone_signed.as_ref().map(|b| b.to_string()),
            )
            .and_nv_ref_maybe(
                &"Delegation Signed",
                &self.delegation_signed.as_ref().map(|b| b.to_string()),
            )
            .and_nv_ref_maybe(
                &"Max Sig Life",
                &self.max_sig_life.as_ref().map(|u| u.to_string()),
            );

        // ds data
        if let Some(ds_data) = &self.ds_data {
            for (i, ds) in ds_data.iter().enumerate() {
                let header = format!("DS Data ({i})").replace_md_chars();
                table = table
                    .header_ref(&header)
                    .and_nv_ref(&"Key Tag", &ds.key_tag.as_ref().map(|k| k.to_string()))
                    .and_nv_ref(
                        &"Algorithm",
                        &dns_algorithm(&ds.algorithm.as_ref().and_then(|a| a.as_u8())),
                    )
                    .and_nv_ref(&"Digest", &ds.digest)
                    .and_nv_ref(
                        &"Digest Type",
                        &dns_digest_type(&ds.digest_type.as_ref().and_then(|d| d.as_u8())),
                    );
                if let Some(events) = &ds.events {
                    let ds_header = format!("DS ({i}) Events");
                    table = events_to_table(events, table, &ds_header, params);
                }
                if let Some(links) = &ds.links {
                    let ds_header = format!("DS ({i}) Links");
                    table = links_to_table(links, table, &ds_header);
                }
            }
        }

        // key data
        if let Some(key_data) = &self.key_data {
            for (i, key) in key_data.iter().enumerate() {
                let header = format!("Key Data ({i})").replace_md_chars();
                table = table
                    .header_ref(&header)
                    .and_nv_ref(&"Flags", &key.flags.as_ref().map(|k| k.to_string()))
                    .and_nv_ref(&"Protocol", &key.protocol.as_ref().map(|a| a.to_string()))
                    .and_nv_ref(&"Public Key", &key.public_key)
                    .and_nv_ref(
                        &"Algorithm",
                        &dns_algorithm(&key.algorithm.as_ref().and_then(|a| a.as_u8())),
                    );
                if let Some(events) = &key.events {
                    let key_header = format!("Key ({i}) Events");
                    table = events_to_table(events, table, &key_header, params);
                }
                if let Some(links) = &key.links {
                    let key_header = format!("Key ({i}) Links");
                    table = links_to_table(links, table, &key_header);
                }
            }
        }

        table
    }
}

fn dns_algorithm(alg: &Option<u8>) -> Option<String> {
    alg.map(|alg| {
        DnsAlgorithmType::mnemonic(alg).map_or(format!("{alg} - Unassigned or Reserved"), |a| {
            format!("{alg} - {a}")
        })
    })
}

fn dns_digest_type(dt: &Option<u8>) -> Option<String> {
    dt.map(|dt| {
        DnsDigestType::mnemonic(dt).map_or(format!("{dt} - Unassigned or Reserved"), |a| {
            format!("{dt} - {a}")
        })
    })
}

impl MdUtil for Domain {
    fn get_header_text(&self) -> MdHeaderText {
        let header_text = if let Some(unicode_name) = &self.unicode_name {
            format!("Domain {}", unicode_name.replace_md_chars())
        } else if let Some(ldh_name) = &self.ldh_name {
            format!("Domain {}", ldh_name.replace_md_chars())
        } else if let Some(handle) = &self.object_common.handle {
            format!("Domain {}", handle.replace_md_chars())
        } else {
            "Domain".to_string()
        };
        let mut header_text = MdHeaderText::builder().header_text(header_text);
        if let Some(entities) = &self.object_common.entities {
            for entity in entities {
                header_text = header_text.children_entry(entity.get_header_text());
            }
        };
        if let Some(nameservers) = &self.nameservers {
            for ns in nameservers {
                header_text = header_text.children_entry(ns.get_header_text());
            }
        };
        if let Some(network) = &self.network {
            header_text = header_text.children_entry(network.get_header_text());
        }
        header_text.build()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use goldenfile::Mint;
    use icann_rdap_common::{
        httpdata::HttpData,
        prelude::{
            redacted::{Method, Name, Redacted},
            Domain, DsDatum, Event, Link, SecureDns, ToResponse, Variant, VariantName,
        },
    };

    use crate::{
        md::{MdOptions, MdParams, ToMd},
        rdap::RequestData,
    };

    static MINT_PATH: &str = "src/test_files/md/domain";

    #[test]
    fn test_md_domain_with_ldh_and_handle() {
        // GIVEN domain
        let domain = Domain::builder()
            .ldh_name("foo.example.com")
            .handle("123-ABC")
            .build();
        let response = domain.clone().to_response();

        // WHEN represented as markdown
        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
            source_host: "example",
            source_type: crate::rdap::SourceType::DomainRegistry,
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
        let actual = domain.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_ldh_and_handle.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_domain_with_ldh_only() {
        // GIVEN domain
        let domain = Domain::builder().ldh_name("foo.example.com").build();
        let response = domain.clone().to_response();

        // WHEN represented as markdown
        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
            source_host: "example",
            source_type: crate::rdap::SourceType::DomainRegistry,
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
        let actual = domain.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_ldh_only.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_domain_with_ldh_with_events() {
        // GIVEN domain
        let domain = Domain::builder()
            .ldh_name("foo.example.com")
            .event(
                Event::builder()
                    .event_action("updated")
                    .event_date("1990-12-31T23:59:59Z")
                    .build(),
            )
            .build();
        let response = domain.clone().to_response();

        // WHEN represented as markdown
        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
            source_host: "example",
            source_type: crate::rdap::SourceType::DomainRegistry,
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
        let actual = domain.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_ldh_with_events.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_domain_with_ldh_with_empty_events() {
        // GIVEN domain
        let domain = Domain::builder()
            .ldh_name("foo.example.com")
            .events(vec![])
            .build();
        let response = domain.clone().to_response();

        // WHEN represented as markdown
        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
            source_host: "example",
            source_type: crate::rdap::SourceType::DomainRegistry,
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
        let actual = domain.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint
            .new_goldenfile("with_ldh_with_empty_events.md")
            .unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_domain_with_ldh_with_empty_links() {
        // GIVEN domain
        let domain = Domain::builder()
            .ldh_name("foo.example.com")
            .links(vec![])
            .build();
        let response = domain.clone().to_response();

        // WHEN represented as markdown
        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
            source_host: "example",
            source_type: crate::rdap::SourceType::DomainRegistry,
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
        let actual = domain.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_ldh_with_empty_links.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_domain_with_ldh_with_one_link() {
        // GIVEN domain
        let domain = Domain::builder()
            .ldh_name("foo.example.com")
            .link(
                Link::builder()
                    .rel("about")
                    .value("https://foo.example")
                    .media_type("application/json")
                    .href("https://bar.example")
                    .build(),
            )
            .build();
        let response = domain.clone().to_response();

        // WHEN represented as markdown
        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
            source_host: "example",
            source_type: crate::rdap::SourceType::DomainRegistry,
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
        let actual = domain.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_ldh_with_one_link.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_domain_with_ldh_with_two_links() {
        // GIVEN domain
        let domain = Domain::builder()
            .ldh_name("foo.example.com")
            .link(
                Link::builder()
                    .rel("about")
                    .value("https://foo.example")
                    .media_type("application/json")
                    .href("https://bar.example")
                    .build(),
            )
            .link(
                Link::builder()
                    .rel("related")
                    .value("https://foo.example")
                    .media_type("application/json")
                    .href("https://foo.example")
                    .build(),
            )
            .build();
        let response = domain.clone().to_response();

        // WHEN represented as markdown
        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
            source_host: "example",
            source_type: crate::rdap::SourceType::DomainRegistry,
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
        let actual = domain.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_ldh_with_two_links.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_domain_with_ldh_and_variants() {
        // GIVEN domain
        let domain = Domain::builder()
            .ldh_name("foo.example.com")
            .variant(
                Variant::builder()
                    .relation("registered")
                    .relation("conjoined")
                    .idn_table(".EXAMPLE Swedish")
                    .variant_name(
                        VariantName::builder()
                            .ldh_name("xn--fo-8ja.example")
                            .unicode_name("fôo.example")
                            .build(),
                    )
                    .build(),
            )
            .variant(
                Variant::builder()
                    .relation("registration restricted")
                    .relation("unregistered")
                    .variant_name(
                        VariantName::builder()
                            .ldh_name("xn--fo-cka.example")
                            .unicode_name("fõo.example")
                            .build(),
                    )
                    .variant_name(
                        VariantName::builder()
                            .ldh_name("xn--fo-fka.example")
                            .unicode_name("föo.example")
                            .build(),
                    )
                    .build(),
            )
            .build();
        let response = domain.clone().to_response();

        // WHEN represented as markdown
        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
            source_host: "example",
            source_type: crate::rdap::SourceType::DomainRegistry,
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
        let actual = domain.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_ldh_and_variants.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_domain_with_ldh_and_secure_dns() {
        // GIVEN domain
        let domain = Domain::builder()
            .ldh_name("foo.example.com")
            .secure_dns(
                SecureDns::builder()
                    .delegation_signed(true)
                    .zone_signed(false)
                    .max_sig_life(1)
                    .ds_data(
                        DsDatum::builder()
                            .key_tag(8)
                            .algorithm(128)
                            .digest("12345939191039129495959920al121kk3999494994")
                            .event(
                                Event::builder()
                                    .event_action("updated")
                                    .event_date("1990-12-31T23:59:59Z")
                                    .build(),
                            )
                            .build(),
                    )
                    .ds_data(
                        DsDatum::builder()
                            .key_tag(4)
                            .algorithm(12)
                            .digest("as5902320elldwkl2909802800809803")
                            .event(
                                Event::builder()
                                    .event_action("updated")
                                    .event_date("1990-12-31T23:59:59Z")
                                    .build(),
                            )
                            .build(),
                    )
                    .build(),
            )
            .build();
        let response = domain.clone().to_response();

        // WHEN represented as markdown
        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
            source_host: "example",
            source_type: crate::rdap::SourceType::DomainRegistry,
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
        let actual = domain.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_ldh_and_secure_dns.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_domain_with_ldh_and_redactions() {
        // GIVEN domain
        let redactions = vec![
            Redacted::builder()
                .name(Name::builder().type_field("Tech Name").build())
                .method(Method::Removal)
                .build(),
            Redacted::builder()
                .name(Name::builder().type_field("Tech Email").build())
                .method(Method::Removal)
                .build(),
        ];
        let domain = Domain::builder()
            .ldh_name("foo.example.com")
            .redacted(redactions)
            .build();
        let response = domain.clone().to_response();

        // WHEN represented as markdown
        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
            source_host: "example",
            source_type: crate::rdap::SourceType::DomainRegistry,
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
        let actual = domain.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint
            .new_goldenfile("with_handle_and_redactions.md")
            .unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_md_domain_with_ldh_and_no_show_redactions() {
        // GIVEN domain
        let redactions = vec![
            Redacted::builder()
                .name(Name::builder().type_field("Tech Name").build())
                .method(Method::Removal)
                .build(),
            Redacted::builder()
                .name(Name::builder().type_field("Tech Email").build())
                .method(Method::Removal)
                .build(),
        ];
        let domain = Domain::builder()
            .ldh_name("foo.example.com")
            .redacted(redactions)
            .build();
        let response = domain.clone().to_response();

        // WHEN represented as markdown
        let http_data = HttpData::example().build();
        let req_data = RequestData {
            req_number: 1,
            req_target: false,
            source_host: "example",
            source_type: crate::rdap::SourceType::DomainRegistry,
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
        let actual = domain.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint
            .new_goldenfile("with_handle_and_no_show_redactions.md")
            .unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }
}
