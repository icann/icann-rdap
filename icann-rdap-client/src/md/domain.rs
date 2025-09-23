use std::any::TypeId;

use icann_rdap_common::{
    dns_types::{DnsAlgorithmType, DnsDigestType},
    response::{Domain, SecureDns, Variant},
};

use icann_rdap_common::check::{CheckParams, GetChecks, GetSubChecks};

use crate::rdap::registered_redactions::{self, text_or_registered_redaction};

use super::{
    redacted::REDACTED_TEXT,
    string::{StringListUtil, StringUtil},
    table::{MultiPartTable, ToMpTable},
    types::{checks_to_table, events_to_table, links_to_table, public_ids_to_table},
    FromMd, MdHeaderText, MdParams, MdUtil, ToMd, HR,
};

impl ToMd for Domain {
    fn to_md(&self, params: MdParams) -> String {
        let typeid = TypeId::of::<Self>();
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent(typeid)));

        // header
        let header_text = self.get_header_text();
        md.push_str(
            &header_text
                .to_string()
                .to_header(params.heading_level, params.options),
        );

        // multipart data
        let mut table = MultiPartTable::new();

        let domain_handle = text_or_registered_redaction(
            params.root,
            &registered_redactions::RedactedName::RegistryDomainId,
            &self.object_common.handle,
            REDACTED_TEXT,
        );

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
            .and_nv_ref_maybe(&"Handle", &domain_handle);
        if let Some(public_ids) = &self.public_ids {
            table = public_ids_to_table(public_ids, table);
        }

        // common object stuff
        table = self.object_common.add_to_mptable(table, params);

        // checks
        let check_params = CheckParams::from_md(params, typeid);
        let mut checks = self.object_common.get_sub_checks(check_params);
        checks.push(self.get_checks(check_params));
        table = checks_to_table(checks, table, params);

        // render table
        md.push_str(&table.to_md(params));

        // variants require a custom table
        if let Some(variants) = &self.variants {
            md.push_str(&do_variants(variants, params))
        }

        // secure dns
        if let Some(secure_dns) = &self.secure_dns {
            md.push_str(&do_secure_dns(secure_dns, params))
        }

        // remarks
        md.push_str(&self.object_common.remarks.to_md(params.from_parent(typeid)));

        // only other object classes from here
        md.push_str(HR);

        // entities
        md.push_str(
            &self
                .object_common
                .entities
                .to_md(params.from_parent(typeid)),
        );

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
        if let Some(redacted) = &self.object_common.redacted {
            md.push_str(&redacted.as_slice().to_md(params.from_parent(typeid)));
        }

        md.push('\n');
        md
    }
}

fn do_variants(variants: &[Variant], params: MdParams) -> String {
    let mut md = String::new();
    md.push_str(&format!(
        "|:-:|\n|{}|\n",
        "Domain Variants".to_right_bold(8, params.options)
    ));
    md.push_str("|:-:|:-:|:-:|\n|Relations|IDN Table|Variant Names|\n");
    variants.iter().for_each(|v| {
        md.push_str(&format!(
            "|{}|{}|{}|",
            v.relations().make_title_case_list(),
            v.idn_table.as_deref().unwrap_or_default(),
            v.variant_names
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|dv| format!(
                    "ldh: '{}' utf:'{}'",
                    dv.ldh_name.as_deref().unwrap_or_default(),
                    dv.unicode_name.as_deref().unwrap_or_default()
                ))
                .collect::<Vec<String>>()
                .join(", "),
        ))
    });
    md.push('\n');
    md
}

fn do_secure_dns(secure_dns: &SecureDns, params: MdParams) -> String {
    let mut md = String::new();
    if secure_dns.zone_signed().is_none()
        && secure_dns.delegation_signed.is_none()
        && secure_dns.max_sig_life().is_none()
        && secure_dns.ds_data().is_empty()
        && secure_dns.key_data().is_empty()
    {
        return md;
    }
    // multipart data
    let mut table = MultiPartTable::new();

    table = table
        .header_ref(&"DNSSEC Information")
        .and_nv_ref_maybe(
            &"Zone Signed",
            &secure_dns.zone_signed.as_ref().map(|b| b.to_string()),
        )
        .and_nv_ref_maybe(
            &"Delegation Signed",
            &secure_dns.delegation_signed.as_ref().map(|b| b.to_string()),
        )
        .and_nv_ref_maybe(
            &"Max Sig Life",
            &secure_dns.max_sig_life.as_ref().map(|u| u.to_string()),
        );

    if let Some(ds_data) = &secure_dns.ds_data {
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

    if let Some(key_data) = &secure_dns.key_data {
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

    // checks
    let typeid = TypeId::of::<Domain>();
    let check_params = CheckParams::from_md(params, typeid);
    let checks = secure_dns.get_sub_checks(check_params);
    table = checks_to_table(checks, table, params);

    // render table
    md.push_str(&table.to_md(params));
    md
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
    use std::{any::TypeId, io::Write};

    use goldenfile::Mint;
    use icann_rdap_common::{
        httpdata::HttpData,
        prelude::{Domain, Event, Link, ToResponse},
    };

    use crate::{
        md::{MdOptions, MdParams, ToMd},
        rdap::RequestData,
    };

    static MINT_PATH: &str = "src/test_files/md/domain";

    #[test]
    fn test_domain_with_ldh_and_handle() {
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
            parent_type: TypeId::of::<Domain>(),
            check_types: &[],
            options: &MdOptions::default(),
            req_data: &req_data,
        };
        let actual = domain.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_ldh_and_handle.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_domain_with_ldh_only() {
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
            parent_type: TypeId::of::<Domain>(),
            check_types: &[],
            options: &MdOptions::default(),
            req_data: &req_data,
        };
        let actual = domain.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_ldh_only.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_domain_with_ldh_with_events() {
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
            parent_type: TypeId::of::<Domain>(),
            check_types: &[],
            options: &MdOptions::default(),
            req_data: &req_data,
        };
        let actual = domain.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_ldh_with_events.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_domain_with_ldh_with_empty_events() {
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
            parent_type: TypeId::of::<Domain>(),
            check_types: &[],
            options: &MdOptions::default(),
            req_data: &req_data,
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
    fn test_domain_with_ldh_with_empty_links() {
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
            parent_type: TypeId::of::<Domain>(),
            check_types: &[],
            options: &MdOptions::default(),
            req_data: &req_data,
        };
        let actual = domain.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_ldh_with_empty_links.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_domain_with_ldh_with_one_link() {
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
            parent_type: TypeId::of::<Domain>(),
            check_types: &[],
            options: &MdOptions::default(),
            req_data: &req_data,
        };
        let actual = domain.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_ldh_with_one_link.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }

    #[test]
    fn test_domain_with_ldh_with_two_links() {
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
            parent_type: TypeId::of::<Domain>(),
            check_types: &[],
            options: &MdOptions::default(),
            req_data: &req_data,
        };
        let actual = domain.to_md(params);

        // THEN compare with golden file
        let mut mint = Mint::new(MINT_PATH);
        let mut expected = mint.new_goldenfile("with_ldh_with_two_links.md").unwrap();
        expected.write_all(actual.as_bytes()).unwrap();
    }
}
