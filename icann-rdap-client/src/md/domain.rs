use std::any::TypeId;

use icann_rdap_common::dns_types::{DnsAlgorithmType, DnsDigestType};
use icann_rdap_common::response::domain::{Domain, SecureDns, Variant};

use icann_rdap_common::check::{CheckParams, GetChecks, GetSubChecks};

use crate::registered_redactions::{self, text_or_registered_redaction};

use super::redacted::REDACTED_TEXT;
use super::types::{events_to_table, links_to_table, public_ids_to_table};
use super::FromMd;
use super::{
    string::StringListUtil,
    string::StringUtil,
    table::{MultiPartTable, ToMpTable},
    types::checks_to_table,
    MdParams, ToMd, HR,
};

impl ToMd for Domain {
    fn to_md(&self, params: MdParams) -> String {
        let typeid = TypeId::of::<Domain>();
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent(typeid)));

        // header
        let header_text = if let Some(unicode_name) = &self.unicode_name {
            format!("Domain {unicode_name}")
        } else if let Some(ldh_name) = &self.ldh_name {
            format!("Domain {ldh_name}")
        } else if let Some(handle) = &self.object_common.handle {
            format!("Domain {handle}")
        } else {
            "Domain".to_string()
        };
        md.push_str(&header_text.to_header(params.heading_level, params.options));

        // multipart data
        let mut table = MultiPartTable::new();

        let domain_handle = text_or_registered_redaction(
            params.root,
            &registered_redactions::RedactedName::RegistryDomainId,
            &self.object_common.handle,
            REDACTED_TEXT,
        );

        // identifiers
        table = table
            .header_ref(&"Identifiers")
            .and_data_ref(&"LDH Name", &self.ldh_name)
            .and_data_ref(&"Unicode Name", &self.unicode_name)
            .and_data_ref(&"Handle", &domain_handle);
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
            v.relation
                .as_deref()
                .unwrap_or_default()
                .make_title_case_list(),
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
    md.push_str("|\n");
    md
}

fn do_secure_dns(secure_dns: &SecureDns, params: MdParams) -> String {
    let mut md = String::new();
    // multipart data
    let mut table = MultiPartTable::new();

    table = table
        .header_ref(&"DNSSEC Information")
        .and_data_ref(
            &"Zone Signed",
            &secure_dns.zone_signed.map(|b| b.to_string()),
        )
        .and_data_ref(
            &"Delegation Signed",
            &secure_dns.delegation_signed.map(|b| b.to_string()),
        )
        .and_data_ref(
            &"Max Sig Life",
            &secure_dns.max_sig_life.map(|u| u.to_string()),
        );

    if let Some(ds_data) = &secure_dns.ds_data {
        for (i, ds) in ds_data.iter().enumerate() {
            let header = format!("DS Data ({i})");
            table = table
                .header_ref(&header)
                .and_data_ref(&"Key Tag", &ds.key_tag.map(|k| k.to_string()))
                .and_data_ref(&"Algorithm", &dns_algorithm(&ds.algorithm))
                .and_data_ref(&"Digest", &ds.digest)
                .and_data_ref(&"Digest Type", &dns_digest_type(&ds.digest_type));
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
            let header = format!("Key Data ({i})");
            table = table
                .header_ref(&header)
                .and_data_ref(&"Flags", &key.flags.map(|k| k.to_string()))
                .and_data_ref(&"Protocol", &key.protocol.map(|a| a.to_string()))
                .and_data_ref(&"Public Key", &key.public_key)
                .and_data_ref(&"Algorithm", &dns_algorithm(&key.algorithm));
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
