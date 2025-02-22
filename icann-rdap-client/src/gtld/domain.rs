use super::{GtldParams, ToGtldWhois};
use icann_rdap_common::response::Boolish;
use icann_rdap_common::response::Domain;
use icann_rdap_common::response::Event;
use icann_rdap_common::response::Nameserver;
use icann_rdap_common::response::Network;
use icann_rdap_common::response::SecureDns;

impl ToGtldWhois for Domain {
    fn to_gtld_whois(&self, params: &mut GtldParams) -> String {
        let mut gtld = String::new();

        gtld.push_str("\n\n");
        // Domain Name
        let domain_name = format_domain_name(self);
        gtld.push_str(&domain_name);

        // Domain ID
        let domain_id = format_domain_id(self.object_common.handle.as_ref());
        gtld.push_str(&domain_id);

        // Date Time for Registry
        let date_info = format_registry_dates(&self.object_common.events);
        gtld.push_str(&date_info);

        // Common Object Stuff
        let domain_info = format_domain_info(
            &self.object_common.status.as_ref().map(|v| v.vec().clone()),
            &self.object_common.port_43,
        );
        gtld.push_str(&domain_info);

        // Enitities: registrar and abuse/tech/admin/registrant info
        let formatted_data = self.object_common.entities.to_gtld_whois(params);
        gtld.push_str(&formatted_data);

        // nameservers and network
        let additional_info =
            format_nameservers_and_network(&self.nameservers, &self.network, params);
        gtld.push_str(&additional_info);

        // secure dns
        let dnssec_info = format_dnssec_info(&self.secure_dns);
        gtld.push_str(&dnssec_info);

        gtld.push_str(
            "URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\n",
        );

        // last update info
        format_last_update_info(&self.object_common.events, &mut gtld);

        gtld
    }
}

fn format_domain_name(domain: &Domain) -> String {
    if let Some(unicode_name) = &domain.unicode_name {
        format!("Domain Name: {unicode_name}\n")
    } else if let Some(ldh_name) = &domain.ldh_name {
        format!("Domain Name: {ldh_name}\n")
    } else if let Some(handle) = &domain.object_common.handle {
        format!("Domain Name: {handle}\n")
    } else {
        "Domain Name: \n".to_string()
    }
}

fn format_domain_id(handle: Option<&String>) -> String {
    if let Some(handle) = handle {
        format!("Registry Domain ID: {handle}\n")
    } else {
        "Registry Domain ID: \n".to_string()
    }
}

fn format_registry_dates(events: &Option<Vec<Event>>) -> String {
    let mut formatted_dates = String::new();
    if let Some(events) = events {
        for event in events {
            if let Some(event_action) = &event.event_action {
                match event_action.as_str() {
                    "last changed" => {
                        if let Some(event_date) = &event.event_date {
                            formatted_dates.push_str(&format!("Updated Date: {}\n", event_date));
                        }
                    }
                    "registration" => {
                        if let Some(event_date) = &event.event_date {
                            formatted_dates.push_str(&format!("Creation Date: {}\n", event_date));
                        }
                    }
                    "expiration" => {
                        if let Some(event_date) = &event.event_date {
                            formatted_dates
                                .push_str(&format!("Registry Expiry Date: {}\n", event_date));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    formatted_dates
}

fn format_domain_info(status: &Option<Vec<String>>, port_43: &Option<String>) -> String {
    let mut info = String::new();
    if let Some(status) = status {
        for value in status {
            info.push_str(&format!("Domain Status: {}\n", *value));
        }
    }
    if let Some(port_43) = port_43 {
        if !port_43.is_empty() {
            info.push_str(&format!("Registrar Whois Server: {}\n", port_43));
        }
    }

    info
}

fn format_nameservers_and_network(
    nameservers: &Option<Vec<Nameserver>>,
    network: &Option<Network>,
    params: &mut GtldParams,
) -> String {
    let mut gtld = String::new();

    if let Some(nameservers) = nameservers {
        nameservers
            .iter()
            .for_each(|ns| gtld.push_str(&ns.to_gtld_whois(params)));
    }

    if let Some(network) = network {
        gtld.push_str(&network.to_gtld_whois(params));
    }

    gtld
}

fn format_dnssec_info(secure_dns: &Option<SecureDns>) -> String {
    let mut dnssec_info = String::new();

    if let Some(secure_dns) = secure_dns {
        if secure_dns
            .delegation_signed
            .as_ref()
            .unwrap_or(&Boolish::from(false))
            .into_bool()
        {
            dnssec_info.push_str("DNSSEC: signedDelegation\n");
            if let Some(ds_data) = &secure_dns.ds_data {
                for ds in ds_data {
                    if let (Some(key_tag), Some(algorithm), Some(digest_type), Some(digest)) = (
                        ds.key_tag.as_ref(),
                        ds.algorithm.as_ref(),
                        ds.digest_type.as_ref(),
                        ds.digest.as_ref(),
                    ) {
                        dnssec_info.push_str(&format!(
                            "DNSSEC DS Data: {} {} {} {}\n",
                            key_tag, algorithm, digest_type, digest
                        ));
                    }
                }
            }
        }
    }

    dnssec_info
}

fn format_last_update_info(events: &Option<Vec<Event>>, gtld: &mut String) {
    if let Some(events) = events {
        for event in events {
            if let Some(event_action) = &event.event_action {
                if event_action == "last update of RDAP database" {
                    if let Some(event_date) = &event.event_date {
                        gtld.push_str(&format!(
                            ">>> Last update of RDAP database: {} <<<\n",
                            event_date
                        ));
                    }
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use crate::gtld::ToGtldWhois;

    use super::GtldParams;
    use icann_rdap_common::response::Domain;
    use icann_rdap_common::response::RdapResponse;
    use serde_json::Value;
    use std::any::TypeId;
    use std::error::Error;
    use std::fs::File;
    use std::io::Read;

    fn process_gtld_file(file_path: &str) -> Result<String, Box<dyn Error>> {
        let mut file = File::open(file_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let toplevel_json_response: Value = serde_json::from_str(&contents)?;

        let actual = serde_json::from_value::<Domain>(toplevel_json_response);
        let gtld_version_of_the_domain = match actual {
            Ok(domain) => {
                let rdap_response = RdapResponse::Domain(Domain::builder().ldh_name("").build());
                let mut gtld_params = GtldParams {
                    root: &rdap_response,
                    parent_type: TypeId::of::<Domain>(),
                    label: "".to_string(),
                };
                domain.to_gtld_whois(&mut gtld_params)
            }
            Err(e) => {
                return Err(Box::new(e));
            }
        };

        Ok(gtld_version_of_the_domain)
    }

    #[test]
    fn test_ms_click_response() {
        let expected_output =
            std::fs::read_to_string("src/test_files/microsoft.click-expected.gtld").unwrap();

        let output = process_gtld_file("src/test_files/microsoft.click.json").unwrap();
        assert_eq!(output, expected_output);
    }

    #[test]
    fn test_lemonde_response() {
        let expected_output =
            std::fs::read_to_string("src/test_files/lemonde.fr-expected.gtld").unwrap();

        let output = process_gtld_file("src/test_files/lemonde.fr.json").unwrap();
        assert_eq!(output, expected_output);
    }

    #[test]
    fn test_moscow_response() {
        let expected_output =
            std::fs::read_to_string("src/test_files/home.moscow-expected.gtld").unwrap();

        let output = process_gtld_file("src/test_files/home.moscow.json").unwrap();
        assert_eq!(output, expected_output);
    }
}
