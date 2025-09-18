//! Converts RDAP structures to gTLD Whois output.

use {
    icann_rdap_common::{contact::PostalAddress, response::RdapResponse},
    std::any::TypeId,
};

pub mod domain;
pub mod entity;
pub mod nameserver;
pub mod network;
pub mod types;

#[derive(Clone)]
pub struct GtldParams<'a> {
    pub root: &'a RdapResponse,
    pub parent_type: TypeId,
    pub label: String,
}

impl GtldParams<'_> {
    pub fn from_parent(&mut self, parent_type: TypeId) -> Self {
        Self {
            parent_type,
            root: self.root,
            label: self.label.clone(),
        }
    }

    pub fn next_level(&self) -> Self {
        Self {
            label: self.label.clone(),
            ..*self
        }
    }
}

pub trait ToGtldWhois {
    fn to_gtld_whois(&self, params: &mut GtldParams) -> String;
}

impl ToGtldWhois for RdapResponse {
    fn to_gtld_whois(&self, params: &mut GtldParams) -> String {
        let mut gtld = String::new();
        let variant_gtld = match &self {
            Self::Domain(domain) => domain.to_gtld_whois(params),
            // if this gets expanded, the exception handling in main.rs needs to be updated
            _ => String::new(),
        };
        gtld.push_str(&variant_gtld);
        gtld
    }
}

impl ToGtldWhois for PostalAddress {
    fn to_gtld_whois(&self, params: &mut GtldParams) -> String {
        let label = &params.label;

        let street = self
            .street_parts
            .as_ref()
            .map(|parts| parts.join(" "))
            .unwrap_or_default();
        let city = self.locality.as_deref().unwrap_or("");
        let state = self.region_name.as_deref().unwrap_or("");
        let postal_code = self.postal_code.as_deref().unwrap_or("");
        let country = self.country_code.as_deref().unwrap_or("");

        format!(
            "{} Street: {}\n{} City: {}\n{} State/Province: {}\n{} Postal Code: {}\n{} Country: {}\n",
            label, street, label, city, label, state, label, postal_code, label, country
        )
    }
}

#[derive(Default)]
pub struct RoleInfo {
    name: String,
    org: String,
    adr: String,
    email: String,
    phone: String,
    fax: String,
}
