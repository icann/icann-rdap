//! Easy representation of contact information found in an Entity.
//!
//! This module converts contact information to and from vCard/jCard, which is hard to
//! work with directly. It is also intended as a way of bridging the between vCard/jCard
//! and any new contact model.
//!
//! This struct can be built using the builder.
//!
//! ```rust
//! use icann_rdap_common::contact::Contact;
//!
//! let contact = Contact::builder()
//!   .kind("individual")
//!   .full_name("Bob Smurd")
//!   .build();
//! ```
//!
//! Once built, a Contact struct can be converted to an array of [serde_json::Value]'s,
//! which can be used with serde to serialize to JSON.
//!
//! ```rust
//! use icann_rdap_common::contact::Contact;
//! use serde::Serialize;
//! use serde_json::Value;
//!
//! let contact = Contact::builder()
//!   .kind("individual")
//!   .full_name("Bob Smurd")
//!   .build();
//!
//! let v = contact.to_vcard();
//! let json = serde_json::to_string(&v);
//! ```
//!
//! To deserialize, use the `from_vcard` function.
//!
//! ```rust
//! use icann_rdap_common::contact::Contact;
//! use serde::Deserialize;
//! use serde_json::Value;
//!
//! let json = r#"
//! [
//!   "vcard",
//!   [
//!     ["version", {}, "text", "4.0"],
//!     ["fn", {}, "text", "Joe User"],
//!     ["kind", {}, "text", "individual"],
//!     ["org", {
//!       "type":"work"
//!     }, "text", "Example"],
//!     ["title", {}, "text", "Research Scientist"],
//!     ["role", {}, "text", "Project Lead"],
//!     ["adr",
//!       { "type":"work" },
//!       "text",
//!       [
//!         "",
//!         "Suite 1234",
//!         "4321 Rue Somewhere",
//!         "Quebec",
//!         "QC",
//!         "G1V 2M2",
//!         "Canada"
//!       ]
//!     ],
//!     ["tel",
//!       { "type":["work", "voice"], "pref":"1" },
//!       "uri", "tel:+1-555-555-1234;ext=102"
//!     ],
//!     ["email",
//!       { "type":"work" },
//!       "text", "joe.user@example.com"
//!     ]
//!   ]
//! ]"#;
//!
//! let data: Vec<Value> = serde_json::from_str(json).unwrap();
//! let contact = Contact::from_vcard(&data).unwrap();
//!
//! // use the getter functions to access the data.
//! let kind = contact.kind();
//! let email_addr = contact.emails().first().unwrap().email();
//! ```

mod from_vcard;
pub(crate) mod jscontact;
mod to_vcard;

use std::{collections::BTreeMap, fmt::Display};

use buildstructor::Builder;

use crate::prelude::to_opt_vec;

/// Represents a contact. This more closely represents an EPP Contact with some
/// things taken from JSContact.
///
/// Using the builder to create the Contact:
/// ```rust
/// use icann_rdap_common::contact::Contact;
///
/// let contact = Contact::builder()
///   .kind("individual")
///   .full_name("Bob Smurd")
///   .build();
/// ```
///
///
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Contact {
    /// Preferred languages.
    pub(crate) langs: Option<Vec<Lang>>,

    /// The kind such as individual, company, etc...
    pub(crate) kind: Option<String>,

    /// Email addresses.
    pub(crate) emails: Option<Vec<Email>>,

    /// Phone numbers.
    pub(crate) phones: Option<Vec<Phone>>,

    /// Contact URIs.
    pub(crate) contact_uris: Option<Vec<String>>,

    /// URLs
    pub(crate) urls: Option<Vec<String>>,

    /// The unlocalalized parts.
    pub(crate) unlocalized: Localizable,

    /// Localizations
    pub(crate) localizations: BTreeMap<String, Localizable>,
}

#[buildstructor::buildstructor]
impl Contact {
    #[builder(visibility = "pub")]
    fn new(
        langs: Vec<Lang>,
        kind: Option<String>,
        full_name: Option<String>,
        name_parts: Option<NameParts>,
        nick_names: Vec<String>,
        titles: Vec<String>,
        roles: Vec<String>,
        organization_names: Vec<String>,
        postal_addresses: Vec<PostalAddress>,
        emails: Vec<Email>,
        phones: Vec<Phone>,
        contact_uris: Vec<String>,
        urls: Vec<String>,
    ) -> Self {
        Self {
            langs: to_opt_vec(langs),
            kind,
            unlocalized: Localizable {
                full_name,
                name_parts,
                nick_names: to_opt_vec(nick_names),
                titles: to_opt_vec(titles),
                roles: to_opt_vec(roles),
                organization_names: to_opt_vec(organization_names),
                postal_addresses: to_opt_vec(postal_addresses),
            },
            emails: to_opt_vec(emails),
            phones: to_opt_vec(phones),
            contact_uris: to_opt_vec(contact_uris),
            urls: to_opt_vec(urls),
            localizations: BTreeMap::new(),
        }
    }

    /// Returns false if there is data in the Contact.
    pub fn is_non_empty(&self) -> bool {
        self.langs.is_some()
            || self.kind.is_some()
            || self.unlocalized.full_name.is_some()
            || self.unlocalized.name_parts.is_some()
            || self.unlocalized.nick_names.is_some()
            || self.unlocalized.titles.is_some()
            || self.unlocalized.roles.is_some()
            || self.unlocalized.organization_names.is_some()
            || self.unlocalized.postal_addresses.is_some()
            || self.emails.is_some()
            || self.phones.is_some()
            || self.contact_uris.is_some()
            || self.urls.is_some()
    }

    /// Set a localization.
    pub fn with_localization(mut self, lang: String, localization: Localizable) -> Self {
        self.localizations.insert(lang, localization);
        self
    }

    /// Set the set of emails.
    pub fn with_email_addresses(mut self, emails: &[impl ToString]) -> Self {
        let emails: Vec<Email> = emails
            .iter()
            .map(|e| Email::builder().email(e.to_string()).build())
            .collect();
        self.emails = (!emails.is_empty()).then_some(emails);
        self
    }

    /// Set the emails.
    pub fn with_emails(mut self, emails: Vec<Email>) -> Self {
        self.emails = Some(emails);
        self
    }

    /// Add a voice phone to the set of phones.
    pub fn with_voice_phone_numbers(mut self, phones: &[impl ToString]) -> Self {
        let mut phones: Vec<Phone> = phones
            .iter()
            .map(|p| {
                Phone::builder()
                    .contexts(vec!["voice".to_string()])
                    .phone(p.to_string())
                    .build()
            })
            .collect();
        if let Some(mut self_phones) = self.phones.clone() {
            phones.append(&mut self_phones);
        } else {
            self.phones = (!phones.is_empty()).then_some(phones);
        }
        self
    }

    /// Add a facsimile phone to the set of phones.
    pub fn with_fax_phone_numbers(mut self, phones: &[impl ToString]) -> Self {
        let mut phones: Vec<Phone> = phones
            .iter()
            .map(|p| {
                Phone::builder()
                    .contexts(vec!["fax".to_string()])
                    .phone(p.to_string())
                    .build()
            })
            .collect();
        if let Some(mut self_phones) = self.phones.clone() {
            phones.append(&mut self_phones);
        } else {
            self.phones = (!phones.is_empty()).then_some(phones);
        }
        self
    }

    /// Set the phones.
    pub fn with_phones(mut self, phones: Vec<Phone>) -> Self {
        self.phones = Some(phones);
        self
    }

    /// Set the set of postal addresses to only be the passed in postal address.
    pub fn with_postal_address(mut self, postal_address: PostalAddress) -> Self {
        self.unlocalized.postal_addresses = Some(vec![postal_address]);
        self
    }

    /// Set the complete set of postal addresses.
    pub fn with_postal_addresses(mut self, postal_addresses: Vec<PostalAddress>) -> Self {
        self.unlocalized.postal_addresses = Some(postal_addresses);
        self
    }

    /// Set the full name.
    pub fn with_full_name(mut self, full_name: String) -> Self {
        self.unlocalized.full_name = Some(full_name);
        self
    }

    /// Set the name parts.
    pub fn with_name_parts(mut self, name_parts: Option<NameParts>) -> Self {
        self.unlocalized.name_parts = name_parts;
        self
    }

    /// Set the nick names.
    pub fn with_nick_names(mut self, nick_names: Vec<String>) -> Self {
        self.unlocalized.nick_names = (!nick_names.is_empty()).then_some(nick_names);
        self
    }

    /// Set the titles.
    pub fn with_titles(mut self, titles: Vec<String>) -> Self {
        self.unlocalized.titles = (!titles.is_empty()).then_some(titles);
        self
    }

    /// Set the organizational roles.
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.unlocalized.roles = (!roles.is_empty()).then_some(roles);
        self
    }

    /// Set the organization names.
    pub fn with_organization_names(mut self, organization_names: Vec<String>) -> Self {
        self.unlocalized.organization_names = Some(organization_names);
        self
    }

    /// Set the kind.
    pub fn with_kind(mut self, kind: String) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Set the langs.
    pub fn with_langs(mut self, langs: Vec<Lang>) -> Self {
        self.langs = (!langs.is_empty()).then_some(langs);
        self
    }

    /// Get the langs.
    pub fn langs(&self) -> &[Lang] {
        self.langs.as_deref().unwrap_or_default()
    }

    /// Get the first language tag.
    pub fn lang(&self) -> Option<&Lang> {
        self.langs().first()
    }

    /// Get the kind.
    pub fn kind(&self) -> Option<&str> {
        self.kind.as_deref()
    }

    /// Get the full name.
    pub fn full_name(&self) -> Option<&str> {
        self.unlocalized.full_name.as_deref()
    }

    /// Get the name parts.
    pub fn name_parts(&self) -> Option<&NameParts> {
        self.unlocalized.name_parts.as_ref()
    }

    /// Get the nick names.
    pub fn nick_names(&self) -> &[String] {
        self.unlocalized.nick_names.as_deref().unwrap_or_default()
    }

    /// Get the titles.
    pub fn titles(&self) -> &[String] {
        self.unlocalized.titles.as_deref().unwrap_or_default()
    }

    /// Get the organizational roles.
    pub fn roles(&self) -> &[String] {
        self.unlocalized.roles.as_deref().unwrap_or_default()
    }

    /// Get the organization names.
    pub fn organization_names(&self) -> &[String] {
        self.unlocalized
            .organization_names
            .as_deref()
            .unwrap_or_default()
    }

    /// Get the first organization name.
    pub fn organization_name(&self) -> Option<&str> {
        self.organization_names().first().map(|x| x.as_str())
    }

    /// Get the postal addresses.
    pub fn postal_addresses(&self) -> &[PostalAddress] {
        self.unlocalized
            .postal_addresses
            .as_deref()
            .unwrap_or_default()
    }

    /// Get the first postal address.
    pub fn postal_address(&self) -> Option<&PostalAddress> {
        self.postal_addresses().first()
    }

    /// Get the emails.
    pub fn emails(&self) -> &[Email] {
        self.emails.as_deref().unwrap_or_default()
    }

    /// Get the first email.
    pub fn email(&self) -> Option<&Email> {
        self.emails().first()
    }

    /// Get the phones.
    pub fn phones(&self) -> &[Phone] {
        self.phones.as_deref().unwrap_or_default()
    }

    /// Get the first phone.
    pub fn phone(&self) -> Option<&Phone> {
        self.phones().first()
    }

    /// Get the first phone with the voice feature.
    pub fn voice_phone(&self) -> Option<&Phone> {
        self.phones()
            .iter()
            .find(|phone| phone.features().contains(&"voice".to_string()))
    }

    /// Get the first phone with the fax feature.
    pub fn fax_phone(&self) -> Option<&Phone> {
        self.phones()
            .iter()
            .find(|phone| phone.features().contains(&"fax".to_string()))
    }

    /// Get the voice phone else get the first phone.
    pub fn prefer_voice_phone(&self) -> Option<&Phone> {
        self.voice_phone().or_else(|| self.phone())
    }

    /// Get the contact uris.
    pub fn contact_uris(&self) -> &[String] {
        self.contact_uris.as_deref().unwrap_or_default()
    }

    /// Get the first contact uri.
    pub fn contact_uri(&self) -> Option<&str> {
        self.contact_uris().first().map(|x| x.as_str())
    }

    /// Get the URLs.
    pub fn urls(&self) -> &[String] {
        self.urls.as_deref().unwrap_or_default()
    }

    /// Get the first URL.
    pub fn url(&self) -> Option<&str> {
        self.urls().first().map(|x| x.as_str())
    }

    /// Get a localization for a language tag.
    pub fn localization(&self, lang: &str) -> Option<&Localizable> {
        self.localizations.get(lang)
    }

    /// Get an iterator over the localizations.
    pub fn localizations_iter(&self) -> impl Iterator<Item = (&String, &Localizable)> {
        self.localizations.iter()
    }

    /// Get a mutable iterator over the localizations.
    pub fn localizations_iter_mut(&mut self) -> impl Iterator<Item = (&String, &mut Localizable)> {
        self.localizations.iter_mut()
    }

    /// Are there no localizations.
    pub fn localizations_is_empty(&self) -> bool {
        self.localizations.is_empty()
    }
}

/// Represents parts of the contact that can be localized.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Localizable {
    /// Full name of the contact.
    pub(crate) full_name: Option<String>,

    /// Structured parts of the name.
    pub(crate) name_parts: Option<NameParts>,

    /// Nick names.
    pub(crate) nick_names: Option<Vec<String>>,

    /// Titles.
    pub(crate) titles: Option<Vec<String>>,

    /// Organizational Roles
    pub(crate) roles: Option<Vec<String>>,

    /// Organization names.
    pub(crate) organization_names: Option<Vec<String>>,

    /// Postal addresses.
    pub(crate) postal_addresses: Option<Vec<PostalAddress>>,
}

#[buildstructor::buildstructor]
impl Localizable {
    #[builder(visibility = "pub")]
    fn new(
        full_name: Option<String>,
        name_parts: Option<NameParts>,
        nick_names: Vec<String>,
        titles: Vec<String>,
        roles: Vec<String>,
        organization_names: Vec<String>,
        postal_addresses: Vec<PostalAddress>,
    ) -> Self {
        Self {
            full_name,
            name_parts,
            nick_names: to_opt_vec(nick_names),
            titles: to_opt_vec(titles),
            roles: to_opt_vec(roles),
            organization_names: to_opt_vec(organization_names),
            postal_addresses: to_opt_vec(postal_addresses),
        }
    }

    /// Get the full name.
    pub fn full_name(&self) -> Option<&str> {
        self.full_name.as_deref()
    }

    /// Get the name parts.
    pub fn name_parts(&self) -> Option<&NameParts> {
        self.name_parts.as_ref()
    }

    /// Get the nick names.
    pub fn nick_names(&self) -> &[String] {
        self.nick_names.as_deref().unwrap_or_default()
    }

    /// Get the titles.
    pub fn titles(&self) -> &[String] {
        self.titles.as_deref().unwrap_or_default()
    }

    /// Get the organizational roles.
    pub fn roles(&self) -> &[String] {
        self.roles.as_deref().unwrap_or_default()
    }

    /// Get the organization names.
    pub fn organization_names(&self) -> &[String] {
        self.organization_names.as_deref().unwrap_or_default()
    }

    /// Get the first organization name.
    pub fn organization_name(&self) -> Option<&str> {
        self.organization_names().first().map(|x| x.as_str())
    }

    /// Get the postal addresses.
    pub fn postal_addresses(&self) -> &[PostalAddress] {
        self.postal_addresses.as_deref().unwrap_or_default()
    }

    /// Get the first postal address.
    pub fn postal_address(&self) -> Option<&PostalAddress> {
        self.postal_addresses().first()
    }

    /// Set the set of postal addresses to only be the passed in postal address.
    pub fn with_postal_address(mut self, postal_address: PostalAddress) -> Self {
        self.postal_addresses = Some(vec![postal_address]);
        self
    }

    /// Set the complete set of postal addresses.
    pub fn with_postal_addresses(mut self, postal_addresses: Vec<PostalAddress>) -> Self {
        self.postal_addresses = Some(postal_addresses);
        self
    }

    /// Set the full name.
    pub fn with_full_name(mut self, full_name: String) -> Self {
        self.full_name = Some(full_name);
        self
    }

    /// Set the organization names.
    pub fn with_organization_names(mut self, organization_names: Vec<String>) -> Self {
        self.organization_names = Some(organization_names);
        self
    }

    /// Set the name parts.
    pub fn with_name_parts(mut self, name_parts: Option<NameParts>) -> Self {
        self.name_parts = name_parts;
        self
    }

    /// Set the nick names.
    pub fn with_nick_names(mut self, nick_names: Vec<String>) -> Self {
        self.nick_names = (!nick_names.is_empty()).then_some(nick_names);
        self
    }

    /// Set the titles.
    pub fn with_titles(mut self, titles: Vec<String>) -> Self {
        self.titles = (!titles.is_empty()).then_some(titles);
        self
    }

    /// Set the organizational roles.
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = (!roles.is_empty()).then_some(roles);
        self
    }
}

/// The language preference of the contact.
#[derive(Debug, Builder, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lang {
    /// The ordinal of the preference for this language.
    pub preference: Option<u64>,

    /// RFC 5646 language tag.
    pub tag: String,
}

impl Lang {
    /// Get the preference.
    pub fn preference(&self) -> Option<u64> {
        self.preference
    }

    /// Get the RFC 5646 language tag.
    pub fn tag(&self) -> &str {
        self.tag.as_str()
    }
}

impl Display for Lang {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(pref) = self.preference {
            write!(f, "{} (pref: {})", self.tag, pref)
        } else {
            f.write_str(&self.tag)
        }
    }
}

/// Name parts of a name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NameParts {
    /// Name prefixes such as titles or honorifics (e.g. "Mr., Mrs., Dr.").
    pub prefixes: Option<Vec<String>>,

    /// Surnames or last names.
    pub surnames: Option<Vec<String>>,

    /// Middle names.
    pub middle_names: Option<Vec<String>>,

    /// Given or first names.
    pub given_names: Option<Vec<String>>,

    /// Name suffixes such as credentials and honorifics (e.g. "Esq.").
    pub suffixes: Option<Vec<String>>,

    /// Generation markers (e.g. "Jr.", "III").
    pub generations: Option<Vec<String>>,
}

#[buildstructor::buildstructor]
impl NameParts {
    #[builder(visibility = "pub")]
    fn new(
        prefixes: Vec<String>,
        surnames: Vec<String>,
        middle_names: Vec<String>,
        given_names: Vec<String>,
        suffixes: Vec<String>,
        generations: Vec<String>,
    ) -> Self {
        Self {
            prefixes: to_opt_vec(prefixes),
            surnames: to_opt_vec(surnames),
            middle_names: to_opt_vec(middle_names),
            given_names: to_opt_vec(given_names),
            suffixes: to_opt_vec(suffixes),
            generations: to_opt_vec(generations),
        }
    }

    /// Get the name prefixes.
    pub fn prefixes(&self) -> &[String] {
        self.prefixes.as_deref().unwrap_or_default()
    }

    /// Get the first prefix.
    pub fn prefix(&self) -> Option<&str> {
        self.prefixes().first().map(|x| x.as_str())
    }

    /// Get the sur names.
    pub fn surnames(&self) -> &[String] {
        self.surnames.as_deref().unwrap_or_default()
    }

    /// Get the first surname.
    pub fn surname(&self) -> Option<&str> {
        self.surnames().first().map(|x| x.as_str())
    }

    /// Get the middle names.
    pub fn middle_names(&self) -> &[String] {
        self.middle_names.as_deref().unwrap_or_default()
    }

    /// Get the first middle name.
    pub fn middle_name(&self) -> Option<&str> {
        self.middle_names().first().map(|x| x.as_str())
    }

    /// Get the given names.
    pub fn given_names(&self) -> &[String] {
        self.given_names.as_deref().unwrap_or_default()
    }

    /// Get the first given name.
    pub fn given_name(&self) -> Option<&str> {
        self.given_names().first().map(|x| x.as_str())
    }

    /// Get the suffixes.
    pub fn suffixes(&self) -> &[String] {
        self.suffixes.as_deref().unwrap_or_default()
    }

    /// Get the first suffix.
    pub fn suffix(&self) -> Option<&str> {
        self.suffixes().first().map(|x| x.as_str())
    }

    /// Get the generations.
    pub fn generations(&self) -> &[String] {
        self.generations.as_deref().unwrap_or_default()
    }

    /// Get the first generation.
    pub fn generation(&self) -> Option<&str> {
        self.generations().first().map(|x| x.as_str())
    }
}

/// A postal address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PostalAddress {
    /// Preference of this address in relation to others.
    pub preference: Option<u64>,

    /// Work, home, etc.... Known as "type" in JCard.
    pub contexts: Option<Vec<String>>,

    /// An unstructured address. An unstructured postal address is
    /// usually the complete postal address. That is, this string
    /// would contain the street address, country, region, postal code, etc...
    ///
    /// Depending on how the postal address is given, it can either
    /// be structured or unstructured. If it is given as unstructured,
    /// then this value is populated.
    ///
    /// It is possible that a single postal address is given as both,
    /// in which case this value is populated along with the other
    /// values of the postal address.   
    pub full_address: Option<String>,

    /// Invidual street lines.
    pub street_parts: Option<Vec<String>>,

    /// City name, county name, etc...
    pub locality: Option<String>,

    /// Name of region (i.e. state, province, etc...).
    pub region_name: Option<String>,

    /// Code for region.
    pub region_code: Option<String>,

    /// Name of the country.
    pub country_name: Option<String>,

    /// Code of the country.
    pub country_code: Option<String>,

    /// Postal code.
    pub postal_code: Option<String>,
}

#[buildstructor::buildstructor]
impl PostalAddress {
    #[builder(visibility = "pub")]
    fn new(
        preference: Option<u64>,
        contexts: Vec<String>,
        full_address: Option<String>,
        street_parts: Vec<String>,
        locality: Option<String>,
        region_name: Option<String>,
        region_code: Option<String>,
        country_name: Option<String>,
        country_code: Option<String>,
        postal_code: Option<String>,
    ) -> Self {
        Self {
            preference,
            contexts: to_opt_vec(contexts),
            full_address,
            street_parts: to_opt_vec(street_parts),
            locality,
            region_name,
            region_code,
            country_name,
            country_code,
            postal_code,
        }
    }

    /// Get the preference.
    pub fn preference(&self) -> Option<u64> {
        self.preference
    }

    /// Get the contexts.
    pub fn contexts(&self) -> &[String] {
        self.contexts.as_deref().unwrap_or_default()
    }

    /// Get the full address.
    ///
    /// An unstructured address. An unstructured postal address is
    /// usually the complete postal address. That is, this string
    /// would contain the street address, country, region, postal code, etc...
    ///
    /// Depending on how the postal address is given, it can either
    /// be structured or unstructured. If it is given as unstructured,
    /// then this value is populated.
    ///
    /// It is possible that a single postal address is given as both,
    /// in which case this value is populated along with the other
    /// values of the postal address.   
    pub fn full_address(&self) -> Option<&str> {
        self.full_address.as_deref()
    }

    /// Get the street parts.
    pub fn street_parts(&self) -> &[String] {
        self.street_parts.as_deref().unwrap_or_default()
    }

    /// Get the locality.
    pub fn locality(&self) -> Option<&str> {
        self.locality.as_deref()
    }

    /// Get the region name.
    pub fn region_name(&self) -> Option<&str> {
        self.region_name.as_deref()
    }

    /// Get the region code.
    pub fn region_code(&self) -> Option<&str> {
        self.region_code.as_deref()
    }

    /// Get the country name.
    pub fn country_name(&self) -> Option<&str> {
        self.country_name.as_deref()
    }

    /// Get the country code.
    pub fn country_code(&self) -> Option<&str> {
        self.country_code.as_deref()
    }

    /// Get the postal code.
    pub fn postal_code(&self) -> Option<&str> {
        self.postal_code.as_deref()
    }

    /// Set the postal code.
    pub fn with_postal_code(mut self, postal_code: String) -> Self {
        self.postal_code = Some(postal_code);
        self
    }

    /// Set the locality.
    pub fn with_locality(mut self, locality: String) -> Self {
        self.locality = Some(locality);
        self
    }

    pub fn with_street_parts(mut self, street_parts: Vec<String>) -> Self {
        self.street_parts = Some(street_parts);
        self
    }
}

/// Represents an email address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Email {
    /// Preference of this email in relation to others.
    pub preference: Option<u64>,

    /// Work, home, etc.... Known as "type" in JCard.
    pub contexts: Option<Vec<String>>,

    /// The email address.
    pub email: String,
}

#[buildstructor::buildstructor]
impl Email {
    #[builder(visibility = "pub")]
    fn new(preference: Option<u64>, contexts: Vec<String>, email: String) -> Self {
        Self {
            preference,
            contexts: to_opt_vec(contexts),
            email,
        }
    }

    /// Get the preference.
    pub fn preference(&self) -> Option<u64> {
        self.preference
    }

    /// Get the contexts.
    pub fn contexts(&self) -> &[String] {
        self.contexts.as_deref().unwrap_or_default()
    }

    /// Get the email address.
    pub fn email(&self) -> &str {
        self.email.as_str()
    }
}

impl Display for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut qualifiers = vec![];
        if let Some(pref) = self.preference {
            qualifiers.push(format!("(pref: {pref})"));
        }
        if let Some(contexts) = &self.contexts {
            qualifiers.push(format!("({})", contexts.join(",")));
        }
        let qualifiers = qualifiers.join(" ");
        if qualifiers.is_empty() {
            f.write_str(&self.email)
        } else {
            write!(f, "{} {}", &self.email, qualifiers)
        }
    }
}

/// Represents phone number.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Phone {
    /// Preference of this phone in relation to others.
    pub preference: Option<u64>,

    /// Work, home, etc.... Known as "type" in JCard.
    pub contexts: Option<Vec<String>>,

    /// The phone number.
    pub phone: String,

    /// Features (voice, fax, etc...)
    pub features: Option<Vec<String>>,
}

#[buildstructor::buildstructor]
impl Phone {
    #[builder(visibility = "pub")]
    fn new(
        preference: Option<u64>,
        contexts: Vec<String>,
        phone: String,
        features: Vec<String>,
    ) -> Self {
        Self {
            preference,
            contexts: to_opt_vec(contexts),
            phone,
            features: to_opt_vec(features),
        }
    }

    /// Get the preference.
    pub fn preference(&self) -> Option<u64> {
        self.preference
    }

    /// Get the contexts.
    pub fn contexts(&self) -> &[String] {
        self.contexts.as_deref().unwrap_or_default()
    }

    /// Get the phone number.
    pub fn phone(&self) -> &str {
        self.phone.as_str()
    }

    /// Get the phone features.
    pub fn features(&self) -> &[String] {
        self.features.as_deref().unwrap_or_default()
    }
}

impl Display for Phone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut qualifiers = vec![];
        if let Some(pref) = self.preference {
            qualifiers.push(format!("(pref: {pref})"));
        }
        if let Some(contexts) = &self.contexts {
            qualifiers.push(format!("({})", contexts.join(",")));
        }
        if let Some(features) = &self.features {
            qualifiers.push(format!("({})", features.join(",")));
        }
        let qualifiers = qualifiers.join(" ");
        if qualifiers.is_empty() {
            f.write_str(&self.phone)
        } else {
            write!(f, "{} {}", &self.phone, qualifiers)
        }
    }
}
