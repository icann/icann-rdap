pub mod from_vcard;
pub mod to_vcard;

use buildstructor::Builder;

/// Represents a contact. This more closely represents an EPP Contact with some
/// things taken from JSContact.
#[derive(Debug, Builder, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Contact {
    /// Preferred languages.
    pub langs: Option<Vec<Lang>>,

    /// The kind such as individual, company, etc...
    pub kind: Option<String>,

    /// Full name of the contact.
    pub full_name: Option<String>,

    /// Structured parts of the name.
    pub name_parts: Option<NameParts>,

    /// Nick names.
    pub nick_names: Option<Vec<String>>,

    /// Titles.
    pub titles: Option<Vec<String>>,

    /// Organization names.
    pub organization_names: Option<Vec<String>>,

    /// Postal addresses.
    pub postal_addresses: Option<Vec<PostalAddress>>,

    /// Email addresses.
    pub emails: Option<Vec<Email>>,

    /// Phone numbers.
    pub phones: Option<Vec<Phone>>,
}

/// The language preference of the contact.
#[derive(Debug, Builder, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lang {
    /// The ordinal of the preference for this language.
    pub preference: Option<u64>,

    /// RFC 5646 language tag.
    pub tag: String,
}

/// Name parts of a name.
#[derive(Debug, Builder, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NameParts {
    /// Name prefixes.
    pub prefixes: Option<Vec<String>>,

    /// Surnames or last names.
    pub surnames: Option<Vec<String>>,

    /// Middle names.
    pub middle_names: Option<Vec<String>>,

    /// Given or first names.
    pub given_names: Option<Vec<String>>,

    /// Name suffixes.
    pub suffixes: Option<Vec<String>>,
}

/// A postal address.
#[derive(Debug, Builder, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PostalAddress {
    /// Preference of this address in relation to others.
    pub preference: Option<u64>,

    /// Work, home, etc.... Known as "type" in JCard.
    pub contexts: Option<Vec<String>>,

    /// An unstructured address.
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

/// Represents an email address.
#[derive(Debug, Builder, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Email {
    /// Preference of this email in relation to others.
    pub preference: Option<u64>,

    /// Work, home, etc.... Known as "type" in JCard.
    pub contexts: Option<Vec<String>>,

    /// The email address.
    pub email: String,
}

/// Represents phone number.
#[derive(Debug, Builder, Clone, PartialEq, Eq, PartialOrd, Ord)]
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
