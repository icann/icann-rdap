//! Things representing registrations from the IANA RDAP registries.

use {
    super::Extension,
    serde::{Deserialize, Serialize},
    strum_macros::{AsRefStr, Display, EnumString},
};

/// Extension Identifiers
///
/// This enum uses [EnumString] and [AsRefStr] to allow serialization
/// and deserialization of the variant to the matching name in the IANA registry.
///
/// To get the variant from a string:
///
/// ```rust
/// use std::str::FromStr;
/// use icann_rdap_common::prelude::*;
///
/// let cidr0 = ExtensionId::from_str("cidr0").unwrap();
/// assert_eq!(cidr0, ExtensionId::Cidr0);
/// println!("{}", cidr0.to_string());
/// ```
///
/// To get the enum variants as a string:
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let s = ExtensionId::Cidr0.to_string();
/// ```
///
/// To get the enum variants as a &str:
///
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let s = ExtensionId::Cidr0.as_ref();
/// ```
#[derive(Serialize, Deserialize, EnumString, Display, Debug, PartialEq, Eq, AsRefStr)]
pub enum ExtensionId {
    #[strum(serialize = "rdap_level_0")]
    RdapLevel0,
    #[strum(serialize = "arin_originas0")]
    ArinOriginAs0,
    #[strum(serialize = "artRecord")]
    ArtRecord,
    #[strum(serialize = "cidr0")]
    Cidr0,
    #[strum(serialize = "farv1")]
    Farv1,
    #[strum(serialize = "fred")]
    Fred,
    #[strum(serialize = "extErr")]
    ExtendedError, // TODO register this extension
    #[strum(serialize = "icann_rdap_response_profile_0")]
    IcannRdapResponseProfile0,
    #[strum(serialize = "icann_rdap_response_profile_1")]
    IcannRdapResponseProfile1,
    #[strum(serialize = "icann_rdap_technical_implementation_guide_0")]
    IcannRdapTechnicalImplementationGuide0,
    #[strum(serialize = "icann_rdap_technical_implementation_guide_1")]
    IcannRdapTechnicalImplementationGuide1,
    #[strum(serialize = "nro_rdap_profile_0")]
    NroRdapProfile0,
    #[strum(serialize = "nro_rdap_profile_asn_flat_0")]
    NroRdapProfileAsnFlat0,
    #[strum(serialize = "nro_rdap_profile_asn_hierarchical_0")]
    NroRdapProfileAsnHierarchical0,
    #[strum(serialize = "paging")]
    Paging,
    #[strum(serialize = "platformNS")]
    PlatformNs,
    #[strum(serialize = "rdap_objectTag")]
    RdapObjectTag,
    #[strum(serialize = "redacted")]
    Redacted,
    #[strum(serialize = "redirect_with_content")]
    RedirectWithContent,
    #[strum(serialize = "regType")]
    RegType,
    #[strum(serialize = "reverse_search")]
    ReverseSearch,
    #[strum(serialize = "sorting")]
    Sorting,
    #[strum(serialize = "subsetting")]
    Subsetting,
}

impl ExtensionId {
    /// Gets an [Extension] from an Extension ID.
    pub fn to_extension(&self) -> Extension {
        Extension(self.to_string())
    }
}
