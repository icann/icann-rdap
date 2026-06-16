//! IANA registered roles for entities.

use super::EnumDisplay;
use strum::EnumString;

/// Entity Roles registered with IANA.
#[derive(PartialEq, Eq, Debug, EnumString, EnumDisplay)]
#[strum(serialize_all = "lowercase")]
pub enum EntityRole {
    Registrant,
    Technical,
    Administrative,
    Abuse,
    Billing,
    Registrar,
    Reseller,
    Sponsor,
    Proxy,
    Notifications,
    Noc,
}
