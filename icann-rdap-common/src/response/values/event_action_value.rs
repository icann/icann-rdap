//! Event Actions

use super::EnumDisplay;
use strum::EnumString;

#[derive(PartialEq, Eq, Debug, EnumString, EnumDisplay)]
pub enum EventActionValue {
    #[strum(serialize = "registration")]
    Registration,
    #[strum(serialize = "reregistration")]
    Reregistration,
    #[strum(serialize = "last changed")]
    LastChanged,
    #[strum(serialize = "expiration")]
    Expiration,
    #[strum(serialize = "deletion")]
    Deletion,
    #[strum(serialize = "reinstantiation")]
    Reinstantiation,
    #[strum(serialize = "transfer")]
    Transfer,
    #[strum(serialize = "locked")]
    Locked,
    #[strum(serialize = "unlocked")]
    Unlocked,
    #[strum(serialize = "last update of RDAP database")]
    LastUpdateOfRDAPDatabase,
    #[strum(serialize = "registrar expiration")]
    RegistrarExpiration,
    #[strum(serialize = "enum validation expiration")]
    EnumValidationExpiration,
}
