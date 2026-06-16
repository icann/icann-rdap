//! Status Values

use super::EnumDisplay;
use strum::EnumString;

/// RDAP status values registered with IANA.
#[derive(PartialEq, Eq, Debug, EnumString, EnumDisplay)]
pub enum StatusValue {
    #[strum(serialize = "validated")]
    Validated,
    #[strum(serialize = "renew prohibited")]
    RenewProhibited,
    #[strum(serialize = "update prohibited")]
    UpdatedProhibited,
    #[strum(serialize = "transfer prohibited")]
    TransferProhibited,
    #[strum(serialize = "delete prohibited")]
    DeleteProhibited,
    #[strum(serialize = "proxy")]
    Proxy,
    #[strum(serialize = "private")]
    Private,
    #[strum(serialize = "removed")]
    Removed,
    #[strum(serialize = "obscured")]
    Obscured,
    #[strum(serialize = "associated")]
    Associated,
    #[strum(serialize = "active")]
    Active,
    #[strum(serialize = "inactive")]
    Inactive,
    #[strum(serialize = "locked")]
    Locked,
    #[strum(serialize = "pending create")]
    PendingCreate,
    #[strum(serialize = "pending renew")]
    PendingRenew,
    #[strum(serialize = "pending transfer")]
    PendingTransfer,
    #[strum(serialize = "pending update")]
    PendingUpdate,
    #[strum(serialize = "pending delete")]
    PendingDelete,
    #[strum(serialize = "add period")]
    AddPeriod,
    #[strum(serialize = "auto renew period")]
    AutoRenewPeriod,
    #[strum(serialize = "client delete prohibited")]
    ClientDeleteProhibited,
    #[strum(serialize = "client hold")]
    ClientHold,
    #[strum(serialize = "client renew prohibited")]
    ClientRenewProhibited,
    #[strum(serialize = "client transfer prohibited")]
    ClientTransferProhibited,
    #[strum(serialize = "client update prohibited")]
    ClientUpdateProhibited,
    #[strum(serialize = "pending restore")]
    PendingRestore,
    #[strum(serialize = "redemption period")]
    RedemptionPeriod,
    #[strum(serialize = "renew period")]
    RenewPeriod,
    #[strum(serialize = "server delete prohibited")]
    ServerDeleteProhibited,
    #[strum(serialize = "server renew prohibited")]
    ServerRenewProhibited,
    #[strum(serialize = "server transfer prohibited")]
    ServerTransferProhibited,
    #[strum(serialize = "server update prohibited")]
    ServerUpdateProhibited,
    #[strum(serialize = "server hold")]
    ServerHold,
    #[strum(serialize = "transfer hold")]
    TransferPeriod,
    #[strum(serialize = "administrative")]
    Administrative,
    #[strum(serialize = "reserved")]
    Reserved,
}
