//! Notice/Remark Values.

use super::EnumDisplay;
use strum::EnumString;

#[derive(PartialEq, Eq, Debug, EnumString, EnumDisplay)]
pub enum NrType {
    #[strum(serialize = "result set truncated due to authorization")]
    ResultSetTruncatedDueToAuthorization,
    #[strum(serialize = "result set truncated due to excessive load")]
    ResultSetTruncatedDueToExcessiveLoad,
    #[strum(serialize = "result set truncated due to unexplainable reasons")]
    ResultSetTruncatedDueToUnexplainableReasons,
    #[strum(serialize = "object truncated due to authorization")]
    ObjectTruncatedDueToAuthorization,
    #[strum(serialize = "object truncated due to excessive load")]
    ObjectTruncatedDueToExcessiveLoad,
    #[strum(serialize = "object truncated due to unexplainable reasons")]
    ObjectTruncatedDueToUnexplainableReasons,
    #[strum(serialize = "object redacted due to authorization")]
    ObjectRedactedDueToAuthorization,
}
