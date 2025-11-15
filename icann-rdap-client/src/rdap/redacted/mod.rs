//! Redaction logic.

#[doc(inline)]
pub use registered_redactions::*;
#[doc(inline)]
pub use simplify::*;

pub(crate) mod registered_redactions;
pub(crate) mod simplify;
mod simplify_ids;
mod simplify_names;
