//! IANA and RDAP Bootstrapping

#[doc(inline)]
pub use bootstrap::*;
#[doc(inline)]
pub use iana_request::*;

pub(crate) mod bootstrap;
pub(crate) mod iana_request;
